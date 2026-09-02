use std::{
    fs,
    io::{Read, Write},
    sync::Mutex,
    time::Duration,
};

use jni::{
    JNIEnv,
    objects::{JObject, JString, JValue},
};
use pif_common::{BuildClass, MAX_PROFILE_BYTES, PifProfile};
use zygisk_api::{
    ZygiskModule,
    api::{
        V4, ZygiskApi,
        v4::{AppSpecializeArgs, ServerSpecializeArgs, ZygiskOption},
    },
};

const PROFILE_PATH: &str = "/data/misc/keystore/omk/data/pif_fingerprint.json";
const GMS_PROCESS: &str = "com.google.android.gms.unstable";
const GMS_PACKAGE: &str = "com.google.android.gms";
const IPC_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct PifSpoofModule {
    profile: Mutex<Option<PifProfile>>,
}

impl ZygiskModule for PifSpoofModule {
    type Api = V4;

    fn pre_app_specialize<'a>(
        &self,
        mut api: ZygiskApi<'a, V4>,
        mut env: JNIEnv<'a>,
        args: &'a mut AppSpecializeArgs<'_>,
    ) {
        let process = read_java_string(&mut env, args.nice_name);
        let data_dir = read_java_string(&mut env, args.app_data_dir);
        if process.as_deref() != Some(GMS_PROCESS)
            || !data_dir.as_deref().is_some_and(is_gms_data_dir)
        {
            api.set_option(ZygiskOption::DlCloseModuleLibrary);
            return;
        }

        let loaded = api
            .with_companion(read_profile_from_companion)
            .ok()
            .and_then(Result::ok)
            .flatten();
        let Some(profile) = loaded else {
            log_android("PIF profile is disabled or unavailable");
            api.set_option(ZygiskOption::DlCloseModuleLibrary);
            return;
        };
        if let Ok(mut current) = self.profile.lock() {
            *current = Some(profile);
        } else {
            log_android("PIF profile state lock is poisoned");
            api.set_option(ZygiskOption::DlCloseModuleLibrary);
        }
    }

    fn post_app_specialize<'a>(
        &self,
        mut api: ZygiskApi<'a, V4>,
        mut env: JNIEnv<'a>,
        _args: &'a AppSpecializeArgs<'a>,
    ) {
        let profile = self
            .profile
            .lock()
            .ok()
            .and_then(|mut current| current.take());
        if let Some(profile) = profile {
            match apply_build_fields(&mut env, &profile) {
                Ok(()) => log_android("PIF Build fields applied to GMS unstable"),
                Err(error) => log_android(&format!("failed to apply PIF Build fields: {error}")),
            }
        }
        api.set_option(ZygiskOption::DlCloseModuleLibrary);
    }

    fn pre_server_specialize<'a>(
        &self,
        mut api: ZygiskApi<'a, V4>,
        _env: JNIEnv<'a>,
        _args: &'a mut ServerSpecializeArgs<'_>,
    ) {
        api.set_option(ZygiskOption::DlCloseModuleLibrary);
    }
}

fn is_gms_data_dir(path: &str) -> bool {
    let allowed_root = path.starts_with("/data/user/")
        || path.starts_with("/data/user_de/")
        || path.starts_with("/mnt/expand/");
    allowed_root
        && path
            .strip_suffix(GMS_PACKAGE)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

fn read_java_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Option<String> {
    env.get_string(value).ok().map(Into::into)
}

fn read_profile_from_companion(
    stream: &mut std::os::unix::net::UnixStream,
) -> std::io::Result<Option<PifProfile>> {
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Ok(None);
    }
    if length > MAX_PROFILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "companion PIF profile exceeds the 4 KiB limit",
        ));
    }
    let mut contents = vec![0u8; length];
    stream.read_exact(&mut contents)?;
    PifProfile::from_json(&contents)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn companion(stream: &mut std::os::unix::net::UnixStream) {
    let payload = load_profile_for_companion().unwrap_or_else(|error| {
        log_android(&format!("PIF companion rejected profile: {error}"));
        Vec::new()
    });
    if let Err(error) = stream
        .set_write_timeout(Some(IPC_TIMEOUT))
        .and_then(|()| stream.write_all(&(payload.len() as u32).to_be_bytes()))
        .and_then(|()| stream.write_all(&payload))
    {
        log_android(&format!("PIF companion write failed: {error}"));
    }
}

fn load_profile_for_companion() -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(PROFILE_PATH)
        .map_err(|error| format!("failed to inspect profile: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("profile path is not a regular file".to_string());
    }
    if metadata.len() > MAX_PROFILE_BYTES as u64 {
        return Err("profile file exceeds the 4 KiB limit".to_string());
    }
    let contents =
        fs::read(PROFILE_PATH).map_err(|error| format!("failed to read profile: {error}"))?;
    let profile = PifProfile::from_json(&contents)?;
    let canonical = profile.to_canonical_json()?.into_bytes();
    if contents != canonical {
        return Err("profile file is not canonical JSON".to_string());
    }
    Ok(canonical)
}

fn apply_build_fields(env: &mut JNIEnv<'_>, profile: &PifProfile) -> Result<(), String> {
    profile.validate()?;
    let build = env
        .find_class("android/os/Build")
        .map_err(|error| format!("cannot find android.os.Build: {error}"))?;
    let version = env
        .find_class("android/os/Build$VERSION")
        .map_err(|error| format!("cannot find android.os.Build.VERSION: {error}"))?;

    for (name, value, owner) in profile.build_fields() {
        let class = match owner {
            BuildClass::Build => &build,
            BuildClass::Version => &version,
        };
        let java_value = env
            .new_string(value)
            .map_err(|error| format!("cannot create {name} value: {error}"))?;
        let object = JObject::from(java_value);
        env.set_static_field(
            class,
            (class, name, "Ljava/lang/String;"),
            JValue::Object(&object),
        )
        .map_err(|error| format!("cannot set {name}: {error}"))?;
        env.delete_local_ref(object)
            .map_err(|error| format!("cannot release {name} value: {error}"))?;
    }
    Ok(())
}

fn log_android(message: &str) {
    let tag = c"OhMyKeymint-PIF";
    let Ok(message) = std::ffi::CString::new(message) else {
        return;
    };
    unsafe {
        __android_log_write(4, tag.as_ptr(), message.as_ptr());
    }
}

#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        priority: i32,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> i32;
}

zygisk_api::register_module!(PifSpoofModule);
zygisk_api::register_companion!(companion);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_supported_gms_data_directories() {
        for path in [
            "/data/user/0/com.google.android.gms",
            "/data/user_de/10/com.google.android.gms",
            "/mnt/expand/volume/user/0/com.google.android.gms",
        ] {
            assert!(is_gms_data_dir(path), "{path}");
        }
        for path in [
            "/data/user/0/com.google.android.gms.evil",
            "/data/local/tmp/com.google.android.gms",
            "/data/user/0/other/com.google.android.gms/",
            "com.google.android.gms",
        ] {
            assert!(!is_gms_data_dir(path), "{path}");
        }
    }
}
