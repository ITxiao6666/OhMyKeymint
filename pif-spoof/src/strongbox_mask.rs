use std::{
    ffi::CString,
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
    time::Duration,
};

use jni::JNIEnv;
use serde::Deserialize;
use zygisk_api::api::{V4, ZygiskApi};

const CONFIG_PATH: &str = "/data/misc/keystore/omk/config.toml";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const COMPANION_REQUEST: u8 = 3;
const IPC_TIMEOUT: Duration = Duration::from_secs(2);

static INSTALL: AtomicPtr<libc::c_void> = AtomicPtr::new(ptr::null_mut());

#[derive(Default, Deserialize)]
#[serde(default)]
struct MaskConfig {
    main: MainConfig,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct MainConfig {
    mask_strongbox_feature: bool,
}

pub(super) fn request_enabled(stream: &mut UnixStream) -> std::io::Result<bool> {
    stream.set_write_timeout(Some(IPC_TIMEOUT))?;
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    stream.write_all(&[COMPANION_REQUEST])?;
    let mut response = [0];
    stream.read_exact(&mut response)?;
    match response[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid StrongBox mask response",
        )),
    }
}

pub(super) fn serve_companion(stream: &mut UnixStream) {
    let enabled = match read_enabled_config() {
        Ok(enabled) => enabled,
        Err(error) => {
            super::log_android(&format!("StrongBox feature mask config unavailable: {error}"));
            false
        }
    };
    let _ = stream.write_all(&[u8::from(enabled)]);
}

fn read_enabled_config() -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(CONFIG_PATH) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("failed to inspect config.toml: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("config.toml is not a regular file".to_string());
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err("config.toml exceeds the 1 MiB limit".to_string());
    }

    let contents = fs::read_to_string(CONFIG_PATH)
        .map_err(|error| format!("failed to read config.toml: {error}"))?;
    let config: MaskConfig = toml::from_str(&contents)
        .map_err(|error| format!("failed to parse config.toml: {error}"))?;
    Ok(config.main.mask_strongbox_feature)
}

pub(super) fn prepare(api: &mut ZygiskApi<'_, V4>) -> bool {
    let module = api.get_module_dir();
    if module < 0 {
        super::log_android("StrongBox feature mask module directory unavailable");
        return false;
    }

    let bridge = unsafe {
        libc::openat(
            module,
            if cfg!(target_arch = "aarch64") {
                c"libs/arm64-v8a/libomk_engineer.so".as_ptr()
            } else {
                c"libs/x86_64/libomk_engineer.so".as_ptr()
            },
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    unsafe {
        libc::close(module);
    }
    if bridge < 0 {
        super::log_android("StrongBox feature mask bridge unavailable");
        return false;
    }

    let path = match CString::new(format!("/proc/self/fd/{bridge}")) {
        Ok(path) => path,
        Err(_) => {
            unsafe { libc::close(bridge) };
            super::log_android("StrongBox feature mask bridge path is invalid");
            return false;
        }
    };
    let library = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    unsafe {
        libc::close(bridge);
    }
    if library.is_null() {
        super::log_android("StrongBox feature mask bridge could not be loaded");
        return false;
    }

    let install = unsafe { libc::dlsym(library, c"omk_strongbox_mask_install".as_ptr()) };
    if install.is_null() {
        super::log_android("StrongBox feature mask bridge entry point is missing");
        return false;
    }
    INSTALL.store(install, Ordering::Release);
    true
}

pub(super) fn install(env: &mut JNIEnv<'_>) -> bool {
    let install = INSTALL.load(Ordering::Acquire);
    if install.is_null() {
        return false;
    }
    type Install = unsafe extern "system" fn(*mut jni::sys::JNIEnv) -> bool;
    let install: Install = unsafe { std::mem::transmute(install) };
    unsafe { install(env.get_raw()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_mask_defaults_to_disabled() {
        assert!(
            !toml::from_str::<MaskConfig>("[main]\nlog_level = \"info\"")
                .unwrap()
                .main
                .mask_strongbox_feature
        );
    }

    #[test]
    fn parses_mask_setting_without_reading_other_main_fields() {
        let config: MaskConfig = toml::from_str(
            "version = 3\n[main]\nmask_strongbox_feature = true\nlog_level = \"debug\"",
        )
        .unwrap();
        assert!(config.main.mask_strongbox_feature);
    }
}
