//! App-local Oplus engineering display compatibility, not key provisioning.
//! Wire behavior references tricky-soter-service host/module.cpp (AGPL-3.0+).

use std::{
    ffi::c_void,
    io::{Read, Write},
    os::{
        fd::{FromRawFd, IntoRawFd},
        unix::net::UnixStream,
    },
    ptr,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering},
    },
};

use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject, JValue},
    strings::JNIString,
    sys::{JNINativeMethod, jboolean, jint, jobject},
};
use zygisk_api::api::{V4, ZygiskApi};

const PACKAGE: &str = "com.oplus.engineermode";
const SERVICE: &str = "vendor.oplus.hardware.cryptoeng.ICryptoeng/default";
static PRE_CHANNEL: AtomicI32 = AtomicI32::new(-1);
static CHANNEL: Mutex<Option<UnixStream>> = Mutex::new(None);
static INSTALL: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
const DEX: &[u8] = include_bytes!(env!("OMK_ENGINEER_DEX"));
type Transact = unsafe extern "system" fn(
    *mut jni::sys::JNIEnv,
    jobject,
    jint,
    jobject,
    jobject,
    jint,
) -> jboolean;

static BINDER: OnceLock<GlobalRef> = OnceLock::new();
static ORIGINAL: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REPORTED: AtomicBool = AtomicBool::new(false);

pub(super) fn selected(process: Option<&str>, directory: Option<&str>) -> bool {
    process == Some(PACKAGE)
        && directory.is_none_or(|path| path.is_empty() || super::is_package_data_dir(path, PACKAGE))
}

pub(super) fn prepare(api: &mut ZygiskApi<'_, V4>, uid: u32) {
    let channel = api.with_companion(|stream| -> std::io::Result<UnixStream> {
        stream.set_write_timeout(Some(super::IPC_TIMEOUT))?;
        stream.write_all(&[2])?;
        stream.write_all(&uid.to_be_bytes())?;
        stream.try_clone()
    });
    if let Ok(Ok(channel)) = channel {
        let fd = channel.into_raw_fd();
        let _ = api.exempt_fd(fd);
        PRE_CHANNEL.store(fd, Ordering::Release);
    }
    let module = api.get_module_dir();
    if module < 0 {
        return;
    }
    // The loader grants a module directory FD before app specialization.
    // Loading by FD does not expose /data/adb or create an app-readable copy.
    let fd = unsafe {
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
    if fd < 0 {
        super::log_android("EngineerMode Java bridge file unavailable");
        return;
    }
    let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let library = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    unsafe {
        libc::close(fd);
    }
    if !library.is_null() {
        let install = unsafe { libc::dlsym(library, c"omk_engineer_install".as_ptr()) };
        INSTALL.store(install, Ordering::Release);
        // Keep the LSPlant image loaded while its process-local hooks exist.
    } else {
        super::log_android("EngineerMode Java bridge could not be loaded");
    }
}

pub(super) fn serve_selection(stream: &mut UnixStream) {
    let mut bytes = [0; 4];
    if stream.read_exact(&mut bytes).is_err() {
        return;
    }
    let uid = u32::from_be_bytes(bytes);
    if uid % 100000 != 1000 {
        return;
    }
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(Some(super::IPC_TIMEOUT));
    let mut request = [0];
    while stream.read_exact(&mut request).is_ok() && request == [1] {
        let binary = if std::path::Path::new("/data/adb/omk/inject").is_file() {
            "/data/adb/omk/inject"
        } else {
            if cfg!(target_arch = "aarch64") {
                "/data/adb/modules/oh_my_keymint/libs/arm64-v8a/inject"
            } else {
                "/data/adb/modules/oh_my_keymint/libs/x86_64/inject"
            }
        };
        let selected = std::process::Command::new(binary)
            .args(["--webui-engineer-selected", &uid.to_string()])
            .output()
            .ok()
            .is_some_and(|out| out.status.success() && out.stdout == b"true\n");
        if stream.write_all(&[u8::from(selected)]).is_err() {
            return;
        }
    }
}

fn current_selection() -> bool {
    let Ok(mut guard) = CHANNEL.lock() else {
        return false;
    };
    let Some(stream) = guard.as_mut() else {
        return false;
    };
    let mut result = [0];
    if stream.write_all(&[1]).and_then(|()| stream.read_exact(&mut result)).is_err() {
        *guard = None;
        return false;
    }
    result == [1]
}

unsafe extern "system" fn java_selected(_env: *mut jni::sys::JNIEnv, _class: jobject) -> jboolean {
    let selected = current_selection();
    super::log_android(if selected {
        "EngineerMode Attestation Key display override selected"
    } else {
        "EngineerMode Attestation Key display uses original check"
    });
    u8::from(selected)
}

pub(super) fn install(api: &mut ZygiskApi<'_, V4>, env: &mut JNIEnv<'_>) {
    if env.exception_check().unwrap_or(true) {
        return;
    }
    let fd = PRE_CHANNEL.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        // Some loaders refuse exemptFd; a post-specialization duplicate owns
        // its lifetime independently of the zygote's pending close list.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate >= 0 {
            unsafe {
                libc::close(fd);
            }
            let channel = unsafe { UnixStream::from_raw_fd(duplicate) };
            let _ = channel.set_read_timeout(Some(super::IPC_TIMEOUT));
            let _ = channel.set_write_timeout(Some(super::IPC_TIMEOUT));
            if let Ok(mut slot) = CHANNEL.lock() {
                *slot = Some(channel);
            }
        }
    }
    let entry = INSTALL.load(Ordering::Acquire);
    if !entry.is_null() {
        type Install =
            unsafe extern "C" fn(*mut jni::sys::JNIEnv, *const u8, usize, *const c_void) -> bool;
        let install: Install = unsafe { std::mem::transmute(entry) };
        let ready = unsafe {
            install(env.get_raw(), DEX.as_ptr(), DEX.len(), java_selected as *const c_void)
        };
        if !ready {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
        super::log_android(if ready {
            "EngineerMode Java status bridge installed"
        } else {
            "EngineerMode Java status bridge unavailable; original result retained"
        });
    }
    let result = env.with_local_frame(8, |env| {
        let manager = env.find_class("android/os/ServiceManager")?;
        let name = JObject::from(env.new_string(SERVICE)?);
        let binder = env
            .call_static_method(
                manager,
                "getService",
                "(Ljava/lang/String;)Landroid/os/IBinder;",
                &[JValue::Object(&name)],
            )?
            .l()?;
        if binder.is_null() {
            return Ok(false);
        }
        let parcel = env.find_class("android/os/Parcel")?;
        env.get_method_id(&parcel, "setDataPosition", "(I)V")?;
        env.get_method_id(&parcel, "writeInt", "(I)V")?;
        env.get_method_id(&parcel, "writeByteArray", "([B)V")?;
        if BINDER.set(env.new_global_ref(binder)?).is_err() {
            return Ok(false);
        }
        let mut methods = [JNINativeMethod {
            name: c"transactNative".as_ptr().cast_mut(),
            signature: c"(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z".as_ptr().cast_mut(),
            fnPtr: transact as *mut c_void,
        }];
        // The replacement follows BinderProxy's exact JNI ABI and remains
        // mapped for this selected process. Zygisk returns the original entry.
        unsafe {
            api.hook_jni_native_methods(
                env.unsafe_clone(),
                JNIString::from("android/os/BinderProxy"),
                &mut methods,
            );
        }
        let original = methods[0].fnPtr;
        if original.is_null() || original == transact as *mut c_void {
            return Ok(false);
        }
        ORIGINAL.store(original, Ordering::Release);
        Ok::<_, jni::errors::Error>(true)
    });
    match result {
        Ok(true) => super::log_android("EngineerMode cryptoeng display hook installed"),
        Ok(false) => super::log_android(
            "EngineerMode cryptoeng service or native hook unavailable; unchanged",
        ),
        Err(error) => {
            // Clear only an exception raised by this optional installation.
            let _ = env.exception_clear();
            super::log_android(&format!("EngineerMode cryptoeng hook unavailable: {error}"));
        }
    }
}

fn intercept(code: jint, flags: jint, same_binder: bool, has_parcels: bool) -> bool {
    code == 1 && flags & 1 == 0 && same_binder && has_parcels
}

unsafe extern "system" fn transact(
    raw: *mut jni::sys::JNIEnv,
    this: jobject,
    code: jint,
    data: jobject,
    reply: jobject,
    flags: jint,
) -> jboolean {
    let original = ORIGINAL.load(Ordering::Acquire);
    if original.is_null() {
        return jni::sys::JNI_FALSE;
    }
    // Published by Zygisk for BinderProxy.transactNative with this same ABI.
    let original: Transact = unsafe { std::mem::transmute(original) };
    if let Ok(mut env) = unsafe { JNIEnv::from_raw(raw) }
        && !env.exception_check().unwrap_or(true)
    {
        // JNI local arguments remain borrowed for the duration of this call.
        let this_ref = unsafe { JObject::from_raw(this) };
        let same = BINDER
            .get()
            .is_some_and(|binder| env.is_same_object(&this_ref, binder.as_obj()).unwrap_or(false));
        if intercept(code, flags, same, !data.is_null() && !reply.is_null()) && current_selection()
        {
            let result = env.with_local_frame(4, |env| {
                let reply = unsafe { JObject::from_raw(reply) };
                let zeros = JObject::from(env.byte_array_from_slice(&[0; 4])?);
                env.call_method(&reply, "setDataPosition", "(I)V", &[JValue::Int(0)])?;
                env.call_method(&reply, "writeInt", "(I)V", &[JValue::Int(0)])?;
                env.call_method(&reply, "writeByteArray", "([B)V", &[JValue::Object(&zeros)])?;
                env.call_method(&reply, "setDataPosition", "(I)V", &[JValue::Int(0)])?;
                Ok::<_, jni::errors::Error>(())
            });
            if result.is_ok() {
                if !REPORTED.swap(true, Ordering::Relaxed) {
                    super::log_android(
                        "EngineerMode cryptoeng display success synthesized; hardware keys unchanged",
                    );
                }
                return jni::sys::JNI_TRUE;
            }
            // Do not report success or invoke vendor code after a partial
            // synthetic reply. Preserve the Java exception for its caller.
            if !env.exception_check().unwrap_or(true) {
                let _ =
                    env.throw_new("java/lang/IllegalStateException", "OMK cryptoeng reply failed");
            }
            return jni::sys::JNI_FALSE;
        }
    }
    unsafe { original(raw, this, code, data, reply, flags) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_engineering_app_is_selected() {
        assert!(selected(Some(PACKAGE), Some("/data/user/0/com.oplus.engineermode")));
        assert!(selected(Some(PACKAGE), None));
        assert!(!selected(Some("com.oplus.engineermode:remote"), None));
        assert!(!selected(Some("com.tencent.soter.soterserver"), None));
        assert!(!selected(Some(PACKAGE), Some("/data/user/0/com.example.app")));
    }

    #[test]
    fn only_synchronous_cryptoeng_code_one_is_replaced() {
        assert!(intercept(1, 0, true, true));
        for args in
            [(2, 0, true, true), (1, 1, true, true), (1, 0, false, true), (1, 0, true, false)]
        {
            assert!(!intercept(args.0, args.1, args.2, args.3));
        }
    }
}
