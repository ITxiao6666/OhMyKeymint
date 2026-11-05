//! App-local Oplus engineering display compatibility, not key provisioning.
//! Wire behavior references tricky-soter-service host/module.cpp (AGPL-3.0+).

use std::{
    ffi::c_void,
    ptr,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicPtr, Ordering},
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

pub(super) fn install(api: &mut ZygiskApi<'_, V4>, env: &mut JNIEnv<'_>) {
    if env.exception_check().unwrap_or(true) {
        return;
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
        if intercept(code, flags, same, !data.is_null() && !reply.is_null()) {
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
