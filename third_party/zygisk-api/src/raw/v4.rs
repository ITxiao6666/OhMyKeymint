use core::ptr::NonNull;

use jni::{JNIEnv, sys::JNINativeMethod};
use libc::{c_char, c_int, c_long, dev_t, ino_t};

use crate::api::{V4, ZygiskApi};

use super::{ApiTableRef, BaseApi, Instance, ModuleAbi, ModuleAbiRef, ZygiskRaw};

pub(crate) mod transparent {
    pub use crate::raw::v1::transparent::{ServerSpecializeArgs, ZygiskOption};
    pub use crate::raw::v2::transparent::StateFlags;
    pub use crate::raw::v3::transparent::AppSpecializeArgs;
}

#[repr(C)]
pub struct ApiTable {
    pub(crate) base: BaseApi<V4>,

    pub(crate) hook_jni_native_methods_fn:
        unsafe extern "C" fn(JNIEnv<'_>, *const c_char, NonNull<JNINativeMethod>, c_int),
    pub(crate) plt_hook_register_fn: unsafe extern "C" fn(
        dev_t,
        ino_t,
        *const c_char,
        *const libc::c_void,
        &mut *const libc::c_void,
    ),
    pub(crate) exempt_fd_fn: extern "C" fn(c_int) -> bool,
    pub(crate) plt_hook_commit_fn: extern "C" fn() -> bool,
    pub(crate) connect_companion_fn: unsafe extern "C" fn(NonNull<Instance>) -> c_int,
    pub(crate) set_option_fn: unsafe extern "C" fn(NonNull<Instance>, transparent::ZygiskOption),
    pub(crate) get_module_dir_fn: unsafe extern "C" fn(NonNull<Instance>) -> c_int,
    pub(crate) get_flags_fn: unsafe extern "C" fn(NonNull<Instance>) -> u32,
}

impl<'a> ZygiskRaw<'a> for V4 {
    const API_VERSION: c_long = 4;
    type ApiTable = ApiTable;
    type AppSpecializeArgs = transparent::AppSpecializeArgs<'a>;
    type ServerSpecializeArgs = transparent::ServerSpecializeArgs<'a>;

    #[inline(always)]
    fn abi_from_module(module: &'a mut super::RawModule<'a, Self>) -> ModuleAbi<'a, Self> {
        extern "C" fn pre_app_specialize<'a>(
            m: &mut super::RawModule<'a, V4>,
            args: &'a mut transparent::AppSpecializeArgs<'a>,
        ) {
            m.dispatch.pre_app_specialize(
                ZygiskApi::<V4>(m.api_table),
                unsafe { m.jni_env.unsafe_clone() },
                args,
            );
        }

        extern "C" fn post_app_specialize<'a>(
            m: &mut super::RawModule<'a, V4>,
            args: &'a transparent::AppSpecializeArgs<'a>,
        ) {
            m.dispatch.post_app_specialize(
                ZygiskApi::<V4>(m.api_table),
                unsafe { m.jni_env.unsafe_clone() },
                args,
            );
        }

        extern "C" fn pre_server_specialize<'a>(
            m: &mut super::RawModule<'a, V4>,
            args: &'a mut transparent::ServerSpecializeArgs<'a>,
        ) {
            m.dispatch.pre_server_specialize(
                ZygiskApi::<V4>(m.api_table),
                unsafe { m.jni_env.unsafe_clone() },
                args,
            );
        }

        extern "C" fn post_server_specialize<'a>(
            m: &mut super::RawModule<'a, V4>,
            args: &'a transparent::ServerSpecializeArgs<'a>,
        ) {
            m.dispatch.post_server_specialize(
                ZygiskApi::<V4>(m.api_table),
                unsafe { m.jni_env.unsafe_clone() },
                args,
            );
        }

        ModuleAbi {
            api_version: Self::API_VERSION,
            this: module,
            pre_app_specialize_fn: pre_app_specialize,
            post_app_specialize_fn: post_app_specialize,
            pre_server_specialize_fn: pre_server_specialize,
            post_server_specialize_fn: post_server_specialize,
        }
    }

    #[inline(always)]
    fn register_module_fn(
        table: ApiTableRef<Self>,
    ) -> unsafe extern "C" fn(ApiTableRef<Self>, ModuleAbiRef<'_, Self>) -> bool {
        unsafe { &*table.0 }.base.register_module_fn
    }
}
