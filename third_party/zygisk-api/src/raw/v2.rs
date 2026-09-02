use core::ptr::NonNull;

use jni::{JNIEnv, sys::JNINativeMethod};
use libc::{c_char, c_int, c_long};

use crate::{
    api::{V2, ZygiskApi},
    raw::RawModule,
};

use super::{ApiTableRef, BaseApi, Instance, ModuleAbi, ModuleAbiRef, ZygiskRaw};

pub(crate) mod transparent {

    pub use crate::raw::v1::transparent::{AppSpecializeArgs, ServerSpecializeArgs, ZygiskOption};

    bitflags::bitflags! {
        pub struct StateFlags: u32 {
            const PROCESS_GRANTED_ROOT = (1 << 0);
            const PROCESS_ON_DENYLIST = (1 << 1);
        }
    }
}
#[repr(C)]
pub struct ApiTable {
    pub(crate) base: BaseApi<V2>,

    pub(crate) hook_jni_native_methods_fn:
        for<'a> unsafe extern "C" fn(JNIEnv<'a>, *const c_char, NonNull<JNINativeMethod>, c_int),
    pub(crate) plt_hook_register_fn: unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const libc::c_void,
        &mut *const libc::c_void,
    ),
    pub(crate) plt_hook_exclude_fn: unsafe extern "C" fn(*const c_char, *const c_char),
    pub(crate) plt_hook_commit_fn: extern "C" fn() -> bool,
    pub(crate) connect_companion_fn: unsafe extern "C" fn(NonNull<Instance>) -> c_int,
    pub(crate) set_option_fn: unsafe extern "C" fn(NonNull<Instance>, transparent::ZygiskOption),
    pub(crate) get_module_dir_fn: unsafe extern "C" fn(NonNull<Instance>) -> c_int,
    pub(crate) get_flags_fn: unsafe extern "C" fn(NonNull<Instance>) -> u32,
}

impl<'a> ZygiskRaw<'a> for V2 {
    const API_VERSION: c_long = 2;
    type ApiTable = ApiTable;
    type AppSpecializeArgs = transparent::AppSpecializeArgs<'a>;
    type ServerSpecializeArgs = transparent::ServerSpecializeArgs<'a>;

    #[inline(always)]
    fn abi_from_module(module: &'a mut super::RawModule<'a, V2>) -> ModuleAbi<'a, Self> {
        extern "C" fn pre_app_specialize<'a>(
            m: &mut RawModule<'a, V2>,
            args: &'a mut transparent::AppSpecializeArgs<'a>,
        ) {
            m.dispatch.pre_app_specialize(
                ZygiskApi::<V2>(m.api_table),
                unsafe { m.jni_env.unsafe_clone() },
                args,
            );
        }

        extern "C" fn post_app_specialize<'a>(
            m: &mut RawModule<'a, V2>,
            args: &'a transparent::AppSpecializeArgs<'a>,
        ) {
            m.dispatch.post_app_specialize(
                ZygiskApi::<V2>(m.api_table),
                unsafe { m.jni_env.unsafe_clone() },
                args,
            );
        }

        extern "C" fn pre_server_specialize<'a>(
            m: &mut RawModule<'a, V2>,
            args: &'a mut transparent::ServerSpecializeArgs<'a>,
        ) {
            m.dispatch.pre_server_specialize(
                ZygiskApi::<V2>(m.api_table),
                unsafe { m.jni_env.unsafe_clone() },
                args,
            );
        }

        extern "C" fn post_server_specialize<'a>(
            m: &mut RawModule<'a, V2>,
            args: &'a transparent::ServerSpecializeArgs<'a>,
        ) {
            m.dispatch.post_server_specialize(
                ZygiskApi::<V2>(m.api_table),
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
