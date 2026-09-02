#![warn(clippy::std_instead_of_core)]
#![no_std]
extern crate std;

use api::ZygiskApi;
use jni::JNIEnv;
use raw::ZygiskRaw;

pub mod api;
// `aux.rs` is a reserved filename on Windows, so the vendored source uses a
// portable module name while preserving the upstream API surface.
mod aux_mod;
pub use aux_mod::*;
pub mod error;
pub mod raw;

#[doc(hidden)]
pub mod utils;
pub(crate) mod impl_sealing {
    pub trait Sealed {}
}

#[allow(unused_variables)]
pub trait ZygiskModule {
    /// The API version that this module is built against
    type Api: for<'a> ZygiskRaw<'a>;

    /// This method gets called as soon as the Zygisk module gets loaded into the target process
    fn on_load(&self, api: ZygiskApi<'_, Self::Api>, env: JNIEnv<'_>) {}

    /// This method gets called before the target process is specialized as an app process
    ///
    /// At this point, this process just got forked from zygote, but no app-specific specialization process has been done yet.
    /// This means that the process is still running with the same privilege as zygote.
    ///
    /// All of the arguments that will get used to specialize the app process is available for mutation through the exclusive `AppSpecializeArgs` reference (`args`).
    /// Modules can read and overwrite these arguments to change behaviors of the app specialization.
    ///
    /// If you need to perform operations as the superuser, the `api.with_companion(..)` instance method can be used to safely communicate with a root companion process through a closure.
    fn pre_app_specialize<'a>(
        &self,
        api: ZygiskApi<'a, Self::Api>,
        env: JNIEnv<'a>,
        args: &'a mut <Self::Api as ZygiskRaw<'_>>::AppSpecializeArgs,
    ) {
    }

    /// This method gets called after the target process has been specialized as an app process.
    ///
    /// At this point, the process has been fully specialized, and is running with the privileges of the target app.
    fn post_app_specialize<'a>(
        &self,
        api: ZygiskApi<'a, Self::Api>,
        env: JNIEnv<'a>,
        args: &'a <Self::Api as ZygiskRaw<'_>>::AppSpecializeArgs,
    ) {
    }

    /// This method gets called before the target process is specialized as the system server process.
    ///
    /// See [`ZygiskModule::pre_app_specialize`] for more details.
    fn pre_server_specialize<'a>(
        &self,
        api: ZygiskApi<'a, Self::Api>,
        env: JNIEnv<'a>,
        args: &'a mut <Self::Api as ZygiskRaw<'_>>::ServerSpecializeArgs,
    ) {
    }

    /// This method gets called after the target process has been specialized as the system server process.
    ///
    /// At this point, the process has been fully specialized, and is running with the privileges of the system server.
    fn post_server_specialize<'a>(
        &self,
        api: ZygiskApi<'a, Self::Api>,
        env: JNIEnv<'a>,
        args: &'a <Self::Api as ZygiskRaw<'_>>::ServerSpecializeArgs,
    ) {
    }
}

/// Registers a [`ZygiskModule`] implementation as the module's entry point.
///
/// This macro exports a function symbol named `zygisk_module_entry` that Zygisk will use as an entry point to initialize the module.
/// The provided type must implement the [`ZygiskModule`] trait and have a [`Default`] implementation.
///
/// # Example
///
/// ```
/// #[derive(Default)]
/// struct MyModule;
///
/// impl zygisk_api::ZygiskModule for MyModule {
///    type Api = zygisk_api::api::V5;
/// }
///
/// zygisk_api::register_module!(MyModule);
/// ```
///
/// If a reference to the entry function is needed, it can be obtained through an `extern "C"` block:
///
/// ```ignore
/// unsafe extern "C" {
///     #[link_name = "zygisk_module_entry"]
///      fn entry_fn(
///          api_table: *const (),
///          env: *mut jni::sys::JNIEnv,
///      );
/// }
/// ```
#[macro_export]
macro_rules! register_module {
    ($module:ty) => {
        const _: () = {
            #[unsafe(export_name = "zygisk_module_entry")]
            unsafe extern "C" fn module_entry(
                api_table: *const (),
                env: *mut $crate::jni::sys::JNIEnv,
            ) {
                if ::std::panic::catch_unwind(
                    #[inline(always)]
                    move || {
                        type Api = <$module as $crate::ZygiskModule>::Api;
                        type RawModule<'a> = $crate::raw::RawModule<'a, Api>;
                        type ModuleAbi<'a> = $crate::raw::ModuleAbi<'a, Api>;

                        #[repr(transparent)]
                        struct AssertSyncUnsafeCell<T>(::core::cell::UnsafeCell<T>);

                        unsafe impl<T> Sync for AssertSyncUnsafeCell<T> {}

                        impl<T> AssertSyncUnsafeCell<T> {
                            #[inline(always)]
                            const fn new(value: T) -> Self {
                                Self(::core::cell::UnsafeCell::new(value))
                            }
                        }

                        static INSTANCE: AssertSyncUnsafeCell<::core::mem::MaybeUninit<$module>> =
                            const { AssertSyncUnsafeCell::new(::core::mem::MaybeUninit::uninit()) };
                        static RAW_MODULE: AssertSyncUnsafeCell<
                            ::core::mem::MaybeUninit<RawModule<'static>>,
                        > = AssertSyncUnsafeCell::new(::core::mem::MaybeUninit::uninit());
                        static MODULE_ABI: AssertSyncUnsafeCell<
                            ::core::mem::MaybeUninit<ModuleAbi<'static>>,
                        > = const { AssertSyncUnsafeCell::new(::core::mem::MaybeUninit::uninit()) };

                        unsafe { &mut *INSTANCE.0.get() }
                            .write(<$module as ::core::default::Default>::default());
                        let api_table =
                            unsafe { $crate::raw::ApiTableRef::from_raw(api_table as *const _) };

                        unsafe { &mut *RAW_MODULE.0.get() }.write($crate::raw::RawModule {
                            dispatch: unsafe { (&*INSTANCE.0.get()).assume_init_ref() },
                            api_table: ::core::clone::Clone::clone(&api_table),
                            jni_env: unsafe {
                                $crate::jni::JNIEnv::from_raw(env).unwrap_unchecked()
                            },
                        });

                        unsafe { &mut *MODULE_ABI.0.get() }.write(
                            <Api as $crate::raw::ZygiskRaw>::abi_from_module(unsafe {
                                (&mut *RAW_MODULE.0.get()).assume_init_mut()
                            }),
                        );

                        let abi = unsafe {
                            $crate::raw::ModuleAbiRef::from_raw(
                                (&mut *MODULE_ABI.0.get()).as_mut_ptr(),
                            )
                        };

                        if unsafe {
                            <Api as $crate::raw::ZygiskRaw>::register_module_fn(api_table)(
                                api_table, abi,
                            )
                        } {
                            unsafe { (&*INSTANCE.0.get()).assume_init_ref() }
                                .on_load($crate::api::ZygiskApi(api_table), unsafe {
                                    $crate::jni::JNIEnv::from_raw(env).unwrap_unchecked()
                                })
                        }
                    },
                )
                .is_err()
                {
                    ::std::process::abort();
                }
            }
        };
    };
}

/// Registers a function that will act as the entry point for the module's companion process
///
/// The provided function must have the signature `fn(&mut std::os::unix::net::UnixStream)`.
/// This function will be called when the companion process is started, and it will receive a
/// `UnixStream` connected to the Zygisk module
#[macro_export]
macro_rules! register_companion {
    ($func: expr) => {
        const _: () = {
            #[unsafe(export_name = "zygisk_companion_entry")]
            extern "C" fn companion_entry(sock_fd: ::std::os::fd::OwnedFd) {
                if ::std::panic::catch_unwind(
                    #[inline(always)]
                    move || {
                        let mut stream =
                            <::std::os::unix::net::UnixStream as ::core::convert::From<
                                ::std::os::fd::OwnedFd,
                            >>::from(sock_fd);

                        let func: for<'a> fn(&'a mut ::std::os::unix::net::UnixStream) = $func;
                        func(&mut stream)
                    },
                )
                .is_err()
                {
                    ::std::process::abort();
                }
            }
        };
    };
}

#[cfg(test)]
mod compile_test {
    use crate::{ZygiskModule, api};

    #[derive(Default)]
    struct MyModule;

    impl ZygiskModule for MyModule {
        type Api = api::V5;
    }
    register_module!(MyModule);

    register_companion!(|_| ());
}
