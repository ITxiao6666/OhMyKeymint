use core::{ffi, mem, ops::Deref, ptr::NonNull};
use std::os::{fd::FromRawFd, unix::net::UnixStream};

use jni::{JNIEnv, strings::JNIStr, sys::JNINativeMethod};

use crate::utils;
use crate::{error::ZygiskError, impl_sealing::Sealed};

pub use crate::raw::v1::transparent::*;

#[derive(Clone, Copy)]
pub struct V1;

impl Sealed for V1 {}

impl super::ZygiskApi<'_, V1> {
    /// Connect to a root companion process and get a Unix domain socket for IPC.
    ///
    /// This API only works in the `pre[XXX]Specialize` functions due to SELinux restrictions.
    ///
    /// The `pre[XXX]Specialize` functions run with the same privilege of zygote.
    /// If you would like to do some operations with superuser permissions, register a handler
    /// function that would be called in the root process with `zygisk_companion!(handler_func)`.
    /// Another good use case for a companion process is that if you want to share some resources
    /// across multiple processes, hold the resources in the companion process and pass it over.
    ///
    /// The root companion process is ABI aware; that is, when calling this function from a 32-bit
    /// process, you will be connected to a 32-bit companion process, and vice versa for 64-bit.
    ///
    /// Returns a [UnixStream] that is connected to the socket passed to your module's companion
    /// request handler. Returns `Err` if the connection attempt failed.
    #[inline(always)]
    pub fn with_companion<R>(
        &mut self,
        f: impl FnOnce(&mut UnixStream) -> R,
    ) -> Result<R, ZygiskError> {
        let api_dispatch = unsafe { self.dispatch() };

        match unsafe { (api_dispatch.connect_companion_fn)(api_dispatch.base.this) } {
            -1 => Err(ZygiskError::ConnectCompanionError),
            fd => {
                let mut companion_sock = unsafe { UnixStream::from_raw_fd(fd) };
                Ok(f(&mut companion_sock))
            }
        }
    }

    /// Set various options for your module.
    /// Check [ZygiskOption] for the full list of options available.
    #[inline(always)]
    pub fn set_option(&mut self, option: ZygiskOption) {
        let api_dispatch = unsafe { self.dispatch() };

        unsafe { (api_dispatch.set_option_fn)(api_dispatch.base.this, option) };
    }

    /// Hook JNI native methods for a Java class.
    ///
    /// This looks up all registered JNI native methods and replaces them with your own functions.
    /// The original function pointer will be saved in each `JNINativeMethod`'s `fnPtr` (thus the
    /// `&mut` requirement in the function signature).
    ///
    /// If no matching class, method name, or signature is found, that specific `JNINativeMethod.fnPtr`
    /// will be set to [std::ptr::null_mut()].
    ///
    /// ## Safety
    ///
    /// This function is unsafe, since a badly designed hook or misuse of raw pointers may lead to
    /// memory unsafety.
    #[inline(always)]
    pub unsafe fn hook_jni_native_methods(
        &mut self,
        env: JNIEnv,
        class_name: impl Deref<Target = JNIStr>,
        mut methods: impl AsMut<[JNINativeMethod]>,
    ) {
        let class_name = class_name.deref();
        let methods = methods.as_mut();

        (unsafe { self.dispatch().hook_jni_native_methods_fn })(
            env,
            class_name.as_ptr(),
            unsafe { NonNull::new_unchecked(methods.as_mut_ptr()) },
            methods.len() as _,
        );
    }

    /// Hook functions in the PLT (Procedure Linkage Table) of ELFs loaded in memory.
    ///
    /// Parsing `/proc/[PID]/maps` will give you the memory map of a process. As an example:
    ///
    /// ```text
    ///       <address>       <perms>  <offset>   <dev>  <inode>           <pathname>
    /// 56b4346000-56b4347000  r-xp    00002000   fe:00    235       /system/bin/app_process64
    /// ```
    /// (More details: https://man7.org/linux/man-pages/man5/proc.5.html)
    ///
    /// The `dev` and `inode` pair uniquely identifies a file being mapped into memory.
    /// For matching ELFs loaded in memory, replace function `symbol` with `new_func`.
    /// If `old_func` is not [`None`], the original function pointer will be saved to `old_func`.
    ///
    /// ## Safety
    ///
    /// This function is unsafe, since a badly designed hook or misuse of raw pointers may lead to
    /// memory unsafety.
    #[inline(always)]
    pub unsafe fn plt_hook_register<'a, 'b, S>(
        &'a mut self,
        regex: S,
        symbol: S,
        new_func: *const (),
        old_func: &'b mut *const (),
    ) where
        'b: 'a,
        S: AsRef<ffi::CStr>,
    {
        let regex = regex.as_ref();
        let symbol = symbol.as_ref();

        // fail compilation if data and function pointer sizes don't match (not supported)
        let _: () = utils::ShapeAssertion::<*const (), extern "C" fn()>::ASSERT;

        let old_func =
            unsafe { mem::transmute::<&'b mut *const (), &'b mut *const libc::c_void>(old_func) };

        unsafe {
            (self.dispatch().plt_hook_register_fn)(
                regex.to_bytes_with_nul().as_ptr().cast(),
                symbol.to_bytes_with_nul().as_ptr().cast(),
                new_func.cast(),
                old_func,
            )
        }
    }

    /// For ELFs loaded in memory matching `regex`, exclude hooks registered for `symbol`.
    /// If symbol is empty, then all symbols will be excluded.
    #[inline(always)]
    pub fn plt_hook_exclude<S>(&mut self, regex: S, symbol: S)
    where
        S: AsRef<ffi::CStr>,
    {
        let regex = regex.as_ref();
        let symbol = symbol.as_ref();

        unsafe {
            (self.dispatch().plt_hook_exclude_fn)(
                regex.to_bytes_with_nul().as_ptr().cast(),
                symbol.to_bytes_with_nul().as_ptr().cast(),
            )
        }
    }

    /// Commit all the hooks that was previously registered.
    ///
    /// Returns [`ZygiskError::PltHookCommitError`] if any error occurs.
    #[inline(always)]
    pub fn plt_hook_commit(&mut self) -> Result<(), ZygiskError> {
        match unsafe { (self.dispatch().plt_hook_commit_fn)() } {
            true => Ok(()),
            false => Err(ZygiskError::PltHookCommitError),
        }
    }
}
