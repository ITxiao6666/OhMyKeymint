use core::{ffi, mem, ops::Deref, ptr::NonNull};
use std::os::{
    fd::{FromRawFd, RawFd},
    unix::net::UnixStream,
};

use jni::{JNIEnv, strings::JNIStr, sys::JNINativeMethod};
use libc::{dev_t, ino_t};

use crate::{error::ZygiskError, impl_sealing::Sealed, utils};

pub use crate::raw::v5::transparent::*;

#[derive(Clone, Copy)]
pub struct V5;

impl Sealed for V5 {}

impl super::ZygiskApi<'_, V5> {
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

    #[inline(always)]
    pub fn get_module_dir(&self) -> RawFd {
        let api_dispatch = unsafe { self.dispatch() };

        unsafe { (api_dispatch.get_module_dir_fn)(api_dispatch.base.this) }
    }

    #[inline(always)]
    pub fn set_option(&mut self, option: ZygiskOption) {
        let api_dispatch = unsafe { self.dispatch() };

        unsafe { (api_dispatch.set_option_fn)(api_dispatch.base.this, option) }
    }

    #[inline(always)]
    pub fn get_flags(&self) -> Result<StateFlags, ZygiskError> {
        let api_dispatch = unsafe { self.dispatch() };

        let flags = unsafe { (api_dispatch.get_flags_fn)(api_dispatch.base.this) };

        match StateFlags::from_bits(flags) {
            Some(flags) => Ok(flags),
            None => Err(ZygiskError::UnrecognizedStateFlag(flags)),
        }
    }

    /// # Safety
    ///
    #[inline(always)]
    pub unsafe fn hook_jni_native_methods(
        &mut self,
        env: JNIEnv,
        class_name: impl Deref<Target = JNIStr>,
        mut methods: impl AsMut<[JNINativeMethod]>,
    ) {
        let class_name = class_name.deref();
        let methods = methods.as_mut();

        unsafe {
            (self.dispatch().hook_jni_native_methods_fn)(
                env,
                class_name.as_ptr(),
                NonNull::new_unchecked(methods.as_mut_ptr()),
                methods.len() as _,
            )
        };
    }

    /// # Safety
    ///
    #[inline(always)]
    pub unsafe fn plt_hook_register<'a, 'b>(
        &'a mut self,
        device: dev_t,
        inode: ino_t,
        symbol: impl AsRef<ffi::CStr>,
        replacement: *const (),
        original: &'b mut *const (),
    ) where
        'b: 'a,
    {
        let symbol = symbol.as_ref();

        // fail compilation if data and function pointer sizes don't match (not supported)
        let _: () = utils::ShapeAssertion::<*const (), extern "C" fn()>::ASSERT;

        // SAFETY: We ensure that the lifetime of `original` outlives the call to the C function.
        let original =
            unsafe { mem::transmute::<&'b mut *const (), &'b mut *const libc::c_void>(original) };

        unsafe {
            (self.dispatch().plt_hook_register_fn)(
                device,
                inode,
                symbol.to_bytes_with_nul().as_ptr().cast(),
                replacement.cast(),
                original,
            )
        }
    }

    #[inline(always)]
    pub fn plt_hook_commit(&mut self) -> Result<(), ZygiskError> {
        match unsafe { (self.dispatch().plt_hook_commit_fn)() } {
            true => Ok(()),
            false => Err(ZygiskError::PltHookCommitError),
        }
    }
}
