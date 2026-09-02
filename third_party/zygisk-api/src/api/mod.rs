use crate::raw::{ApiTableRef, ZygiskRaw};

pub mod v1;
pub use v1::V1;

pub mod v2;
pub use v2::V2;

pub mod v3;
pub use v3::V3;

pub mod v4;
pub use v4::V4;

pub mod v5;
pub use v5::V5;

#[repr(transparent)]
pub struct ZygiskApi<'a, Version>(#[doc(hidden)] pub ApiTableRef<'a, Version>)
where
    Version: ZygiskRaw<'a> + 'a;

impl<'a, Version> ZygiskApi<'a, Version>
where
    Version: ZygiskRaw<'a> + 'a,
{
    #[doc(hidden)]
    #[inline(always)]
    pub unsafe fn dispatch(&self) -> &<Version as ZygiskRaw<'a>>::ApiTable {
        unsafe { &*self.0.0 }
    }
}
