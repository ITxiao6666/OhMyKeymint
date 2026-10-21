//! Optional D-Soter-compatible experiment, not hardware or payment-key recovery.
//!
//! Binder reply shapes follow ajfkdk/D-soter (Apache-2.0), commit
//! 6148e02ea5977cb95b5a162a405fc915e39c01db, module/jni/dsoter.cpp.
//! Public software fixtures sign exports, never biometric/payment challenges.

use std::{
    ffi::{CStr, c_char, c_void},
    mem::{align_of, size_of},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering},
    },
};

use zygisk_api::api::{V4, ZygiskApi};

pub(crate) mod relay;
mod wire;

pub(crate) const PACKAGE: &str = "com.tencent.soter.soterserver";
const DESCRIPTOR: &CStr = c"com.tencent.soter.soterserver.ISoterService";
const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_READ_BYTES;
const BINDER_WRITE_READ: i32 = 0xc030_6201u32 as i32;
const BR_TRANSACTION: u32 = 0x8040_7202;
const BR_TRANSACTION_SEC_CTX: u32 = 0x8048_7202;
const BINDER_TYPE_BINDER: u32 = 0x7362_2a85;
const BAD_VALUE: i32 = -libc::EINVAL;
const UNKNOWN_TRANSACTION: i32 = -libc::EBADMSG;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Transaction {
    target: u64,
    cookie: u64,
    code: u32,
    flags: u32,
    sender_pid: i32,
    sender_euid: u32,
    data_size: u64,
    offsets_size: u64,
    buffer: u64,
    offsets: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct WriteRead {
    write_size: u64,
    write_consumed: u64,
    write_buffer: u64,
    read_size: u64,
    read_consumed: u64,
    read_buffer: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target {
    ptr: u64,
    cookie: u64,
}

type Ioctl = unsafe extern "C" fn(i32, i32, *mut c_void) -> i32;
type OnCreate = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type OnDestroy = unsafe extern "C" fn(*mut c_void);
type OnTransact = unsafe extern "C" fn(*mut c_void, u32, *const c_void, *mut c_void) -> i32;
type ClassDefine =
    unsafe extern "C" fn(*const c_char, OnCreate, OnDestroy, OnTransact) -> *mut c_void;
type DisableInterfaceHeader = unsafe extern "C" fn(*mut c_void);
type BinderNew = unsafe extern "C" fn(*const c_void, *mut c_void) -> *mut c_void;
type BinderRef = unsafe extern "C" fn(*mut c_void);
type ParcelCreate = unsafe extern "C" fn() -> *mut c_void;
type ParcelDelete = unsafe extern "C" fn(*mut c_void);
type WriteBinder = unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32;
type ParcelSize = unsafe extern "C" fn(*const c_void) -> i32;
type ViewPlatform = unsafe extern "C" fn(*const c_void) -> *const c_void;
type PlatformData = unsafe extern "C" fn(*const c_void) -> *const u8;
type PlatformSize = unsafe extern "C" fn(*const c_void) -> usize;
type WriteInt32 = unsafe extern "C" fn(*mut c_void, i32) -> i32;
type WriteInt64 = unsafe extern "C" fn(*mut c_void, i64) -> i32;
type WriteBytes = unsafe extern "C" fn(*mut c_void, *const i8, i32) -> i32;
type CallingUid = unsafe extern "C" fn() -> u32;

// Exact Android 12/13 NDK parcel_internal.h layout, matching OMK's injector.
// Android 14+ must provide the platform accessor instead of using this layout.
#[repr(C)]
struct LegacyParcel {
    binder: *const c_void,
    parcel: *const c_void,
    owns_parcel: u8,
}

struct NativeApi {
    parcel_size: ParcelSize,
    view_platform: Option<ViewPlatform>,
    legacy_layout: bool,
    platform_data: PlatformData,
    platform_size: PlatformSize,
    platform_objects: PlatformSize,
    write_i32: WriteInt32,
    write_i64: WriteInt64,
    write_bytes: WriteBytes,
    calling_uid: CallingUid,
}

struct NativeStub {
    api: NativeApi,
    binder: usize,
    target: Target,
    state: Mutex<wire::SoftwareState>,
}

static NATIVE: OnceLock<Result<NativeStub, String>> = OnceLock::new();
static INSTALL: OnceLock<Result<(usize, usize), String>> = OnceLock::new();
static ORIGINAL_IOCTL: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ACTIVE: AtomicBool = AtomicBool::new(false);
static REMOTE_MODE: AtomicBool = AtomicBool::new(false);
static MATCHED_CODES: AtomicU32 = AtomicU32::new(0);
static REPLIED_CODES: AtomicU32 = AtomicU32::new(0);
static FAILED_CODES: AtomicU32 = AtomicU32::new(0);

pub(crate) fn log(message: &str) {
    let Ok(message) = std::ffi::CString::new(message) else {
        return;
    };
    unsafe {
        crate::__android_log_write(4, c"OhMyKeymint-Soter".as_ptr(), message.as_ptr());
    }
}

fn log_code_once(codes: &AtomicU32, code: u32, event: &str) {
    if (1..=13).contains(&code) && codes.fetch_or(1 << code, Ordering::Relaxed) & (1 << code) == 0 {
        log(&format!("{event}: code={code}"));
    }
}

/// The caller must retain the module after this call, including on failure:
/// Zygisk may have installed the PLT hook before returning a commit error.
pub(crate) fn install(api: &mut ZygiskApi<'_, V4>) -> Result<(), String> {
    INSTALL
        .get_or_init(|| {
            if size_of::<usize>() != 8 {
                return Err("Soter hook requires a 64-bit process".to_string());
            }
            // Load libraries and register the PLT hook while Zygisk's API is
            // available. Do not construct/parcel a Binder object here:
            // flattenBinder creates IPCThreadState/ProcessState and opens the
            // Binder driver before Android finishes specializing the child.
            let ndk = library(c"libbinder_ndk.so")?;
            let binder = library(c"libbinder.so")?;
            let maps = std::fs::read_to_string("/proc/self/maps")
                .map_err(|error| format!("cannot inspect libbinder mapping: {error}"))?;
            let binder_maps = maps
                .lines()
                .filter(|line| line.ends_with("/libbinder.so"))
                .collect::<Vec<_>>()
                .join("\n");
            let targets = crate::parse_hook_targets(&binder_maps);
            if targets.len() != 1 {
                return Err("Soter hook requires one unambiguous libbinder mapping".to_string());
            }
            let original = crate::resolve_symbol_address(c"ioctl")
                .ok_or_else(|| "Soter hook cannot resolve the original ioctl".to_string())?;
            ORIGINAL_IOCTL.store(original, Ordering::Release);
            // Zygisk retains this address until PLT commit. Its lifetime also
            // covers a partially successful commit, so it is never freed.
            let backup = Box::leak(Box::new(ptr::null()));
            unsafe {
                api.plt_hook_register(
                    targets[0].device,
                    targets[0].inode,
                    c"ioctl",
                    ioctl_hook as *const (),
                    backup,
                );
            }
            let result = api.plt_hook_commit();
            if !backup.is_null() {
                ORIGINAL_IOCTL.store((*backup).cast_mut().cast(), Ordering::Release);
            }
            result.map_err(|error| format!("Soter hook PLT commit failed: {error}"))?;
            if backup.is_null() {
                return Err(
                    "libbinder does not import ioctl; Soter hook stays inactive".to_string()
                );
            }
            Ok((ndk, binder))
        })
        .as_ref()
        .map(|_| ())
        .map_err(Clone::clone)
}

pub(crate) fn prepare_relay(api: &mut ZygiskApi<'_, V4>) -> Result<(), String> {
    relay::prepare(api)?;
    REMOTE_MODE.store(true, Ordering::Release);
    Ok(())
}

/// No Zygisk API is used here. Binder state is initialized only after Android
/// has assigned the app's UID, SELinux context and file-descriptor state.
pub(crate) fn activate() {
    let Some(Ok((ndk, binder))) = INSTALL.get() else {
        return;
    };
    match NATIVE.get_or_init(|| load_native(*ndk, *binder)) {
        Ok(_) => {
            ACTIVE.store(true, Ordering::Release);
            let remote = REMOTE_MODE.load(Ordering::Acquire);
            if remote && let Err(error) = relay::activate() {
                log(&format!("Soter authorization refresh unavailable: {error}"));
            }
            log(if remote {
                "Per-app Soter relay hook active; unselected callers retain stock transactions"
            } else {
                "Soter Beta software test mode active; public fixture keys, no biometric authentication"
            });
        }
        Err(error) => log(&format!("Soter native handler unavailable: {error}")),
    }
}

unsafe extern "C" fn ioctl_hook(fd: i32, request: i32, argument: *mut c_void) -> i32 {
    let original = ORIGINAL_IOCTL.load(Ordering::Acquire);
    if original.is_null() {
        unsafe { *libc::__errno() = libc::ENOSYS };
        return -1;
    }
    let original: Ioctl = unsafe { std::mem::transmute(original) };
    let result = unsafe { original(fd, request, argument) };
    let saved_errno = unsafe { *libc::__errno() };
    if result >= 0
        && request == BINDER_WRITE_READ
        && !argument.is_null()
        && ACTIVE.load(Ordering::Acquire)
    {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            inspect_read(argument.cast());
        }));
    }
    unsafe { *libc::__errno() = saved_errno };
    result
}

unsafe fn inspect_read(argument: *const WriteRead) {
    let Some(Ok(native)) = NATIVE.get() else {
        return;
    };
    let read = unsafe { ptr::read_unaligned(argument) };
    if read.read_consumed == 0
        || read.read_consumed > read.read_size
        || read.read_consumed > MAX_READ_BYTES as u64
        || !valid_pointer_range(read.read_buffer, read.read_consumed)
    {
        return;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(read.read_buffer as *mut u8, read.read_consumed as usize)
    };
    if !valid_read_commands(bytes) {
        return;
    }
    visit_transactions(bytes, |transaction| {
        if !candidate(transaction) {
            return;
        }
        let data = unsafe {
            std::slice::from_raw_parts(
                transaction.buffer as *const u8,
                transaction.data_size as usize,
            )
        };
        if retarget(
            transaction,
            data,
            native.target,
            REMOTE_MODE.load(Ordering::Acquire),
            relay::selected,
        ) {
            log_code_once(
                &MATCHED_CODES,
                transaction.code,
                "Soter request intercepted",
            );
        }
    });
}

fn valid_pointer_range(pointer: u64, size: u64) -> bool {
    pointer != 0
        && size <= isize::MAX as u64
        && pointer
            .checked_add(size)
            .is_some_and(|end| end <= usize::MAX as u64)
}

fn candidate(transaction: &Transaction) -> bool {
    (1..=13).contains(&transaction.code)
        && transaction.target != 0
        // The kernel owns and validates the payload and its object offsets.
        // Required arguments are primitive values; OEM trailing objects and
        // transaction flags remain owned and validated by the driver.
        && transaction.data_size <= MAX_REQUEST_BYTES as u64
        && valid_pointer_range(transaction.buffer, transaction.data_size)
}

fn retarget(
    transaction: &mut Transaction,
    data: &[u8],
    target: Target,
    remote: bool,
    selected: impl FnOnce(u32) -> bool,
) -> bool {
    if candidate(transaction)
        && transaction.data_size as usize == data.len()
        && wire::valid_request(transaction.code, data)
        && (!remote || ((1..=11).contains(&transaction.code) && selected(transaction.sender_euid)))
    {
        transaction.target = target.ptr;
        transaction.cookie = target.cookie;
        return true;
    }
    false
}

fn valid_read_commands(bytes: &[u8]) -> bool {
    let mut position = 0usize;
    while position < bytes.len() {
        let Some(header) = bytes.get(position..position + 4) else {
            return false;
        };
        let command = u32::from_ne_bytes(header.try_into().expect("four-byte command"));
        let size = ((command >> 16) & 0x3fff) as usize;
        position += 4;
        if bytes.len() - position < size {
            return false;
        }
        position += size;
    }
    true
}

fn visit_transactions(bytes: &mut [u8], mut visit: impl FnMut(&mut Transaction)) {
    let mut position = 0usize;
    while position + 4 <= bytes.len() {
        let command = u32::from_ne_bytes(bytes[position..position + 4].try_into().unwrap());
        position += 4;
        let size = ((command >> 16) & 0x3fff) as usize;
        let Some(payload) = bytes.get_mut(position..position + size) else {
            return;
        };
        if matches!(command, BR_TRANSACTION | BR_TRANSACTION_SEC_CTX) {
            let mut transaction =
                unsafe { ptr::read_unaligned(payload.as_ptr().cast::<Transaction>()) };
            visit(&mut transaction);
            unsafe {
                ptr::write_unaligned(payload.as_mut_ptr().cast::<Transaction>(), transaction)
            };
        }
        position += size;
    }
}

fn symbol<T: Copy>(library: usize, name: &CStr) -> Result<T, String> {
    let symbol = unsafe { libc::dlsym(library as *mut c_void, name.as_ptr()) };
    if symbol.is_null() || size_of::<T>() != size_of::<*mut c_void>() {
        return Err(format!(
            "Soter native API unavailable: {}",
            name.to_string_lossy()
        ));
    }
    Ok(unsafe { std::mem::transmute_copy(&symbol) })
}

fn library(name: &CStr) -> Result<usize, String> {
    // Handles stay resident with the callback and the native Binder stub.
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let error = unsafe { libc::dlerror() };
        let detail = if error.is_null() {
            "unknown linker error".into()
        } else {
            unsafe { CStr::from_ptr(error) }.to_string_lossy()
        };
        return Err(format!(
            "Soter hook cannot load {}: {detail}",
            name.to_string_lossy()
        ));
    }
    Ok(handle as usize)
}

fn load_native(ndk: usize, binder: usize) -> Result<NativeStub, String> {
    let view_platform = symbol(ndk, c"_Z26AParcel_viewPlatformParcelPK7AParcel").ok();
    let device_api_address = crate::resolve_symbol_address(c"android_get_device_api_level")
        .ok_or_else(|| "Soter hook cannot identify the Android API level".to_string())?;
    let device_api: unsafe extern "C" fn() -> i32 =
        unsafe { std::mem::transmute(device_api_address) };
    let sdk = unsafe { device_api() };
    if sdk < 31 || (view_platform.is_none() && !matches!(sdk, 31..=33)) {
        return Err("Soter hook cannot access this Android version's native Parcel".to_string());
    }
    let api = NativeApi {
        parcel_size: symbol(ndk, c"AParcel_getDataSize")?,
        view_platform,
        legacy_layout: matches!(sdk, 31..=33),
        platform_data: symbol(binder, c"_ZNK7android6Parcel4dataEv")?,
        platform_size: symbol(binder, c"_ZNK7android6Parcel8dataSizeEv")?,
        platform_objects: symbol(binder, c"_ZNK7android6Parcel12objectsCountEv")?,
        write_i32: symbol(ndk, c"AParcel_writeInt32")?,
        write_i64: symbol(ndk, c"AParcel_writeInt64")?,
        write_bytes: symbol(ndk, c"AParcel_writeByteArray")?,
        calling_uid: symbol(ndk, c"AIBinder_getCallingUid")?,
    };
    let define: ClassDefine = symbol(ndk, c"AIBinder_Class_define")?;
    let new: BinderNew = symbol(ndk, c"AIBinder_new")?;
    let dec_strong: BinderRef = symbol(ndk, c"AIBinder_decStrong")?;
    let create: ParcelCreate = symbol(ndk, c"AParcel_create")?;
    let delete: ParcelDelete = symbol(ndk, c"AParcel_delete")?;
    let write_binder: WriteBinder = symbol(ndk, c"AParcel_writeStrongBinder")?;
    let class = unsafe { define(DESCRIPTOR.as_ptr(), on_create, on_destroy, on_transact) };
    if class.is_null() {
        return Err("Soter hook cannot define native Binder class".to_string());
    }
    // Android 13+ supports legacy Binder interfaces without enforcing a
    // particular header layout. Descriptor matching remains in our handler,
    // as in D-soter. Android 12 retains the standard platform AIDL header check.
    if sdk >= 33 {
        let disable_header: DisableInterfaceHeader =
            symbol(ndk, c"AIBinder_Class_disableInterfaceTokenHeader")?;
        unsafe { disable_header(class) };
    }
    let stub = unsafe { new(class, ptr::null_mut()) };
    if stub.is_null() {
        return Err("Soter hook cannot allocate native Binder".to_string());
    }
    let carrier = unsafe { create() };
    if carrier.is_null() {
        unsafe { dec_strong(stub) };
        return Err("Soter hook cannot allocate Binder carrier".to_string());
    }
    let target = (|| {
        let status = unsafe { write_binder(carrier, stub) };
        if status != 0 {
            return Err(format!("Soter Binder carrier write failed: {status}"));
        }
        let bytes = unsafe { api.bytes(carrier, ptr::null(), true, Some(1))? };
        parse_carrier(bytes).ok_or_else(|| "Soter native Binder carrier is unsupported".to_string())
    })();
    unsafe { delete(carrier) };
    match target {
        Ok(target) => Ok(NativeStub {
            api,
            binder: stub as usize,
            target,
            state: Mutex::new(wire::SoftwareState::default()),
        }),
        Err(error) => {
            unsafe { dec_strong(stub) };
            Err(error)
        }
    }
}

fn parse_carrier(bytes: &[u8]) -> Option<Target> {
    if bytes.len() != 28 || u32::from_ne_bytes(bytes[0..4].try_into().ok()?) != BINDER_TYPE_BINDER {
        return None;
    }
    let ptr = u64::from_ne_bytes(bytes[8..16].try_into().ok()?);
    let cookie = u64::from_ne_bytes(bytes[16..24].try_into().ok()?);
    (ptr != 0 && cookie != 0).then_some(Target { ptr, cookie })
}

impl NativeApi {
    unsafe fn bytes<'a>(
        &self,
        parcel: *const c_void,
        binder: *const c_void,
        owns: bool,
        objects: Option<usize>,
    ) -> Result<&'a [u8], String> {
        if parcel.is_null() {
            return Err("Soter hook received a null Parcel".to_string());
        }
        let platform = if let Some(view) = self.view_platform {
            unsafe { view(parcel) }
        } else if self.legacy_layout {
            let legacy = unsafe { &*parcel.cast::<LegacyParcel>() };
            if legacy.binder != binder || legacy.owns_parcel != u8::from(owns) {
                return Err("Soter hook received an incompatible legacy Parcel".to_string());
            }
            legacy.parcel
        } else {
            ptr::null()
        };
        if platform.is_null() || !(platform as usize).is_multiple_of(align_of::<usize>()) {
            return Err("Soter hook received an invalid platform Parcel".to_string());
        }
        let size = unsafe { (self.platform_size)(platform) };
        if size > MAX_REQUEST_BYTES
            || unsafe { (self.parcel_size)(parcel) } != size as i32
            || objects
                .is_some_and(|expected| unsafe { (self.platform_objects)(platform) != expected })
        {
            return Err(
                "Soter hook received an unsupported Parcel size or object count".to_string(),
            );
        }
        if size == 0 {
            return Ok(&[]);
        }
        let data = unsafe { (self.platform_data)(platform) };
        if !valid_pointer_range(data as u64, size as u64) {
            return Err("Soter hook received an invalid Parcel buffer".to_string());
        }
        Ok(unsafe { std::slice::from_raw_parts(data, size) })
    }
}

unsafe extern "C" fn on_create(data: *mut c_void) -> *mut c_void {
    data
}
unsafe extern "C" fn on_destroy(_: *mut c_void) {}

unsafe extern "C" fn on_transact(
    binder: *mut c_void,
    code: u32,
    input: *const c_void,
    output: *mut c_void,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(Ok(native)) = NATIVE.get() else {
            return UNKNOWN_TRANSACTION;
        };
        if binder as usize != native.binder || !(1..=13).contains(&code) {
            return UNKNOWN_TRANSACTION;
        }
        let remote = REMOTE_MODE.load(Ordering::Acquire);
        let Ok(bytes) = (unsafe { native.api.bytes(input, binder, false, remote.then_some(0)) })
        else {
            return BAD_VALUE;
        };
        if !wire::valid_request(code, bytes) {
            return BAD_VALUE;
        }
        // A one-way call has no reply to deliver. The upstream stub accepts it
        // without invoking the original service.
        if output.is_null() {
            return 0;
        }
        let Ok(reply) = (unsafe { native.api.bytes(output, binder, false, Some(0)) }) else {
            return BAD_VALUE;
        };
        if !reply.is_empty() {
            return BAD_VALUE;
        }
        if remote {
            return relay::write_reply(
                unsafe { (native.api.calling_uid)() },
                code,
                bytes,
                &mut NativeWriter {
                    api: &native.api,
                    output,
                },
            )
            .map_or_else(|status| status, |()| 0);
        }
        native
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .write_reply(
                code,
                bytes,
                &mut NativeWriter {
                    api: &native.api,
                    output,
                },
            )
            .map_or_else(|status| status, |()| 0)
    }))
    .unwrap_or(-libc::EFAULT);
    if result == 0 {
        log_code_once(
            &REPLIED_CODES,
            code,
            if REMOTE_MODE.load(Ordering::Acquire) {
                "Soter remote relay reply delivered"
            } else {
                "Soter software test reply delivered"
            },
        );
    } else {
        log_code_once(
            &FAILED_CODES,
            code,
            &format!("Soter reply failed (status={result})"),
        );
    }
    result
}

struct NativeWriter<'a> {
    api: &'a NativeApi,
    output: *mut c_void,
}

impl wire::Writer for NativeWriter<'_> {
    fn int32(&mut self, value: i32) -> Result<(), i32> {
        status(unsafe { (self.api.write_i32)(self.output, value) })
    }
    fn int64(&mut self, value: i64) -> Result<(), i32> {
        status(unsafe { (self.api.write_i64)(self.output, value) })
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), i32> {
        status(unsafe {
            (self.api.write_bytes)(self.output, value.as_ptr().cast(), value.len() as i32)
        })
    }
}

fn status(value: i32) -> Result<(), i32> {
    if value == 0 { Ok(()) } else { Err(value) }
}

#[cfg(test)]
mod tests;
