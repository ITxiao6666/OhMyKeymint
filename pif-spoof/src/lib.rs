use std::{
    ffi::{CStr, CString},
    fs,
    io::{Read, Write},
    mem::{align_of, size_of},
    ptr,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicPtr, Ordering},
    },
    time::Duration,
};

use jni::{
    JNIEnv,
    objects::{JObject, JString, JValue},
};
use pif_common::{BuildClass, MAX_PROFILE_BYTES, PifProfile};
use zygisk_api::{
    ZygiskModule,
    api::{
        V4, ZygiskApi,
        v4::{AppSpecializeArgs, ServerSpecializeArgs, ZygiskOption},
    },
};

use libc::{c_char, c_void};

const PROFILE_PATH: &str = "/data/misc/keystore/omk/data/pif_fingerprint.json";
const GMS_PROCESS: &str = "com.google.android.gms.unstable";
const GMS_PACKAGE: &str = "com.google.android.gms";
const VENDING_PROCESS: &str = "com.android.vending";
const VENDING_PACKAGE: &str = "com.android.vending";
const IPC_TIMEOUT: Duration = Duration::from_secs(2);
const PROPERTY_READ_SYMBOL: &CStr = c"__system_property_read_callback";
const PROPERTY_FIND_SYMBOL: &CStr = c"__system_property_find";
const PROPERTY_GET_SYMBOL: &CStr = c"__system_property_get";
const PROPERTY_READ_LEGACY_SYMBOL: &CStr = c"__system_property_read";
const PROPERTY_VALUE_MAX: usize = 92;
const DEVICE_INITIAL_SDK_INT: &str = "21";
const MAX_CALLBACK_WRAPPER_INSTRUCTIONS: usize = 16;
const INLINE_PATCH_BYTES: usize = 24;
const MAX_DISPATCH_SPAN: usize = 32 * 1024 * 1024;

// The bionic callback API is intentionally kept private here.  The type is
// ABI-compatible with prop_info*, while avoiding a dependency on bionic's
// private struct definition.
type PropertyCallback = unsafe extern "C" fn(
    cookie: *mut c_void,
    name: *const c_char,
    value: *const c_char,
    serial: u32,
);
type PropertyReadCallbackApi = unsafe extern "C" fn(
    property: *const c_void,
    callback: Option<PropertyCallback>,
    cookie: *mut c_void,
);
type PropertyFind = unsafe extern "C" fn(name: *const c_char) -> *const c_void;
type PropertyGet = unsafe extern "C" fn(*const c_char, *mut c_char) -> libc::c_int;
type PropertyReadLegacy = unsafe extern "C" fn(
    property: *const c_void,
    name: *mut c_char,
    value: *mut c_char,
) -> libc::c_int;
type SystemPropertiesReadCallback = unsafe extern "C" fn(
    system_properties: *const c_void,
    property: *const c_void,
    callback: Option<PropertyCallback>,
    cookie: *mut c_void,
);

static ORIGINAL_PLT_PROPERTY_READ: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ORIGINAL_PLT_PROPERTY_GET: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ORIGINAL_PLT_PROPERTY_READ_LEGACY: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static SYSTEM_PROPERTIES_INSTANCE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static SYSTEM_PROPERTIES_READ_CALLBACK: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static PROPERTY_SPOOF: OnceLock<PropertyValues> = OnceLock::new();
static INLINE_PROPERTY_READ_HOOKED: OnceLock<()> = OnceLock::new();

#[derive(Default)]
struct PifSpoofModule {
    profile: Mutex<Option<PifProfile>>,
}

impl ZygiskModule for PifSpoofModule {
    type Api = V4;

    fn pre_app_specialize<'a>(
        &self,
        mut api: ZygiskApi<'a, V4>,
        mut env: JNIEnv<'a>,
        args: &'a mut AppSpecializeArgs<'_>,
    ) {
        let process = read_java_string(&mut env, args.nice_name);
        let data_dir = read_java_string(&mut env, args.app_data_dir);
        if !is_target_process(process.as_deref(), data_dir.as_deref()) {
            api.set_option(ZygiskOption::DlCloseModuleLibrary);
            return;
        }

        log_android(&format!(
            "PIF target selected: process={}, data_dir={}",
            process.as_deref().unwrap_or("<unknown>"),
            data_dir.as_deref().unwrap_or("<unknown>")
        ));

        let loaded = match api.with_companion(read_profile_from_companion) {
            Ok(Ok(profile)) => profile,
            Ok(Err(error)) => {
                log_android(&format!(
                    "PIF companion returned an invalid profile: {error}"
                ));
                None
            }
            Err(error) => {
                log_android(&format!("PIF companion connection failed: {error}"));
                None
            }
        };
        let Some(profile) = loaded else {
            log_android("PIF profile is disabled or unavailable");
            api.set_option(ZygiskOption::DlCloseModuleLibrary);
            return;
        };

        // Zygisk only permits its API (including PLT registration) before app
        // specialization.  Register every available native path while the
        // process still has zygote privileges; the Java fields are applied in
        // post_app_specialize after Android has finished specialization.
        match install_property_hook(&mut api, &profile) {
            Ok(count) => log_android(&format!(
                "PIF native PLT hooks installed for {count} imported symbol(s)"
            )),
            Err(error) => log_android(&format!(
                "PIF native PLT hooks unavailable; continuing with inline/Java spoof: {error}"
            )),
        }
        // libc is already mapped in the specialized child, while native app
        // initialization has not started yet. Install the process-wide
        // callback fallback here so later-loaded native code sees the profile.
        match install_inline_property_hook() {
            Ok(bytes) if bytes > 0 => log_android(&format!(
                "PIF inline property callback hook installed ({bytes} bytes)"
            )),
            Ok(_) => log_android("PIF inline property callback hook already installed"),
            Err(error) => log_android(&format!(
                "PIF inline property callback hook unavailable: {error}"
            )),
        }
        api.set_option(ZygiskOption::ForceDenylistUnmount);
        if let Ok(mut current) = self.profile.lock() {
            *current = Some(profile);
        } else {
            log_android("PIF profile state lock is poisoned");
        }
    }

    fn post_app_specialize<'a>(
        &self,
        _api: ZygiskApi<'a, V4>,
        mut env: JNIEnv<'a>,
        _args: &'a AppSpecializeArgs<'a>,
    ) {
        let Some(profile) = self
            .profile
            .lock()
            .ok()
            .and_then(|mut current| current.take())
        else {
            return;
        };
        match apply_build_fields(&mut env, &profile) {
            Ok(()) => log_android("PIF Build fields applied to the target Google process"),
            Err(error) => log_android(&format!("failed to apply PIF Build fields: {error}")),
        }

        log_property_probe();
    }

    fn pre_server_specialize<'a>(
        &self,
        mut api: ZygiskApi<'a, V4>,
        _env: JNIEnv<'a>,
        _args: &'a mut ServerSpecializeArgs<'_>,
    ) {
        api.set_option(ZygiskOption::DlCloseModuleLibrary);
    }
}

struct PropertyValues {
    fingerprint: CString,
    manufacturer: CString,
    model: CString,
    brand: CString,
    product: CString,
    device: CString,
    release: CString,
    id: CString,
    incremental: CString,
    build_type: CString,
    tags: CString,
    security_patch: CString,
    api_level: CString,
}

impl PropertyValues {
    fn from_profile(profile: &PifProfile) -> Result<Self, String> {
        profile.validate()?;
        Ok(Self {
            fingerprint: property_string("fingerprint", &profile.fingerprint)?,
            manufacturer: property_string("manufacturer", &profile.manufacturer)?,
            model: property_string("model", &profile.model)?,
            brand: property_string("brand", &profile.brand)?,
            product: property_string("product", &profile.product)?,
            device: property_string("device", &profile.device)?,
            release: property_string("release", &profile.release)?,
            id: property_string("id", &profile.id)?,
            incremental: property_string("incremental", &profile.incremental)?,
            build_type: property_string("build_type", &profile.build_type)?,
            tags: property_string("tags", &profile.tags)?,
            security_patch: property_string("security_patch", &profile.security_patch)?,
            api_level: property_string("api_level", DEVICE_INITIAL_SDK_INT)?,
        })
    }

    fn value_for(&self, name: &[u8]) -> Option<&CStr> {
        if name.ends_with(b".build.fingerprint") {
            return Some(self.fingerprint.as_c_str());
        }
        if name.ends_with(b"api_level") {
            return Some(self.api_level.as_c_str());
        }
        if name.ends_with(b".build.id") {
            return Some(self.id.as_c_str());
        }
        if name.ends_with(b".security_patch") {
            return Some(self.security_patch.as_c_str());
        }
        if name.ends_with(b".build.version.release") {
            return Some(self.release.as_c_str());
        }
        if name.ends_with(b".build.version.incremental") {
            return Some(self.incremental.as_c_str());
        }
        if name.ends_with(b".build.type") {
            return Some(self.build_type.as_c_str());
        }
        if name.ends_with(b".build.tags") {
            return Some(self.tags.as_c_str());
        }
        if name.ends_with(b".build.product") {
            return Some(self.device.as_c_str());
        }
        if is_product_property(name, b"manufacturer") {
            return Some(self.manufacturer.as_c_str());
        }
        if is_product_property(name, b"model") {
            return Some(self.model.as_c_str());
        }
        if is_product_property(name, b"brand") {
            return Some(self.brand.as_c_str());
        }
        if is_product_property(name, b"name") {
            return Some(self.product.as_c_str());
        }
        if is_product_property(name, b"device") {
            return Some(self.device.as_c_str());
        }
        None
    }
}

fn property_string(name: &str, value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("PIF {name} contains an embedded NUL"))
}

fn is_product_property(name: &[u8], field: &[u8]) -> bool {
    const PROPERTY_PREFIXES: &[&[u8]] = &[
        b"ro.product.",
        b"ro.product.system.",
        b"ro.product.system_ext.",
        b"ro.product.vendor.",
        b"ro.product.odm.",
        b"ro.product.product.",
        b"ro.system.product.",
        b"ro.system_ext.product.",
        b"ro.vendor.product.",
        b"ro.odm.product.",
    ];
    PROPERTY_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix) && &name[prefix.len()..] == field)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HookTarget {
    device: libc::dev_t,
    inode: libc::ino_t,
}

fn install_property_hook(
    api: &mut ZygiskApi<'_, V4>,
    profile: &PifProfile,
) -> Result<usize, String> {
    initialize_property_spoof(profile)?;

    let targets = read_hook_targets()?;
    if targets.is_empty() {
        return Err("no file-backed ELF mappings were found".to_string());
    }

    // LSPlt stores each `original` address and fills it during
    // `plt_hook_commit()`.  The backup slots therefore must remain allocated
    // until after the commit; stack locals inside the registration loop are
    // invalid at that point.  Pre-size the vectors and never mutate them
    // again, which keeps every element address stable for the whole call.
    let mut callback_backups = vec![ptr::null(); targets.len()];
    let mut get_backups = vec![ptr::null(); targets.len()];
    let mut legacy_backups = vec![ptr::null(); targets.len()];
    for (index, target) in targets.iter().enumerate() {
        unsafe {
            api.plt_hook_register(
                target.device,
                target.inode,
                PROPERTY_READ_SYMBOL,
                property_read_plt_hook as *const (),
                &mut callback_backups[index],
            );
        }

        unsafe {
            api.plt_hook_register(
                target.device,
                target.inode,
                PROPERTY_GET_SYMBOL,
                property_get_plt_hook as *const (),
                &mut get_backups[index],
            );
        }

        unsafe {
            api.plt_hook_register(
                target.device,
                target.inode,
                PROPERTY_READ_LEGACY_SYMBOL,
                property_read_legacy_plt_hook as *const (),
                &mut legacy_backups[index],
            );
        }
    }

    let commit_result = api.plt_hook_commit();
    let original_callback = first_non_null(&callback_backups);
    let original_get = first_non_null(&get_backups);
    let original_read = first_non_null(&legacy_backups);
    let installed = usize::from(!original_callback.is_null())
        + usize::from(!original_get.is_null())
        + usize::from(!original_read.is_null());
    if !original_callback.is_null() {
        ORIGINAL_PLT_PROPERTY_READ.store(original_callback as *mut c_void, Ordering::Release);
    }
    if !original_get.is_null() {
        ORIGINAL_PLT_PROPERTY_GET.store(original_get as *mut c_void, Ordering::Release);
    }
    if !original_read.is_null() {
        ORIGINAL_PLT_PROPERTY_READ_LEGACY.store(original_read as *mut c_void, Ordering::Release);
    }

    if let Err(error) = commit_result {
        if installed > 0 {
            log_android(&format!(
                "PIF native property hook partially committed: {error}"
            ));
        }
        return Err(format!("PLT hook commit failed: {error}"));
    }
    if installed == 0 {
        return Err("the property symbol was not imported by any mapped ELF".to_string());
    }
    Ok(installed)
}

/// PLT hooks only affect already-loaded callers that use imported
/// relocations. Bionic's callback export is a small wrapper around
/// `SystemProperties::ReadCallback`; resolve that dispatch before replacing
/// the wrapper so later-loaded native code is covered without a trampoline.
#[cfg(target_arch = "aarch64")]
fn install_inline_property_hook() -> Result<usize, String> {
    if INLINE_PROPERTY_READ_HOOKED.get().is_some() {
        return Ok(0);
    }
    if PROPERTY_SPOOF.get().is_none() {
        return Err("no validated profile is loaded".to_string());
    }

    let target = resolve_symbol_address(PROPERTY_READ_SYMBOL)
        .ok_or_else(|| "__system_property_read_callback was not exported by libc".to_string())?;
    let (dispatch, mapping) = resolve_property_read_dispatch(target)?;

    SYSTEM_PROPERTIES_INSTANCE.store(dispatch.instance as *mut c_void, Ordering::Release);
    SYSTEM_PROPERTIES_READ_CALLBACK.store(dispatch.method as *mut c_void, Ordering::Release);
    if let Err(error) = patch_property_read_callback(
        target.cast::<u8>(),
        property_read_inline_hook as *const () as *const c_void,
        &mapping,
    ) {
        SYSTEM_PROPERTIES_INSTANCE.store(ptr::null_mut(), Ordering::Release);
        SYSTEM_PROPERTIES_READ_CALLBACK.store(ptr::null_mut(), Ordering::Release);
        return Err(error);
    }
    let _ = INLINE_PROPERTY_READ_HOOKED.set(());
    Ok(INLINE_PATCH_BYTES)
}

#[cfg(not(target_arch = "aarch64"))]
fn install_inline_property_hook() -> Result<usize, String> {
    Err("the inline property callback hook requires AArch64".to_string())
}

fn initialize_property_spoof(profile: &PifProfile) -> Result<(), String> {
    if PROPERTY_SPOOF.get().is_some() {
        return Ok(());
    }
    let values = PropertyValues::from_profile(profile)?;
    // A module instance normally handles one specialization.  If a loader
    // invokes it concurrently, retaining the first validated snapshot is
    // preferable to exposing a partially initialized property table.
    let _ = PROPERTY_SPOOF.set(values);
    Ok(())
}

fn log_property_probe() {
    let Some(find_address) = resolve_symbol_address(PROPERTY_FIND_SYMBOL) else {
        log_android("PIF property probe could not resolve __system_property_find");
        return;
    };
    let Some(read_address) = resolve_symbol_address(PROPERTY_READ_SYMBOL) else {
        log_android("PIF property probe could not resolve __system_property_read_callback");
        return;
    };
    let find: PropertyFind = unsafe { std::mem::transmute(find_address) };
    let read: PropertyReadCallbackApi = unsafe { std::mem::transmute(read_address) };
    let name = c"ro.build.fingerprint";
    let property = unsafe { find(name.as_ptr()) };
    if property.is_null() {
        log_android("PIF property probe could not find ro.build.fingerprint");
        return;
    }
    let mut probe = PropertyProbe::default();
    unsafe {
        read(
            property,
            Some(property_probe_callback),
            (&mut probe as *mut PropertyProbe).cast(),
        );
    }
    let Some(observed) = probe.value else {
        log_android("PIF property probe callback returned no value");
        return;
    };
    let expected = PROPERTY_SPOOF
        .get()
        .map(|values| values.fingerprint.to_string_lossy())
        .unwrap_or_default();
    log_android(&format!(
        "PIF property probe {}: observed={}, expected={}, matched={}",
        name.to_string_lossy(),
        observed,
        expected,
        observed == expected.as_ref()
    ));
}

#[derive(Default)]
struct PropertyProbe {
    value: Option<String>,
}

unsafe extern "C" fn property_probe_callback(
    context: *mut c_void,
    _name: *const c_char,
    value: *const c_char,
    _serial: u32,
) {
    let Some(context) = (unsafe { context.cast::<PropertyProbe>().as_mut() }) else {
        return;
    };
    if value.is_null() {
        return;
    }
    context.value = Some(
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned(),
    );
}

fn resolve_symbol_address(symbol: &CStr) -> Option<*mut c_void> {
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    (!address.is_null()).then_some(address)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegisterValue {
    Unknown,
    Argument(u8),
    Address(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PropertyReadDispatch {
    instance: usize,
    method: usize,
    wrapper_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MemoryMapping {
    start: usize,
    end: usize,
    protection: libc::c_int,
    private: bool,
    device: libc::dev_t,
    inode: libc::ino_t,
    path: Option<String>,
    bti: bool,
    mte: bool,
}

impl MemoryMapping {
    fn contains(&self, address: usize, length: usize) -> bool {
        address >= self.start
            && address
                .checked_add(length)
                .is_some_and(|end| end <= self.end)
    }

    fn readable(&self) -> bool {
        self.protection & libc::PROT_READ != 0
    }

    fn writable(&self) -> bool {
        self.protection & libc::PROT_WRITE != 0
    }

    fn executable(&self) -> bool {
        self.protection & libc::PROT_EXEC != 0
    }
}

fn decode_property_read_dispatch(
    instructions: &[u32],
    base_address: usize,
) -> Result<PropertyReadDispatch, String> {
    let mut registers = [RegisterValue::Unknown; 31];
    registers[0] = RegisterValue::Argument(0);
    registers[1] = RegisterValue::Argument(1);
    registers[2] = RegisterValue::Argument(2);

    for (index, instruction) in instructions.iter().copied().enumerate() {
        let offset = index
            .checked_mul(size_of::<u32>())
            .ok_or_else(|| "property callback wrapper offset overflowed".to_string())?;
        let pc = base_address
            .checked_add(offset)
            .ok_or_else(|| "property callback wrapper address overflowed".to_string())?;

        if let Some(method) = decode_unconditional_branch(instruction, pc) {
            let RegisterValue::Address(instance) = registers[0] else {
                return Err("property callback wrapper did not resolve its instance".to_string());
            };
            if registers[1] != RegisterValue::Argument(0)
                || registers[2] != RegisterValue::Argument(1)
                || registers[3] != RegisterValue::Argument(2)
            {
                return Err(
                    "property callback wrapper has an unexpected argument layout".to_string(),
                );
            }
            return Ok(PropertyReadDispatch {
                instance,
                method,
                wrapper_bytes: offset + size_of::<u32>(),
            });
        }

        if is_ignored_wrapper_instruction(instruction) {
            continue;
        }
        if let Some((register, address)) = decode_adr(instruction, pc) {
            registers[register] = RegisterValue::Address(address);
            continue;
        }
        if let Some((destination, source, immediate)) = decode_add_immediate(instruction) {
            registers[destination] = match registers[source] {
                RegisterValue::Address(address) => add_signed(address, immediate as i64)
                    .map(RegisterValue::Address)
                    .unwrap_or(RegisterValue::Unknown),
                value if immediate == 0 => value,
                _ => RegisterValue::Unknown,
            };
            continue;
        }
        if let Some((destination, source)) = decode_move_register(instruction) {
            registers[destination] = registers[source];
            continue;
        }
        return Err(format!(
            "unsupported property callback wrapper instruction 0x{instruction:08x} at +0x{offset:x}"
        ));
    }
    Err("property callback wrapper has no recognized tail branch".to_string())
}

fn is_ignored_wrapper_instruction(instruction: u32) -> bool {
    matches!(
        instruction,
        0xd503_201f // NOP
            | 0xd503_241f // BTI
            | 0xd503_245f // BTI c
            | 0xd503_249f // BTI j
            | 0xd503_24df // BTI jc
    )
}

fn decode_move_register(instruction: u32) -> Option<(usize, usize)> {
    if instruction & 0xffe0_ffe0 != 0xaa00_03e0 {
        return None;
    }
    let destination = (instruction & 0x1f) as usize;
    let source = ((instruction >> 16) & 0x1f) as usize;
    (destination < 31 && source < 31).then_some((destination, source))
}

fn decode_add_immediate(instruction: u32) -> Option<(usize, usize, usize)> {
    if instruction & 0xff80_0000 != 0x9100_0000 {
        return None;
    }
    let destination = (instruction & 0x1f) as usize;
    let source = ((instruction >> 5) & 0x1f) as usize;
    if destination >= 31 || source >= 31 {
        return None;
    }
    let immediate = ((instruction >> 10) & 0x0fff) as usize;
    let shift = if instruction & (1 << 22) != 0 { 12 } else { 0 };
    immediate
        .checked_shl(shift)
        .map(|immediate| (destination, source, immediate))
}

fn decode_adr(instruction: u32, pc: usize) -> Option<(usize, usize)> {
    let opcode = instruction & 0x9f00_0000;
    if opcode != 0x1000_0000 && opcode != 0x9000_0000 {
        return None;
    }
    let destination = (instruction & 0x1f) as usize;
    if destination >= 31 {
        return None;
    }
    let immediate = (((instruction >> 5) & 0x7ffff) << 2) | ((instruction >> 29) & 0x3);
    let immediate = sign_extend(immediate as u64, 21);
    let (base, offset) = if opcode == 0x9000_0000 {
        (pc & !0xfff, immediate.checked_mul(4096)?)
    } else {
        (pc, immediate)
    };
    add_signed(base, offset).map(|address| (destination, address))
}

fn decode_unconditional_branch(instruction: u32, pc: usize) -> Option<usize> {
    if instruction & 0xfc00_0000 != 0x1400_0000 {
        return None;
    }
    let immediate = sign_extend(((instruction & 0x03ff_ffff) as u64) << 2, 28);
    add_signed(pc, immediate)
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    ((value << (64 - bits)) as i64) >> (64 - bits)
}

fn add_signed(base: usize, offset: i64) -> Option<usize> {
    if offset >= 0 {
        base.checked_add(offset as usize)
    } else {
        base.checked_sub(offset.unsigned_abs() as usize)
    }
}

fn parse_smaps_mappings(contents: &str) -> Vec<MemoryMapping> {
    let mut mappings = Vec::new();
    let mut current = None;
    for line in contents.lines() {
        if let Some(mapping) = parse_memory_mapping_header(line) {
            if let Some(previous) = current.replace(mapping) {
                mappings.push(previous);
            }
            continue;
        }
        if let Some(flags) = line.strip_prefix("VmFlags:")
            && let Some(mapping) = current.as_mut()
        {
            for flag in flags.split_whitespace() {
                mapping.bti |= flag == "bt";
                mapping.mte |= flag == "mt";
            }
        }
    }
    if let Some(mapping) = current {
        mappings.push(mapping);
    }
    mappings
}

fn parse_memory_mapping_header(line: &str) -> Option<MemoryMapping> {
    let mut fields = line.split_whitespace();
    let (start, end) = fields.next()?.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    if start >= end {
        return None;
    }
    let permissions = fields.next()?.as_bytes();
    if permissions.len() != 4 {
        return None;
    }
    let mut protection = 0;
    if permissions[0] == b'r' {
        protection |= libc::PROT_READ;
    }
    if permissions[1] == b'w' {
        protection |= libc::PROT_WRITE;
    }
    if permissions[2] == b'x' {
        protection |= libc::PROT_EXEC;
    }
    let private = permissions[3] == b'p';
    let _offset = fields.next()?;
    let device = parse_map_device(fields.next()?)?;
    let inode = fields.next()?.parse::<libc::ino_t>().ok()?;
    let path = fields.next().map(str::to_string);
    Some(MemoryMapping {
        start,
        end,
        protection,
        private,
        device,
        inode,
        path,
        bti: false,
        mte: false,
    })
}

fn mapping_containing(
    mappings: &[MemoryMapping],
    address: usize,
    length: usize,
) -> Option<&MemoryMapping> {
    mappings
        .iter()
        .find(|mapping| mapping.contains(address, length))
}

#[cfg(target_arch = "aarch64")]
fn resolve_property_read_dispatch(
    target: *mut c_void,
) -> Result<(PropertyReadDispatch, MemoryMapping), String> {
    let target_address = target as usize;
    if !target_address.is_multiple_of(align_of::<u32>()) {
        return Err("property callback address is not instruction-aligned".to_string());
    }
    let smaps = fs::read_to_string("/proc/self/smaps")
        .map_err(|error| format!("failed to read /proc/self/smaps: {error}"))?;
    let mappings = parse_smaps_mappings(&smaps);
    let target_mapping = mapping_containing(&mappings, target_address, INLINE_PATCH_BYTES)
        .ok_or_else(|| "property callback patch crosses its memory mapping".to_string())?;
    if !target_mapping.private
        || !target_mapping.readable()
        || !target_mapping.executable()
        || target_mapping.writable()
        || target_mapping.device == 0
        || target_mapping.inode == 0
        || !target_mapping
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("/libc.so"))
    {
        return Err(
            "property callback is not in a private read-only libc text mapping".to_string(),
        );
    }

    let instruction_count = ((target_mapping.end - target_address) / size_of::<u32>())
        .min(MAX_CALLBACK_WRAPPER_INSTRUCTIONS);
    let instructions =
        unsafe { std::slice::from_raw_parts(target_address as *const u32, instruction_count) };
    let dispatch = decode_property_read_dispatch(instructions, target_address)?;
    if dispatch.wrapper_bytes < INLINE_PATCH_BYTES {
        return Err(format!(
            "property callback wrapper is only {} bytes",
            dispatch.wrapper_bytes
        ));
    }
    if !dispatch.method.is_multiple_of(align_of::<u32>())
        || !dispatch.instance.is_multiple_of(align_of::<usize>())
        || dispatch.method.abs_diff(target_address) > MAX_DISPATCH_SPAN
        || dispatch.instance.abs_diff(target_address) > MAX_DISPATCH_SPAN
    {
        return Err("property callback dispatch addresses failed validation".to_string());
    }

    let method_mapping = mapping_containing(&mappings, dispatch.method, size_of::<u32>())
        .ok_or_else(|| "property callback method is not mapped".to_string())?;
    if !method_mapping.readable()
        || !method_mapping.executable()
        || method_mapping.writable()
        || method_mapping.device != target_mapping.device
        || method_mapping.inode != target_mapping.inode
    {
        return Err("property callback method is not in the same libc text".to_string());
    }
    if method_mapping.bti {
        let landing = unsafe { ptr::read(dispatch.method as *const u32) };
        if !is_call_compatible_landing_pad(landing) {
            return Err(
                "property callback method has no BTI-compatible call landing pad".to_string(),
            );
        }
    }

    let instance_mapping = mapping_containing(&mappings, dispatch.instance, size_of::<usize>())
        .ok_or_else(|| "property callback instance is not mapped".to_string())?;
    if !instance_mapping.readable() || !instance_mapping.writable() || instance_mapping.executable()
    {
        return Err("property callback instance is not in writable data".to_string());
    }

    let replacement = property_read_inline_hook as *const () as usize;
    let replacement_mapping = mapping_containing(&mappings, replacement, size_of::<u32>())
        .ok_or_else(|| "property callback replacement is not mapped".to_string())?;
    if !replacement_mapping.executable() || replacement_mapping.writable() {
        return Err(
            "property callback replacement is not in read-only executable memory".to_string(),
        );
    }
    if replacement_mapping.bti {
        let landing = unsafe { ptr::read(replacement as *const u32) };
        if !is_call_compatible_landing_pad(landing) {
            return Err(
                "property callback replacement has no BTI-compatible landing pad".to_string(),
            );
        }
    }

    Ok((dispatch, target_mapping.clone()))
}

fn is_call_compatible_landing_pad(instruction: u32) -> bool {
    matches!(
        instruction,
        0xd503_245f // BTI c
            | 0xd503_24df // BTI jc
            | 0xd503_233f // PACIASP
            | 0xd503_237f // PACIBSP
    )
}

fn patch_page_range(address: usize, length: usize, page_size: usize) -> Option<(usize, usize)> {
    if length == 0 || !page_size.is_power_of_two() {
        return None;
    }
    let page_start = address & !(page_size - 1);
    let end = address.checked_add(length)?;
    let page_end = end
        .checked_add(page_size - 1)?
        .checked_div(page_size)?
        .checked_mul(page_size)?;
    page_end
        .checked_sub(page_start)
        .filter(|length| *length > 0)
        .map(|length| (page_start, length))
}

#[cfg(target_arch = "aarch64")]
fn patch_property_read_callback(
    target: *mut u8,
    replacement: *const c_void,
    mapping: &MemoryMapping,
) -> Result<(), String> {
    ensure_single_threaded()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err("sysconf(_SC_PAGESIZE) returned an invalid value".to_string());
    }
    let page_size = usize::try_from(page_size)
        .map_err(|_| "system page size does not fit usize".to_string())?;
    if !page_size.is_power_of_two() {
        return Err(format!(
            "system page size {page_size} is not a power of two"
        ));
    }

    let target_address = target as usize;
    let (page_start, page_length) = patch_page_range(target_address, INLINE_PATCH_BYTES, page_size)
        .ok_or_else(|| "property callback patch page range is invalid".to_string())?;
    let page_end = page_start
        .checked_add(page_length)
        .ok_or_else(|| "property callback patch page range overflowed".to_string())?;
    if page_start < mapping.start || page_end > mapping.end {
        return Err("property callback patch crosses a memory mapping boundary".to_string());
    }

    const PROT_BTI: libc::c_int = 0x10;
    const PROT_MTE: libc::c_int = 0x20;
    let restore_protection = mapping.protection
        | if mapping.bti { PROT_BTI } else { 0 }
        | if mapping.mte { PROT_MTE } else { 0 };
    change_memory_protection(page_start, page_length, restore_protection)
        .map_err(|error| format!("property callback protection preflight failed: {error}"))?;

    let mut patch = [0u8; INLINE_PATCH_BYTES];
    patch[0..4].copy_from_slice(&0xd503_245fu32.to_le_bytes()); // BTI c
    patch[4..8].copy_from_slice(&0x5800_0070u32.to_le_bytes()); // LDR x16, #12
    patch[8..12].copy_from_slice(&0xd61f_0200u32.to_le_bytes()); // BR x16
    patch[12..16].copy_from_slice(&0xd503_201fu32.to_le_bytes()); // NOP
    patch[16..24].copy_from_slice(&(replacement as usize as u64).to_le_bytes());

    let mut original = [0u8; INLINE_PATCH_BYTES];
    unsafe {
        ptr::copy_nonoverlapping(target.cast_const(), original.as_mut_ptr(), original.len());
    }
    // Other libc entry points share this page. Keep it executable during the
    // short patch transaction so an asynchronous signal cannot fault merely
    // by entering an unrelated property helper on the same page.
    let writable_protection = restore_protection | libc::PROT_WRITE;
    change_memory_protection(page_start, page_length, writable_protection)
        .map_err(|error| format!("failed to make property callback writable: {error}"))?;
    unsafe {
        ptr::copy_nonoverlapping(patch.as_ptr(), target, patch.len());
    }
    flush_instruction_cache(target.cast_const(), patch.len());

    if let Err(restore_error) =
        change_memory_protection(page_start, page_length, restore_protection)
    {
        unsafe {
            ptr::copy_nonoverlapping(original.as_ptr(), target, original.len());
        }
        flush_instruction_cache(target.cast_const(), original.len());
        let rollback = change_memory_protection(page_start, page_length, restore_protection);
        return match rollback {
            Ok(()) => Err(format!(
                "failed to restore property callback protection; original bytes restored: {restore_error}"
            )),
            Err(rollback_error) => fatal_patch_failure(&format!(
                "property callback protection restore failed ({restore_error}); rollback protection also failed ({rollback_error})"
            )),
        };
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", not(test)))]
fn ensure_single_threaded() -> Result<(), String> {
    let mut count = 0usize;
    for entry in fs::read_dir("/proc/self/task")
        .map_err(|error| format!("failed to inspect /proc/self/task: {error}"))?
    {
        entry.map_err(|error| format!("failed to inspect process thread: {error}"))?;
        count += 1;
        if count > 1 {
            return Err(
                "inline property callback patch requires a single-threaded child".to_string(),
            );
        }
    }
    if count == 1 {
        Ok(())
    } else {
        Err("process thread list was empty".to_string())
    }
}

#[cfg(all(target_arch = "aarch64", test))]
fn ensure_single_threaded() -> Result<(), String> {
    // libtest keeps a harness thread alive even with --test-threads=1. The
    // ignored Android runtime test invokes the patch before any other work in
    // its dedicated process.
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn change_memory_protection(
    start: usize,
    length: usize,
    protection: libc::c_int,
) -> std::io::Result<()> {
    let result = unsafe { libc::mprotect(start as *mut c_void, length, protection) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_arch = "aarch64")]
fn fatal_patch_failure(message: &str) -> ! {
    log_android(message);
    unsafe { libc::_exit(127) }
}

#[cfg(target_arch = "aarch64")]
fn flush_instruction_cache(start: *const u8, length: usize) {
    let Some(end) = (start as usize).checked_add(length) else {
        return;
    };
    let mut ctr_el0: usize;
    unsafe {
        core::arch::asm!(
            "mrs {value}, ctr_el0",
            value = out(reg) ctr_el0,
            options(nostack, preserves_flags)
        );
    }
    let data_line_size = 4usize << ((ctr_el0 >> 16) & 0xf);
    let instruction_line_size = 4usize << (ctr_el0 & 0xf);

    let mut address = (start as usize) & !(data_line_size - 1);
    while address < end {
        unsafe {
            core::arch::asm!(
                "dc cvau, {address}",
                address = in(reg) address,
                options(nostack, preserves_flags)
            );
        }
        address += data_line_size;
    }
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
    }

    address = (start as usize) & !(instruction_line_size - 1);
    while address < end {
        unsafe {
            core::arch::asm!(
                "ic ivau, {address}",
                address = in(reg) address,
                options(nostack, preserves_flags)
            );
        }
        address += instruction_line_size;
    }
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

fn first_non_null(values: &[*const ()]) -> *const () {
    values
        .iter()
        .copied()
        .find(|value| !value.is_null())
        .unwrap_or(ptr::null())
}

fn read_hook_targets() -> Result<Vec<HookTarget>, String> {
    let maps = fs::read_to_string("/proc/self/maps")
        .map_err(|error| format!("failed to read /proc/self/maps: {error}"))?;
    Ok(parse_hook_targets(&maps))
}

fn parse_hook_targets(contents: &str) -> Vec<HookTarget> {
    let mut targets = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let _range = fields.next();
        let Some(perms) = fields.next() else {
            continue;
        };
        // V4 delegates the final ELF scan to LSPlt, which considers private,
        // readable file mappings and ignores bracketed pseudo mappings.
        let permission_bytes = perms.as_bytes();
        if permission_bytes.first() != Some(&b'r') || permission_bytes.get(3) != Some(&b'p') {
            continue;
        }
        let _offset = fields.next();
        let Some(device_text) = fields.next() else {
            continue;
        };
        let Some(inode_text) = fields.next() else {
            continue;
        };
        let Some(path) = fields.next() else {
            continue;
        };
        if path.starts_with('[') {
            continue;
        }
        let Some(device) = parse_map_device(device_text) else {
            continue;
        };
        let Ok(inode) = inode_text.parse::<libc::ino_t>() else {
            continue;
        };
        if device == 0 || inode == 0 {
            continue;
        }
        let target = HookTarget { device, inode };
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets
}

fn parse_map_device(value: &str) -> Option<libc::dev_t> {
    let (major, minor) = value.split_once(':')?;
    let major = u32::from_str_radix(major, 16).ok()?;
    let minor = u32::from_str_radix(minor, 16).ok()?;
    Some(libc::makedev(major, minor))
}

#[repr(C)]
struct CallbackContext {
    callback: PropertyCallback,
    cookie: *mut c_void,
}

unsafe extern "C" fn property_read_plt_hook(
    property: *const c_void,
    callback: Option<PropertyCallback>,
    cookie: *mut c_void,
) {
    forward_property_read(
        ORIGINAL_PLT_PROPERTY_READ.load(Ordering::Acquire),
        property,
        callback,
        cookie,
    );
}

unsafe extern "C" fn property_read_inline_hook(
    property: *const c_void,
    callback: Option<PropertyCallback>,
    cookie: *mut c_void,
) {
    let instance = SYSTEM_PROPERTIES_INSTANCE.load(Ordering::Acquire);
    let method = SYSTEM_PROPERTIES_READ_CALLBACK.load(Ordering::Acquire);
    if instance.is_null() || method.is_null() {
        return;
    }
    let method: SystemPropertiesReadCallback = unsafe { std::mem::transmute(method) };
    let Some(callback) = callback else {
        unsafe { method(instance, property, None, cookie) };
        return;
    };
    let context = CallbackContext { callback, cookie };
    unsafe {
        method(
            instance,
            property,
            Some(property_value_callback),
            (&context as *const CallbackContext).cast_mut().cast(),
        );
    }
}

fn forward_property_read(
    original: *mut c_void,
    property: *const c_void,
    callback: Option<PropertyCallback>,
    cookie: *mut c_void,
) {
    if original.is_null() {
        return;
    }
    // Both the bionic export and Zygisk's PLT backup use this exact ABI.
    let original: PropertyReadCallbackApi = unsafe { std::mem::transmute(original) };
    let Some(callback) = callback else {
        unsafe { original(property, None, cookie) };
        return;
    };
    let context = CallbackContext { callback, cookie };
    unsafe {
        original(
            property,
            Some(property_value_callback),
            (&context as *const CallbackContext).cast_mut().cast(),
        );
    }
}

unsafe extern "C" fn property_get_plt_hook(name: *const c_char, value: *mut c_char) -> libc::c_int {
    forward_property_get(
        ORIGINAL_PLT_PROPERTY_GET.load(Ordering::Acquire),
        name,
        value,
    )
}

fn forward_property_get(
    original: *mut c_void,
    name: *const c_char,
    value: *mut c_char,
) -> libc::c_int {
    if original.is_null() {
        return 0;
    }
    let original: PropertyGet = unsafe { std::mem::transmute(original) };
    let result = unsafe { original(name, value) };
    if result <= 0 || name.is_null() || value.is_null() {
        return result;
    }
    let Some(replacement) = property_value_for_name(name) else {
        return result;
    };
    let Some(bytes) = legacy_replacement_bytes(replacement) else {
        return result;
    };
    unsafe {
        ptr::copy_nonoverlapping(
            replacement.as_ptr().cast::<u8>(),
            value.cast::<u8>(),
            bytes.len() + 1,
        );
    }
    bytes.len().try_into().unwrap_or(result)
}

unsafe extern "C" fn property_read_legacy_plt_hook(
    property: *const c_void,
    name: *mut c_char,
    value: *mut c_char,
) -> libc::c_int {
    forward_property_read_legacy(
        ORIGINAL_PLT_PROPERTY_READ_LEGACY.load(Ordering::Acquire),
        property,
        name,
        value,
    )
}

fn forward_property_read_legacy(
    original: *mut c_void,
    property: *const c_void,
    name: *mut c_char,
    value: *mut c_char,
) -> libc::c_int {
    if original.is_null() {
        return 0;
    }
    let original: PropertyReadLegacy = unsafe { std::mem::transmute(original) };
    let result = unsafe { original(property, name, value) };
    if result <= 0 || name.is_null() || value.is_null() {
        return result;
    }
    let Some(replacement) = property_value_for_name(name) else {
        return result;
    };
    let Some(bytes) = legacy_replacement_bytes(replacement) else {
        return result;
    };
    unsafe {
        ptr::copy_nonoverlapping(
            replacement.as_ptr().cast::<u8>(),
            value.cast::<u8>(),
            bytes.len() + 1,
        );
    }
    bytes.len().try_into().unwrap_or(result)
}

fn legacy_replacement_bytes(replacement: &CStr) -> Option<&[u8]> {
    let bytes = replacement.to_bytes();
    (bytes.len() < PROPERTY_VALUE_MAX).then_some(bytes)
}

fn property_value_for_name(name: *const c_char) -> Option<&'static CStr> {
    if name.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(name) };
    PROPERTY_SPOOF
        .get()
        .and_then(|values| values.value_for(name.to_bytes()))
}

unsafe extern "C" fn property_value_callback(
    context: *mut c_void,
    name: *const c_char,
    value: *const c_char,
    serial: u32,
) {
    let Some(context) = (unsafe { context.cast::<CallbackContext>().as_ref() }) else {
        return;
    };
    let replacement = property_value_for_name(name);
    let value = replacement.map_or(value, |replacement| replacement.as_ptr());
    unsafe { (context.callback)(context.cookie, name, value, serial) };
}

fn is_target_process(process: Option<&str>, data_dir: Option<&str>) -> bool {
    match (process, data_dir) {
        // A few Zygisk loaders expose the process name before the app data
        // directory has been converted to a Java string.  The exact process
        // names are supplied by Android's zygote, so accepting a missing or
        // empty directory preserves compatibility without matching arbitrary
        // applications.
        (Some(process), None) if process_name_matches(process, GMS_PROCESS) => true,
        (Some(process), None) if process_name_matches(process, VENDING_PROCESS) => true,
        (Some(process), Some("")) if process_name_matches(process, GMS_PROCESS) => true,
        (Some(process), Some("")) if process_name_matches(process, VENDING_PROCESS) => true,
        (Some(process), Some(path)) if process_name_matches(process, GMS_PROCESS) => {
            is_gms_data_dir(path)
        }
        (Some(process), Some(path)) if process_name_matches(process, VENDING_PROCESS) => {
            is_package_data_dir(path, VENDING_PACKAGE)
        }
        _ => false,
    }
}

fn process_name_matches(process: &str, base: &str) -> bool {
    process == base
        || process
            .strip_prefix(base)
            .is_some_and(|suffix| suffix.starts_with(':') && suffix.len() > 1)
}

fn is_package_data_dir(path: &str, package: &str) -> bool {
    let allowed_root = path.starts_with("/data/data/")
        || path.starts_with("/data/user/")
        || path.starts_with("/data/user_de/")
        || path.starts_with("/mnt/expand/");
    allowed_root
        && path
            .strip_suffix(package)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

fn is_gms_data_dir(path: &str) -> bool {
    is_package_data_dir(path, GMS_PACKAGE)
}

fn read_java_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Option<String> {
    env.get_string(value).ok().map(Into::into)
}

fn read_profile_from_companion(
    stream: &mut std::os::unix::net::UnixStream,
) -> std::io::Result<Option<PifProfile>> {
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Ok(None);
    }
    if length > MAX_PROFILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "companion PIF profile exceeds the 4 KiB limit",
        ));
    }
    let mut contents = vec![0u8; length];
    stream.read_exact(&mut contents)?;
    PifProfile::from_json(&contents)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn companion(stream: &mut std::os::unix::net::UnixStream) {
    let payload = load_profile_for_companion().unwrap_or_else(|error| {
        log_android(&format!("PIF companion rejected profile: {error}"));
        Vec::new()
    });
    if let Err(error) = stream
        .set_write_timeout(Some(IPC_TIMEOUT))
        .and_then(|()| stream.write_all(&(payload.len() as u32).to_be_bytes()))
        .and_then(|()| stream.write_all(&payload))
    {
        log_android(&format!("PIF companion write failed: {error}"));
    }
}

fn load_profile_for_companion() -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(PROFILE_PATH)
        .map_err(|error| format!("failed to inspect profile: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("profile path is not a regular file".to_string());
    }
    if metadata.len() > MAX_PROFILE_BYTES as u64 {
        return Err("profile file exceeds the 4 KiB limit".to_string());
    }
    let contents =
        fs::read(PROFILE_PATH).map_err(|error| format!("failed to read profile: {error}"))?;
    let profile = PifProfile::from_json(&contents)?;
    let canonical = profile.to_canonical_json()?.into_bytes();
    if contents != canonical {
        return Err("profile file is not canonical JSON".to_string());
    }
    Ok(canonical)
}

fn apply_build_fields(env: &mut JNIEnv<'_>, profile: &PifProfile) -> Result<(), String> {
    profile.validate()?;
    let build = env
        .find_class("android/os/Build")
        .map_err(|error| format!("cannot find android.os.Build: {error}"))?;
    let version = env
        .find_class("android/os/Build$VERSION")
        .map_err(|error| format!("cannot find android.os.Build.VERSION: {error}"))?;

    for (name, value, owner) in profile.build_fields() {
        let class = match owner {
            BuildClass::Build => &build,
            BuildClass::Version => &version,
        };
        let java_value = env
            .new_string(value)
            .map_err(|error| format!("cannot create {name} value: {error}"))?;
        let object = JObject::from(java_value);
        env.set_static_field(
            class,
            (class, name, "Ljava/lang/String;"),
            JValue::Object(&object),
        )
        .map_err(|error| format!("cannot set {name}: {error}"))?;
        env.delete_local_ref(object)
            .map_err(|error| format!("cannot release {name} value: {error}"))?;
    }
    Ok(())
}

fn log_android(message: &str) {
    let tag = c"OhMyKeymint-PIF";
    let Ok(message) = std::ffi::CString::new(message) else {
        return;
    };
    unsafe {
        __android_log_write(4, tag.as_ptr(), message.as_ptr());
    }
}

#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        priority: i32,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> i32;
}

zygisk_api::register_module!(PifSpoofModule);
zygisk_api::register_companion!(companion);

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> PifProfile {
        PifProfile {
            version: 1,
            model: "Pixel 7".to_string(),
            product: "panther_beta".to_string(),
            manufacturer: "Google".to_string(),
            fingerprint: "google/panther_beta/panther:14/AP2A.240905.003/1234567:user/release-keys"
                .to_string(),
            brand: "google".to_string(),
            device: "panther".to_string(),
            release: "14".to_string(),
            id: "AP2A.240905.003".to_string(),
            incremental: "1234567".to_string(),
            build_type: "user".to_string(),
            tags: "release-keys".to_string(),
            security_patch: "2024-09-05".to_string(),
        }
    }

    #[test]
    fn accepts_only_supported_gms_data_directories() {
        for path in [
            "/data/user/0/com.google.android.gms",
            "/data/user_de/10/com.google.android.gms",
            "/mnt/expand/volume/user/0/com.google.android.gms",
        ] {
            assert!(is_gms_data_dir(path), "{path}");
        }
        for path in [
            "/data/user/0/com.google.android.gms.evil",
            "/data/local/tmp/com.google.android.gms",
            "/data/user/0/other/com.google.android.gms/",
            "com.google.android.gms",
        ] {
            assert!(!is_gms_data_dir(path), "{path}");
        }
    }

    #[test]
    fn targets_gms_unstable_and_play_store_only() {
        assert!(is_target_process(
            Some(GMS_PROCESS),
            Some("/data/user/0/com.google.android.gms")
        ));
        assert!(is_target_process(
            Some(VENDING_PROCESS),
            Some("/data/user/0/com.android.vending")
        ));
        assert!(is_target_process(
            Some(VENDING_PROCESS),
            Some("/data/data/com.android.vending")
        ));
        assert!(is_target_process(
            Some("com.google.android.gms.unstable:background"),
            Some("/data/user/0/com.google.android.gms")
        ));
        assert!(is_target_process(
            Some("com.android.vending:instant"),
            Some("/data/user/0/com.android.vending")
        ));
        assert!(!is_target_process(
            Some("com.google.android.gms"),
            Some("/data/user/0/com.google.android.gms")
        ));
        assert!(!is_target_process(
            Some("com.google.android.gms.unstable:"),
            Some("/data/user/0/com.google.android.gms")
        ));
        assert!(!is_target_process(
            Some("com.android.vending.evil"),
            Some("/data/user/0/com.android.vending")
        ));
        assert!(!is_target_process(
            Some(VENDING_PROCESS),
            Some("/data/user/0/com.google.android.gms")
        ));
        assert!(is_target_process(Some(GMS_PROCESS), None));
        assert!(is_target_process(Some(VENDING_PROCESS), Some("")));
        assert!(!is_target_process(Some("com.google.android.gms"), None));
    }

    #[test]
    fn parses_unique_private_readable_file_mappings() {
        let maps = concat!(
            "7f000000-7f001000 r-xp 00000000 fe:01 42 /system/lib64/libone.so\n",
            "7f001000-7f002000 r--p 00001000 fe:01 42 /system/lib64/libone.so\n",
            "7f002000-7f003000 r-xp 00000000 fe:02 99 /data/app/libtwo.so\n",
            "7f003000-7f004000 r-xs 00000000 fe:03 100 /system/lib64/shared.so\n",
            "7f004000-7f005000 rw-p 00000000 fe:04 101 /system/lib64/writable.so\n",
            "7f005000-7f006000 r-xp 00000000 00:00 0 [vdso]\n",
        );
        let targets = parse_hook_targets(maps);
        assert_eq!(
            targets,
            vec![
                HookTarget {
                    device: libc::makedev(0xfe, 0x01),
                    inode: 42,
                },
                HookTarget {
                    device: libc::makedev(0xfe, 0x02),
                    inode: 99,
                },
                HookTarget {
                    device: libc::makedev(0xfe, 0x04),
                    inode: 101,
                },
            ]
        );
    }

    #[test]
    fn maps_profile_values_to_bionic_properties() {
        let values = PropertyValues::from_profile(&test_profile()).unwrap();
        assert_eq!(
            values
                .value_for(b"ro.build.fingerprint")
                .unwrap()
                .to_bytes(),
            b"google/panther_beta/panther:14/AP2A.240905.003/1234567:user/release-keys"
        );
        assert_eq!(
            values
                .value_for(b"ro.vendor.build.security_patch")
                .unwrap()
                .to_bytes(),
            b"2024-09-05"
        );
        assert_eq!(
            values
                .value_for(b"ro.product.system.model")
                .unwrap()
                .to_bytes(),
            b"Pixel 7"
        );
        assert_eq!(
            values
                .value_for(b"ro.product.first_api_level")
                .unwrap()
                .to_bytes(),
            b"21"
        );
        assert_eq!(
            values.value_for(b"ro.build.product").unwrap().to_bytes(),
            b"panther"
        );
        assert_eq!(
            values.value_for(b"ro.product.name").unwrap().to_bytes(),
            b"panther_beta"
        );
        assert!(values.value_for(b"ro.boot.verifiedbootstate").is_none());
    }

    #[test]
    fn callback_values_accept_long_read_only_properties() {
        let mut profile = test_profile();
        profile.incremental = "1".repeat(32);
        profile.fingerprint = format!(
            "google/{}/{}:{}/{}/{}:{}/{}",
            profile.product,
            profile.device,
            profile.release,
            profile.id,
            profile.incremental,
            profile.build_type,
            profile.tags
        );
        assert!(profile.fingerprint.len() >= PROPERTY_VALUE_MAX);
        assert!(profile.fingerprint.len() <= pif_common::MAX_VALUE_BYTES);
        let values = PropertyValues::from_profile(&profile).unwrap();
        let fingerprint = values.value_for(b"ro.build.fingerprint").unwrap();
        assert_eq!(fingerprint.to_bytes(), profile.fingerprint.as_bytes());
        assert!(legacy_replacement_bytes(fingerprint).is_none());

        let short = CString::new("x".repeat(PROPERTY_VALUE_MAX - 1)).unwrap();
        assert_eq!(
            legacy_replacement_bytes(short.as_c_str()).unwrap().len(),
            PROPERTY_VALUE_MAX - 1
        );
    }

    #[test]
    fn decodes_android_15_property_callback_wrapper() {
        let instructions = [
            0xaa00_03e8,
            0xaa02_03e3,
            0xaa01_03e2,
            0xd503_201f,
            0x1041_1dc0,
            0xaa08_03e1,
            0x17ff_88f2,
        ];
        assert_eq!(
            decode_property_read_dispatch(&instructions, 0x7a660).unwrap(),
            PropertyReadDispatch {
                instance: 0xfca28,
                method: 0x5ca40,
                wrapper_bytes: 28,
            }
        );
    }

    #[test]
    fn decodes_bti_and_adrp_property_callback_wrapper() {
        // The instruction PC is in a different 4 KiB subpage of its 16 KiB
        // kernel page, proving ADRP keeps its architectural 4 KiB semantics.
        let base = 0x1000_7000usize;
        let instance = 0x1001_6abcusize;
        let method = 0x0ff0_2000usize;
        let instructions = [
            0xd503_245f,
            0xaa00_03e8,
            0xaa02_03e3,
            0xaa01_03e2,
            encode_adrp(0, base + 16, instance),
            encode_add_immediate(0, 0, instance & 0xfff),
            0xaa08_03e1,
            encode_branch(base + 28, method),
        ];
        assert_eq!(
            decode_property_read_dispatch(&instructions, base).unwrap(),
            PropertyReadDispatch {
                instance,
                method,
                wrapper_bytes: 32,
            }
        );
    }

    #[test]
    fn rejects_unknown_or_incorrect_callback_wrappers() {
        let base = 0x2000usize;
        let instance = 0x3000usize;
        let method = 0x1000usize;
        let valid = [
            0xaa02_03e3,
            0xaa01_03e2,
            0xaa00_03e1,
            encode_adr(0, base + 12, instance),
            encode_branch(base + 16, method),
        ];
        let decoded = decode_property_read_dispatch(&valid, base).unwrap();
        assert_eq!(decoded.wrapper_bytes, 20);
        assert!(decoded.wrapper_bytes < INLINE_PATCH_BYTES);

        let mut unknown = valid;
        unknown[1] = 0xd65f_03c0;
        assert!(decode_property_read_dispatch(&unknown, base).is_err());

        let mut incorrect = valid;
        incorrect[0] = 0xaa01_03e3;
        assert!(decode_property_read_dispatch(&incorrect, base).is_err());

        let mut call = valid;
        call[4] |= 0x8000_0000;
        assert!(decode_property_read_dispatch(&call, base).is_err());
    }

    #[test]
    fn parses_smaps_security_flags_and_permissions() {
        let mappings = parse_smaps_mappings(concat!(
            "1000-4000 r-xp 00000000 07:01 42 /apex/runtime/lib64/bionic/libc.so\n",
            "Size:                 12 kB\n",
            "VmFlags: rd ex mr mw me bt\n",
            "4000-8000 rw-p 00000000 00:00 0 [anon:.bss]\n",
            "Size:                 16 kB\n",
            "VmFlags: rd wr mr mw me mt\n",
        ));
        assert_eq!(mappings.len(), 2);
        assert!(mappings[0].private);
        assert!(mappings[0].readable());
        assert!(mappings[0].executable());
        assert!(!mappings[0].writable());
        assert!(mappings[0].bti);
        assert!(!mappings[0].mte);
        assert!(mappings[1].writable());
        assert!(mappings[1].mte);
        assert_eq!(
            mapping_containing(&mappings, 0x3ff0, 0x10),
            Some(&mappings[0])
        );
        assert!(mapping_containing(&mappings, 0x3ff0, 0x11).is_none());
    }

    #[test]
    fn computes_4k_and_16k_patch_page_ranges() {
        assert_eq!(patch_page_range(0x1ff0, 24, 4096), Some((0x1000, 0x2000)));
        assert_eq!(
            patch_page_range(0x4ff0, 24, 16 * 1024),
            Some((0x4000, 16 * 1024))
        );
        assert_eq!(
            patch_page_range(0x7ff0, 24, 16 * 1024),
            Some((0x4000, 32 * 1024))
        );
        assert!(patch_page_range(usize::MAX - 4, 24, 4096).is_none());
        assert!(patch_page_range(0x1000, 24, 0).is_none());
        assert!(patch_page_range(0x1000, 24, 6000).is_none());
    }

    #[test]
    fn recognizes_only_call_compatible_bti_landings() {
        for instruction in [0xd503_245f, 0xd503_24df, 0xd503_233f, 0xd503_237f] {
            assert!(is_call_compatible_landing_pad(instruction));
        }
        for instruction in [0xd503_201f, 0xd503_241f, 0xd503_249f, 0xd65f_03c0] {
            assert!(!is_call_compatible_landing_pad(instruction));
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    #[ignore = "mutates process-local libc; run explicitly on an Android device"]
    fn android_runtime_installs_callback_hook_without_permission_drift() {
        initialize_property_spoof(&test_profile()).unwrap();
        let target = resolve_symbol_address(PROPERTY_READ_SYMBOL).unwrap();
        let before = parse_smaps_mappings(&fs::read_to_string("/proc/self/smaps").unwrap());
        let before_target = mapping_containing(&before, target as usize, INLINE_PATCH_BYTES)
            .unwrap()
            .clone();
        let before_rwx: Vec<(usize, usize)> = before
            .iter()
            .filter(|mapping| mapping.writable() && mapping.executable())
            .map(|mapping| (mapping.start, mapping.end))
            .collect();

        assert_eq!(install_inline_property_hook().unwrap(), INLINE_PATCH_BYTES);

        let after = parse_smaps_mappings(&fs::read_to_string("/proc/self/smaps").unwrap());
        let after_target = mapping_containing(&after, target as usize, INLINE_PATCH_BYTES).unwrap();
        assert_eq!(after_target.protection, before_target.protection);
        assert_eq!(after_target.bti, before_target.bti);
        assert_eq!(after_target.mte, before_target.mte);
        let after_rwx: Vec<(usize, usize)> = after
            .iter()
            .filter(|mapping| mapping.writable() && mapping.executable())
            .map(|mapping| (mapping.start, mapping.end))
            .collect();
        assert_eq!(after_rwx, before_rwx);

        let find: PropertyFind =
            unsafe { std::mem::transmute(resolve_symbol_address(PROPERTY_FIND_SYMBOL).unwrap()) };
        let read: PropertyReadCallbackApi = unsafe { std::mem::transmute(target) };
        let property = unsafe { find(c"ro.build.fingerprint".as_ptr()) };
        assert!(!property.is_null());
        let mut probe = PropertyProbe::default();
        unsafe {
            read(
                property,
                Some(property_probe_callback),
                (&mut probe as *mut PropertyProbe).cast(),
            );
        }
        assert_eq!(
            probe.value.as_deref(),
            Some(test_profile().fingerprint.as_str())
        );
    }

    fn encode_adr(destination: u32, pc: usize, target: usize) -> u32 {
        let delta = target as i64 - pc as i64;
        assert!((-(1 << 20)..(1 << 20)).contains(&delta));
        let immediate = (delta as u64) & 0x1f_ffff;
        0x1000_0000
            | (((immediate as u32) & 0x3) << 29)
            | ((((immediate as u32) >> 2) & 0x7ffff) << 5)
            | destination
    }

    fn encode_adrp(destination: u32, pc: usize, target: usize) -> u32 {
        let pc_page = pc & !0xfff;
        let target_page = target & !0xfff;
        let delta = (target_page as i64 - pc_page as i64) / 4096;
        assert!((-(1 << 20)..(1 << 20)).contains(&delta));
        let immediate = (delta as u64) & 0x1f_ffff;
        0x9000_0000
            | (((immediate as u32) & 0x3) << 29)
            | ((((immediate as u32) >> 2) & 0x7ffff) << 5)
            | destination
    }

    fn encode_add_immediate(destination: u32, source: u32, immediate: usize) -> u32 {
        assert!(immediate < 4096);
        0x9100_0000 | ((immediate as u32) << 10) | (source << 5) | destination
    }

    fn encode_branch(pc: usize, target: usize) -> u32 {
        let delta = target as i64 - pc as i64;
        assert_eq!(delta % 4, 0);
        let immediate = delta / 4;
        assert!((-(1 << 25)..(1 << 25)).contains(&immediate));
        0x1400_0000 | ((immediate as u32) & 0x03ff_ffff)
    }

    #[test]
    fn selects_first_backup_after_deferred_commit() {
        let first_value = ();
        let second_value = ();
        let first = &first_value as *const ();
        let second = &second_value as *const ();
        assert_eq!(first_non_null(&[ptr::null(), first, second]), first);
        assert_eq!(first_non_null(&[ptr::null(), ptr::null()]), ptr::null());
    }
}
