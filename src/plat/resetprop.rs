use std::{
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    path::Path,
    process::Command,
    sync::{Mutex, OnceLock},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{hub, Status, StatusCode};

const ANDROID_PACKAGE: &str = "android";
const PACKAGE_MANAGER_NATIVE_DESCRIPTOR: &str = "android.content.pm.IPackageManagerNative";
const PACKAGE_MANAGER_NATIVE_SERVICE: &str = "package_native";
const PHONE_DESCRIPTOR: &str = "com.android.internal.telephony.ITelephony";
const PHONE_SERVICE: &str = "phone";
const PHONE_SUB_INFO_DESCRIPTOR: &str = "com.android.internal.telephony.IPhoneSubInfo";
const PHONE_SUB_INFO_SERVICE: &str = "iphonesubinfo";
const TELEPHONY_FEATURE: &str = "android.hardware.telephony";
const TELEPHONY_GSM_FEATURE: &str = "android.hardware.telephony.gsm";
const TELEPHONY_CDMA_FEATURE: &str = "android.hardware.telephony.cdma";
const GET_DEVICE_ID_FOR_PHONE_TRANSACTION: rsbinder::TransactionCode =
    rsbinder::FIRST_CALL_TRANSACTION + 3;

pub(crate) const SYSTEM_SECURITY_PATCH_PROPERTY: &str = "ro.build.version.security_patch";
pub(crate) const VENDOR_SECURITY_PATCH_PROPERTY: &str = "ro.vendor.build.security_patch";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SecurityPatchProperties {
    pub system: String,
    pub vendor: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TelephonyTransactions {
    get_imei_for_slot: rsbinder::TransactionCode,
    get_meid_for_slot: Option<rsbinder::TransactionCode>,
}

#[derive(Clone, Copy)]
enum PhoneIdentifierKind {
    DeviceId,
    Imei,
    Meid,
}

impl PhoneIdentifierKind {
    fn command(self) -> &'static str {
        match self {
            Self::DeviceId => "GET_DEVICE_ID",
            Self::Imei => "GET_IMEI",
            Self::Meid => "GET_MEID",
        }
    }

    fn from_command(command: &str) -> Option<Self> {
        match command {
            "GET_DEVICE_ID" => Some(Self::DeviceId),
            "GET_IMEI" => Some(Self::Imei),
            "GET_MEID" => Some(Self::Meid),
            _ => None,
        }
    }
}

const RESETPROP_FALLBACKS: &[(&str, Option<&str>)] = &[
    // Prefer the binaries owned by the active root implementation.  Some
    // vendor images ship an unrelated `resetprop` utility under /system; it
    // accepts different arguments and must not shadow the root tool.
    ("/data/adb/ksu/bin/resetprop", None),
    ("/data/adb/magisk/resetprop", None),
    // APatch exposes the Magisk-compatible tool both as a symlink and as an
    // `apd resetprop` multicall entry point.
    ("/data/adb/ap/bin/resetprop", None),
    ("/data/adb/ksud", Some("resetprop")),
    ("/data/adb/apd", Some("resetprop")),
    // Keep system locations as a last-resort fallback for root solutions that
    // deliberately install their compatible helper there.
    ("/system_ext/bin/resetprop", None),
    ("/system/bin/resetprop", None),
];
// Keep early reads independent from the Rust property-area singleton.  The
// absolute paths avoid inheriting a root implementation's PATH while the
// property service is still coming up.
const EARLY_PROPERTY_READ_FALLBACKS: &[(&str, Option<&str>)] = &[
    ("/system/bin/getprop", None),
    ("/system_ext/bin/getprop", None),
    ("/vendor/bin/getprop", None),
    ("/data/adb/ksu/bin/resetprop", None),
    ("/data/adb/magisk/resetprop", None),
    ("/data/adb/ap/bin/resetprop", None),
    ("/data/adb/ksud", Some("resetprop")),
    ("/data/adb/apd", Some("resetprop")),
    ("/system_ext/bin/resetprop", None),
    ("/system/bin/resetprop", None),
];
const MAX_EARLY_PROPERTY_OUTPUT_BYTES: usize = 256;
const EARLY_SECURITY_PATCH_WRITE_ATTEMPTS: usize = 5;
const EARLY_SECURITY_PATCH_WRITE_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct ResetpropCommand {
    program: String,
    prepend_arg: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelephonyFeatures {
    pub any: bool,
    pub gsm: bool,
    pub cdma: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("service {0} unavailable")]
pub(crate) struct BinderServiceUnavailable(pub(crate) String);

fn require_binder_service<T>(name: &str, lookup: rsbinder::Result<Option<T>>) -> Result<T> {
    match lookup {
        Ok(Some(service)) => Ok(service),
        Ok(None) | Err(StatusCode::DeadObject) | Err(StatusCode::NotEnoughData) => {
            Err(BinderServiceUnavailable(name.to_string()).into())
        }
        // FailedTransaction is deliberately excluded: rsbinder also uses it for AIDL exceptions.
        Err(error) => {
            Err(error).with_context(|| format!("failed to look up Binder service {name}"))
        }
    }
}

static HELPER: OnceLock<Mutex<ResetpropHelperClient>> = OnceLock::new();

pub fn bootstrap_privileged_helper() -> Result<()> {
    if HELPER.get().is_some() {
        return Ok(());
    }

    let commands = match find_resetprop_commands() {
        Ok(commands) => commands,
        Err(error) => {
            log::warn!("resetprop unavailable to privileged helper: {error:#}");
            Vec::new()
        }
    };

    let (parent, child) = UnixStream::pair().context("failed to create resetprop socketpair")?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to fork resetprop helper");
    }
    if pid == 0 {
        drop(parent);
        let exit_code = match helper_loop(child, commands) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("resetprop helper exiting after fatal error: {error:#}");
                1
            }
        };
        unsafe { libc::_exit(exit_code) };
    }

    drop(child);
    let client = ResetpropHelperClient { stream: parent };
    if HELPER.set(Mutex::new(client)).is_err() {
        log::debug!("resetprop helper was already installed");
    } else {
        log::info!("started privileged resetprop helper process pid={pid}");
    }

    Ok(())
}

pub fn runtime_write_and_verify_property(property: &str, value: &str) -> Result<()> {
    with_helper(|helper| helper.write_and_verify_property(property, value))
}

pub fn runtime_get_device_id_for_phone(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::DeviceId, slot)
}

pub fn runtime_get_imei_for_slot(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::Imei, slot)
}

pub fn runtime_get_meid_for_slot(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::Meid, slot)
}

fn runtime_get_phone_identifier(kind: PhoneIdentifierKind, slot: i32) -> Result<Option<String>> {
    if !matches!(slot, 0 | 1) {
        bail!("unsupported phone slot {slot}");
    }
    with_helper(|helper| helper.get_phone_identifier(kind, slot))
}

pub fn runtime_telephony_features() -> Result<TelephonyFeatures> {
    with_helper(|helper| {
        Ok(TelephonyFeatures {
            any: helper.has_system_feature(TELEPHONY_FEATURE)?,
            gsm: helper.has_system_feature(TELEPHONY_GSM_FEATURE)?,
            cdma: helper.has_system_feature(TELEPHONY_CDMA_FEATURE)?,
        })
    })
}

pub(crate) fn is_binder_service_unavailable(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<BinderServiceUnavailable>().is_some())
}

fn with_helper<T>(call: impl FnOnce(&mut ResetpropHelperClient) -> Result<T>) -> Result<T> {
    let helper = HELPER
        .get()
        .ok_or_else(|| anyhow!("privileged resetprop helper is unavailable"))?;
    let mut helper = helper
        .lock()
        .map_err(|_| anyhow!("privileged resetprop helper lock poisoned"))?;
    call(&mut helper)
}

pub fn direct_write_and_verify_property(property: &str, value: &str) -> Result<()> {
    let commands = find_resetprop_commands()?;
    execute_write_and_verify_candidates(&commands, property, value, false)
}

pub(crate) fn direct_write_and_verify_security_patch_properties(
    expected: &SecurityPatchProperties,
    desired: &SecurityPatchProperties,
) -> Result<()> {
    let commands = find_resetprop_commands()?;
    write_security_patch_properties_with_rollback(
        |property, value| execute_write_and_verify_candidates(&commands, property, value, false),
        // Keep the paired precondition/rollback checks on the same fresh
        // command-backed reader used by the early replay path.  The Rust
        // property-area view can be stale on vendor builds even after a
        // resetprop write succeeds.
        read_early_string_property,
        expected,
        desired,
    )
}

/// Update the paired security-patch properties without running property
/// triggers. This variant is used only from blocking early-boot hooks, where
/// init may still be publishing the same read-only properties. It retries the
/// desired pair without rolling either value back: restoring an observed old
/// value during that race would make the boot-time override less reliable.
/// Regular runtime updates keep the strict trigger-enabled paired rollback.
pub(crate) fn direct_write_and_verify_security_patch_properties_no_triggers(
    expected: &SecurityPatchProperties,
    desired: &SecurityPatchProperties,
) -> Result<()> {
    let commands = find_resetprop_commands()?;
    write_security_patch_properties_early(
        |property, value| execute_write_and_verify_candidates(&commands, property, value, true),
        read_early_string_property,
        expected,
        desired,
        EARLY_SECURITY_PATCH_WRITE_ATTEMPTS,
        || std::thread::sleep(EARLY_SECURITY_PATCH_WRITE_RETRY_INTERVAL),
    )
}

pub fn read_string_property(name: &str) -> Option<String> {
    rsproperties::get::<String>(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Read a security-patch property without depending solely on the process's
/// cached `rsproperties` initialization.  `rsproperties` latches an init
/// failure for the lifetime of the process, which is common when this mode is
/// started before init has published `/dev/__properties__`; a fresh getprop or
/// resetprop process can still read the property area once it is ready.
pub(crate) fn read_early_string_property(name: &str) -> Option<String> {
    if !is_security_patch_property(name) {
        return read_string_property(name);
    }

    // Prefer a fresh command read so a stale/partially initialized Rust view
    // cannot hide a value that init has since published.
    read_property_with_early_command(name).or_else(|| read_string_property(name))
}

pub(crate) fn read_early_security_patch_properties() -> Result<SecurityPatchProperties> {
    read_security_patch_properties_with(read_early_string_property)
}

fn is_security_patch_property(name: &str) -> bool {
    matches!(
        name,
        SYSTEM_SECURITY_PATCH_PROPERTY | VENDOR_SECURITY_PATCH_PROPERTY
    )
}

fn read_property_with_early_command(name: &str) -> Option<String> {
    if !is_security_patch_property(name) {
        return None;
    }

    for (program, prepend_arg) in early_property_read_candidates() {
        let path = Path::new(&program);
        if !is_executable_file(path) {
            continue;
        }

        let mut command = Command::new(path);
        if let Some(prepend_arg) = &prepend_arg {
            command.arg(prepend_arg);
        }
        let output = match command.arg(name).output() {
            Ok(output) => output,
            Err(error) => {
                log::debug!("failed to execute {program} while reading {name}: {error}");
                continue;
            }
        };
        if !output.status.success() {
            log::debug!(
                "{program} returned status {} while reading {name}",
                output.status
            );
            continue;
        }
        if let Some(value) = normalize_early_property_output(&output.stdout) {
            return Some(value.to_string());
        }
        if output.stdout.len() > MAX_EARLY_PROPERTY_OUTPUT_BYTES {
            log::debug!("{program} returned an oversized value while reading {name}");
        } else if std::str::from_utf8(&output.stdout).is_err() {
            log::debug!("{program} returned non-UTF-8 data while reading {name}");
        } else {
            log::debug!("{program} returned an empty value while reading {name}");
        }
    }
    None
}

fn early_property_read_candidates() -> Vec<(String, Option<String>)> {
    let mut candidates = EARLY_PROPERTY_READ_FALLBACKS
        .iter()
        .map(|(program, prepend_arg)| ((*program).to_string(), (*prepend_arg).map(str::to_string)))
        .collect::<Vec<_>>();

    // Keep PATH as a last-resort read source for root implementations that
    // install resetprop outside their conventional /data/adb location.  The
    // explicit platform `getprop` and trusted root paths above always win.
    if let Some(path) = std::env::var_os("PATH") {
        for candidate in std::env::split_paths(&path).map(|directory| directory.join("resetprop")) {
            if !is_executable_file(&candidate) {
                continue;
            }
            let program = candidate.to_string_lossy().into_owned();
            if !candidates
                .iter()
                .any(|(existing, prepend_arg)| existing == &program && prepend_arg.is_none())
            {
                candidates.push((program, None));
            }
        }
    }
    candidates
}

fn normalize_early_property_output(output: &[u8]) -> Option<&str> {
    if output.len() > MAX_EARLY_PROPERTY_OUTPUT_BYTES {
        return None;
    }
    let value = std::str::from_utf8(output).ok()?.trim();
    (!value.is_empty()).then_some(value)
}

pub(crate) fn read_security_patch_properties() -> Result<SecurityPatchProperties> {
    read_security_patch_properties_with(read_string_property)
}

fn read_security_patch_properties_with<R>(reader: R) -> Result<SecurityPatchProperties>
where
    R: Fn(&str) -> Option<String>,
{
    let vendor = reader(VENDOR_SECURITY_PATCH_PROPERTY)
        .ok_or_else(|| anyhow!("property {VENDOR_SECURITY_PATCH_PROPERTY} is missing or empty"))?;
    let system = reader(SYSTEM_SECURITY_PATCH_PROPERTY)
        .ok_or_else(|| anyhow!("property {SYSTEM_SECURITY_PATCH_PROPERTY} is missing or empty"))?;
    Ok(SecurityPatchProperties { system, vendor })
}

fn write_security_patch_properties_with_rollback<W, R>(
    mut writer: W,
    reader: R,
    expected: &SecurityPatchProperties,
    desired: &SecurityPatchProperties,
) -> Result<()>
where
    W: FnMut(&str, &str) -> Result<()>,
    R: Fn(&str) -> Option<String>,
{
    validate_security_patch_property_values(expected, desired)?;

    let current = read_security_patch_properties_with(&reader)?;
    if current != *expected {
        bail!("security-patch properties changed before the paired update");
    }
    let updates = [
        (
            VENDOR_SECURITY_PATCH_PROPERTY,
            desired.vendor.as_str(),
            expected.vendor.as_str(),
        ),
        (
            SYSTEM_SECURITY_PATCH_PROPERTY,
            desired.system.as_str(),
            expected.system.as_str(),
        ),
    ];

    for (index, (property, value, _)) in updates.iter().enumerate() {
        if let Err(write_error) =
            write_and_confirm_security_patch_property(&mut writer, &reader, property, value)
        {
            let rollback = rollback_security_patch_properties(
                &mut writer,
                &reader,
                &updates[..=index],
                expected,
            );
            return match rollback {
                Ok(()) => Err(write_error).with_context(|| {
                    format!(
                        "failed to update {property}; previous security patch properties restored"
                    )
                }),
                Err(rollback_error) => Err(anyhow!(
                    "failed to update {property}: {write_error:#}; security patch property rollback failed: {rollback_error:#}"
                )),
            };
        }
    }

    let verification_error = match read_security_patch_properties_with(&reader) {
        Ok(actual) if actual == *desired => return Ok(()),
        Ok(_) => anyhow!("security-patch properties changed before final paired verification"),
        Err(error) => error.context("failed final paired security-patch verification"),
    };
    match rollback_security_patch_properties(&mut writer, &reader, &updates, expected) {
        Ok(()) => Err(verification_error)
            .context("paired security-patch verification failed; previous values restored"),
        Err(rollback_error) => Err(anyhow!(
            "paired security-patch verification failed: {verification_error:#}; security patch property rollback failed: {rollback_error:#}"
        )),
    }
}

fn write_security_patch_properties_early<W, R, S>(
    mut writer: W,
    reader: R,
    expected: &SecurityPatchProperties,
    desired: &SecurityPatchProperties,
    attempts: usize,
    mut retry_delay: S,
) -> Result<()>
where
    W: FnMut(&str, &str) -> Result<()>,
    R: Fn(&str) -> Option<String>,
    S: FnMut(),
{
    validate_security_patch_property_values(expected, desired)?;
    if attempts == 0 {
        bail!("early security-patch replay requires at least one write attempt");
    }

    let desired_values = [
        (VENDOR_SECURITY_PATCH_PROPERTY, desired.vendor.as_str()),
        (SYSTEM_SECURITY_PATCH_PROPERTY, desired.system.as_str()),
    ];
    let mut last_failure = String::new();

    for attempt in 1..=attempts {
        let mut failures = Vec::new();
        for (property, value) in desired_values {
            match reader(property) {
                Some(current) if current == value => continue,
                Some(_) | None => {
                    if let Err(error) = writer(property, value) {
                        failures.push(format!("{property} write failed: {error:#}"));
                    }
                }
            }
        }

        match read_security_patch_properties_with(&reader) {
            Ok(actual) if actual == *desired => return Ok(()),
            Ok(actual) => failures.push(format!(
                "observed system={} vendor={} after attempt {attempt}",
                actual.system, actual.vendor
            )),
            Err(error) => failures.push(format!(
                "could not verify the property pair after attempt {attempt}: {error:#}"
            )),
        }
        last_failure = failures.join("; ");
        if attempt < attempts {
            retry_delay();
        }
    }

    bail!("early security-patch replay did not stabilize after {attempts} attempts: {last_failure}")
}

fn validate_security_patch_property_values(
    expected: &SecurityPatchProperties,
    desired: &SecurityPatchProperties,
) -> Result<()> {
    for (label, properties) in [("expected", expected), ("desired", desired)] {
        for (property, value) in [
            (VENDOR_SECURITY_PATCH_PROPERTY, properties.vendor.as_str()),
            (SYSTEM_SECURITY_PATCH_PROPERTY, properties.system.as_str()),
        ] {
            if value.trim().is_empty() {
                bail!("refusing to use an empty {label} value for {property}");
            }
        }
    }
    Ok(())
}

fn write_and_confirm_security_patch_property<W, R>(
    writer: &mut W,
    reader: &R,
    property: &str,
    value: &str,
) -> Result<()>
where
    W: FnMut(&str, &str) -> Result<()>,
    R: Fn(&str) -> Option<String>,
{
    let write_result = writer(property, value);
    let actual = reader(property);
    if actual.as_deref() == Some(value) {
        if let Err(error) = write_result {
            log::warn!(
                "resetprop returned an error for {property}, but the requested value was verified: {error:#}"
            );
        }
        return Ok(());
    }

    let actual = actual.as_deref().unwrap_or("<missing>");
    match write_result {
        Ok(()) => {
            bail!("property verification failed for {property}: expected {value}, got {actual}")
        }
        Err(error) => Err(error).with_context(|| {
            format!("property update failed for {property}: expected {value}, got {actual}")
        }),
    }
}

fn rollback_security_patch_properties<W, R>(
    writer: &mut W,
    reader: &R,
    attempted: &[(&str, &str, &str)],
    previous: &SecurityPatchProperties,
) -> Result<()>
where
    W: FnMut(&str, &str) -> Result<()>,
    R: Fn(&str) -> Option<String>,
{
    let mut failures = Vec::new();
    for (property, attempted_value, previous_value) in attempted.iter().rev() {
        match reader(property) {
            Some(current) if current == *previous_value => continue,
            Some(current) if current == *attempted_value => {
                if let Err(error) = write_and_confirm_security_patch_property(
                    writer,
                    reader,
                    property,
                    previous_value,
                ) {
                    failures.push(format!("{property}: {error:#}"));
                }
            }
            Some(current) => failures.push(format!(
                "{property}: changed concurrently to {current}; rollback skipped"
            )),
            None => failures.push(format!("{property}: disappeared; rollback skipped")),
        }
    }

    if !failures.is_empty() {
        bail!(failures.join("; "));
    }
    let restored = read_security_patch_properties_with(reader)?;
    if restored == *previous {
        Ok(())
    } else {
        bail!("property values changed while rollback was in progress")
    }
}

fn append_resetprop_candidate(
    candidates: &mut Vec<ResetpropCommand>,
    program: impl Into<String>,
    prepend_arg: Option<impl Into<String>>,
) {
    let program = program.into();
    let prepend_arg = prepend_arg.map(Into::into);
    if candidates
        .iter()
        .any(|candidate| candidate.program == program && candidate.prepend_arg == prepend_arg)
    {
        return;
    }
    candidates.push(ResetpropCommand {
        program,
        prepend_arg,
    });
}

/// Return every executable resetprop implementation in trusted preference
/// order.  Root managers occasionally leave a compatibility wrapper at the
/// first path that accepts the command but cannot update read-only properties;
/// callers must be able to continue with the next implementation after a
/// write/verification failure.
fn find_resetprop_commands() -> Result<Vec<ResetpropCommand>> {
    let mut candidates = Vec::new();
    for (program, prepend_arg) in RESETPROP_FALLBACKS {
        if is_executable_file(Path::new(program)) {
            append_resetprop_candidate(
                &mut candidates,
                *program,
                (*prepend_arg).map(str::to_string),
            );
        }
    }

    // A root implementation may expose a compatible helper only through PATH
    // (for example a per-session wrapper).  Consult PATH after the explicit
    // trusted locations so an OEM utility cannot shadow those helpers.
    if let Some(path) = std::env::var_os("PATH") {
        for candidate in std::env::split_paths(&path).map(|directory| directory.join("resetprop")) {
            if is_executable_file(&candidate) {
                append_resetprop_candidate(
                    &mut candidates,
                    candidate.to_string_lossy().into_owned(),
                    None::<String>,
                );
            }
        }
    }

    if candidates.is_empty() {
        Err(anyhow!("no usable resetprop binary found"))
    } else {
        Ok(candidates)
    }
}

pub fn find_resetprop_command() -> Result<ResetpropCommand> {
    find_resetprop_commands()?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no usable resetprop binary found"))
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn execute_write_and_verify(command: &ResetpropCommand, property: &str, value: &str) -> Result<()> {
    execute_write_and_verify_with_mode(command, property, value, false)
}

fn execute_write_and_verify_no_triggers(
    command: &ResetpropCommand,
    property: &str,
    value: &str,
) -> Result<()> {
    execute_write_and_verify_with_mode(command, property, value, true)
}

fn execute_write_and_verify_with_mode(
    command: &ResetpropCommand,
    property: &str,
    value: &str,
    no_triggers: bool,
) -> Result<()> {
    let mut process = Command::new(&command.program);
    let args = resetprop_command_args(command, property, value, no_triggers);
    let status = process
        .args(args)
        .status()
        .with_context(|| format!("failed to execute resetprop for {property}"))?;
    if !status.success() {
        bail!("resetprop failed for {property} with status {status}");
    }

    // `rsproperties` can retain an early-boot failure or observe a different
    // property-area mapping from resetprop on vendor builds.  Security-patch
    // verification therefore uses a fresh command read even for normal
    // runtime writes; other properties retain the cheaper in-process reader.
    let read_property = if no_triggers || is_security_patch_property(property) {
        read_early_string_property
    } else {
        read_string_property
    };
    let actual = read_property(property)
        .ok_or_else(|| anyhow!("property {property} missing after resetprop write"))?;
    if actual.eq_ignore_ascii_case(value) {
        Ok(())
    } else {
        bail!(
            "property verification failed for {property}: expected {value}, got {}",
            actual
        )
    }
}

fn execute_write_and_verify_candidates(
    commands: &[ResetpropCommand],
    property: &str,
    value: &str,
    no_triggers: bool,
) -> Result<()> {
    execute_write_and_verify_candidates_with(
        commands,
        property,
        value,
        no_triggers,
        |command, property, value, no_triggers| {
            if no_triggers {
                execute_write_and_verify_no_triggers(command, property, value)
            } else {
                execute_write_and_verify(command, property, value)
            }
        },
    )
}

fn execute_write_and_verify_candidates_with<E>(
    commands: &[ResetpropCommand],
    property: &str,
    value: &str,
    no_triggers: bool,
    mut execute: E,
) -> Result<()>
where
    E: FnMut(&ResetpropCommand, &str, &str, bool) -> Result<()>,
{
    if commands.is_empty() {
        bail!("no usable resetprop binary found");
    }

    let mut failures = Vec::with_capacity(commands.len());
    for command in commands {
        match execute(command, property, value, no_triggers) {
            Ok(()) => return Ok(()),
            Err(error) => {
                log::debug!(
                    "resetprop candidate {} failed for {}: {error:#}",
                    command.program,
                    property
                );
                failures.push(format!("{}: {error:#}", command.program));
            }
        }
    }

    bail!(
        "all resetprop candidates failed for {property}: {}",
        failures.join("; ")
    )
}

fn resetprop_command_args(
    command: &ResetpropCommand,
    property: &str,
    value: &str,
    no_triggers: bool,
) -> Vec<String> {
    let mut args = Vec::with_capacity(3 + usize::from(command.prepend_arg.is_some()));
    if let Some(prepend_arg) = &command.prepend_arg {
        args.push(prepend_arg.clone());
    }
    if no_triggers {
        args.push("-n".to_string());
    }
    args.push(property.to_string());
    args.push(value.to_string());
    args
}

struct ResetpropHelperClient {
    stream: UnixStream,
}

impl ResetpropHelperClient {
    fn write_and_verify_property(&mut self, property: &str, value: &str) -> Result<()> {
        let response = self.request(&format!("SET\t{property}\t{value}\n"))?;
        if response == "OK" {
            Ok(())
        } else {
            bail!("unexpected resetprop helper response")
        }
    }

    fn get_phone_identifier(
        &mut self,
        kind: PhoneIdentifierKind,
        slot: i32,
    ) -> Result<Option<String>> {
        let response = self.request(&format!("{}\t{slot}\n", kind.command()))?;
        if response == "NONE" {
            return Ok(None);
        }
        if let Some(value) = response.strip_prefix("OK\t") {
            if value.is_empty() {
                bail!("phone identifier helper returned an empty value");
            }
            return Ok(Some(value.to_string()));
        }
        bail!("unexpected phone identifier helper response")
    }

    fn has_system_feature(&mut self, feature: &str) -> Result<bool> {
        match self.request(&format!("HAS_FEATURE\t{feature}\n"))?.as_str() {
            "TRUE" => Ok(true),
            "FALSE" => Ok(false),
            _ => bail!("unexpected telephony feature helper response"),
        }
    }

    fn request(&mut self, request: &str) -> Result<String> {
        self.stream
            .write_all(request.as_bytes())
            .context("failed to send privileged helper request")?;
        self.stream
            .flush()
            .context("failed to flush privileged helper request")?;

        let mut response = String::new();
        let mut reader = BufReader::new(
            self.stream
                .try_clone()
                .context("failed to clone privileged helper stream")?,
        );
        let read = reader
            .read_line(&mut response)
            .context("failed to read privileged helper response")?;
        if read == 0 {
            bail!("privileged helper closed unexpectedly");
        }
        let response = response.trim_end_matches(['\r', '\n']);
        if let Some(service) = response.strip_prefix("UNAVAILABLE\t") {
            return Err(BinderServiceUnavailable(service.to_string()).into());
        }
        if let Some(error) = response.strip_prefix("ERR\t") {
            bail!("{error}");
        }
        Ok(response.to_string())
    }
}

fn execute_phone_identifier(kind: PhoneIdentifierKind, slot: i32) -> Result<Option<String>> {
    rsbinder::ProcessState::init_default()
        .map_err(|error| anyhow!("failed to initialize Binder in privileged helper: {error}"))?;

    let transactions = telephony_transactions();
    let (service, expected_descriptor, transaction, label) = match kind {
        PhoneIdentifierKind::DeviceId => (
            PHONE_SUB_INFO_SERVICE,
            PHONE_SUB_INFO_DESCRIPTOR,
            Some(GET_DEVICE_ID_FOR_PHONE_TRANSACTION),
            "device ID",
        ),
        PhoneIdentifierKind::Imei => (
            PHONE_SERVICE,
            PHONE_DESCRIPTOR,
            Some(transactions.get_imei_for_slot),
            "IMEI",
        ),
        PhoneIdentifierKind::Meid => (
            PHONE_SERVICE,
            PHONE_DESCRIPTOR,
            transactions.get_meid_for_slot,
            "MEID",
        ),
    };
    let Some(transaction) = transaction else {
        return Ok(None);
    };

    let binder = require_binder_service(service, hub::try_get_service(service))?;
    let descriptor = binder.descriptor();
    if descriptor != expected_descriptor {
        bail!("{service} descriptor mismatch: {descriptor}");
    }
    let proxy = binder
        .as_proxy()
        .with_context(|| format!("{service} binder was unexpectedly local"))?;
    let mut data = proxy
        .prepare_transact(true)
        .with_context(|| format!("failed to prepare {label} transaction"))?;
    data.write(&slot)
        .with_context(|| format!("failed to write {label} slot"))?;
    data.write(ANDROID_PACKAGE)
        .with_context(|| format!("failed to write {label} calling package"))?;
    data.write(ANDROID_PACKAGE)
        .with_context(|| format!("failed to write {label} calling feature"))?;

    let mut reply = proxy
        .submit_transact(transaction, &data, rsbinder::FLAG_CLEAR_BUF)
        .with_context(|| format!("{label} transact failed"))?
        .with_context(|| format!("{label} returned no reply"))?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .with_context(|| format!("failed to decode {label} reply status"))?;
    if !status.is_ok() {
        bail!("{label} returned non-ok status: {status}");
    }

    let Some(value): Option<String> = reply
        .read()
        .with_context(|| format!("failed to decode {label} value"))?
    else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        bail!("{label} returned an invalid identifier");
    }
    Ok(Some(value.to_string()))
}

fn execute_has_system_feature(feature: &str) -> Result<bool> {
    rsbinder::ProcessState::init_default()
        .map_err(|error| anyhow!("failed to initialize Binder in privileged helper: {error}"))?;

    let binder = require_binder_service(
        PACKAGE_MANAGER_NATIVE_SERVICE,
        hub::try_get_service(PACKAGE_MANAGER_NATIVE_SERVICE),
    )?;
    let descriptor = binder.descriptor();
    if descriptor != PACKAGE_MANAGER_NATIVE_DESCRIPTOR {
        bail!("PackageManager descriptor mismatch: {descriptor}");
    }
    let proxy = binder
        .as_proxy()
        .context("PackageManager binder was unexpectedly local")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare PackageManager transaction")?;
    data.write(feature)
        .context("failed to write PackageManager feature name")?;
    data.write(&0_i32)
        .context("failed to write PackageManager feature version")?;

    let mut reply = proxy
        .submit_transact(
            has_system_feature_transaction(kmr_common::android_version::android_major_version()),
            &data,
            rsbinder::FLAG_CLEAR_BUF,
        )
        .context("PackageManager hasSystemFeature transact failed")?
        .context("PackageManager hasSystemFeature returned no reply")?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .context("failed to decode PackageManager hasSystemFeature status")?;
    if !status.is_ok() {
        bail!("PackageManager hasSystemFeature returned non-ok status: {status}");
    }
    reply
        .read()
        .context("failed to decode PackageManager hasSystemFeature result")
}

fn has_system_feature_transaction(android_major: Option<i32>) -> rsbinder::TransactionCode {
    let offset = match android_major {
        Some(..=13) => 12,
        Some(14) => 9,
        Some(15 | 16) | None => 10,
        Some(17..) => 13,
    };
    rsbinder::FIRST_CALL_TRANSACTION + offset
}

fn telephony_transactions() -> TelephonyTransactions {
    telephony_transactions_for(kmr_common::android_version::android_major_version())
}

fn telephony_transactions_for(android_major: Option<i32>) -> TelephonyTransactions {
    let (imei_offset, meid_offset) = match android_major {
        Some(version) if version <= 12 => (149, Some(151)),
        Some(13) => (145, Some(147)),
        Some(14) => (148, Some(151)),
        Some(version) if version >= 17 => (132, None),
        _ => (147, Some(150)),
    };

    TelephonyTransactions {
        get_imei_for_slot: rsbinder::FIRST_CALL_TRANSACTION + imei_offset,
        get_meid_for_slot: meid_offset.map(|offset| rsbinder::FIRST_CALL_TRANSACTION + offset),
    }
}

fn parse_phone_identifier_request(line: &str) -> Option<(PhoneIdentifierKind, &str)> {
    let (command, slot) = line.split_once('\t')?;
    PhoneIdentifierKind::from_command(command).map(|kind| (kind, slot))
}

fn parse_feature_request(line: &str) -> Option<&str> {
    let feature = line.strip_prefix("HAS_FEATURE\t")?;
    matches!(
        feature,
        TELEPHONY_FEATURE | TELEPHONY_GSM_FEATURE | TELEPHONY_CDMA_FEATURE
    )
    .then_some(feature)
}

fn helper_error_response(error: &anyhow::Error) -> String {
    if let Some(error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<BinderServiceUnavailable>())
    {
        format!("UNAVAILABLE\t{}\n", error.0)
    } else {
        format!("ERR\t{error:#}\n")
    }
}

fn helper_loop(stream: UnixStream, commands: Vec<ResetpropCommand>) -> Result<()> {
    let reader_stream = stream
        .try_clone()
        .context("failed to clone resetprop helper socket")?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .context("failed to read resetprop helper request")?;
        if read == 0 {
            return Ok(());
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        let response = if let Some(feature) = parse_feature_request(trimmed) {
            match execute_has_system_feature(feature) {
                Ok(true) => "TRUE\n".to_string(),
                Ok(false) => "FALSE\n".to_string(),
                Err(error) => helper_error_response(&error),
            }
        } else if let Some((kind, slot)) = parse_phone_identifier_request(trimmed) {
            match slot.parse::<i32>() {
                Ok(slot) if matches!(slot, 0 | 1) => match execute_phone_identifier(kind, slot) {
                    Ok(Some(value)) => format!("OK\t{value}\n"),
                    Ok(None) => "NONE\n".to_string(),
                    Err(error) => helper_error_response(&error),
                },
                _ => "ERR\tinvalid phone identifier helper request\n".to_string(),
            }
        } else {
            match parse_request(&line) {
                Ok((property, value)) => {
                    match execute_write_and_verify_candidates(&commands, &property, &value, false) {
                        Ok(()) => "OK\n".to_string(),
                        Err(error) => helper_error_response(&error),
                    }
                }
                Err(error) => format!("ERR\t{error:#}\n"),
            }
        };
        writer
            .write_all(response.as_bytes())
            .context("failed to write resetprop helper response")?;
        writer
            .flush()
            .context("failed to flush resetprop helper response")?;
    }
}

fn parse_request(line: &str) -> Result<(String, String)> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, '\t');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("SET"), Some(property), Some(value))
            if !property.trim().is_empty() && !value.trim().is_empty() =>
        {
            Ok((property.to_string(), value.to_string()))
        }
        _ => Err(anyhow!("invalid resetprop helper request: {trimmed:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap};

    fn patch_properties(system: &str, vendor: &str) -> SecurityPatchProperties {
        SecurityPatchProperties {
            system: system.to_string(),
            vendor: vendor.to_string(),
        }
    }

    fn property_map(values: &SecurityPatchProperties) -> HashMap<String, String> {
        HashMap::from([
            (
                SYSTEM_SECURITY_PATCH_PROPERTY.to_string(),
                values.system.clone(),
            ),
            (
                VENDOR_SECURITY_PATCH_PROPERTY.to_string(),
                values.vendor.clone(),
            ),
        ])
    }

    #[test]
    fn resetprop_command_args_preserve_normal_and_no_trigger_forms() {
        let direct = ResetpropCommand {
            program: "/system/bin/resetprop".to_string(),
            prepend_arg: None,
        };
        assert_eq!(
            resetprop_command_args(&direct, "ro.example", "value", false),
            vec!["ro.example", "value"]
        );
        assert_eq!(
            resetprop_command_args(&direct, "ro.example", "value", true),
            vec!["-n", "ro.example", "value"]
        );

        let ksud = ResetpropCommand {
            program: "/data/adb/ksud".to_string(),
            prepend_arg: Some("resetprop".to_string()),
        };
        assert_eq!(
            resetprop_command_args(&ksud, "ro.example", "value", true),
            vec!["resetprop", "-n", "ro.example", "value"]
        );

        let apd = ResetpropCommand {
            program: "/data/adb/apd".to_string(),
            prepend_arg: Some("resetprop".to_string()),
        };
        assert_eq!(
            resetprop_command_args(&apd, "ro.example", "value", true),
            vec!["resetprop", "-n", "ro.example", "value"]
        );
    }

    #[test]
    fn resetprop_fallbacks_prefer_root_owned_tools_over_system_tools() {
        let first_system = RESETPROP_FALLBACKS
            .iter()
            .position(|(path, _)| path == &"/system_ext/bin/resetprop")
            .unwrap();
        let root_tools = [
            "/data/adb/ksu/bin/resetprop",
            "/data/adb/magisk/resetprop",
            "/data/adb/ap/bin/resetprop",
            "/data/adb/ksud",
            "/data/adb/apd",
        ];
        for root_tool in root_tools {
            let position = RESETPROP_FALLBACKS
                .iter()
                .position(|(path, _)| path == &root_tool)
                .unwrap();
            assert!(
                position < first_system,
                "root resetprop candidate {root_tool} must precede system candidates"
            );
        }
    }

    #[test]
    fn resetprop_candidate_execution_continues_after_a_failed_wrapper() {
        let commands = vec![
            ResetpropCommand {
                program: "/data/adb/first/resetprop".to_string(),
                prepend_arg: None,
            },
            ResetpropCommand {
                program: "/data/adb/working/resetprop".to_string(),
                prepend_arg: None,
            },
        ];
        let attempted = RefCell::new(Vec::new());

        execute_write_and_verify_candidates_with(
            &commands,
            SYSTEM_SECURITY_PATCH_PROPERTY,
            "2026-08-05",
            false,
            |command, property, value, no_triggers| {
                attempted.borrow_mut().push((
                    command.program.clone(),
                    property.to_string(),
                    value.to_string(),
                    no_triggers,
                ));
                if command.program.contains("first") {
                    bail!("wrapper cannot update the property")
                }
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            *attempted.borrow(),
            vec![
                (
                    "/data/adb/first/resetprop".to_string(),
                    SYSTEM_SECURITY_PATCH_PROPERTY.to_string(),
                    "2026-08-05".to_string(),
                    false,
                ),
                (
                    "/data/adb/working/resetprop".to_string(),
                    SYSTEM_SECURITY_PATCH_PROPERTY.to_string(),
                    "2026-08-05".to_string(),
                    false,
                ),
            ]
        );
    }

    #[test]
    fn append_resetprop_candidate_deduplicates_same_invocation() {
        let mut candidates = Vec::new();
        append_resetprop_candidate(&mut candidates, "/data/adb/ksud", Some("resetprop"));
        append_resetprop_candidate(&mut candidates, "/data/adb/ksud", Some("resetprop"));
        append_resetprop_candidate(&mut candidates, "/data/adb/ksud", None::<String>);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].program, "/data/adb/ksud");
        assert_eq!(candidates[0].prepend_arg.as_deref(), Some("resetprop"));
        assert_eq!(candidates[1].prepend_arg, None);
    }

    #[test]
    fn early_property_output_is_trimmed_and_bounded() {
        assert_eq!(
            normalize_early_property_output(b"  2026-08-05\n"),
            Some("2026-08-05")
        );
        assert_eq!(normalize_early_property_output(b"\n\t"), None);
        assert_eq!(
            normalize_early_property_output(&[b'x'; MAX_EARLY_PROPERTY_OUTPUT_BYTES + 1]),
            None
        );
        assert_eq!(normalize_early_property_output(&[0xff, 0xfe]), None);
    }

    #[test]
    fn early_property_reader_is_restricted_to_security_patch_names() {
        assert!(is_security_patch_property(SYSTEM_SECURITY_PATCH_PROPERTY));
        assert!(is_security_patch_property(VENDOR_SECURITY_PATCH_PROPERTY));
        assert!(!is_security_patch_property("ro.build.fingerprint"));
        assert!(EARLY_PROPERTY_READ_FALLBACKS
            .iter()
            .all(|(path, _)| path.starts_with('/')));
    }

    #[test]
    fn reads_security_patch_properties_as_a_pair() {
        let expected = patch_properties("2026-08-05", "2026-07-05");
        let properties = property_map(&expected);

        assert_eq!(
            read_security_patch_properties_with(|property| properties.get(property).cloned())
                .unwrap(),
            expected
        );
        assert!(read_security_patch_properties_with(|property| {
            (property == SYSTEM_SECURITY_PATCH_PROPERTY).then(|| "2026-08-05".to_string())
        })
        .unwrap_err()
        .to_string()
        .contains(VENDOR_SECURITY_PATCH_PROPERTY));
    }

    #[test]
    fn writes_and_verifies_security_patch_properties_as_a_pair() {
        let previous = patch_properties("2026-06-05", "2026-05-05");
        let desired = patch_properties("2026-08-05", "2026-08-05");
        let properties = RefCell::new(property_map(&previous));
        let writes = RefCell::new(Vec::new());

        write_security_patch_properties_with_rollback(
            |property, value| {
                writes
                    .borrow_mut()
                    .push((property.to_string(), value.to_string()));
                properties
                    .borrow_mut()
                    .insert(property.to_string(), value.to_string());
                Ok(())
            },
            |property| properties.borrow().get(property).cloned(),
            &previous,
            &desired,
        )
        .unwrap();

        assert_eq!(*properties.borrow(), property_map(&desired));
        assert_eq!(
            *writes.borrow(),
            vec![
                (
                    VENDOR_SECURITY_PATCH_PROPERTY.to_string(),
                    desired.vendor.clone()
                ),
                (
                    SYSTEM_SECURITY_PATCH_PROPERTY.to_string(),
                    desired.system.clone()
                ),
            ]
        );
    }

    #[test]
    fn security_patch_pair_write_rejects_a_stale_expected_value() {
        let expected = patch_properties("2026-06-05", "2026-05-05");
        let current = patch_properties("2026-06-05", "2026-06-01");
        let desired = patch_properties("2026-08-05", "2026-08-05");
        let properties = RefCell::new(property_map(&current));
        let writes = RefCell::new(0_u32);

        let error = write_security_patch_properties_with_rollback(
            |_, _| {
                *writes.borrow_mut() += 1;
                Ok(())
            },
            |property| properties.borrow().get(property).cloned(),
            &expected,
            &desired,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("changed before the paired update"));
        assert_eq!(*writes.borrow(), 0);
        assert_eq!(*properties.borrow(), property_map(&current));
    }

    #[test]
    fn second_security_patch_write_failure_rolls_back_the_first() {
        let previous = patch_properties("2026-06-05", "2026-05-05");
        let desired = patch_properties("2026-08-05", "2026-08-05");
        let properties = RefCell::new(property_map(&previous));

        let error = write_security_patch_properties_with_rollback(
            |property, value| {
                if property == SYSTEM_SECURITY_PATCH_PROPERTY && value == desired.system {
                    bail!("injected system property write failure");
                }
                properties
                    .borrow_mut()
                    .insert(property.to_string(), value.to_string());
                Ok(())
            },
            |property| properties.borrow().get(property).cloned(),
            &previous,
            &desired,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("previous security patch properties restored"));
        assert_eq!(*properties.borrow(), property_map(&previous));
    }

    #[test]
    fn security_patch_write_reports_an_incomplete_rollback() {
        let previous = patch_properties("2026-06-05", "2026-05-05");
        let desired = patch_properties("2026-08-05", "2026-08-05");
        let properties = RefCell::new(property_map(&previous));

        let error = write_security_patch_properties_with_rollback(
            |property, value| {
                if property == SYSTEM_SECURITY_PATCH_PROPERTY && value == desired.system {
                    bail!("injected system property write failure");
                }
                if property == VENDOR_SECURITY_PATCH_PROPERTY && value == previous.vendor {
                    bail!("injected vendor property rollback failure");
                }
                properties
                    .borrow_mut()
                    .insert(property.to_string(), value.to_string());
                Ok(())
            },
            |property| properties.borrow().get(property).cloned(),
            &previous,
            &desired,
        )
        .unwrap_err();

        assert!(error.to_string().contains("property rollback failed"));
        assert_eq!(
            properties
                .borrow()
                .get(VENDOR_SECURITY_PATCH_PROPERTY)
                .map(String::as_str),
            Some(desired.vendor.as_str())
        );
    }

    #[test]
    fn final_pair_verification_does_not_overwrite_a_concurrent_change() {
        let previous = patch_properties("2026-06-05", "2026-05-05");
        let desired = patch_properties("2026-08-05", "2026-08-05");
        let concurrent_vendor = "2026-07-05";
        let properties = RefCell::new(property_map(&previous));

        let error = write_security_patch_properties_with_rollback(
            |property, value| {
                properties
                    .borrow_mut()
                    .insert(property.to_string(), value.to_string());
                if property == SYSTEM_SECURITY_PATCH_PROPERTY && value == desired.system {
                    properties.borrow_mut().insert(
                        VENDOR_SECURITY_PATCH_PROPERTY.to_string(),
                        concurrent_vendor.to_string(),
                    );
                }
                Ok(())
            },
            |property| properties.borrow().get(property).cloned(),
            &previous,
            &desired,
        )
        .unwrap_err();

        assert!(error.to_string().contains("property rollback failed"));
        assert_eq!(
            properties
                .borrow()
                .get(VENDOR_SECURITY_PATCH_PROPERTY)
                .map(String::as_str),
            Some(concurrent_vendor)
        );
        assert_eq!(
            properties
                .borrow()
                .get(SYSTEM_SECURITY_PATCH_PROPERTY)
                .map(String::as_str),
            Some(previous.system.as_str())
        );
    }

    #[test]
    fn early_pair_write_retries_after_init_republishes_an_old_value_without_rollback() {
        let previous = patch_properties("2026-06-05", "2026-05-05");
        let desired = patch_properties("2026-08-05", "2026-08-05");
        let properties = RefCell::new(property_map(&previous));
        let writes = RefCell::new(Vec::new());
        let init_republished = RefCell::new(false);

        write_security_patch_properties_early(
            |property, value| {
                writes
                    .borrow_mut()
                    .push((property.to_string(), value.to_string()));
                properties
                    .borrow_mut()
                    .insert(property.to_string(), value.to_string());
                // Simulate init loading the vendor property again while the
                // paired system update is in flight. The next attempt must
                // write the desired vendor value again, rather than rolling
                // the already-written system value back to `previous`.
                if property == SYSTEM_SECURITY_PATCH_PROPERTY && !*init_republished.borrow() {
                    *init_republished.borrow_mut() = true;
                    properties.borrow_mut().insert(
                        VENDOR_SECURITY_PATCH_PROPERTY.to_string(),
                        previous.vendor.clone(),
                    );
                }
                Ok(())
            },
            |property| properties.borrow().get(property).cloned(),
            &previous,
            &desired,
            3,
            || {},
        )
        .unwrap();

        assert_eq!(*properties.borrow(), property_map(&desired));
        assert_eq!(
            *writes.borrow(),
            vec![
                (
                    VENDOR_SECURITY_PATCH_PROPERTY.to_string(),
                    desired.vendor.clone()
                ),
                (
                    SYSTEM_SECURITY_PATCH_PROPERTY.to_string(),
                    desired.system.clone()
                ),
                (
                    VENDOR_SECURITY_PATCH_PROPERTY.to_string(),
                    desired.vendor.clone()
                ),
            ]
        );
    }

    #[test]
    fn early_pair_write_can_create_properties_that_are_not_published_yet() {
        let previous = patch_properties("2026-06-05", "2026-05-05");
        let desired = patch_properties("2026-08-05", "2026-08-05");
        let properties = RefCell::new(HashMap::new());

        write_security_patch_properties_early(
            |property, value| {
                properties
                    .borrow_mut()
                    .insert(property.to_string(), value.to_string());
                Ok(())
            },
            |property| properties.borrow().get(property).cloned(),
            &previous,
            &desired,
            1,
            || {},
        )
        .unwrap();

        assert_eq!(*properties.borrow(), property_map(&desired));
    }

    #[test]
    fn telephony_transactions_match_android_12_through_17() {
        use rsbinder::FIRST_CALL_TRANSACTION;

        assert_eq!(
            GET_DEVICE_ID_FOR_PHONE_TRANSACTION,
            FIRST_CALL_TRANSACTION + 3
        );
        for (version, offset) in [(12, 12), (13, 12), (14, 9), (15, 10), (16, 10), (17, 13)] {
            assert_eq!(
                has_system_feature_transaction(Some(version)),
                FIRST_CALL_TRANSACTION + offset
            );
        }
        for (version, imei, meid) in [
            (12, 149, Some(151)),
            (13, 145, Some(147)),
            (14, 148, Some(151)),
            (15, 147, Some(150)),
            (16, 147, Some(150)),
            (17, 132, None),
        ] {
            let transactions = telephony_transactions_for(Some(version));
            assert_eq!(
                transactions.get_imei_for_slot,
                FIRST_CALL_TRANSACTION + imei
            );
            assert_eq!(
                transactions.get_meid_for_slot,
                meid.map(|offset| FIRST_CALL_TRANSACTION + offset)
            );
        }
    }

    #[test]
    fn feature_helper_accepts_only_telephony_features() {
        for feature in [
            TELEPHONY_FEATURE,
            TELEPHONY_GSM_FEATURE,
            TELEPHONY_CDMA_FEATURE,
        ] {
            assert_eq!(
                parse_feature_request(&format!("HAS_FEATURE\t{feature}")),
                Some(feature)
            );
        }
        assert_eq!(
            parse_feature_request("HAS_FEATURE\tandroid.hardware.camera"),
            None
        );
        assert_eq!(parse_feature_request("HAS_FEATURE"), None);
    }

    #[test]
    fn service_unavailable_response_round_trips() {
        let (client_stream, mut helper_stream) = UnixStream::pair().unwrap();
        let unavailable: anyhow::Error = BinderServiceUnavailable(PHONE_SERVICE.to_string()).into();
        helper_stream
            .write_all(helper_error_response(&unavailable).as_bytes())
            .unwrap();

        let mut client = ResetpropHelperClient {
            stream: client_stream,
        };
        let error = client
            .get_phone_identifier(PhoneIdentifierKind::Imei, 0)
            .unwrap_err();

        assert!(is_binder_service_unavailable(&error));
        assert_eq!(error.to_string(), "service phone unavailable");
    }

    #[test]
    fn service_lookup_only_retries_missing_or_transport_failures() {
        assert_eq!(
            require_binder_service(PHONE_SERVICE, Ok(Some(7_u8))).unwrap(),
            7
        );

        let unavailable: [rsbinder::Result<Option<()>>; 3] = [
            Ok(None),
            Err(StatusCode::DeadObject),
            Err(StatusCode::NotEnoughData),
        ];
        for lookup in unavailable {
            let error = require_binder_service(PHONE_SERVICE, lookup).unwrap_err();
            assert!(is_binder_service_unavailable(&error));
            assert_eq!(helper_error_response(&error), "UNAVAILABLE\tphone\n");
        }

        for status in [
            StatusCode::NameNotFound,
            StatusCode::PermissionDenied,
            StatusCode::FailedTransaction,
            StatusCode::WouldBlock,
            StatusCode::TimedOut,
            StatusCode::RpcError,
        ] {
            let error = require_binder_service::<()>(PHONE_SERVICE, Err(status)).unwrap_err();
            assert!(!is_binder_service_unavailable(&error));
            assert!(error
                .chain()
                .any(|cause| cause.downcast_ref::<StatusCode>() == Some(&status)));
            assert!(helper_error_response(&error).starts_with("ERR\t"));
        }
    }
}
