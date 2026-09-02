use std::{
    fs::{self, File},
    os::fd::AsRawFd,
    path::Path,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use serde::{Deserialize, Serialize};
use ureq::http::Uri;

use crate::{
    config::{self, ConfigFile, RawTrustConfig},
    plat::{
        resetprop::{
            self, SecurityPatchProperties, SYSTEM_SECURITY_PATCH_PROPERTY,
            VENDOR_SECURITY_PATCH_PROPERTY,
        },
        vbmeta,
    },
    root_path,
    webui_http::{self, DownloadPolicy},
};

const DEFAULTS_PATH: &str = root_path!("data/security_patch_defaults.toml");
const ANDROID_SECURITY_BULLETIN_PATH: &str = "/docs/security/bulletin/asb-overview";
const ANDROID_SECURITY_BULLETIN_HOSTS: [&str; 2] =
    ["source.android.com", "source.android.google.cn"];
const MAX_BULLETIN_BYTES: usize = 2 * 1024 * 1024;
const MAX_BULLETIN_REDIRECTS: usize = 3;
const BULLETIN_TIMEOUT: Duration = Duration::from_secs(15);
const BULLETIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SNAPSHOT_VERSION: u32 = 1;
const BUILD_FINGERPRINT_PROPERTY: &str = "ro.build.fingerprint";
const MAX_SNAPSHOT_BYTES: u64 = 4096;
const MAX_FINGERPRINT_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecurityPatchDefaults {
    version: u32,
    build_fingerprint: String,
    #[serde(rename = "ro.vendor.build.security_patch")]
    vendor_security_patch: String,
    #[serde(rename = "ro.build.version.security_patch")]
    system_security_patch: String,
}

impl SecurityPatchDefaults {
    fn new(build_fingerprint: &str, properties: &SecurityPatchProperties) -> Result<Self> {
        validate_fingerprint(build_fingerprint)?;
        validate_properties(properties, "default")?;
        Ok(Self {
            version: SNAPSHOT_VERSION,
            build_fingerprint: build_fingerprint.to_string(),
            vendor_security_patch: properties.vendor.clone(),
            system_security_patch: properties.system.clone(),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.version != SNAPSHOT_VERSION {
            bail!(
                "unsupported security-patch defaults version {}",
                self.version
            );
        }
        validate_fingerprint(&self.build_fingerprint)?;
        validate_properties(&self.properties(), "saved default")
    }

    fn properties(&self) -> SecurityPatchProperties {
        SecurityPatchProperties {
            system: self.system_security_patch.clone(),
            vendor: self.vendor_security_patch.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatchIntent {
    Auto,
    Synchronized(String),
    Other,
}

struct PatchOperation<'a> {
    config_file: &'a ConfigFile,
    state_path: &'a Path,
    fingerprint: &'a str,
}

pub(crate) struct OperationLock(File);

impl OperationLock {
    fn acquire(state_path: &Path) -> Result<Self> {
        let parent = state_path
            .parent()
            .ok_or_else(|| anyhow!("security-patch defaults path has no parent"))?;
        let file = File::open(parent).with_context(|| {
            format!(
                "failed to open security-patch state directory {}",
                parent.display()
            )
        })?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to lock security-patch state directory");
        }
        Ok(Self(file))
    }
}

pub(crate) fn acquire_operation_lock() -> Result<OperationLock> {
    OperationLock::acquire(Path::new(DEFAULTS_PATH))
}

pub(crate) fn acquire_data_operation_lock(state_path: &Path) -> Result<OperationLock> {
    OperationLock::acquire(state_path)
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn is_official_security_bulletin_uri(uri: &Uri) -> bool {
    if uri.scheme_str() != Some("https") || uri.path() != ANDROID_SECURITY_BULLETIN_PATH {
        return false;
    }

    let Some(authority) = uri.authority() else {
        return false;
    };
    let authority_text = authority.as_str();
    if authority_text.contains('@') {
        return false;
    }

    // `http::Authority::port_u16()` returns `None` both when no port is
    // present and when a malformed port cannot be parsed.  Compare the
    // authority text directly so values such as `:bad` or `:0443` cannot pass
    // as the default HTTPS port.
    let host = match authority_text.strip_suffix(":443") {
        Some(host) if !host.contains(':') => host,
        Some(_) => return false,
        None if authority_text.contains(':') => return false,
        None => authority_text,
    };

    ANDROID_SECURITY_BULLETIN_HOSTS
        .iter()
        .any(|allowed_host| host.eq_ignore_ascii_case(allowed_host))
}

/// Download one explicitly allowed Android Security Bulletin overview page.
///
/// The WebUI invokes this entry point in a short-lived `keymint` process so
/// devices do not need to provide curl, wget, or a particular root-shell PATH.
pub fn download_android_security_bulletin(url: &str) -> Result<String> {
    let requested_uri: Uri = url
        .parse()
        .context("Android Security Bulletin URL is invalid")?;
    if !is_official_security_bulletin_uri(&requested_uri) {
        bail!("Android Security Bulletin URL is not an allowed Google page");
    }

    webui_http::download_https_utf8(
        requested_uri,
        &DownloadPolicy {
            resource: "Android Security Bulletin",
            redirect_allowlist: "the allowed Google page",
            max_bytes: MAX_BULLETIN_BYTES,
            max_size_label: "2 MiB",
            max_redirects: MAX_BULLETIN_REDIRECTS,
            timeout: BULLETIN_TIMEOUT,
            connect_timeout: BULLETIN_CONNECT_TIMEOUT,
        },
        is_official_security_bulletin_uri,
    )
}

pub fn apply_webui_security_patch(value: &str) -> Result<()> {
    config::validate_security_patch_sync_value(value)?;
    let _lock = acquire_operation_lock()?;
    let config_file = config::load_config_file()
        .context("failed to read the active config before changing security patches")?;
    let fingerprint = current_build_fingerprint()?;
    let state_path = Path::new(DEFAULTS_PATH);

    apply_webui_security_patch_with(
        value,
        PatchOperation {
            config_file: &config_file,
            state_path,
            fingerprint: &fingerprint,
        },
        resetprop::read_security_patch_properties,
        read_build_security_patch_properties,
        resetprop::direct_write_and_verify_security_patch_properties,
        persist_and_verify_config,
    )
}

/// Reapply an active WebUI patch override before the regular vbmeta bootstrap
/// can change the system property. This also refreshes defaults after an OTA.
pub(crate) fn prepare_startup(config_file: &ConfigFile, _lock: &OperationLock) -> Result<()> {
    let PatchIntent::Synchronized(date) = patch_intent(&config_file.trust) else {
        return Ok(());
    };

    let fingerprint = current_build_fingerprint()?;
    let state_path = Path::new(DEFAULTS_PATH);
    prepare_startup_with(
        config_file,
        state_path,
        &fingerprint,
        resetprop::read_security_patch_properties,
        read_build_security_patch_properties,
        resetprop::direct_write_and_verify_security_patch_properties,
    )
    .with_context(|| format!("failed to reapply synchronized security patch {date}"))
}

fn apply_webui_security_patch_with<RuntimeReader, DefaultReader, PropertyWriter, ConfigWriter>(
    value: &str,
    operation: PatchOperation<'_>,
    mut read_runtime: RuntimeReader,
    mut read_defaults: DefaultReader,
    mut write_properties: PropertyWriter,
    mut write_config: ConfigWriter,
) -> Result<()>
where
    RuntimeReader: FnMut() -> Result<SecurityPatchProperties>,
    DefaultReader: FnMut() -> Result<SecurityPatchProperties>,
    PropertyWriter: FnMut(&SecurityPatchProperties, &SecurityPatchProperties) -> Result<()>,
    ConfigWriter: FnMut(&str) -> Result<()>,
{
    config::validate_security_patch_sync_value(value)?;
    let intent = patch_intent(&operation.config_file.trust);
    let snapshot = ensure_defaults_snapshot(
        operation.state_path,
        operation.fingerprint,
        matches!(intent, PatchIntent::Auto),
        &mut read_runtime,
        &mut read_defaults,
    )?;
    let before = read_runtime().context("failed to read current security-patch properties")?;
    validate_properties(&before, "current")?;

    let desired = if value == "auto" {
        snapshot.properties()
    } else {
        SecurityPatchProperties {
            system: value.to_string(),
            vendor: value.to_string(),
        }
    };
    write_properties(&before, &desired).with_context(|| {
        if value == "auto" {
            "failed to restore default security-patch properties"
        } else {
            "failed to synchronize security-patch properties"
        }
    })?;

    if let Err(config_error) = write_config(value) {
        return Err(config_error_with_property_rollback(
            config_error,
            &desired,
            &before,
            &mut write_properties,
        ));
    }

    if value == "auto" {
        remove_snapshot(operation.state_path)
            .context("security patches were restored, but the defaults snapshot was not removed")?;
    }
    Ok(())
}

fn prepare_startup_with<RuntimeReader, DefaultReader, PropertyWriter>(
    config_file: &ConfigFile,
    state_path: &Path,
    fingerprint: &str,
    mut read_runtime: RuntimeReader,
    mut read_defaults: DefaultReader,
    mut write_properties: PropertyWriter,
) -> Result<()>
where
    RuntimeReader: FnMut() -> Result<SecurityPatchProperties>,
    DefaultReader: FnMut() -> Result<SecurityPatchProperties>,
    PropertyWriter: FnMut(&SecurityPatchProperties, &SecurityPatchProperties) -> Result<()>,
{
    let PatchIntent::Synchronized(date) = patch_intent(&config_file.trust) else {
        return Ok(());
    };
    let Some(mut snapshot) = load_snapshot(state_path)? else {
        return Ok(());
    };
    if snapshot.build_fingerprint != fingerprint {
        let defaults = read_defaults()
            .context("failed to refresh default security patches from build properties")?;
        snapshot = SecurityPatchDefaults::new(fingerprint, &defaults)?;
        persist_snapshot(state_path, &snapshot)?;
    }
    let desired = SecurityPatchProperties {
        system: date.clone(),
        vendor: date,
    };
    let before = read_runtime().context("failed to read startup security-patch properties")?;
    write_properties(&before, &desired).context("failed to write startup security-patch properties")
}

fn ensure_defaults_snapshot<RuntimeReader, DefaultReader>(
    path: &Path,
    fingerprint: &str,
    runtime_is_default: bool,
    read_runtime: &mut RuntimeReader,
    read_defaults: &mut DefaultReader,
) -> Result<SecurityPatchDefaults>
where
    RuntimeReader: FnMut() -> Result<SecurityPatchProperties>,
    DefaultReader: FnMut() -> Result<SecurityPatchProperties>,
{
    validate_fingerprint(fingerprint)?;
    if let Some(snapshot) = load_snapshot(path)? {
        if snapshot.build_fingerprint == fingerprint {
            return Ok(snapshot);
        }
    }

    let properties = if runtime_is_default {
        read_runtime().context("failed to record current default security-patch properties")?
    } else {
        read_defaults().context("failed to read default security patches from build properties")?
    };
    let snapshot = SecurityPatchDefaults::new(fingerprint, &properties)?;
    persist_snapshot(path, &snapshot)?;
    Ok(snapshot)
}

fn load_snapshot(path: &Path) -> Result<Option<SecurityPatchDefaults>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect security-patch defaults {}",
                    path.display()
                )
            })
        }
    };
    if !metadata.file_type().is_file() {
        bail!(
            "security-patch defaults path is not a regular file: {}",
            path.display()
        );
    }
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        bail!("security-patch defaults file is too large");
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read security-patch defaults {}", path.display()))?;
    let snapshot: SecurityPatchDefaults =
        toml::from_str(&contents).context("invalid security-patch defaults file")?;
    snapshot.validate()?;
    Ok(Some(snapshot))
}

fn persist_snapshot(path: &Path, snapshot: &SecurityPatchDefaults) -> Result<()> {
    snapshot.validate()?;
    let contents =
        toml::to_string_pretty(snapshot).context("failed to serialize security-patch defaults")?;
    let (uid, gid) = if path == Path::new(DEFAULTS_PATH) {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    };
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o600, uid, gid)
        .with_context(|| format!("failed to save security-patch defaults {}", path.display()))
}

fn remove_snapshot(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to remove security-patch defaults {}",
                    path.display()
                )
            })
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("security-patch defaults path has no parent"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("failed to sync security-patch state directory after removal")
}

fn persist_and_verify_config(value: &str) -> Result<()> {
    match config::sync_security_patch(value) {
        Ok(()) => Ok(()),
        Err(write_error) => match config::load_config_file() {
            Ok(config_file) if patch_fields_match(&config_file.trust, value) => Ok(()),
            Ok(_) => Err(write_error).context("security-patch config write was not applied"),
            Err(read_error) => Err(anyhow!(
                "security-patch config write failed: {write_error:#}; verification failed: {read_error:#}"
            )),
        },
    }
}

fn config_error_with_property_rollback<PropertyWriter>(
    config_error: anyhow::Error,
    expected: &SecurityPatchProperties,
    before: &SecurityPatchProperties,
    write_properties: &mut PropertyWriter,
) -> anyhow::Error
where
    PropertyWriter: FnMut(&SecurityPatchProperties, &SecurityPatchProperties) -> Result<()>,
{
    match write_properties(expected, before) {
        Ok(()) => config_error.context(
            "security-patch config update failed; runtime properties were restored",
        ),
        Err(rollback_error) => anyhow!(
            "security-patch config update failed: {config_error:#}; runtime property rollback failed: {rollback_error:#}"
        ),
    }
}

fn read_build_security_patch_properties() -> Result<SecurityPatchProperties> {
    let system = vbmeta::read_build_prop_value(SYSTEM_SECURITY_PATCH_PROPERTY)
        .ok_or_else(|| anyhow!("default {SYSTEM_SECURITY_PATCH_PROPERTY} was not found"))?;
    let vendor = vbmeta::read_build_prop_value(VENDOR_SECURITY_PATCH_PROPERTY)
        .ok_or_else(|| anyhow!("default {VENDOR_SECURITY_PATCH_PROPERTY} was not found"))?;
    let properties = SecurityPatchProperties { system, vendor };
    validate_properties(&properties, "build")?;
    Ok(properties)
}

fn current_build_fingerprint() -> Result<String> {
    let fingerprint = resetprop::read_string_property(BUILD_FINGERPRINT_PROPERTY)
        .ok_or_else(|| anyhow!("{BUILD_FINGERPRINT_PROPERTY} is missing"))?;
    validate_fingerprint(&fingerprint)?;
    Ok(fingerprint)
}

fn validate_fingerprint(fingerprint: &str) -> Result<()> {
    if fingerprint.is_empty()
        || fingerprint.len() > MAX_FINGERPRINT_BYTES
        || fingerprint.chars().any(char::is_control)
    {
        bail!("build fingerprint is empty, too large, or contains control characters");
    }
    Ok(())
}

fn validate_properties(properties: &SecurityPatchProperties, label: &str) -> Result<()> {
    for (property, value) in [
        (SYSTEM_SECURITY_PATCH_PROPERTY, &properties.system),
        (VENDOR_SECURITY_PATCH_PROPERTY, &properties.vendor),
    ] {
        if !config::is_security_patch_date(value) {
            bail!("{label} {property} is not an exact YYYY-MM-DD date");
        }
    }
    Ok(())
}

fn patch_intent(trust: &RawTrustConfig) -> PatchIntent {
    let values = [
        trust.security_patch.trim(),
        trust.os_patchlevel.trim(),
        trust.vendor_patchlevel.trim(),
        trust.boot_patchlevel.trim(),
    ];
    if values.iter().all(|value| *value == "auto") {
        return PatchIntent::Auto;
    }
    if values.iter().all(|value| *value == values[0]) && config::is_security_patch_date(values[0]) {
        return PatchIntent::Synchronized(values[0].to_string());
    }
    PatchIntent::Other
}

fn patch_fields_match(trust: &RawTrustConfig, value: &str) -> bool {
    [
        trust.security_patch.as_str(),
        trust.os_patchlevel.as_str(),
        trust.vendor_patchlevel.as_str(),
        trust.boot_patchlevel.as_str(),
    ]
    .iter()
    .all(|field| field.trim() == value)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fs};

    use super::*;

    const DEFAULT_SYSTEM: &str = "2025-06-05";
    const DEFAULT_VENDOR: &str = "2025-05-05";

    fn properties(system: &str, vendor: &str) -> SecurityPatchProperties {
        SecurityPatchProperties {
            system: system.to_string(),
            vendor: vendor.to_string(),
        }
    }

    fn synchronized_config(date: &str) -> ConfigFile {
        let mut config = ConfigFile::default();
        config.trust.security_patch = date.to_string();
        config.trust.os_patchlevel = date.to_string();
        config.trust.vendor_patchlevel = date.to_string();
        config.trust.boot_patchlevel = date.to_string();
        config
    }

    #[test]
    fn bulletin_uri_allowlist_accepts_only_the_official_overview() {
        for url in [
            "https://source.android.com/docs/security/bulletin/asb-overview",
            "https://source.android.google.cn/docs/security/bulletin/asb-overview?hl=zh-cn",
            "https://source.android.com:443/docs/security/bulletin/asb-overview",
        ] {
            let uri: Uri = url.parse().unwrap();
            assert!(is_official_security_bulletin_uri(&uri), "{url}");
        }

        for url in [
            "http://source.android.com/docs/security/bulletin/asb-overview",
            "https://source.android.com:444/docs/security/bulletin/asb-overview",
            "https://source.android.com:bad/docs/security/bulletin/asb-overview",
            "https://source.android.com:0443/docs/security/bulletin/asb-overview",
            "https://source.android.com.evil.example/docs/security/bulletin/asb-overview",
            "https://source.android.com/docs/security/bulletin/asb-overview/extra",
            "https://source.android.com/docs/security/bulletin/2026-09-01",
        ] {
            let uri: Uri = url.parse().unwrap();
            assert!(!is_official_security_bulletin_uri(&uri), "{url}");
        }
    }

    #[test]
    fn bulletin_redirect_resolution_handles_supported_reference_forms() {
        let base: Uri = "https://source.android.com/docs/security/bulletin/asb-overview"
            .parse()
            .unwrap();
        let cases = [
            (
                "https://source.android.google.cn/docs/security/bulletin/asb-overview?hl=zh-cn",
                "https://source.android.google.cn/docs/security/bulletin/asb-overview?hl=zh-cn",
            ),
            (
                "//source.android.google.cn/docs/security/bulletin/asb-overview?hl=zh-cn",
                "https://source.android.google.cn/docs/security/bulletin/asb-overview?hl=zh-cn",
            ),
            (
                "/docs/security/bulletin/asb-overview?hl=zh-cn",
                "https://source.android.com/docs/security/bulletin/asb-overview?hl=zh-cn",
            ),
            (
                "?hl=zh-cn",
                "https://source.android.com/docs/security/bulletin/asb-overview?hl=zh-cn",
            ),
            (
                "asb-overview?hl=zh-cn",
                "https://source.android.com/docs/security/bulletin/asb-overview?hl=zh-cn",
            ),
        ];

        for (location, expected) in cases {
            let resolved =
                crate::webui_http::resolve_redirect(&base, location, "Android Security Bulletin")
                    .unwrap();
            assert_eq!(resolved.to_string(), expected);
            assert!(is_official_security_bulletin_uri(&resolved));
        }
    }

    #[test]
    fn bulletin_redirect_resolution_rejects_empty_or_unsafe_references() {
        let base: Uri = "https://source.android.com/docs/security/bulletin/asb-overview"
            .parse()
            .unwrap();

        for location in [
            "",
            "   ",
            "https://source.android.com.evil.example/docs/security/bulletin/asb-overview",
            "//source.android.com.evil.example/docs/security/bulletin/asb-overview",
            "/docs/security/bulletin/../bulletin/asb-overview",
        ] {
            let resolved =
                crate::webui_http::resolve_redirect(&base, location, "Android Security Bulletin");
            if let Ok(uri) = resolved {
                assert!(
                    !is_official_security_bulletin_uri(&uri),
                    "unsafe redirect unexpectedly passed: {location}"
                );
            }
        }
    }

    #[test]
    fn first_sync_records_defaults_and_repeated_sync_preserves_them() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        let current = RefCell::new(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR));
        let config_values = RefCell::new(Vec::new());
        let config = ConfigFile::default();

        for date in ["2026-01-05", "2026-02-05"] {
            apply_webui_security_patch_with(
                date,
                PatchOperation {
                    config_file: &config,
                    state_path: &path,
                    fingerprint: "brand/product/device:17/id/release-keys",
                },
                || Ok(current.borrow().clone()),
                || panic!("build defaults should not be used for auto config"),
                |expected, desired| {
                    assert_eq!(&*current.borrow(), expected);
                    *current.borrow_mut() = desired.clone();
                    Ok(())
                },
                |value| {
                    config_values.borrow_mut().push(value.to_string());
                    Ok(())
                },
            )
            .unwrap();
        }

        assert_eq!(*current.borrow(), properties("2026-02-05", "2026-02-05"));
        assert_eq!(
            *config_values.borrow(),
            vec!["2026-01-05".to_string(), "2026-02-05".to_string()]
        );
        let snapshot = load_snapshot(&path).unwrap().unwrap();
        assert_eq!(
            snapshot.properties(),
            properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)
        );
    }

    #[test]
    fn restore_writes_saved_defaults_then_auto_and_removes_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        let fingerprint = "brand/product/device:17/id/release-keys";
        persist_snapshot(
            &path,
            &SecurityPatchDefaults::new(fingerprint, &properties(DEFAULT_SYSTEM, DEFAULT_VENDOR))
                .unwrap(),
        )
        .unwrap();
        let current = RefCell::new(properties("2026-02-05", "2026-02-05"));
        let config_values = RefCell::new(Vec::new());

        apply_webui_security_patch_with(
            "auto",
            PatchOperation {
                config_file: &synchronized_config("2026-02-05"),
                state_path: &path,
                fingerprint,
            },
            || Ok(current.borrow().clone()),
            || panic!("saved defaults should be reused"),
            |expected, desired| {
                assert_eq!(&*current.borrow(), expected);
                *current.borrow_mut() = desired.clone();
                Ok(())
            },
            |value| {
                config_values.borrow_mut().push(value.to_string());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            *current.borrow(),
            properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)
        );
        assert_eq!(*config_values.borrow(), vec!["auto".to_string()]);
        assert!(!path.exists());
    }

    #[test]
    fn config_failure_rolls_runtime_properties_back_and_keeps_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        let fingerprint = "brand/product/device:17/id/release-keys";
        persist_snapshot(
            &path,
            &SecurityPatchDefaults::new(fingerprint, &properties(DEFAULT_SYSTEM, DEFAULT_VENDOR))
                .unwrap(),
        )
        .unwrap();
        let synchronized = properties("2026-02-05", "2026-02-05");
        let current = RefCell::new(synchronized.clone());

        let error = apply_webui_security_patch_with(
            "auto",
            PatchOperation {
                config_file: &synchronized_config("2026-02-05"),
                state_path: &path,
                fingerprint,
            },
            || Ok(current.borrow().clone()),
            || panic!("saved defaults should be reused"),
            |expected, desired| {
                assert_eq!(&*current.borrow(), expected);
                *current.borrow_mut() = desired.clone();
                Ok(())
            },
            |_| Err(anyhow!("config write failed")),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("runtime properties were restored"));
        assert_eq!(*current.borrow(), synchronized);
        assert!(path.exists());
    }

    #[test]
    fn property_failure_keeps_config_unchanged_and_retains_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        let current = properties(DEFAULT_SYSTEM, DEFAULT_VENDOR);
        let config_writes = RefCell::new(0_u32);

        let error = apply_webui_security_patch_with(
            "2026-02-05",
            PatchOperation {
                config_file: &ConfigFile::default(),
                state_path: &path,
                fingerprint: "brand/product/device:17/id/release-keys",
            },
            || Ok(current.clone()),
            || panic!("build defaults should not be used for auto config"),
            |_, _| Err(anyhow!("injected property failure")),
            |_| {
                *config_writes.borrow_mut() += 1;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("injected property failure"));
        assert_eq!(*config_writes.borrow(), 0);
        assert_eq!(load_snapshot(&path).unwrap().unwrap().properties(), current);
    }

    #[test]
    fn restore_without_snapshot_uses_build_defaults_for_explicit_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        let current = RefCell::new(properties("2026-02-05", "2026-02-05"));
        let default_reads = RefCell::new(0_u32);

        apply_webui_security_patch_with(
            "auto",
            PatchOperation {
                config_file: &synchronized_config("2026-02-05"),
                state_path: &path,
                fingerprint: "brand/product/device:17/id/release-keys",
            },
            || Ok(current.borrow().clone()),
            || {
                *default_reads.borrow_mut() += 1;
                Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR))
            },
            |expected, desired| {
                assert_eq!(&*current.borrow(), expected);
                *current.borrow_mut() = desired.clone();
                Ok(())
            },
            |value| {
                assert_eq!(value, "auto");
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(*default_reads.borrow(), 1);
        assert_eq!(
            *current.borrow(),
            properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)
        );
        assert!(!path.exists());
    }

    #[test]
    fn invalid_value_is_rejected_before_snapshot_or_property_changes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        let reads = RefCell::new(0_u32);
        let writes = RefCell::new(0_u32);

        let result = apply_webui_security_patch_with(
            "9999-12-31",
            PatchOperation {
                config_file: &ConfigFile::default(),
                state_path: &path,
                fingerprint: "brand/product/device:17/id/release-keys",
            },
            || {
                *reads.borrow_mut() += 1;
                Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR))
            },
            || Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)),
            |_, _| {
                *writes.borrow_mut() += 1;
                Ok(())
            },
            |_| Ok(()),
        );

        assert!(result.is_err());
        assert_eq!(*reads.borrow(), 0);
        assert_eq!(*writes.borrow(), 0);
        assert!(!path.exists());
    }

    #[test]
    fn changed_fingerprint_replaces_snapshot_with_current_defaults_for_auto_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        persist_snapshot(
            &path,
            &SecurityPatchDefaults::new(
                "brand/product/device:16/old/release-keys",
                &properties("2025-01-05", "2024-12-05"),
            )
            .unwrap(),
        )
        .unwrap();
        let current = RefCell::new(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR));

        apply_webui_security_patch_with(
            "2026-02-05",
            PatchOperation {
                config_file: &ConfigFile::default(),
                state_path: &path,
                fingerprint: "brand/product/device:17/new/release-keys",
            },
            || Ok(current.borrow().clone()),
            || panic!("runtime defaults should be trusted for auto config"),
            |expected, desired| {
                assert_eq!(&*current.borrow(), expected);
                *current.borrow_mut() = desired.clone();
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap();

        let snapshot = load_snapshot(&path).unwrap().unwrap();
        assert_eq!(
            snapshot.properties(),
            properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)
        );
        assert_eq!(
            snapshot.build_fingerprint,
            "brand/product/device:17/new/release-keys"
        );
    }

    #[test]
    fn corrupt_snapshot_fails_closed_without_writing_properties() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        fs::write(&path, "version = 1\nbroken = true\n").unwrap();
        let writes = RefCell::new(0_u32);

        let result = apply_webui_security_patch_with(
            "2026-02-05",
            PatchOperation {
                config_file: &ConfigFile::default(),
                state_path: &path,
                fingerprint: "brand/product/device:17/id/release-keys",
            },
            || Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)),
            || Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)),
            |_, _| {
                *writes.borrow_mut() += 1;
                Ok(())
            },
            |_| Ok(()),
        );

        assert!(result.is_err());
        assert_eq!(*writes.borrow(), 0);
    }

    #[test]
    fn startup_without_snapshot_does_not_treat_manual_exact_config_as_webui_sync() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        let written = RefCell::new(None);
        let default_reads = RefCell::new(0_u32);
        let config = synchronized_config("2026-02-05");

        prepare_startup_with(
            &config,
            &path,
            "brand/product/device:17/id/release-keys",
            || Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)),
            || {
                *default_reads.borrow_mut() += 1;
                Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR))
            },
            |_, desired| {
                *written.borrow_mut() = Some(desired.clone());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(*default_reads.borrow(), 0);
        assert_eq!(*written.borrow(), None);
        assert!(!path.exists());
    }

    #[test]
    fn startup_with_snapshot_reapplies_both_properties() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        let fingerprint = "brand/product/device:17/id/release-keys";
        persist_snapshot(
            &path,
            &SecurityPatchDefaults::new(fingerprint, &properties(DEFAULT_SYSTEM, DEFAULT_VENDOR))
                .unwrap(),
        )
        .unwrap();
        let current = RefCell::new(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR));
        let config = synchronized_config("2026-02-05");

        prepare_startup_with(
            &config,
            &path,
            fingerprint,
            || Ok(current.borrow().clone()),
            || panic!("matching snapshot should not be refreshed"),
            |expected, desired| {
                assert_eq!(&*current.borrow(), expected);
                *current.borrow_mut() = desired.clone();
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(*current.borrow(), properties("2026-02-05", "2026-02-05"));
        assert_eq!(
            load_snapshot(&path).unwrap().unwrap().properties(),
            properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)
        );
    }

    #[test]
    fn startup_refreshes_an_existing_snapshot_after_a_build_change() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        persist_snapshot(
            &path,
            &SecurityPatchDefaults::new(
                "brand/product/device:16/old/release-keys",
                &properties("2025-01-05", "2024-12-05"),
            )
            .unwrap(),
        )
        .unwrap();
        let current = RefCell::new(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR));
        let config = synchronized_config("2026-02-05");

        prepare_startup_with(
            &config,
            &path,
            "brand/product/device:17/new/release-keys",
            || Ok(current.borrow().clone()),
            || Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)),
            |expected, desired| {
                assert_eq!(&*current.borrow(), expected);
                *current.borrow_mut() = desired.clone();
                Ok(())
            },
        )
        .unwrap();

        let snapshot = load_snapshot(&path).unwrap().unwrap();
        assert_eq!(
            snapshot.properties(),
            properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)
        );
        assert_eq!(
            snapshot.build_fingerprint,
            "brand/product/device:17/new/release-keys"
        );
        assert_eq!(*current.borrow(), properties("2026-02-05", "2026-02-05"));
    }

    #[test]
    fn startup_rejects_a_corrupt_snapshot_before_writing_properties() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("security_patch_defaults.toml");
        fs::write(&path, "version = 1\nbroken = true\n").unwrap();
        let writes = RefCell::new(0_u32);

        let result = prepare_startup_with(
            &synchronized_config("2026-02-05"),
            &path,
            "brand/product/device:17/id/release-keys",
            || Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)),
            || Ok(properties(DEFAULT_SYSTEM, DEFAULT_VENDOR)),
            |_, _| {
                *writes.borrow_mut() += 1;
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(*writes.borrow(), 0);
    }
}
