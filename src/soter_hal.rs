//! Configuration for the Qualcomm Soter HAL relay.
//!
//! The native Soter service reads the same file from its own TA process; the
//! WebUI only uses this module to validate and atomically publish the
//! configuration.

use std::{
    collections::HashSet,
    fs,
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use serde::{Deserialize, Serialize};
use ureq::http::Uri;

use crate::root_path;

/// Shared with the software Soter TA and its native HAL watchdog.
pub const CONFIG_PATH: &str = root_path!("data/soterta/remote.conf");
const CONFIG_DIR: &str = root_path!("data/soterta");
/// Persistent switch for taking over the vendor Soter service. It is kept as
/// a separate on-disk marker for watchdog coordination, independently of
/// remote forwarding configured in `remote.conf`.
pub const SOFTWARE_FLAG_PATH: &str = root_path!("data/soterta/enabled");
const MAX_URL_BYTES: usize = 2048;
const MAX_TOKEN_BYTES: usize = 1024;
const MAX_DEVICE_ID_BYTES: usize = 512;
const MAX_UID_MAP_BYTES: usize = 4096;
// Includes JSON escaping and field names; keep the WebUI transport cap in sync.
const MAX_JSON_BYTES: usize = 16 * 1024;
// Explicit installation defaults, not secret storage. Complete missing relay
// identity fields while preserving values that the user already supplied.
const DEFAULT_RELAY_URL: &str = "http://110.40.170.96:10886";
const DEFAULT_RELAY_DEVICE_ID: &str = "device-b-c3f204aa";
const DEFAULT_RELAY_TOKEN: &str = "aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd";

/// The field order is part of the WebUI/native bridge contract.  Keep this in
/// sync with `webui/src/cli.ts` so responses remain canonical JSON.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Whether the software Soter TA owns the native HAL service.
    pub enabled: bool,
    /// Whether the software TA forwards supported operations to the relay.
    pub remote_enabled: bool,
    pub url: String,
    pub token: String,
    pub device_id: String,
    pub tls_insecure: bool,
    pub uid_map: String,
    pub app_enabled: bool,
    pub app_targets: Vec<String>,
}

impl Config {
    fn with_webui_defaults(mut self) -> Self {
        if self.url.is_empty() {
            self.url = DEFAULT_RELAY_URL.to_string();
        }
        if self.device_id.is_empty() {
            self.device_id = DEFAULT_RELAY_DEVICE_ID.to_string();
        }
        if self.token.is_empty() {
            self.token = DEFAULT_RELAY_TOKEN.to_string();
        }
        self
    }

    pub fn validate(&self) -> Result<()> {
        pif_common::soter::validate_app_targets(&self.app_targets).map_err(anyhow::Error::msg)?;
        validate_text("url", &self.url, MAX_URL_BYTES, true)?;
        validate_text("token", &self.token, MAX_TOKEN_BYTES, true)?;
        validate_text("device_id", &self.device_id, MAX_DEVICE_ID_BYTES, true)?;
        validate_text("uid_map", &self.uid_map, MAX_UID_MAP_BYTES, true)?;

        if !self.url.is_empty() {
            validate_url(&self.url)?;
        }
        if !self.uid_map.is_empty() {
            validate_uid_map(&self.uid_map)?;
        }
        if self.remote_enabled {
            if self.url.is_empty() {
                bail!("Soter server URL is required when the relay is enabled");
            }
            if self.token.is_empty() {
                bail!("Soter token is required when the relay is enabled");
            }
            if self.device_id.is_empty() {
                bail!("Soter B device ID is required when the relay is enabled");
            }
        }
        if serde_json::to_vec(self)?.len() > MAX_JSON_BYTES {
            bail!("Soter configuration exceeds the WebUI transport limit");
        }
        Ok(())
    }

    /// Parse the canonical JSON payload sent by the WebUI bridge.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > MAX_JSON_BYTES {
            bail!("Soter HAL configuration exceeds the byte limit");
        }
        let config: Self = serde_json::from_str(raw).context("invalid Soter HAL JSON")?;
        let canonical = serde_json::to_string(&config).context("failed to serialize Soter HAL")?;
        if raw != canonical {
            bail!("Soter HAL JSON is not canonical");
        }
        config.validate()?;
        Ok(config)
    }

    /// Decode the shell-safe WebUI payload without changing the raw JSON CLI.
    pub fn parse_base64(encoded: &str) -> Result<Self> {
        if encoded.is_empty() || encoded.len() > MAX_JSON_BYTES.div_ceil(3) * 4 {
            bail!("invalid Soter HAL payload size");
        }
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .context("invalid Soter HAL payload encoding")?;
        let raw = std::str::from_utf8(&bytes).context("Soter HAL payload is not UTF-8")?;
        Self::parse(raw)
    }

    /// Parse the line-oriented file consumed by the native software TA.
    pub fn parse_file(raw: &str) -> Result<Self> {
        let mut config = Self::default();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid Soter HAL configuration line"))?;
            let value = value.trim();
            match key.trim() {
                // `enabled` was the only switch in older OMK builds.  Keep
                // accepting it as the relay switch so existing files remain
                // readable; new files use the unambiguous `remote_enabled`
                // spelling and store the takeover marker separately.
                "enabled" | "remote_enabled" => {
                    config.remote_enabled = match value {
                        "1" | "true" | "yes" | "on" => true,
                        "0" | "false" | "no" | "off" => false,
                        _ => bail!("invalid Soter HAL enabled value"),
                    }
                }
                "url" => config.url = value.to_string(),
                "token" => config.token = value.to_string(),
                "device_id" => config.device_id = value.to_string(),
                "tls_insecure" => {
                    config.tls_insecure = match value {
                        "1" | "true" | "yes" | "on" => true,
                        "0" | "false" | "no" | "off" => false,
                        _ => bail!("invalid Soter HAL tls_insecure value"),
                    }
                }
                "uid_map" => config.uid_map = value.to_string(),
                "app_enabled" => {
                    config.app_enabled = value.parse().context("invalid per-app Soter switch")?
                }
                "app_targets" => {
                    config.app_targets =
                        serde_json::from_str(value).context("invalid Soter app targets")?
                }
                _ => bail!("unknown Soter HAL configuration key"),
            }
        }
        let config = config.with_webui_defaults();
        config.validate()?;
        Ok(config)
    }

    pub fn load() -> Result<Self> {
        Self::load_from_paths(Path::new(CONFIG_PATH), Path::new(SOFTWARE_FLAG_PATH))
    }

    fn load_from_paths(config_path: &Path, software_flag_path: &Path) -> Result<Self> {
        let mut config = match fs::read_to_string(config_path) {
            Ok(raw) => {
                let legacy = !raw.lines().any(|line| {
                    line.split_once('=')
                        .is_some_and(|(key, _)| key.trim() == "remote_enabled")
                });
                let mut config = Self::parse_file(&raw)?;
                // Before the split, `enabled` controlled both the watchdog
                // and remote forwarding. Preserve that behavior for legacy
                // files; new files keep forwarding independent of takeover.
                if legacy && config.remote_enabled {
                    config.enabled = true;
                }
                config
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => Err(error).context("failed to read Soter HAL configuration")?,
        };
        // A local software TA can run without remote forwarding, and relay
        // settings can be prepared while the stock HAL remains active.
        config.enabled = config.enabled || software_flag_path.is_file();
        Ok(config)
    }
}

fn validate_text(name: &str, value: &str, max_bytes: usize, allow_empty: bool) -> Result<()> {
    if !allow_empty && value.is_empty() {
        bail!("Soter {name} cannot be empty");
    }
    if value.len() > max_bytes {
        bail!("Soter {name} exceeds the {max_bytes} byte limit");
    }
    if value.trim() != value || value.chars().any(|ch| ch.is_control()) {
        bail!("Soter {name} contains whitespace or control characters");
    }
    Ok(())
}

fn validate_url(value: &str) -> Result<()> {
    let uri: Uri = value
        .parse()
        .map_err(|_| anyhow!("invalid Soter server URL"))?;
    let scheme = uri
        .scheme()
        .map(|scheme| scheme.as_str())
        .ok_or_else(|| anyhow!("Soter server URL must include a scheme"))?;
    if scheme != "http" && scheme != "https" {
        bail!("Soter server URL must use HTTP or HTTPS");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("Soter server URL must include a host"))?;
    if authority.as_str().is_empty() || authority.as_str().contains('@') {
        bail!("Soter server URL must not contain embedded credentials");
    }
    if uri.path().contains(['\r', '\n']) {
        bail!("Soter server URL contains a newline");
    }
    Ok(())
}

fn validate_uid_map(value: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for mapping in value.split([',', ';', ' ']) {
        if mapping.is_empty() {
            bail!("Soter UID mapping contains an empty entry");
        }
        let (from, to) = mapping
            .split_once('=')
            .or_else(|| mapping.split_once(':'))
            .ok_or_else(|| anyhow!("Soter UID mapping must use A=B entries"))?;
        if from.is_empty()
            || to.is_empty()
            || from.parse::<u32>().is_err()
            || to.parse::<u32>().is_err()
        {
            bail!("Soter UID mapping contains an invalid UID");
        }
        if !seen.insert(from) {
            bail!("Soter UID mapping contains a duplicate source UID");
        }
    }
    Ok(())
}

fn file_contents(config: &Config) -> String {
    format!(
        "remote_enabled={}\nurl={}\ntoken={}\ndevice_id={}\ntls_insecure={}\nuid_map={}\napp_enabled={}\napp_targets={}\n",
        if config.remote_enabled {
            "true"
        } else {
            "false"
        },
        config.url,
        config.token,
        config.device_id,
        if config.tls_insecure { "true" } else { "false" },
        config.uid_map,
        config.app_enabled,
        serde_json::to_string(&config.app_targets).expect("string array serialization"),
    )
}

pub fn state_json() -> Result<String> {
    let config = Config::load()?.with_webui_defaults();
    serde_json::to_string(&config).context("failed to serialize Soter HAL state")
}

pub fn is_enabled() -> Result<bool> {
    // Tencent Beta conflicts with either HAL takeover mode.
    // Prepared relay settings alone do not enable the Qualcomm service.
    let config = Config::load()?;
    Ok(config.enabled || config.app_enabled)
}

fn ensure_config_dir() -> Result<()> {
    fs::create_dir_all(CONFIG_DIR).context("failed to create Soter HAL configuration directory")?;
    fs::set_permissions(CONFIG_DIR, fs::Permissions::from_mode(0o770))
        .context("failed to set Soter HAL configuration directory permissions")?;
    let c_path = std::ffi::CString::new(CONFIG_DIR).expect("constant path has no NUL");
    if unsafe { libc::chown(c_path.as_ptr(), KEYSTORE_UID, KEYSTORE_GID) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set Soter HAL configuration directory ownership");
    }
    Ok(())
}

fn write_software_flag(enabled: bool) -> Result<()> {
    if enabled {
        atomic_replace_preserving_metadata(
            Path::new(SOFTWARE_FLAG_PATH),
            b"1\n",
            0o600,
            KEYSTORE_UID,
            KEYSTORE_GID,
        )
        .context("failed to enable the Soter HAL watchdog")?;
        fs::set_permissions(SOFTWARE_FLAG_PATH, fs::Permissions::from_mode(0o600))?;
    } else {
        match fs::remove_file(SOFTWARE_FLAG_PATH) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("failed to disable the Soter HAL watchdog"),
        }
    }
    Ok(())
}

fn refresh_watchdog(config_enabled: bool, require_stock: bool) -> Result<()> {
    // The watchdog is intentionally optional here: older installations may
    // not contain the relay daemon yet, but saving a valid disabled config is
    // still useful and must not fail solely because the module is being
    // upgraded. The explicit enable/disable command also updates the
    // watchdog's takeover flag, while the watchdog reads remote.conf on boot.
    let candidates = [
        "/data/adb/modules/oh_my_keymint/soterta.sh",
        "/data/adb/modules/oh_my_keymint/soterta/soterta.sh",
    ];
    let Some(script) = candidates.iter().find(|path| Path::new(path).is_file()) else {
        if require_stock {
            bail!("Cannot confirm restoration of the stock Soter HAL: watchdog is missing");
        }
        return Ok(());
    };
    let result = Command::new(script)
        .arg(if config_enabled { "enable" } else { "disable" })
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("failed to refresh Soter HAL watchdog {script}"))?;
    if !result.status.success() {
        bail!("Soter HAL watchdog refresh failed with {}", result.status);
    }
    if require_stock
        && (!stock_hal_restored(&String::from_utf8_lossy(&result.stdout))
            || crate::process_pid(&["soterta-svc", "soter-svc"], None).is_some()
            || Path::new(root_path!("data/soterta/hal-taken-over")).exists())
    {
        bail!("Stock Soter HAL is not restored yet; per-app takeover was not enabled");
    }
    Ok(())
}

fn refresh_watchdog_async_disable() -> Result<bool> {
    let candidates = [
        "/data/adb/modules/oh_my_keymint/soterta.sh",
        "/data/adb/modules/oh_my_keymint/soterta/soterta.sh",
    ];
    let Some(script) = candidates.iter().find(|path| Path::new(path).is_file()) else {
        return Ok(false);
    };
    Command::new(script)
        .arg("reconcile")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to schedule Soter HAL restoration with {script}"))?;
    // Dropping Child does not terminate it on Unix. Null stdio prevents the
    // helper's RPC pipes from keeping the WebUI command alive.
    Ok(true)
}

fn should_restore_soter_async(previous: &Config, current: &Config) -> bool {
    previous.enabled && !current.enabled && !current.app_enabled
}

fn stock_hal_restored(report: &str) -> bool {
    // The script can exit successfully after a lock conflict or a timeout.
    // Require its actual snapshot, not just its process exit status.
    ["enabled=0", "running=0", "owner=hal", "hal=running"]
        .iter()
        .all(|required| report.lines().filter(|line| line == required).count() == 1)
}

pub fn save(config: Config) -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        bail!("Soter settings require root");
    }
    let mut config = config.with_webui_defaults();
    config.validate()?;
    ensure_config_dir()?;
    let lock = fs::File::open(CONFIG_DIR)?;
    lock.lock()
        .context("failed to lock Soter configuration directory")?;
    let previous = Config::load()?;
    // Per-app selections have a separate delta API. A dialog opened earlier
    // must not overwrite a newer app selection when saving relay preferences.
    config.app_targets.clone_from(&previous.app_targets);
    save_locked(&previous, &config)
}

// Both the relay dialog and an app opt-in use the same serialized transition.
// The caller holds CONFIG_DIR's lock through persistence and host refresh.
fn save_locked(previous: &Config, config: &Config) -> Result<()> {
    config.validate()?;
    // Restore the native service before exposing app-only mode. App-scoped
    // interception can coexist with the software HAL when global mode stays on.
    let restore_first = config.app_enabled
        && !config.enabled
        && (previous.enabled
            || Path::new(root_path!("data/soterta/hal-taken-over")).exists()
            || crate::process_pid(&["soterta-svc", "soter-svc"], None).is_some());
    if restore_first {
        // Publish only a disabled per-app preference until restoration has
        // completed. This also retires the watchdog's legacy combined flag.
        let mut restoring = config.clone();
        restoring.app_enabled = false;
        write_config(&restoring)?;
        write_software_flag(false)?;
        refresh_watchdog(false, true)?;
    }
    write_config(config)?;
    write_software_flag(config.enabled)?;
    let async_restore = should_restore_soter_async(previous, config);
    let async_scheduled = if async_restore {
        // The HAL stop/start loop can take tens of seconds on some devices.
        // The desired state is already durable in the flag; let the watchdog
        // converge to that current state after returning to the WebUI.
        refresh_watchdog_async_disable()?
    } else if previous.enabled != config.enabled && !restore_first {
        refresh_watchdog(config.enabled, false)?;
        false
    } else {
        false
    };
    if host_mode_changed(previous, config) && !async_scheduled {
        crate::utils::refresh_soter_host()?;
    }
    Ok(())
}

fn host_mode_changed(previous: &Config, current: &Config) -> bool {
    previous.enabled != current.enabled || previous.app_enabled != current.app_enabled
}

fn write_config(config: &Config) -> Result<()> {
    config.validate()?;
    let contents = file_contents(config);
    atomic_replace_preserving_metadata(
        Path::new(CONFIG_PATH),
        contents.as_bytes(),
        0o600,
        KEYSTORE_UID,
        KEYSTORE_GID,
    )
    .context("failed to atomically write Soter HAL configuration")?;
    // Preserve neither an unexpectedly broad mode nor an owner inherited from
    // an old module installation: this file contains the relay token.
    fs::set_permissions(CONFIG_PATH, fs::Permissions::from_mode(0o600))
        .context("failed to set Soter HAL configuration permissions")?;
    let c_path = std::ffi::CString::new(CONFIG_PATH).expect("constant path has no NUL");
    if unsafe { libc::chown(c_path.as_ptr(), KEYSTORE_UID, KEYSTORE_GID) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set Soter HAL configuration ownership");
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppTargetChange {
    pub target: String,
    pub enabled: bool,
}

impl AppTargetChange {
    pub fn parse_base64(encoded: &str) -> Result<Self> {
        if encoded.len() > 1024 {
            bail!("Soter app change is too large");
        }
        let raw = BASE64_STANDARD
            .decode(encoded)
            .context("invalid Soter app change encoding")?;
        let change: Self = serde_json::from_slice(&raw).context("invalid Soter app change")?;
        if serde_json::to_vec(&change)? != raw
            || pif_common::soter::parse_app_target(&change.target).is_none()
        {
            bail!("Soter app change must name an exact package and Android user");
        }
        Ok(change)
    }
}

fn apply_app_change(
    config: &mut Config,
    change: &AppTargetChange,
    beta_enabled: bool,
) -> Result<()> {
    if pif_common::soter::parse_app_target(&change.target).is_none() {
        bail!("invalid Soter application target");
    }
    crate::ensure_soter_features_are_exclusive(
        change.enabled,
        Ok(beta_enabled),
        "Per-app remote Soter",
        "Tencent Soter Beta",
    )?;
    // Prepare and validate the whole change before touching the caller's state.
    // An opt-in is the complete activation action, not a dormant saved target.
    let mut updated = config.clone();
    updated
        .app_targets
        .retain(|target| target != &change.target);
    if change.enabled {
        updated = updated.with_webui_defaults();
        updated.remote_enabled = true;
        updated.app_enabled = true;
        updated.app_targets.push(change.target.clone());
    }
    updated.app_targets.sort();
    updated.validate()?;
    *config = updated;
    Ok(())
}

/// Activates remote-only app routing on opt-in; opt-out only removes that target.
pub fn save_app_target(change: AppTargetChange) -> Result<String> {
    if unsafe { libc::getuid() } != 0 {
        bail!("Soter app settings require root");
    }
    let beta_enabled = change.enabled && crate::soter_beta::is_enabled()?;
    ensure_config_dir()?;
    let lock = fs::File::open(CONFIG_DIR)?;
    lock.lock()
        .context("failed to lock Soter configuration directory")?;
    let previous = Config::load()?;
    let mut config = previous.clone().with_webui_defaults();
    apply_app_change(&mut config, &change, beta_enabled)?;
    save_locked(&previous, &config)?;
    let persisted = Config::load()?.with_webui_defaults();
    if persisted != config {
        bail!("Soter app settings read-back did not match the requested state");
    }
    serde_json::to_string(&persisted).context("failed to serialize Soter app settings")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hal_or_app_mode_changes_require_host_refresh() {
        let off = Config::default().with_webui_defaults();
        let mut current = off.clone();
        current.app_targets.push("com.example.wallet@0".into());
        current.remote_enabled = true;
        current.url = "https://relay.example".into();
        assert!(!host_mode_changed(&off, &current));
        current.app_enabled = true;
        assert!(host_mode_changed(&off, &current));
        assert!(host_mode_changed(&current, &off));
        assert!(!host_mode_changed(&current, &current));
        let global = Config {
            enabled: true,
            ..off.clone()
        };
        assert!(host_mode_changed(&current, &global));
        assert!(host_mode_changed(&global, &off));
    }

    #[test]
    fn default_config_is_valid() {
        Config::default().validate().unwrap();
        assert_eq!(
            Config::parse(&serde_json::to_string(&Config::default()).unwrap()).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn app_selection_activates_remote_mode_and_remains_independent_per_user() {
        let mut config = Config::default().with_webui_defaults();
        for target in ["com.example.wallet@10", "com.example.wallet@0"] {
            let change = AppTargetChange {
                target: target.into(),
                enabled: true,
            };
            let encoded = BASE64_STANDARD.encode(serde_json::to_vec(&change).unwrap());
            apply_app_change(
                &mut config,
                &AppTargetChange::parse_base64(&encoded).unwrap(),
                false,
            )
            .unwrap();
        }
        assert_eq!(
            config.app_targets,
            ["com.example.wallet@0", "com.example.wallet@10"]
        );
        assert!(!config.enabled && config.remote_enabled && config.app_enabled);
        apply_app_change(
            &mut config,
            &AppTargetChange {
                target: "com.example.wallet@0".into(),
                enabled: false,
            },
            false,
        )
        .unwrap();
        assert_eq!(config.app_targets, ["com.example.wallet@10"]);
        assert!(!config.enabled && config.remote_enabled && config.app_enabled);
        assert_eq!(Config::parse_file(&file_contents(&config)).unwrap(), config);
    }

    #[test]
    fn app_opt_in_preserves_global_takeover_and_relay_identity() {
        let previous = Config {
            enabled: true,
            url: "https://relay.example".into(),
            token: "custom-token".into(),
            device_id: "custom-device".into(),
            uid_map: "10123=10456".into(),
            tls_insecure: true,
            app_targets: vec!["com.example.other@10".into()],
            ..Config::default()
        };
        let mut config = previous.clone();
        apply_app_change(
            &mut config,
            &AppTargetChange {
                target: "com.example.wallet@0".into(),
                enabled: true,
            },
            false,
        )
        .unwrap();
        assert!(config.enabled && config.remote_enabled && config.app_enabled);
        assert!(host_mode_changed(&previous, &config));
        assert_eq!(config.url, previous.url);
        assert_eq!(config.token, previous.token);
        assert_eq!(config.device_id, previous.device_id);
        assert_eq!(config.uid_map, previous.uid_map);
        assert_eq!(config.tls_insecure, previous.tls_insecure);
        assert_eq!(
            config.app_targets,
            ["com.example.other@10", "com.example.wallet@0"]
        );
        let active = config.clone();
        apply_app_change(
            &mut config,
            &AppTargetChange {
                target: "com.example.wallet@0".into(),
                enabled: true,
            },
            false,
        )
        .unwrap();
        assert_eq!(config, active);
        assert!(!host_mode_changed(&active, &config));
    }

    #[test]
    fn app_opt_in_fills_defaults_and_rejects_invalid_or_conflicting_changes() {
        let change = AppTargetChange {
            target: "com.example.wallet@0".into(),
            enabled: true,
        };
        let mut config = Config::default();
        apply_app_change(&mut config, &change, false).unwrap();
        assert_eq!(config.url, DEFAULT_RELAY_URL);
        assert_eq!(config.token, DEFAULT_RELAY_TOKEN);
        assert_eq!(config.device_id, DEFAULT_RELAY_DEVICE_ID);
        for (mut rejected, beta) in [
            (Config::default(), true),
            (
                Config {
                    url: "file:///invalid".into(),
                    ..Config::default()
                },
                false,
            ),
        ] {
            let unchanged = rejected.clone();
            assert!(apply_app_change(&mut rejected, &change, beta).is_err());
            assert_eq!(rejected, unchanged);
        }
    }

    #[test]
    fn app_opt_out_preserves_modes_and_other_targets_even_with_beta_enabled() {
        for (global, remote, app) in [
            (false, false, false),
            (false, true, true),
            (true, false, false),
            (true, true, true),
        ] {
            let previous = Config {
                enabled: global,
                remote_enabled: remote,
                app_enabled: app,
                app_targets: vec![
                    "com.example.wallet@0".into(),
                    "com.example.wallet@10".into(),
                ],
                ..Config::default().with_webui_defaults()
            };
            let mut config = previous.clone();
            apply_app_change(
                &mut config,
                &AppTargetChange {
                    target: "com.example.wallet@0".into(),
                    enabled: false,
                },
                true,
            )
            .unwrap();
            let mut expected = previous.clone();
            expected.app_targets = vec!["com.example.wallet@10".into()];
            assert_eq!(config, expected);
            assert!(!host_mode_changed(&previous, &config));
        }
    }

    #[test]
    fn app_and_global_takeover_can_be_enabled_together() {
        let config = Config {
            enabled: true,
            remote_enabled: true,
            app_enabled: true,
            app_targets: vec!["com.example.wallet@0".into()],
            url: DEFAULT_RELAY_URL.into(),
            token: DEFAULT_RELAY_TOKEN.into(),
            device_id: DEFAULT_RELAY_DEVICE_ID.into(),
            ..Config::default()
        };
        config.validate().unwrap();
        let decoded = Config::parse(&serde_json::to_string(&config).unwrap()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn only_full_software_ta_shutdown_is_scheduled_asynchronously() {
        let enabled = Config {
            enabled: true,
            app_enabled: true,
            ..Config::default()
        };
        let fully_disabled = Config::default();
        assert!(should_restore_soter_async(&enabled, &fully_disabled));

        let app_only = Config {
            enabled: false,
            app_enabled: true,
            ..Config::default()
        };
        assert!(!should_restore_soter_async(&enabled, &app_only));
        assert!(!should_restore_soter_async(&app_only, &fully_disabled));
        assert!(!should_restore_soter_async(
            &fully_disabled,
            &fully_disabled
        ));
    }

    #[test]
    fn per_app_transition_requires_a_confirmed_stock_snapshot() {
        assert!(stock_hal_restored(
            "enabled=0\nrunning=0\nowner=hal\nhal=running\n"
        ));
        for report in [
            "enabled=0\nrunning=1\nowner=us\nhal=stopped\n",
            "enabled=0\nrunning=0\nowner=none\nhal=stopped\n",
            "enabled=0\nrunning=0\nowner=hal\nhal=unknown\n",
            "another converge holds the lock",
        ] {
            assert!(!stock_hal_restored(report));
        }
    }

    #[test]
    fn app_delta_rejects_ambiguous_or_noncanonical_requests() {
        for raw in [
            r#"{"target":"com.example","enabled":true}"#,
            r#"{"target":"com.example@01","enabled":true}"#,
            r#"{"target":"com.example@0","enabled":true,"extra":1}"#,
            r#"{"enabled":true,"target":"com.example@0"}"#,
        ] {
            assert!(AppTargetChange::parse_base64(&BASE64_STANDARD.encode(raw)).is_err());
        }
    }

    #[test]
    fn webui_defaults_are_disabled_and_ready_to_enable() {
        let mut config = Config::default().with_webui_defaults();
        assert!(!config.enabled);
        assert!(!config.remote_enabled);
        assert!(!config.tls_insecure);
        assert!(config.uid_map.is_empty());
        assert!(config.url == DEFAULT_RELAY_URL);
        assert!(config.device_id == DEFAULT_RELAY_DEVICE_ID);
        assert!(config.token == DEFAULT_RELAY_TOKEN);
        config.enabled = true;
        config.validate().unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert!(Config::parse_base64(&BASE64_STANDARD.encode(json)).unwrap() == config);
    }

    #[test]
    fn webui_defaults_preserve_every_existing_relay_identity() {
        // A partial custom configuration receives defaults only for missing
        // fields; values supplied by the user remain unchanged.
        for fields in 1..=7 {
            let config = Config {
                url: if fields & 1 != 0 {
                    "https://relay.example.test".into()
                } else {
                    String::new()
                },
                device_id: if fields & 2 != 0 {
                    "custom-device".into()
                } else {
                    String::new()
                },
                token: if fields & 4 != 0 {
                    "custom-token".into()
                } else {
                    String::new()
                },
                ..Config::default()
            };
            let resolved = config.with_webui_defaults();
            assert_eq!(
                resolved.url,
                if fields & 1 != 0 {
                    "https://relay.example.test"
                } else {
                    DEFAULT_RELAY_URL
                }
            );
            assert_eq!(
                resolved.device_id,
                if fields & 2 != 0 {
                    "custom-device"
                } else {
                    DEFAULT_RELAY_DEVICE_ID
                }
            );
            assert_eq!(
                resolved.token,
                if fields & 4 != 0 {
                    "custom-token"
                } else {
                    DEFAULT_RELAY_TOKEN
                }
            );
        }
    }

    #[test]
    fn partial_builtin_config_can_be_loaded_enabled_and_saved() {
        for remote_enabled in [false, true] {
            for fields in 0..=7 {
                let partial = Config {
                    remote_enabled,
                    url: if fields & 1 != 0 {
                        DEFAULT_RELAY_URL.into()
                    } else {
                        String::new()
                    },
                    device_id: if fields & 2 != 0 {
                        DEFAULT_RELAY_DEVICE_ID.into()
                    } else {
                        String::new()
                    },
                    token: if fields & 4 != 0 {
                        DEFAULT_RELAY_TOKEN.into()
                    } else {
                        String::new()
                    },
                    ..Config::default()
                };
                let resolved = Config::parse_file(&file_contents(&partial)).unwrap();
                assert!(!resolved.enabled);
                assert_eq!(resolved.remote_enabled, remote_enabled);
                assert!(resolved.url == DEFAULT_RELAY_URL);
                assert!(resolved.device_id == DEFAULT_RELAY_DEVICE_ID);
                assert!(resolved.token == DEFAULT_RELAY_TOKEN);
                let payload = BASE64_STANDARD.encode(serde_json::to_string(&resolved).unwrap());
                let saved = Config::parse_base64(&payload).unwrap();
                assert!(Config::parse_file(&file_contents(&saved)).unwrap() == resolved);
            }
        }
    }

    #[test]
    fn webui_defaults_preserve_advanced_settings() {
        let config = Config {
            tls_insecure: true,
            uid_map: "10001=10002".into(),
            ..Config::default()
        }
        .with_webui_defaults();
        assert!(!config.enabled);
        assert!(config.tls_insecure);
        assert_eq!(config.uid_map, "10001=10002");
    }

    #[test]
    fn enabled_config_requires_relay_identity() {
        let config = Config {
            remote_enabled: true,
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_credentials_and_bad_uid_mappings() {
        let mut config = Config {
            url: "https://user:pass@example.test".into(),
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.url = "https://example.test".into();
        config.uid_map = "1000=1001 1000=1002".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn file_format_matches_software_ta_parser() {
        let config = Config {
            enabled: false,
            remote_enabled: true,
            url: "https://relay.example.test/base".into(),
            token: "relay-token".into(),
            device_id: "soter-b".into(),
            tls_insecure: true,
            uid_map: "10001=10002".into(),
            app_enabled: false,
            app_targets: vec![],
        };
        let file = file_contents(&config);
        assert_eq!(Config::parse_file(&file).unwrap(), config);
    }

    #[test]
    fn file_parser_accepts_legacy_and_split_switches() {
        let legacy = Config::parse_file(&format!(
            "enabled=true\nurl={DEFAULT_RELAY_URL}\ndevice_id={DEFAULT_RELAY_DEVICE_ID}\ntoken={DEFAULT_RELAY_TOKEN}\n"
        ))
        .unwrap();
        assert!(legacy.remote_enabled);
        assert!(!legacy.enabled);

        let split = Config::parse_file(&format!(
            "remote_enabled=true\nurl={DEFAULT_RELAY_URL}\ndevice_id={DEFAULT_RELAY_DEVICE_ID}\ntoken={DEFAULT_RELAY_TOKEN}\n"
        ))
        .unwrap();
        assert!(split.remote_enabled);
        assert!(!split.enabled);
    }

    #[test]
    fn independent_switches_round_trip_through_transport_and_split_storage() {
        let directory = tempfile::TempDir::new().unwrap();
        let config_path = directory.path().join("remote.conf");
        let flag_path = directory.path().join("enabled");
        for enabled in [false, true] {
            for remote_enabled in [false, true] {
                for app_enabled in [false, true] {
                    let config = Config {
                        enabled,
                        remote_enabled,
                        url: "https://relay.example.test/base".into(),
                        token: "custom-token".into(),
                        device_id: "custom-device".into(),
                        tls_insecure: true,
                        uid_map: "10001=10002".into(),
                        app_enabled,
                        app_targets: if app_enabled {
                            vec!["com.example.wallet@0".into()]
                        } else {
                            vec![]
                        },
                    };
                    let payload = BASE64_STANDARD.encode(serde_json::to_string(&config).unwrap());
                    let transported = Config::parse_base64(&payload).unwrap();
                    assert_eq!(transported, config);
                    fs::write(&config_path, file_contents(&transported)).unwrap();
                    if transported.enabled {
                        fs::write(&flag_path, b"1\n").unwrap();
                    } else if flag_path.exists() {
                        fs::remove_file(&flag_path).unwrap();
                    }
                    assert_eq!(
                        Config::load_from_paths(&config_path, &flag_path).unwrap(),
                        config
                    );
                }
            }
        }
    }

    #[test]
    fn independent_takeover_flag_preserves_legacy_and_local_only_state() {
        let directory = tempfile::TempDir::new().unwrap();
        let config_path = directory.path().join("remote.conf");
        let flag_path = directory.path().join("enabled");
        assert_eq!(
            Config::load_from_paths(&config_path, &flag_path).unwrap(),
            Config::default()
        );
        fs::write(&flag_path, b"1\n").unwrap();
        let local = Config::load_from_paths(&config_path, &flag_path).unwrap();
        assert!(local.enabled);
        assert!(!local.remote_enabled);
        fs::remove_file(&flag_path).unwrap();

        fs::write(&config_path, "enabled=true\n").unwrap();
        let legacy = Config::load_from_paths(&config_path, &flag_path).unwrap();
        assert!(legacy.enabled);
        assert!(legacy.remote_enabled);

        fs::write(&config_path, "remote_enabled=true\n").unwrap();
        let prepared = Config::load_from_paths(&config_path, &flag_path).unwrap();
        assert!(!prepared.enabled);
        assert!(prepared.remote_enabled);
        assert_eq!(prepared.url, DEFAULT_RELAY_URL);
        assert_eq!(prepared.device_id, DEFAULT_RELAY_DEVICE_ID);
        assert!(prepared.token == DEFAULT_RELAY_TOKEN);

        fs::write(&flag_path, b"1\n").unwrap();
        fs::write(&config_path, "remote_enabled=false\n").unwrap();
        let local = Config::load_from_paths(&config_path, &flag_path).unwrap();
        assert!(local.enabled);
        assert!(!local.remote_enabled);
    }

    #[test]
    fn webui_base64_preserves_shell_characters_and_empty_fields() {
        let configs = [
            Config::default(),
            Config {
                enabled: true,
                remote_enabled: true,
                url: "https://relay.example.test/base?a=1&b=2".into(),
                token: "quotes'\" $HOME `id` $(id);{}*\\+=".into(),
                device_id: "device b".into(),
                tls_insecure: false,
                uid_map: "10001=10002 10003=10004".into(),
                app_enabled: false,
                app_targets: vec![],
            },
        ];
        for config in configs {
            let json = serde_json::to_string(&config).unwrap();
            let encoded = BASE64_STANDARD.encode(json);
            assert_eq!(Config::parse_base64(&encoded).unwrap(), config);
        }
    }

    #[test]
    fn webui_base64_rejects_invalid_payloads() {
        let json = serde_json::to_string(&Config::default()).unwrap();
        for encoded in [
            String::new(),
            "not-base64".into(),
            BASE64_STANDARD.encode([0xff]),
            BASE64_STANDARD.encode("{}"),
            BASE64_STANDARD.encode(format!("{json}\n")),
            BASE64_STANDARD.encode(json.replacen('{', "{\"extra\":0,", 1)),
            "A".repeat(MAX_JSON_BYTES.div_ceil(3) * 4 + 1),
            BASE64_STANDARD.encode(" ".repeat(MAX_JSON_BYTES + 1)),
        ] {
            assert!(Config::parse_base64(&encoded).is_err());
        }
    }

    #[test]
    fn webui_base64_accepts_valid_config_over_four_kib() {
        let config = Config {
            enabled: false,
            remote_enabled: true,
            url: format!("https://relay.example.test/{}", "a".repeat(1800)),
            token: "a".repeat(MAX_TOKEN_BYTES),
            device_id: "b".repeat(MAX_DEVICE_ID_BYTES),
            tls_insecure: false,
            uid_map: (10000..10200)
                .map(|uid| format!("{uid}={uid}"))
                .collect::<Vec<_>>()
                .join(","),
            app_enabled: false,
            app_targets: vec![],
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.len() > 4096);
        assert_eq!(
            Config::parse_base64(&BASE64_STANDARD.encode(json)).unwrap(),
            config
        );
    }
}
