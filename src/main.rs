#![recursion_limit = "256"]
#![feature(once_cell_try)]

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use std::panic;
use std::sync::Arc;
use std::{ffi::CString, os::unix::fs::PermissionsExt, path::Path};

use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::rpc;
use kmr_common::selinux::{clear_sockcreate_con, set_sockcreate_con};
use log::{debug, error, info, warn, LevelFilter};
use rsbinder::rpc::{PeerIdentity, RpcServer};
use serde::Serialize;

use crate::{
    consts::RPC_SOCKET_CONTEXT,
    keymaster::service::KeystoreService,
    keymaster::{
        authorization::AuthorizationManager, maintenance::MaintenanceManager, metrics::Metrics,
    },
    top::qwq2333::ohmykeymint::IOhMyKsService::BnOhMyKsService,
};

pub mod att_mgr;
pub mod config;
pub mod consts;
pub mod global;
pub mod keybox;
pub mod keymaster;
pub mod keymint;
pub mod logging;
pub mod macros;
pub mod pif_spoof;
pub mod plat;
pub mod proto;
pub mod security_patch;
pub mod selinux;
pub mod soter_beta;
pub mod soter_hal;
pub mod utils;
pub mod watchdog;
pub mod webui_activity;
pub mod webui_http;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));
// include!( "./aidl.rs"); // for development only

fn storage_warn(message: String) {
    if log::log_enabled!(log::Level::Warn) {
        warn!("{message}");
    } else {
        eprintln!("Storage warning: {message}");
    }
}

fn chown_path(path: &str, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    let c_path = CString::new(path).expect("path must not contain interior NUL bytes");
    let result = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn repair_omk_data_files() {
    let entries = match std::fs::read_dir(root_path!("data")) {
        Ok(entries) => entries,
        Err(e) => {
            storage_warn(format!("Failed to list OMK data directory: {e:?}"));
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                storage_warn(format!("Failed to read OMK data directory entry: {e:?}"));
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                storage_warn(format!("Failed to stat OMK data file {path:?}: {e:?}"));
                continue;
            }
        };
        if !file_type.is_file() {
            continue;
        }

        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            storage_warn(format!("Failed to chmod OMK data file {path:?}: {e:?}"));
        }
        let Some(path) = path.to_str() else {
            storage_warn(format!("Skipping non-UTF8 OMK data file path {path:?}"));
            continue;
        };
        if let Err(e) = chown_path(path, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown OMK data file {path}: {e:?}"));
        }
    }
}

fn prepare_android_storage() {
    for dir in [root_path!(), root_path!("data"), root_path!("logs")] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            storage_warn(format!("Failed to create OMK directory {dir}: {e:?}"));
            continue;
        }

        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o770)) {
            storage_warn(format!("Failed to chmod OMK directory {dir}: {e:?}"));
        }

        if let Err(e) = chown_path(dir, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown OMK directory {dir}: {e:?}"));
        }
    }

    if let Err(e) = crate::keybox::ensure_keybox_file(root_path!("keybox.xml")) {
        storage_warn(format!(
            "Failed to seed OMK keybox {}: {e:?}",
            root_path!("keybox.xml")
        ));
    }

    if let Err(e) = crate::keybox::ensure_google_attestation_status_cache() {
        storage_warn(format!(
            "Failed to seed Google attestation status cache {}: {e:?}",
            crate::keybox::GOOGLE_ATTESTATION_STATUS_CACHE_PATH
        ));
    }

    for file in [
        root_path!("keymint.log.lock"),
        root_path!("injector.log.lock"),
    ] {
        match std::fs::remove_file(file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => storage_warn(format!(
                "Failed to remove legacy OMK lock file {file}: {e:?}"
            )),
        }
    }

    for file in [
        root_path!("config.toml"),
        root_path!("config.toml.bak"),
        root_path!("keybox.xml"),
        root_path!("data/google_attestation_status.json"),
        root_path!("crash_count"),
        root_path!("logs/keymint.log"),
        root_path!("logs/keymint.log.1"),
        root_path!("logs/injector.log"),
        root_path!("logs/injector.log.1"),
    ] {
        if !Path::new(file).exists() {
            continue;
        }

        let mode = if file.ends_with(".xml") || file.ends_with("google_attestation_status.json") {
            0o600
        } else {
            0o660
        };

        if let Err(e) = std::fs::set_permissions(file, std::fs::Permissions::from_mode(mode)) {
            storage_warn(format!("Failed to chmod OMK file {file}: {e:?}"));
        }

        if let Err(e) = chown_path(file, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown OMK file {file}: {e:?}"));
        }
    }
}

fn create_rpc_server() -> Result<Arc<RpcServer>> {
    set_sockcreate_con(RPC_SOCKET_CONTEXT)
        .context("failed to set OMK RPC socket SELinux context")?;
    let server = RpcServer::setup_unix_server(rpc::SOCKET);
    let clear_result =
        clear_sockcreate_con().context("failed to clear OMK RPC socket SELinux context");
    let server = server.context("failed to bind OMK RPC socket")?;
    clear_result?;
    server.set_android13plus(rpc::WIRE_MAX_VERSION);
    std::fs::set_permissions(rpc::SOCKET, std::fs::Permissions::from_mode(0o660))
        .context("failed to chmod OMK RPC socket")?;

    server.set_authorizer(|peer| {
        let allowed = matches!(
            peer,
            PeerIdentity::Local { uid, .. } if *uid == KEYSTORE_UID
        );
        if !allowed {
            warn!("rejected OMK RPC peer {peer}");
        }
        allowed
    });

    Ok(server)
}

fn set_keystore_identity() -> Result<()> {
    let failed = unsafe { libc::setgid(KEYSTORE_GID) != 0 || libc::setuid(KEYSTORE_UID) != 0 };
    if failed {
        return Err(std::io::Error::last_os_error()).context("failed to enter keystore uid/gid");
    }
    Ok(())
}

fn should_resolve_module_info_bundle(android_major_version: Option<i32>) -> bool {
    !matches!(android_major_version, Some(version) if version < 16)
}

fn install_module_info_bundle_if_available() -> Result<()> {
    if !should_resolve_module_info_bundle(kmr_common::android_version::android_major_version()) {
        info!("skipping moduleHash input on pre-Android 16 system");
        return Ok(());
    }

    // We can no longer resolve module info after dropping privileges.
    debug!("resolving APEX module info with root privileges");
    match crate::keymaster::apex::resolve_module_info_bundle() {
        Ok(bundle) => {
            let source = bundle.source.as_str();
            let module_count = bundle.modules.len();
            let sha256 = hex::encode(&bundle.sha256);
            global::install_module_info_bundle(bundle)
                .context("failed to install APEX module info bundle")?;
            info!(
                "Initialized moduleHash input from {source} with {module_count} active modules (sha256={sha256})"
            );
        }
        Err(error) => {
            warn!(
                "moduleHash attestation disabled because APEX module info is unavailable: {error:#}"
            );
        }
    }

    Ok(())
}

const WEBUI_KEYBOX_CHUNK_BYTES: usize = 48 * 1024;
const WEBUI_KEYBOX_MAX_CHUNKS: usize = 4;

fn decode_webui_keybox_payload(chunks: Vec<String>) -> Result<Vec<u8>, String> {
    if chunks.is_empty() {
        return Err("--webui-install-keybox requires a base64 payload".to_string());
    }
    if chunks.len() > WEBUI_KEYBOX_MAX_CHUNKS {
        return Err("keybox payload contains too many chunks".to_string());
    }
    if chunks
        .iter()
        .any(|chunk| chunk.is_empty() || chunk.len() > WEBUI_KEYBOX_CHUNK_BYTES)
    {
        return Err("keybox payload contains an invalid chunk".to_string());
    }

    let max_encoded_bytes = keybox::MAX_KEYBOX_XML_BYTES.div_ceil(3) * 4;
    let encoded_len = chunks.iter().map(String::len).sum::<usize>();
    if encoded_len > max_encoded_bytes {
        return Err(format!(
            "keybox payload exceeds the {} byte limit",
            keybox::MAX_KEYBOX_XML_BYTES
        ));
    }

    let mut encoded = String::with_capacity(encoded_len);
    for chunk in chunks {
        encoded.push_str(&chunk);
    }
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|error| format!("invalid keybox payload encoding: {error}"))
}

#[derive(Serialize)]
struct WebUiKeyboxState {
    valid: bool,
    bundled: bool,
    source: &'static str,
    level: &'static str,
    play_integrity: &'static str,
    revocation: &'static str,
}

#[derive(Serialize)]
struct WebUiKeyboxChainInspector {
    algorithm: &'static str,
    chain_length: usize,
    serials: Vec<String>,
    leaf_subject: String,
    leaf_issuer: String,
    valid_from: String,
    valid_until: String,
    certificates: Vec<WebUiKeyboxCertificateInspector>,
}

#[derive(Serialize)]
struct WebUiKeyboxCertificateInspector {
    serial: String,
    subject: String,
    issuer: String,
    valid_from: String,
    valid_until: String,
}

#[derive(Serialize)]
struct WebUiKeyboxInspector {
    valid: bool,
    bundled: bool,
    rsa: Option<WebUiKeyboxChainInspector>,
    ec: Option<WebUiKeyboxChainInspector>,
}

#[derive(Serialize)]
struct WebUiServiceDiagnostic {
    status: &'static str,
    pid: Option<u32>,
}

#[derive(Serialize)]
struct WebUiDiagnostics {
    keymint: WebUiServiceDiagnostic,
    keystore2: WebUiServiceDiagnostic,
    injector: WebUiServiceDiagnostic,
    soter: WebUiServiceDiagnostic,
    tee: WebUiHardwareDiagnostic,
    strongbox: WebUiHardwareDiagnostic,
    rkp_tee: WebUiServiceDiagnostic,
    rkp_strongbox: WebUiServiceDiagnostic,
    selinux: &'static str,
}

#[derive(Serialize)]
struct WebUiHardwareDiagnostic {
    status: &'static str,
    version: Option<i32>,
    name: Option<String>,
}

fn keybox_chain_inspector(chain: keybox::KeyboxChainInspector) -> WebUiKeyboxChainInspector {
    WebUiKeyboxChainInspector {
        algorithm: chain.algorithm,
        chain_length: chain.chain_length,
        serials: chain.serials,
        leaf_subject: chain.leaf_subject,
        leaf_issuer: chain.leaf_issuer,
        valid_from: chain.valid_from,
        valid_until: chain.valid_until,
        certificates: chain
            .certificates
            .into_iter()
            .map(|certificate| WebUiKeyboxCertificateInspector {
                serial: certificate.serial,
                subject: certificate.subject,
                issuer: certificate.issuer,
                valid_from: certificate.valid_from,
                valid_until: certificate.valid_until,
            })
            .collect(),
    }
}

fn webui_keybox_inspector() -> Result<String, String> {
    let (state, inspector) =
        keybox::installed_keybox_inspector().map_err(|error| format!("{error:#}"))?;
    let response = WebUiKeyboxInspector {
        valid: !matches!(state, keybox::KeyboxFileState::Invalid),
        bundled: matches!(state, keybox::KeyboxFileState::Bundled),
        rsa: inspector.rsa.map(keybox_chain_inspector),
        ec: inspector.ec.map(keybox_chain_inspector),
    };
    serde_json::to_string(&response)
        .map_err(|error| format!("failed to serialize keybox inspector: {error}"))
}

fn process_pid(names: &[&str], expected_executable: Option<&Path>) -> Option<u32> {
    let current_pid = std::process::id();
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        if pid == current_pid {
            continue;
        }
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let executable = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
        let Ok(executable) = std::str::from_utf8(executable) else {
            continue;
        };
        let Some(executable) = std::path::Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
        else {
            continue;
        };
        if names.contains(&executable) {
            if let Some(expected) = expected_executable {
                if std::fs::read_link(entry.path().join("exe")).ok().as_deref() != Some(expected) {
                    continue;
                }
            }
            return Some(pid);
        }
    }
    None
}

fn pidfile_process(path: &str, marker: &str) -> Option<u32> {
    let pid = std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    if pid == std::process::id() {
        return None;
    }
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let cmdline = String::from_utf8_lossy(&cmdline);
    cmdline.contains(marker).then_some(pid)
}

fn service_diagnostic(status: &'static str, pid: Option<u32>) -> WebUiServiceDiagnostic {
    WebUiServiceDiagnostic { status, pid }
}

fn hardware_diagnostic(
    level: android::hardware::security::keymint::SecurityLevel::SecurityLevel,
) -> WebUiHardwareDiagnostic {
    match plat::keymint_profile::diagnose_system_keymint(level) {
        Ok(Some(info)) => WebUiHardwareDiagnostic {
            status: "available",
            version: Some(info.versionNumber),
            name: Some(info.keyMintName),
        },
        Ok(None) => WebUiHardwareDiagnostic {
            status: "unavailable",
            version: None,
            name: None,
        },
        Err(_) => WebUiHardwareDiagnostic {
            status: "error",
            version: None,
            name: None,
        },
    }
}

fn rkp_diagnostic(instance: &str) -> WebUiServiceDiagnostic {
    const DESCRIPTOR: &str = "android.hardware.security.keymint.IRemotelyProvisionedComponent";
    let status = match rsbinder::hub::try_get_service(&format!("{DESCRIPTOR}/{instance}")) {
        Ok(Some(binder)) if binder.descriptor() == DESCRIPTOR => {
            if binder.ping_binder().is_ok() {
                "available"
            } else {
                "error"
            }
        }
        Ok(None) => "unavailable",
        _ => "error",
    };
    service_diagnostic(status, None)
}

fn selinux_diagnostic() -> &'static str {
    match std::fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(value) if value.trim() == "1" => "enforcing",
        Ok(value) if value.trim() == "0" => "permissive",
        _ => "unknown",
    }
}

fn webui_diagnostics() -> String {
    use android::hardware::security::keymint::SecurityLevel::SecurityLevel;
    // A vendor KeyMint process does not prove that OMK itself is running.
    let executable = std::env::current_exe().ok();
    let keymint_pid = executable
        .as_deref()
        .and_then(|path| process_pid(&["keymint"], Some(path)));
    let keystore_pid = process_pid(&["keystore2"], None);
    let injector_pid = pidfile_process("/data/adb/omk/injector-daemon.pid", "daemon-injector")
        .or_else(|| process_pid(&["inject"], None));
    let soter_pid = pidfile_process(
        "/data/misc/keystore/omk/data/soterta/daemon.pid",
        "soterta-svc",
    )
    .or_else(|| process_pid(&["soterta-svc", "soter-svc"], None));
    let soter_status = match soter_hal::is_enabled() {
        Ok(true) if soter_pid.is_some() => "running",
        Ok(true) => "configured",
        Ok(false) => "disabled",
        Err(_) => "unknown",
    };
    serde_json::to_string(&WebUiDiagnostics {
        keymint: service_diagnostic(
            if keymint_pid.is_some() {
                "running"
            } else {
                "stopped"
            },
            keymint_pid,
        ),
        keystore2: service_diagnostic(
            if keystore_pid.is_some() {
                "running"
            } else {
                "stopped"
            },
            keystore_pid,
        ),
        injector: service_diagnostic(
            if injector_pid.is_some() {
                "running"
            } else {
                "stopped"
            },
            injector_pid,
        ),
        soter: service_diagnostic(soter_status, soter_pid),
        tee: hardware_diagnostic(SecurityLevel::TRUSTED_ENVIRONMENT),
        strongbox: hardware_diagnostic(SecurityLevel::STRONGBOX),
        rkp_tee: rkp_diagnostic("default"),
        rkp_strongbox: rkp_diagnostic("strongbox"),
        selinux: selinux_diagnostic(),
    })
    .unwrap_or_else(|_| "{}".to_string())
}

fn webui_keybox_state() -> Result<String, String> {
    let (state, metadata, _) =
        keybox::installed_keybox_state_and_metadata().map_err(|error| format!("{error:#}"))?;
    let valid = !matches!(state, keybox::KeyboxFileState::Invalid);
    let response = WebUiKeyboxState {
        valid,
        bundled: matches!(state, keybox::KeyboxFileState::Bundled),
        source: metadata.source.as_str(),
        level: metadata.level.as_str(),
        // A static Keybox cannot provide a Play Integrity verdict. A real
        // verdict must come from an enrolled app and its trusted server.
        play_integrity: "not_checked",
        // The online lookup is a separate command so local Home data does not
        // wait for a slow or unreachable network.
        revocation: keybox::KeyboxRevocationStatus::NotChecked.as_str(),
    };
    serde_json::to_string(&response)
        .map_err(|error| format!("failed to serialize keybox state: {error}"))
}

fn webui_keybox_revocation_status() -> Result<String, String> {
    let (state, _, serials) =
        keybox::installed_keybox_state_and_metadata().map_err(|error| format!("{error:#}"))?;
    if matches!(state, keybox::KeyboxFileState::Invalid) {
        return Ok(keybox::KeyboxRevocationStatus::NotChecked
            .as_str()
            .to_string());
    }
    let serials = serials.ok_or_else(|| {
        "failed to read every certificate serial number from the installed Keybox".to_string()
    })?;
    let status =
        keybox::check_google_attestation_status(&serials).map_err(|error| format!("{error:#}"))?;

    let (current_state, _, current_serials) =
        keybox::installed_keybox_state_and_metadata().map_err(|error| format!("{error:#}"))?;
    if matches!(current_state, keybox::KeyboxFileState::Invalid)
        || current_serials.as_ref() != Some(&serials)
    {
        return Err(
            "installed Keybox changed while its certificate status was checked".to_string(),
        );
    }

    Ok(status.as_str().to_string())
}

fn handle_webui_keybox_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    match args.next()?.as_str() {
        "--webui-install-keybox" => Some(
            decode_webui_keybox_payload(args.collect())
                .and_then(|contents| {
                    keybox::install_keybox_xml(&contents).map_err(|e| format!("{e:#}"))
                })
                .map(|()| "ok".to_string()),
        ),
        "--webui-get-keybox-state" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-keybox-state does not accept arguments".to_string()
                ));
            }
            Some(webui_keybox_state())
        }
        "--webui-check-keybox-revocation" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-check-keybox-revocation does not accept arguments".to_string(),
                ));
            }
            Some(webui_keybox_revocation_status())
        }
        _ => None,
    }
}

fn handle_webui_diagnostics_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    match args.next()?.as_str() {
        "--webui-get-diagnostics" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-diagnostics does not accept arguments".to_string()
                ));
            }
            Some(Ok(webui_diagnostics()))
        }
        "--webui-get-keybox-inspector" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-keybox-inspector does not accept arguments".to_string(),
                ));
            }
            Some(webui_keybox_inspector())
        }
        _ => None,
    }
}

fn handle_webui_app_patch_command(
    mut args: impl Iterator<Item = String>,
) -> Option<Result<String, String>> {
    match args.next()?.as_str() {
        "--webui-get-app-patch-levels" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-app-patch-levels does not accept arguments".to_string(),
                ));
            }
            Some(config::app_patch_levels_json().map_err(|error| format!("{error:#}")))
        }
        "--webui-set-app-patch-levels-base64" => {
            let Some(payload) = args.next() else {
                return Some(Err(
                    "--webui-set-app-patch-levels-base64 requires one payload".to_string(),
                ));
            };
            if payload.len() > 4096 || args.next().is_some() {
                return Some(Err("invalid app patch-level payload arguments".to_string()));
            }
            Some(
                config::save_app_patch_levels_base64(&payload)
                    .map(|()| "app_patch_levels_saved".to_string())
                    .map_err(|error| format!("{error:#}")),
            )
        }
        _ => None,
    }
}

fn ensure_soter_features_are_exclusive(
    requested_enabled: bool,
    other_enabled: Result<bool>,
    requested_name: &str,
    other_name: &str,
) -> Result<()> {
    if !requested_enabled {
        return Ok(());
    }
    if other_enabled? {
        bail!("{requested_name} cannot be enabled while {other_name} is enabled; disable it first");
    }
    Ok(())
}

fn handle_webui_soter_beta_command(
    mut args: impl Iterator<Item = String>,
) -> Option<Result<String, String>> {
    match args.next()?.as_str() {
        "--webui-get-soter-beta" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-soter-beta does not accept arguments".to_string()
                ));
            }
            Some(soter_beta::state_json().map_err(|error| format!("{error:#}")))
        }
        "--webui-set-soter-beta" => {
            let value = args.next();
            if value.is_none() || args.next().is_some() {
                return Some(Err(
                    "--webui-set-soter-beta requires exactly one argument: 0 or 1".to_string(),
                ));
            }
            let enabled = match pif_common::soter::parse(value.unwrap().as_bytes()) {
                Ok(enabled) => enabled,
                Err(error) => return Some(Err(error.to_string())),
            };
            if let Err(error) = soter_beta::require_root() {
                return Some(Err(format!("{error:#}")));
            }
            if enabled {
                if let Err(error) = ensure_soter_features_are_exclusive(
                    true,
                    soter_hal::is_enabled(),
                    "Tencent Soter Beta",
                    "Qualcomm Soter HAL",
                ) {
                    return Some(Err(format!(
                        "failed to validate Soter feature selection: {error:#}"
                    )));
                }
            }
            prepare_android_storage();
            Some(
                soter_beta::save(enabled)
                    .map(|()| "soter_beta_saved".to_string())
                    .map_err(|error| format!("{error:#}")),
            )
        }
        _ => None,
    }
}

fn handle_webui_soter_hal_command(
    mut args: impl Iterator<Item = String>,
) -> Option<Result<String, String>> {
    let command = args.next()?;
    match command.as_str() {
        "--webui-get-soter-hal" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-soter-hal does not accept arguments".to_string()
                ));
            }
            Some(soter_hal::state_json().map_err(|error| format!("{error:#}")))
        }
        "--webui-set-soter-hal" | "--webui-set-soter-hal-base64" => {
            let payload = args.next();
            if payload.is_none() || args.next().is_some() {
                return Some(Err(format!(
                    "{command} requires exactly one configuration argument"
                )));
            }
            let payload = payload.expect("payload checked above");
            let parsed = if command == "--webui-set-soter-hal-base64" {
                soter_hal::Config::parse_base64(&payload)
            } else {
                soter_hal::Config::parse(&payload)
            };
            let config = match parsed {
                Ok(config) => config,
                Err(error) => return Some(Err(format!("{error:#}"))),
            };
            if config.enabled {
                if let Err(error) = ensure_soter_features_are_exclusive(
                    true,
                    soter_beta::is_enabled(),
                    "Qualcomm Soter HAL",
                    "Tencent Soter Beta",
                ) {
                    return Some(Err(format!(
                        "failed to validate Soter feature selection: {error:#}"
                    )));
                }
            }
            prepare_android_storage();
            Some(
                soter_hal::save(config)
                    .map(|()| "soter_hal_saved".to_string())
                    .map_err(|error| format!("{error:#}")),
            )
        }
        _ => None,
    }
}

fn handle_webui_security_patch_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    if args.next()?.as_str() != "--webui-sync-security-patch" {
        return None;
    }

    let value = match args.next() {
        Some(value) => value,
        None => {
            return Some(Err(
                "--webui-sync-security-patch requires exactly one value: auto or YYYY-MM-DD"
                    .to_string(),
            ))
        }
    };
    if args.next().is_some() {
        return Some(Err(
            "--webui-sync-security-patch accepts exactly one value: auto or YYYY-MM-DD".to_string(),
        ));
    }

    prepare_android_storage();
    Some(
        crate::security_patch::apply_webui_security_patch(&value)
            .map_err(|error| format!("{error:#}")),
    )
}

fn handle_webui_security_bulletin_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    if args.next()?.as_str() != "--webui-fetch-security-bulletin" {
        return None;
    }

    let url = match args.next() {
        Some(url) => url,
        None => {
            return Some(Err(
                "--webui-fetch-security-bulletin requires exactly one official URL".to_string(),
            ))
        }
    };
    if args.next().is_some() {
        return Some(Err(
            "--webui-fetch-security-bulletin accepts exactly one official URL".to_string(),
        ));
    }

    Some(
        crate::security_patch::download_android_security_bulletin(&url)
            .map_err(|error| format!("{error:#}")),
    )
}

fn handle_webui_pif_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    let command = args.next()?;

    match command.as_str() {
        "--webui-get-pif-fingerprint-state" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-pif-fingerprint-state does not accept arguments".to_string(),
                ));
            }
            prepare_android_storage();
            Some(pif_spoof::fingerprint_state().map_err(|error| format!("{error:#}")))
        }
        "--webui-list-pif-devices" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-list-pif-devices does not accept arguments".to_string()
                ));
            }
            Some(pif_spoof::list_devices().map_err(|error| format!("{error:#}")))
        }
        "--webui-apply-pif-fingerprint" => {
            let product = match args.next() {
                Some(product) => product,
                None => {
                    return Some(Err(
                        "--webui-apply-pif-fingerprint requires exactly one product".to_string(),
                    ))
                }
            };
            let options: Vec<String> = args.collect();
            let (spoof_build, spoof_props, spoof_vending_build) = match options.as_slice() {
                [] => (true, true, false),
                [build, props] if matches!(build.as_str(), "0" | "1")
                    && matches!(props.as_str(), "0" | "1") => (build == "1", props == "1", false),
                [build, props, vending] if matches!(build.as_str(), "0" | "1")
                    && matches!(props.as_str(), "0" | "1")
                    && matches!(vending.as_str(), "0" | "1") => (build == "1", props == "1", vending == "1"),
                _ => return Some(Err(
                    "--webui-apply-pif-fingerprint accepts a product, optional spoofBuild spoofProps flags, and an optional spoofVendingBuild flag (0 or 1)".to_string(),
                )),
            };
            prepare_android_storage();
            Some(
                pif_spoof::apply_fingerprint(
                    &product,
                    spoof_build,
                    spoof_props,
                    spoof_vending_build,
                )
                .map_err(|error| format!("{error:#}")),
            )
        }
        "--webui-disable-pif-fingerprint" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-disable-pif-fingerprint does not accept arguments".to_string(),
                ));
            }
            prepare_android_storage();
            Some(pif_spoof::disable_fingerprint().map_err(|error| format!("{error:#}")))
        }
        _ => None,
    }
}

fn handle_webui_activity_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    let command = args.next()?;

    match command.as_str() {
        "--webui-get-activity-log" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-activity-log does not accept arguments".to_string()
                ));
            }
            prepare_android_storage();
            Some(webui_activity::list_json().map_err(|error| format!("{error:#}")))
        }
        "--webui-record-activity" => {
            let Some(action) = args.next() else {
                return Some(Err(
                    "--webui-record-activity requires an action and base64 detail".to_string(),
                ));
            };
            let Some(encoded_detail) = args.next() else {
                return Some(Err(
                    "--webui-record-activity requires an action and base64 detail".to_string(),
                ));
            };
            if args.next().is_some() {
                return Some(Err(
                    "--webui-record-activity accepts exactly two arguments".to_string()
                ));
            }
            let max_encoded_bytes = webui_activity::MAX_ACTIVITY_DETAIL_BYTES.div_ceil(3) * 4;
            if encoded_detail.len() > max_encoded_bytes {
                return Some(Err(
                    "--webui-record-activity detail exceeds the byte limit".to_string()
                ));
            }
            let result = BASE64_STANDARD
                .decode(encoded_detail)
                .map_err(|error| format!("invalid WebUI activity detail encoding: {error}"))
                .and_then(|bytes| {
                    String::from_utf8(bytes)
                        .map_err(|error| format!("WebUI activity detail is not UTF-8: {error}"))
                })
                .and_then(|detail| {
                    prepare_android_storage();
                    webui_activity::record(&action, &detail).map_err(|error| format!("{error:#}"))
                })
                .map(|()| "ok".to_string());
            Some(result)
        }
        "--webui-clear-activity-log" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-clear-activity-log does not accept arguments".to_string()
                ));
            }
            prepare_android_storage();
            Some(
                webui_activity::clear()
                    .map(|()| "ok".to_string())
                    .map_err(|error| format!("{error:#}")),
            )
        }
        _ => None,
    }
}

fn main() {
    // WebUI diagnostics query the registered Binder services before entering
    // the long-running KeyMint server path. Initialize the Binder process
    // state first so standalone WebUI bridge invocations can safely perform
    // those read-only queries.
    let _ = rsbinder::ProcessState::init_default();
    if let Some(result) = handle_webui_diagnostics_command()
        .or_else(|| handle_webui_app_patch_command(std::env::args().skip(1)))
    {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_soter_beta_command(std::env::args().skip(1)) {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_soter_hal_command(std::env::args().skip(1)) {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_activity_command() {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_pif_command() {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_security_bulletin_command() {
        match result {
            Ok(output) => print!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_security_patch_command() {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_keybox_command() {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    // A stale WebUI must not start the daemon after a helper command is removed.
    if std::env::args()
        .nth(1)
        .is_some_and(|arg| arg.starts_with("--webui-"))
    {
        eprintln!("unsupported WebUI command");
        std::process::exit(2);
    }

    logging::init_logger();
    prepare_android_storage();
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    if let Err(error) = run() {
        error!("fatal startup error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    crate::keymaster::permission::initialize_runtime_service_context();
    prepare_android_storage();
    plat::resetprop::bootstrap_privileged_helper()
        .context("failed to bootstrap resetprop helper")?;

    // Acquire this only after forking the long-lived helper so the child
    // cannot inherit and retain the flock file description.
    let security_patch_lock = security_patch::acquire_operation_lock()
        .context("failed to lock security-patch operations during startup")?;
    let config_file = config::bootstrap_config_file().context("failed to bootstrap config")?;
    let level = config_file
        .main
        .log_level
        .trim()
        .parse()
        .unwrap_or(LevelFilter::Debug);
    log::set_max_level(level);

    info!("starting OhMyKeymint");

    if let Err(error) = security_patch::prepare_startup(&config_file, &security_patch_lock) {
        warn!("failed to prepare synchronized security-patch properties; continuing startup: {error:#}");
    }

    info!("initial process state");
    let _ = rsbinder::ProcessState::init_default();

    let resolved_trust = plat::vbmeta::bootstrap_vbmeta(&config_file, &security_patch_lock)
        .context("failed to bootstrap vbmeta")?;
    prepare_android_storage();
    config::install_runtime_config(config_file, resolved_trust)
        .context("failed to install runtime config")?;
    drop(security_patch_lock);

    install_module_info_bundle_if_available().context("failed to initialize moduleHash input")?;

    crate::keymaster::entropy::register_feeder();
    global::DB
        .with(|db| {
            crate::keymaster::super_key::SuperKeyManager::set_up_boot_level_cache(
                &global::SUPER_KEY,
                &mut db.borrow_mut(),
            )
        })
        .context("failed to initialize boot-level key cache")?;
    let boot_completed =
        crate::plat::resetprop::read_string_property("sys.boot_completed").as_deref() == Some("1");
    if boot_completed {
        crate::keymaster::maintenance::replay_early_boot_ended()
            .context("failed to replay earlyBootEnded to KeyMint wrappers")?;
    }
    std::thread::spawn(move || {
        global::await_boot_completed();
        if boot_completed {
            return;
        }
        if let Err(error) = crate::keymaster::maintenance::replay_early_boot_ended() {
            error!("failed to replay earlyBootEnded after boot completed: {error:#}");
        }
    });
    repair_omk_data_files();

    keybox::initialize().context("failed to initialize keybox runtime")?;

    info!("setting uid/gid={} role=keystore", KEYSTORE_UID);
    set_keystore_identity()?;

    let injector_rpc_server = create_rpc_server()?;

    crate::keymaster::metrics_store::update_keystore_crash_count();

    info!("starting thread pool");
    rsbinder::ProcessState::start_thread_pool();

    info!("using injector backend");
    let server = injector_rpc_server;

    info!("creating keystore service");
    let dev = KeystoreService::new_native_binder().context("failed to create omk service")?;

    info!("adding OMK service to RPC server");
    let service = BnOhMyKsService::new_binder_with_features(dev, consts::sid_features());
    server
        .add_service(rpc::SERVICE, service.as_binder())
        .context("failed to add OMK RPC service")?;

    info!("creating OMK authorization service");
    let auth = AuthorizationManager::new_omk_binder()
        .context("failed to create OMK authorization service")?;
    info!("adding OMK authorization service to RPC server");
    server
        .add_service(rpc::AUTHORIZATION_SERVICE, auth.as_binder())
        .context("failed to add OMK authorization RPC service")?;

    info!("creating OMK maintenance service");
    let maintenance =
        MaintenanceManager::new_omk_binder().context("failed to create OMK maintenance service")?;
    info!("adding OMK maintenance service to RPC server");
    server
        .add_service(rpc::MAINTENANCE_SERVICE, maintenance.as_binder())
        .context("failed to add OMK maintenance RPC service")?;

    info!("creating OMK metrics service");
    let metrics = Metrics::new_native_binder().context("failed to create OMK metrics service")?;
    info!("adding OMK metrics service to RPC server");
    server
        .add_service(rpc::METRICS_SERVICE, metrics.as_binder())
        .context("failed to add OMK metrics RPC service")?;

    info!("serving OMK RPC socket={}", rpc::SOCKET);
    server.run().context("OMK RPC server stopped")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webui_soter_hal_rejects_invalid_arguments_before_storage_setup() {
        for arguments in [
            vec!["--webui-get-soter-hal", "extra"],
            vec!["--webui-set-soter-hal"],
            vec!["--webui-set-soter-hal", "{}", "extra"],
            vec!["--webui-set-soter-hal-base64"],
            vec!["--webui-set-soter-hal-base64", "e30=", "extra"],
            vec!["--webui-set-soter-hal-base64", "not-base64"],
            vec!["--webui-set-soter-hal-base64", "/w=="],
            vec!["--webui-set-soter-hal-base64", "e30="],
        ] {
            assert!(
                handle_webui_soter_hal_command(arguments.into_iter().map(str::to_string))
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[test]
    fn webui_soter_beta_rejects_invalid_arguments_before_storage_setup() {
        for arguments in [
            vec!["--webui-get-soter-beta", "1"],
            vec!["--webui-set-soter-beta"],
            vec!["--webui-set-soter-beta", "true"],
            vec!["--webui-set-soter-beta", "1", "0"],
            vec!["--webui-set-soter-beta", "1\n"],
        ] {
            assert!(
                handle_webui_soter_beta_command(arguments.into_iter().map(str::to_string))
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[test]
    fn soter_features_allow_one_enabled_service_and_fail_closed_on_conflict() {
        assert!(ensure_soter_features_are_exclusive(
            true,
            Ok(false),
            "Tencent Soter Beta",
            "Qualcomm Soter HAL",
        )
        .is_ok());
        let conflict = ensure_soter_features_are_exclusive(
            true,
            Ok(true),
            "Qualcomm Soter HAL",
            "Tencent Soter Beta",
        )
        .unwrap_err()
        .to_string();
        assert!(conflict.contains("cannot be enabled"));
        assert!(ensure_soter_features_are_exclusive(
            false,
            Err(anyhow::anyhow!("unreadable state")),
            "Tencent Soter Beta",
            "Qualcomm Soter HAL",
        )
        .is_ok());
        assert!(ensure_soter_features_are_exclusive(
            true,
            Err(anyhow::anyhow!("unreadable state")),
            "Tencent Soter Beta",
            "Qualcomm Soter HAL",
        )
        .is_err());
    }

    #[test]
    fn webui_keybox_payload_decodes_multiple_chunks() {
        let decoded = decode_webui_keybox_payload(vec!["YWJj".into(), "ZA==".into()]).unwrap();
        assert_eq!(decoded, b"abcd");
    }

    #[test]
    fn webui_keybox_payload_rejects_invalid_base64() {
        assert!(decode_webui_keybox_payload(vec!["not-base64".into()]).is_err());
    }

    #[test]
    fn webui_keybox_payload_rejects_too_many_chunks() {
        let chunks = vec!["YQ==".to_string(); WEBUI_KEYBOX_MAX_CHUNKS + 1];
        assert!(decode_webui_keybox_payload(chunks).is_err());
    }
}
