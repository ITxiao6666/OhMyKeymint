use std::ffi::c_void;

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use log::{error, info, warn, LevelFilter};
use nix::unistd::Pid;

use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;

mod auto_targets;
pub mod config;
pub mod filter;
pub mod forward;
pub mod hook;
pub mod identify;
pub mod inject;
pub mod ipc;
pub mod legacy;
pub mod logging;
pub mod parcel;
mod soter_watch;
pub mod sys;
pub mod tracker;
pub mod utils;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

fn log_runtime_identity(role: &str) {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let egid = unsafe { libc::getegid() };
    info!(
        "runtime identity role={} uid={} euid={} gid={} egid={}",
        role, uid, euid, gid, egid
    );
}

const WEBUI_GET_TEE_STATUS: &str = "--webui-get-tee-status";

fn parse_webui_tee_status_args(args: &[String]) -> Option<Result<(), String>> {
    let command = args.first()?;
    if command != WEBUI_GET_TEE_STATUS {
        return None;
    }
    if args.len() != 1 {
        return Some(Err(format!(
            "{WEBUI_GET_TEE_STATUS} does not accept arguments"
        )));
    }
    Some(Ok(()))
}

fn enter_keystore_identity() -> anyhow::Result<()> {
    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    if effective_uid == KEYSTORE_UID && effective_gid == KEYSTORE_GID {
        return Ok(());
    }
    if effective_uid != 0 {
        bail!(
            "TEE status probe requires root or keystore uid/gid; current euid={effective_uid} egid={effective_gid}"
        );
    }

    if unsafe { libc::setgid(KEYSTORE_GID) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to enter keystore gid for TEE status probe");
    }
    if unsafe { libc::setuid(KEYSTORE_UID) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to enter keystore uid for TEE status probe");
    }
    if unsafe { libc::geteuid() } != KEYSTORE_UID || unsafe { libc::getegid() } != KEYSTORE_GID {
        bail!("TEE status probe did not enter the keystore uid/gid");
    }
    Ok(())
}

fn probe_tee_status() -> anyhow::Result<()> {
    enter_keystore_identity()?;
    ipc::ensure_process_state();
    ipc::with_omk_once(|omk| {
        let _ = omk.r#getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)?;
        Ok(())
    })
    .context("failed to obtain the OMK TEE security level")
}

fn handle_webui_tee_status_command() -> Option<Result<&'static str, String>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_webui_tee_status_args(&args)? {
        Ok(()) => Some(
            probe_tee_status()
                .map(|()| "normal")
                .map_err(|error| format!("{error:#}")),
        ),
        Err(error) => Some(Err(error)),
    }
}

fn handle_webui_config_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    let command = args.next()?;

    match command.as_str() {
        "--webui-get-auto-targets" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-auto-targets does not accept arguments".into()
                ));
            }
            Some(
                auto_targets::status()
                    .and_then(|state| Ok(serde_json::to_string(&state)?))
                    .map_err(|error| format!("{error:#}")),
            )
        }
        "--webui-set-auto-targets" => {
            let enabled = match args.next().as_deref() {
                Some("0") => false,
                Some("1") => true,
                _ => return Some(Err("--webui-set-auto-targets requires 0 or 1".into())),
            };
            if args.next().is_some() {
                return Some(Err("--webui-set-auto-targets accepts one argument".into()));
            }
            Some(
                auto_targets::set_enabled(enabled)
                    .and_then(|state| Ok(serde_json::to_string(&state)?))
                    .map_err(|error| format!("{error:#}")),
            )
        }
        "--webui-update-scoop" => {
            let Some(encoded) = args.next() else {
                return Some(Err(
                    "--webui-update-scoop requires a base64 JSON delta".into()
                ));
            };
            if args.next().is_some() || encoded.len() > 4 * 1024 * 1024 {
                return Some(Err("invalid scoop delta arguments".into()));
            }
            Some(
                BASE64_STANDARD
                    .decode(encoded)
                    .map_err(|error| error.to_string())
                    .and_then(|payload| {
                        serde_json::from_slice::<config::ScoopDelta>(&payload)
                            .map_err(|error| error.to_string())
                    })
                    .and_then(config::update_scoop_for_webui)
                    .and_then(|targets| {
                        serde_json::to_string(&targets).map_err(|error| error.to_string())
                    }),
            )
        }
        "--webui-get-scoop" => {
            if args.next().is_some() {
                return Some(Err(
                    "--webui-get-scoop does not accept arguments".to_string()
                ));
            }
            Some(
                config::read_scoop_for_webui().and_then(|packages| {
                    serde_json::to_string(&packages).map_err(|e| e.to_string())
                }),
            )
        }
        "--webui-set-scoop" => {
            let Some(encoded) = args.next() else {
                return Some(Err(
                    "--webui-set-scoop requires a base64-encoded JSON array".to_string(),
                ));
            };
            if args.next().is_some() {
                return Some(Err("--webui-set-scoop accepts one argument".to_string()));
            }
            let result = BASE64_STANDARD
                .decode(encoded)
                .map_err(|error| format!("invalid scoop payload encoding: {error}"))
                .and_then(|payload| {
                    serde_json::from_slice::<Vec<String>>(&payload)
                        .map_err(|error| format!("invalid scoop payload: {error}"))
                })
                .and_then(config::replace_scoop_for_webui)
                .map(|()| "ok".to_string());
            Some(result)
        }
        _ => None,
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--soter-watch") {
        if std::env::args().count() != 2 {
            std::process::exit(2);
        }
        logging::init_logger_fallback(LevelFilter::Info);
        if let Err(error) = soter_watch::run() {
            log::error!(target: "omk_soter_remote", "event=soter path=native_remote stage=watch state=failed error={error:#}");
            eprintln!("native SOTER watcher failed: {error:#}");
            std::process::exit(2);
        }
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--auto-targets-watch") {
        if std::env::args().count() != 2 {
            eprintln!("--auto-targets-watch does not accept arguments");
            std::process::exit(2);
        }
        logging::init_logger_fallback(LevelFilter::Warn);
        if let Err(error) = auto_targets::run_watcher() {
            eprintln!("automatic app selection watcher failed: {error:#}");
            std::process::exit(2);
        }
        return;
    }
    if let Some(result) = handle_webui_tee_status_command() {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_config_command() {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    logging::init_logger_fallback(LevelFilter::Debug);
    let config = config::get();
    if config::parse_level_filter(&config.main.log_level).is_none() {
        warn!(
            "injector logging unknown log level '{}', keeping debug fallback",
            config.main.log_level
        );
    }
    log::set_max_level(config.main.log_level_filter());
    log_runtime_identity("Launcher");
    match utils::current_exe_identity() {
        Ok(identity) => {
            info!(
                "injector binary build_id={} build_target={} git_sha={} runtime_arch={} exe={} sha256={} elf={}",
                utils::build_id(),
                utils::build_target(),
                utils::build_git_sha(),
                std::env::consts::ARCH,
                identity.path.display(),
                identity.sha256,
                identity.elf,
            );
        }
        Err(error) => {
            error!("failed to describe current injector binary: {:#}", error);
        }
    }

    let (pid, target_path) = match utils::find_process_by_name("keystore2") {
        Ok(target) => target,
        Err(error) => {
            warn!("event=target_not_ready process=keystore2 error={error:#}; daemon will retry");
            std::process::exit(1);
        }
    };
    match utils::executable_identity(&target_path) {
        Ok(identity) => info!(
            "keystore2 target pid={} exe={} sha256={} elf={}",
            pid,
            identity.path.display(),
            identity.sha256,
            identity.elf,
        ),
        Err(error) => error!(
            "failed to describe keystore2 executable {}: {:#}",
            target_path.display(),
            error
        ),
    }
    let pid = Pid::from_raw(pid);
    match inject::inject_library(pid) {
        Ok(()) => info!("injection completed"),
        Err(e) => {
            error!("injection failed: {:#}", e);
            std::process::exit(1);
        }
    }
}

#[no_mangle]
#[allow(unused)]
pub extern "C" fn entry(handle: *const c_void) -> bool {
    // This runs inside the target process, so we must initialize logging again
    // for that process. On Android this enables both logcat and stdout logging.
    logging::init_logger_fallback(LevelFilter::Debug);
    let config = config::get();
    if config::parse_level_filter(&config.main.log_level).is_none() {
        warn!(
            "injector logging unknown log level '{}', keeping debug fallback",
            config.main.log_level
        );
    }
    log::set_max_level(config.main.log_level_filter());
    log_runtime_identity("Payload");
    log::info!(
        "Injected library entry called! Handle: {:?}, build_id={}, build_target={}, runtime_arch={}, current_exe={}",
        handle,
        utils::build_id(),
        utils::build_target(),
        std::env::consts::ARCH,
        utils::current_exe_path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
    );
    if let Err(error) = ipc::install_direct_rpc_session() {
        error!("failed to initialize OMK RPC session: {error:#}");
        return false;
    }
    if let Err(error) = hook::init_hook() {
        error!("failed to initialize binder ioctl hook: {error:#}");
        return false;
    }
    true
}

/// # Safety
/// Called only by the root native injector with two newly transferred, owned
/// socketpair descriptors. They must be distinct and valid in this process.
#[no_mangle]
pub unsafe extern "C" fn soter_entry(_handle: *const c_void, auth: i32, calls: i32) -> bool {
    use std::os::{fd::FromRawFd, unix::net::UnixStream};
    logging::init_logger_fallback(LevelFilter::Info);
    let auth = UnixStream::from_raw_fd(auth);
    let calls = UnixStream::from_raw_fd(calls);
    match hook::soter::initialize(auth, calls) {
        Ok(()) => true,
        Err(error) => {
            error!("native SOTER entry failed: {error:#}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn tee_status_command_is_dispatched_without_arguments() {
        assert_eq!(
            parse_webui_tee_status_args(&args(&[WEBUI_GET_TEE_STATUS])),
            Some(Ok(()))
        );
    }

    #[test]
    fn tee_status_command_rejects_extra_arguments() {
        assert_eq!(
            parse_webui_tee_status_args(&args(&[WEBUI_GET_TEE_STATUS, "extra"])),
            Some(Err(format!(
                "{WEBUI_GET_TEE_STATUS} does not accept arguments"
            )))
        );
    }

    #[test]
    fn tee_status_parser_leaves_other_commands_for_existing_dispatch() {
        assert_eq!(
            parse_webui_tee_status_args(&args(&["--webui-get-scoop"])),
            None
        );
        assert_eq!(parse_webui_tee_status_args(&[]), None);
    }
}
