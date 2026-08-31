use std::ffi::c_void;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use log::{error, info, warn, LevelFilter};
use nix::unistd::Pid;

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

fn handle_webui_config_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    let command = args.next()?;

    match command.as_str() {
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

    let (pid, target_path) = utils::find_process_by_name("keystore2").unwrap();
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
    hook::init_hook().expect("failed to initialize binder ioctl hook");
    true
}
