//! Root supervisor for the independent native SOTER HAL forwarding role.
use anyhow::{bail, Context, Result};
use nix::unistd::Pid;
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::Duration,
};

pub(crate) fn identity(pid: i32) -> Option<String> {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if cmdline.split(|b| *b == 0).next()? != b"com.tencent.soter.soterserver" {
        return None;
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let start = stat.rsplit_once(')')?.1.split_whitespace().nth(19)?;
    Some(format!("{pid}:{start}"))
}

pub fn run() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("native SOTER supervisor requires root");
    }
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        bail!("native SOTER supervisor requires its root helper");
    }
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot bind native supervisor lifetime");
    }
    if unsafe { libc::getppid() } != parent {
        return Ok(());
    }
    // Use the already-existing module binary for the singleton lock. No PID,
    // state, or socket file is created and the settings lock is not held.
    let singleton = fs::File::open(crate::utils::current_exe_path()?)?;
    if unsafe { libc::flock(singleton.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=watch state=already_running");
        return Ok(());
    }
    let mut injected = BTreeSet::new();
    let mut last_state = None;
    log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=watch state=started");
    loop {
        let state = if matches!(soter_ta::bridge::active_config(), Ok(Some(_))) {
            let mut live = BTreeSet::new();
            let mut unsupported = 0;
            for entry in fs::read_dir("/proc")?.flatten() {
                let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<i32>().ok())
                else {
                    continue;
                };
                let Some(id) = identity(pid) else { continue };
                live.insert(id.clone());
                if injected.contains(&id) {
                    continue;
                }
                // The payload is the arm64 binary. Never ptrace a 32-bit app.
                let mut elf = [0; 20];
                if !fs::File::open(format!("/proc/{pid}/exe"))
                    .and_then(|mut f| f.read_exact(&mut elf))
                    .is_ok()
                    || elf[..5] != [0x7f, b'E', b'L', b'F', 2]
                    || u16::from_le_bytes([elf[18], elf[19]]) != 183
                {
                    unsupported += 1;
                    continue;
                }
                kmr_common::selinux::set_sockcreate_con("u:object_r:system_file:s0")?;
                let channels =
                    (|| -> std::io::Result<_> { Ok((UnixStream::pair()?, UnixStream::pair()?)) })();
                kmr_common::selinux::clear_sockcreate_con()?;
                let ((auth_root, auth_host), (call_root, call_host)) = channels?;
                soter_ta::bridge::serve(auth_root, call_root)?;
                if identity(pid).as_ref() != Some(&id) {
                    log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=inject pid={pid} state=host_changed");
                    continue;
                }
                log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=inject pid={pid} state=start");
                match crate::inject::inject_soter(
                    Pid::from_raw(pid),
                    [auth_host.as_raw_fd(), call_host.as_raw_fd()],
                ) {
                    Ok(()) => {
                        injected.insert(id);
                        log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=inject pid={pid} state=installed");
                    }
                    Err(error) => {
                        log::warn!(target: "omk_soter_remote", "event=soter path=native_remote stage=inject pid={pid} state=failed error={error:#}")
                    }
                }
            }
            injected.retain(|id| live.contains(id));
            if live.is_empty() {
                "waiting_for_soterserver"
            } else if unsupported == live.len() {
                "host_not_arm64_or_unreadable"
            } else if injected.is_empty() {
                "waiting_for_injection"
            } else {
                "host_hooked"
            }
        } else {
            "inactive"
        };
        if last_state != Some(state) {
            log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=watch state={state}");
            last_state = Some(state);
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}
