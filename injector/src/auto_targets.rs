//! Opt-in discovery of newly installed user applications, outside keystore2.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::runtime::{file_watch, fs::atomic_replace_preserving_metadata};
use serde::{Deserialize, Serialize};

use crate::config::{self, DirectoryLock, ScoopDelta, ScoopTarget};

const STATE_PATH: &str = "/data/misc/keystore/omk/data/auto_targets.json";
const MAX_BYTES: usize = 4 * 1024 * 1024;
const SCAN_INTERVAL: Duration = Duration::from_secs(60);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct State {
    enabled: bool,
    /// Users without a successful first snapshot remain uninitialized. Their
    /// first readable snapshot is a baseline, never a batch of new installs.
    users: BTreeMap<u32, Option<BTreeSet<String>>>,
}

#[derive(Serialize)]
pub(crate) struct Status {
    pub enabled: bool,
}

#[derive(Default)]
struct Snapshot {
    users: BTreeMap<u32, Option<BTreeSet<String>>>,
}

fn read_state(path: &Path) -> Result<State> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
        Err(error) => return Err(error).context("cannot read automatic app selection state"),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        bail!("automatic app selection state is too large");
    }
    let state: State =
        serde_json::from_slice(&bytes).context("invalid automatic app selection state")?;
    for (user, packages) in &state.users {
        if *user > u32::MAX / kmr_common::consts::AID_USER_OFFSET {
            bail!("invalid Android user in automatic app selection state");
        }
        for package in packages.iter().flatten() {
            if !matches!(
                config::parse_scoop_target(package),
                Some(ScoopTarget::Package(_))
            ) {
                bail!("invalid package in automatic app selection state");
            }
        }
    }
    Ok(state)
}

fn write_state(path: &Path, state: &State) -> Result<()> {
    let encoded = serde_json::to_vec(state)?;
    if encoded.len() > MAX_BYTES {
        bail!("automatic app selection state is too large");
    }
    atomic_replace_preserving_metadata(path, &encoded, 0o600, KEYSTORE_UID, KEYSTORE_GID)
        .context("cannot save automatic app selection state")
}

pub(crate) fn status() -> Result<Status> {
    Ok(Status {
        enabled: read_state(Path::new(STATE_PATH))?.enabled,
    })
}

pub(crate) fn set_enabled(enabled: bool) -> Result<Status> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("automatic app selection requires root");
    }
    let path = Path::new(STATE_PATH);
    let parent = path.parent().expect("fixed state path has a parent");
    // PackageManager may be slow during boot or profile startup. The data
    // directory lock is shared with other OMK settings; scan before taking it.
    // Recheck the current switch under the lock before committing the baseline.
    let snapshot = if enabled { Some(discover()?) } else { None };
    let _guard =
        DirectoryLock::acquire(parent).context("cannot lock automatic app selection state")?;
    let mut state = read_state(path)?;
    if state.enabled == enabled {
        return Ok(Status { enabled });
    }
    state.users = snapshot.map_or_else(BTreeMap::new, |snapshot| snapshot.users);
    state.enabled = enabled;
    write_state(path, &state)?;
    Ok(Status { enabled })
}

/// Reconcile only successful user snapshots. An unreadable/locked profile must
/// not forget its baseline or cause its existing apps to be added on recovery.
fn reconcile(state: &mut State, snapshot: Snapshot) -> Vec<String> {
    let mut added = Vec::new();
    state
        .users
        .retain(|user, _| snapshot.users.contains_key(user));
    for (user, current) in snapshot.users {
        let Some(current) = current else {
            state.users.entry(user).or_insert(None);
            continue;
        };
        if let Some(Some(previous)) = state.users.get(&user) {
            added.extend(
                current
                    .difference(previous)
                    .map(|package| format!("{package}@{user}")),
            );
        }
        state.users.insert(user, Some(current));
    }
    added
}

fn poll() -> Result<()> {
    let path = Path::new(STATE_PATH);
    let initial = read_state(path)?;
    if !initial.enabled {
        return Ok(());
    }
    // Discovery is read-only and can take time; do not hold the shared data
    // lock while PackageManager is busy. Recheck the switch after locking.
    let snapshot = discover()?;
    let _guard = DirectoryLock::acquire(path.parent().expect("fixed path parent"))?;
    let mut state = read_state(path)?;
    if !state.enabled || state != initial {
        return Ok(());
    }
    let previous = serde_json::to_vec(&state)?;
    let added = reconcile(&mut state, snapshot);
    if !added.is_empty() {
        config::update_scoop_for_webui(ScoopDelta {
            added,
            removed: Vec::new(),
        })
        .map_err(|error| anyhow!(error))?;
    }
    if serde_json::to_vec(&state)? != previous {
        // Persist only after the config update succeeded, so failed writes can
        // retry. Duplicate additions are harmless and preserve existing rules.
        write_state(path, &state)?;
    }
    Ok(())
}

fn parse_users(output: &str) -> Result<BTreeSet<u32>> {
    let mut users = BTreeSet::new();
    for tail in output.split("UserInfo{").skip(1) {
        let id = tail.split(':').next().unwrap_or("");
        if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("invalid Android user list");
        }
        let user: u32 = id.parse()?;
        if user > u32::MAX / kmr_common::consts::AID_USER_OFFSET {
            bail!("Android user is out of range");
        }
        users.insert(user);
    }
    if users.is_empty() || users.len() > 128 {
        bail!("Android user list is unavailable");
    }
    Ok(users)
}

fn parse_packages(output: &str) -> Result<BTreeSet<String>> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let name = line
                .trim()
                .strip_prefix("package:")
                .ok_or_else(|| anyhow!("unexpected PackageManager output"))?;
            if !matches!(
                config::parse_scoop_target(name),
                Some(ScoopTarget::Package(_))
            ) {
                bail!("invalid installed package name");
            }
            Ok(name.to_owned())
        })
        .collect()
}

fn discover() -> Result<Snapshot> {
    let output = run_command(&["user", "list"])?;
    let users = parse_users(&output)?;
    let mut snapshot = Snapshot::default();
    for user in users {
        let output = run_command(&[
            "package",
            "list",
            "packages",
            "-3",
            "--user",
            &user.to_string(),
        ]);
        let packages = output.and_then(|output| parse_packages(&output)).ok();
        snapshot.users.insert(user, packages);
    }
    if snapshot.users.values().all(Option::is_none) {
        bail!("no Android user package snapshot is available");
    }
    Ok(snapshot)
}

/// Bounded argv-only calls into Android's installed package manager, never a
/// shell program or a per-app Binder transaction. No probe files are created.
fn run_command(args: &[&str]) -> Result<String> {
    let mut child = Command::new("/system/bin/cmd")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .context("missing package manager stdout")?;
        let fd = stdout.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error()).context("cannot read package manager output");
        }
        let started = Instant::now();
        let mut output = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(size) => {
                        output.extend_from_slice(&buffer[..size]);
                        if output.len() > MAX_BYTES {
                            bail!("package manager output is too large");
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    bail!("package manager query failed: {status}");
                }
                // Drain the final bytes emitted between the last read and exit.
                stdout
                    .take((MAX_BYTES - output.len() + 1) as u64)
                    .read_to_end(&mut output)?;
                if output.len() > MAX_BYTES {
                    bail!("package manager output is too large");
                }
                return String::from_utf8(output).context("package manager output is not UTF-8");
            }
            if started.elapsed() >= COMMAND_TIMEOUT {
                bail!("package manager query timed out");
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}

pub(crate) fn run_watcher() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("automatic app selection requires root");
    }
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        bail!("automatic app selection watcher has no parent");
    }
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0 {
        return Err(io::Error::last_os_error()).context("cannot bind watcher lifetime to helper");
    }
    if unsafe { libc::getppid() } != parent {
        return Ok(());
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    for path in [STATE_PATH, "/data/system/packages.list"] {
        let sender = sender.clone();
        if let Err(error) =
            file_watch::spawn_path_watcher("omk-auto-app-events", PathBuf::from(path), move |_| {
                let _ = sender.try_send(());
            })
        {
            log::warn!("automatic app event watcher unavailable: {error:#}");
        }
    }
    let mut last_error = None;
    loop {
        if let Err(error) = poll() {
            // PackageManager can be unavailable during boot. Avoid filling the
            // daemon log with the same retry failure every minute.
            let message = format!("{error:#}");
            if last_error.as_ref() != Some(&message) {
                log::warn!("automatic app selection: {message}");
                last_error = Some(message);
            }
        } else {
            last_error = None;
        }
        let _ = receiver.recv_timeout(SCAN_INTERVAL);
        std::thread::sleep(Duration::from_millis(500));
        while receiver.try_recv().is_ok() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packages(names: &[&str]) -> Option<BTreeSet<String>> {
        Some(names.iter().map(|name| (*name).to_string()).collect())
    }

    #[test]
    fn only_new_installs_are_selected_and_updates_do_not_readd() {
        let mut state = State {
            enabled: true,
            users: BTreeMap::from([(0, packages(&["com.old"]))]),
        };
        let scan = || Snapshot {
            users: BTreeMap::from([(0, packages(&["com.old", "com.new"]))]),
        };
        assert_eq!(reconcile(&mut state, scan()), ["com.new@0"]);
        assert!(reconcile(&mut state, scan()).is_empty());
    }

    #[test]
    fn unreadable_profiles_keep_baseline_and_first_read_is_not_bulk_added() {
        let mut state = State {
            enabled: true,
            users: BTreeMap::from([(0, packages(&["com.old"])), (10, None)]),
        };
        let first = Snapshot {
            users: BTreeMap::from([(0, None), (10, packages(&["com.profile"]))]),
        };
        assert!(reconcile(&mut state, first).is_empty());
        assert_eq!(state.users[&0], packages(&["com.old"]));
        let second = Snapshot {
            users: BTreeMap::from([
                (0, packages(&["com.old"])),
                (10, packages(&["com.profile", "com.new"])),
            ]),
        };
        assert_eq!(reconcile(&mut state, second), ["com.new@10"]);
    }

    #[test]
    fn uninstall_then_reinstall_is_a_new_install() {
        let mut state = State {
            enabled: true,
            users: BTreeMap::from([(0, packages(&["com.app"]))]),
        };
        assert!(reconcile(
            &mut state,
            Snapshot {
                users: BTreeMap::from([(0, packages(&[]))])
            }
        )
        .is_empty());
        assert_eq!(
            reconcile(
                &mut state,
                Snapshot {
                    users: BTreeMap::from([(0, packages(&["com.app"]))])
                }
            ),
            ["com.app@0"]
        );
    }

    #[test]
    fn package_manager_outputs_are_validated() {
        assert_eq!(
            parse_users("Users:\n UserInfo{0:Owner:c13} running\n UserInfo{10:Work:30}").unwrap(),
            BTreeSet::from([0, 10])
        );
        assert!(parse_users("Error: service unavailable").is_err());
        assert!(parse_packages("Error: permission denied").is_err());
        assert!(parse_packages("package:com.app@0").is_err());
        assert_eq!(
            parse_packages("package:com.app\npackage:com.app\n")
                .unwrap()
                .len(),
            1
        );
        assert!(parse_packages("").unwrap().is_empty());
    }
}
