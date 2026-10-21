use std::{fs, io, path::Path};

use anyhow::{bail, Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppUid(pub i64);

/// This returns the current time (in milliseconds) as an instance of a monotonic clock,
/// by invoking the system call since Rust does not support getting monotonic time instance
/// as an integer.
pub fn get_current_time_in_milliseconds() -> i64 {
    let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The pointer is valid because it comes from a reference, and clock_gettime doesn't
    // retain it beyond the call.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut current_time) };
    current_time.tv_sec * 1000 + (current_time.tv_nsec / 1_000_000)
}

pub trait ParcelExt {
    fn data(&self) -> &[u8];
}

impl ParcelExt for rsbinder::Parcel {
    fn data(&self) -> &[u8] {
        unsafe {
            let data = self.as_ptr();
            let parcel_size = self.data_size();
            std::slice::from_raw_parts(data, parcel_size)
        }
    }
}

pub(crate) fn refresh_soter_host() -> Result<()> {
    stop_processes_matching(|name| name == b"com.tencent.soter.soterserver")
        .context("Soter settings were saved, but SoterServer could not be refreshed; restart the service before using the new mode")
}

/// Stop matching Android processes without setting the package's force-stop
/// flag. Android may rebind services normally with their updated configuration.
pub(crate) fn stop_processes_matching(matches: impl Fn(&[u8]) -> bool) -> Result<()> {
    stop_processes_in(Path::new("/proc"), matches, |pid| {
        if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })
}

fn stop_processes_in(
    proc_root: &Path,
    matches: impl Fn(&[u8]) -> bool,
    mut stop: impl FnMut(i32) -> io::Result<()>,
) -> Result<()> {
    let entries = fs::read_dir(proc_root).context("failed to scan processes for refresh")?;
    let mut failures = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|pid| *pid > 1)
        else {
            continue;
        };
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let name = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
        if !matches(name) {
            continue;
        }
        if let Err(error) = stop(pid) {
            // A matching process can exit between the /proc scan and kill.
            if error.raw_os_error() != Some(libc::ESRCH) {
                failures.push(format!(
                    "{} (pid {pid}): {error}",
                    String::from_utf8_lossy(name)
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to stop matching process(es): {}",
            failures.join("; ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_stops_all_exact_hosts_without_stopping_other_processes() {
        let proc_root = tempfile::tempdir().unwrap();
        for (pid, name) in [
            ("0", "com.tencent.soter.soterserver"),
            ("1", "com.tencent.soter.soterserver"),
            ("201", "com.tencent.soter.soterserver"),
            ("202", "com.tencent.soter.soterserver"),
            ("203", "com.tencent.soter.soterserver:other"),
            ("204", "com.tencent.soter.soterserver.extra"),
            ("205", "com.tencent.mm"),
            ("self", "com.tencent.soter.soterserver"),
        ] {
            let directory = proc_root.path().join(pid);
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("cmdline"), format!("{name}\0argument\0")).unwrap();
        }
        let mut stopped = Vec::new();
        stop_processes_in(
            proc_root.path(),
            |name| name == b"com.tencent.soter.soterserver",
            |pid| {
                stopped.push(pid);
                Ok(())
            },
        )
        .unwrap();
        stopped.sort_unstable();
        assert_eq!(stopped, [201, 202]);
    }

    #[test]
    fn refresh_accepts_exited_processes_but_reports_stop_failures() {
        let proc_root = tempfile::tempdir().unwrap();
        let directory = proc_root.path().join("201");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("cmdline"), b"target\0").unwrap();
        stop_processes_in(
            proc_root.path(),
            |_| true,
            |_| Err(io::Error::from_raw_os_error(libc::ESRCH)),
        )
        .unwrap();
        let error = stop_processes_in(
            proc_root.path(),
            |_| true,
            |_| Err(io::Error::from_raw_os_error(libc::EPERM)),
        )
        .unwrap_err();
        assert!(error.to_string().contains("target (pid 201)"));
        fs::remove_dir_all(directory).unwrap();
        stop_processes_in(proc_root.path(), |_| true, |_| panic!("no process")).unwrap();
    }
}
