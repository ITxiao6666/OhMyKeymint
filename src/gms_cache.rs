use std::{
    ffi::{CString, OsStr},
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;

const PACKAGES: [&str; 2] = ["com.google.android.gms", "com.android.vending"];
const CACHES: [&str; 2] = ["cache", "code_cache"];
const PROCESSES: [&str; 2] = ["com.google.android.gms.unstable", "com.android.vending"];

#[derive(Default, Serialize)]
struct Report {
    cleared_cache_dirs: usize,
    removed_entries: usize,
    processes: Vec<ProcessResult>,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct ProcessResult {
    name: &'static str,
    status: &'static str,
}

/// Clear only internal cache and code_cache contents, then stop the two requested
/// processes. Application data, accounts and cache-directory metadata are retained.
pub fn clear() -> Result<String> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("clearing Google application caches requires root");
    }

    let mut report = Report::default();
    clear_storage_root(
        Path::new("/data/user"),
        Some(Path::new("/data/data")),
        &mut report,
    );
    clear_storage_root(Path::new("/data/user_de"), None, &mut report);

    // These commands intentionally run after cache cleanup, including a partial
    // cleanup failure. They never invoke pm clear or remove application data.
    for name in PROCESSES {
        match kill_command(name).output() {
            Ok(output) if output.status.success() => report.processes.push(ProcessResult {
                name,
                status: "stopped",
            }),
            Ok(_) if crate::process_pid(&[name], None).is_none() => {
                report.processes.push(ProcessResult {
                    name,
                    status: "not_running",
                });
            }
            Ok(output) => report.errors.push(format!(
                "killall failed for {name}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => report
                .errors
                .push(format!("could not execute killall for {name}: {error}")),
        }
    }

    // Report partial failures instead of claiming that all caches were cleared.
    // Returning the structured report also retains successful work for the UI.
    serde_json::to_string(&report).context("failed to serialize Google cache cleanup result")
}

fn kill_command(name: &str) -> Command {
    let mut command = Command::new("/system/bin/killall");
    command.args(["-v", name]);
    command
}

fn directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    // Both package and cache directories are opened relative to a verified,
    // held directory. App-controlled symlinks cannot redirect the cleanup.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this function.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn descriptor_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn clear_storage_root(root: &Path, user_zero_alias: Option<&Path>, report: &mut Report) {
    let result = (|| -> Result<()> {
        let storage = match directory(root) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("cannot open application storage"),
        };
        for entry in fs::read_dir(descriptor_path(&storage))? {
            let entry = entry?;
            let user = entry.file_name();
            let Some(user_name) = user.to_str() else {
                continue;
            };
            if !user_name
                .parse::<u32>()
                .is_ok_and(|id| id.to_string() == user_name)
            {
                continue;
            }
            let opened_user = directory_at(&storage, &user).or_else(|error| {
                // Android may expose /data/user/0 as the root-owned symlink
                // /data/data. Only this exact system alias is accepted.
                if let Some(alias) = user_zero_alias.filter(|alias| {
                    user_name == "0"
                        && fs::read_link(root.join(&user)).ok().as_deref() == Some(*alias)
                }) {
                    return directory(alias);
                }
                Err(error)
            });
            let user_directory = match opened_user {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    report.errors.push(format!(
                        "cannot open {} user {user_name}: {error}",
                        root.display()
                    ));
                    continue;
                }
            };
            for package in PACKAGES {
                clear_package(&user_directory, root, user_name, package, report);
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        report.errors.push(format!("{}: {error:#}", root.display()));
    }
}

fn clear_package(parent: &File, root: &Path, user: &str, package: &str, report: &mut Report) {
    let result = (|| -> Result<()> {
        let package_directory = match directory_at(parent, OsStr::new(package)) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("cannot open application directory"),
        };
        for cache in CACHES {
            let cache_directory = match directory_at(&package_directory, OsStr::new(cache)) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    report.errors.push(format!(
                        "cannot open {} user {user} {package}/{cache}: {error}",
                        root.display()
                    ));
                    continue;
                }
            };
            match clear_directory_contents(&cache_directory) {
                Ok(count) => {
                    report.cleared_cache_dirs += 1;
                    report.removed_entries += count;
                }
                Err(error) => report.errors.push(format!(
                    "cannot clear {} user {user} {package}/{cache}: {error:#}",
                    root.display()
                )),
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        report.errors.push(format!(
            "{} user {user} {package}: {error:#}",
            root.display()
        ));
    }
}

fn clear_directory_contents(directory: &File) -> Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(descriptor_path(directory))? {
        let entry = entry?;
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        // Rust's Unix remove_dir_all does not follow symlinks and protects
        // against symlink races. The parent /proc/self/fd is pinned above.
        let result = if file_type.is_dir() {
            fs::remove_dir_all(entry.path())
        } else {
            fs::remove_file(entry.path())
        };
        match result {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    #[test]
    fn clears_only_cache_contents_for_both_packages_and_users() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        for user in ["0", "10"] {
            for package in PACKAGES {
                let base = root.join(user).join(package);
                for cache in CACHES {
                    fs::create_dir_all(base.join(cache).join("nested")).unwrap();
                    fs::write(base.join(cache).join("nested/item"), b"cache").unwrap();
                    fs::set_permissions(base.join(cache), fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                for data in ["databases", "shared_prefs", "files", "no_backup"] {
                    fs::create_dir_all(base.join(data)).unwrap();
                    fs::write(base.join(data).join("keep"), b"data").unwrap();
                }
            }
        }
        fs::create_dir_all(root.join("0/com.example.other/cache")).unwrap();
        fs::write(root.join("0/com.example.other/cache/keep"), b"other").unwrap();
        let mut report = Report::default();
        clear_storage_root(&root, None, &mut report);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.cleared_cache_dirs, 8);
        assert_eq!(report.removed_entries, 8);
        for user in ["0", "10"] {
            for package in PACKAGES {
                let base = root.join(user).join(package);
                for cache in CACHES {
                    assert_eq!(fs::read_dir(base.join(cache)).unwrap().count(), 0);
                    assert_eq!(
                        fs::metadata(base.join(cache)).unwrap().mode() & 0o777,
                        0o700
                    );
                }
                for data in ["databases", "shared_prefs", "files", "no_backup"] {
                    assert_eq!(fs::read(base.join(data).join("keep")).unwrap(), b"data");
                }
            }
        }
        assert_eq!(
            fs::read(root.join("0/com.example.other/cache/keep")).unwrap(),
            b"other"
        );
    }

    #[test]
    fn does_not_follow_symlinks_outside_cache() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        let package = root.join("0").join(PACKAGES[0]);
        let outside = temp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), b"data").unwrap();
        fs::create_dir_all(package.join("cache")).unwrap();
        symlink(&outside, package.join("cache/link")).unwrap();
        symlink(&outside, package.join("code_cache")).unwrap();
        symlink(&outside, root.join("0").join(PACKAGES[1])).unwrap();
        let mut report = Report::default();
        clear_storage_root(&root, None, &mut report);
        assert_eq!(report.cleared_cache_dirs, 1);
        assert_eq!(report.errors.len(), 2);
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"data");
        assert_eq!(fs::read_dir(package.join("cache")).unwrap().count(), 0);
    }

    #[test]
    fn accepts_only_the_explicit_user_zero_system_alias() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        let alias = temp.path().join("data");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(alias.join(PACKAGES[0]).join("cache")).unwrap();
        fs::write(alias.join(PACKAGES[0]).join("cache/item"), b"cache").unwrap();
        symlink(&alias, root.join("0")).unwrap();
        symlink(&alias, root.join("10")).unwrap();
        let mut report = Report::default();
        clear_storage_root(&root, Some(&alias), &mut report);
        assert_eq!(report.cleared_cache_dirs, 1);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(
            fs::read_dir(alias.join(PACKAGES[0]).join("cache"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn absent_storage_is_an_empty_success_and_commands_are_exact() {
        let temp = tempfile::tempdir().unwrap();
        let mut report = Report::default();
        clear_storage_root(&temp.path().join("missing"), None, &mut report);
        assert!(report.errors.is_empty());
        assert_eq!(report.cleared_cache_dirs, 0);
        for name in PROCESSES {
            let command = kill_command(name);
            assert_eq!(command.get_program(), "/system/bin/killall");
            assert_eq!(command.get_args().collect::<Vec<_>>(), ["-v", name]);
        }
    }
}
