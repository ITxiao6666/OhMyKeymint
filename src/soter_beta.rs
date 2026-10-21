use std::fs::{self, OpenOptions};
use std::io;
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::runtime::fs::atomic_replace_preserving_metadata;
use pif_common::soter;

pub fn require_root() -> Result<()> {
    require_uid(unsafe { libc::geteuid() })
}

fn require_uid(uid: u32) -> Result<()> {
    if uid != 0 {
        bail!("Soter Beta settings require root");
    }
    Ok(())
}

pub fn state_json() -> Result<String> {
    require_root()?;
    let enabled = is_enabled()?;
    Ok(format!("{{\"enabled\":{enabled}}}"))
}

pub fn is_enabled() -> Result<bool> {
    soter::read().context("failed to read Soter Beta state")
}

pub fn save(enabled: bool) -> Result<()> {
    require_root()?;
    let changed = save_to(
        Path::new(soter::STATE_PATH),
        enabled,
        KEYSTORE_UID,
        KEYSTORE_GID,
    )?;
    if changed {
        crate::utils::refresh_soter_host()?;
    }
    Ok(())
}

fn save_to(path: &Path, enabled: bool, uid: u32, gid: u32) -> Result<bool> {
    let parent = path
        .parent()
        .context("Soter Beta state has no parent directory")?;
    let metadata =
        fs::symlink_metadata(parent).context("failed to inspect Soter Beta state directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Soter Beta state directory is not a regular directory");
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            bail!("Soter Beta state is not a regular file")
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect Soter Beta state"),
    }
    let previous = soter::read_from(path).context("failed to read previous Soter Beta state")?;
    atomic_replace_preserving_metadata(path, soter::canonical_bytes(enabled), 0o600, uid, gid)
        .context("failed to save Soter Beta state")?;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .context("failed to reopen Soter Beta state")?;
    if !file.metadata()?.is_file() {
        bail!("Soter Beta state is not a regular file");
    }
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
    {
        return Err(io::Error::last_os_error())
            .context("failed to set Soter Beta state permissions");
    }
    file.sync_all().context("failed to sync Soter Beta state")?;
    if soter::read_from(path).context("failed to verify Soter Beta state")? != enabled {
        bail!("Soter Beta state changed while being saved");
    }
    Ok(previous != enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    #[test]
    fn accepts_only_root_uid() {
        require_uid(0).unwrap();
        for uid in [1000, 1017, 2000, 10000] {
            assert!(require_uid(uid).is_err());
        }
    }

    #[test]
    fn saves_canonical_state_and_restricts_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        for enabled in [true, false] {
            save_to(&path, enabled, uid, gid).unwrap();
            assert_eq!(fs::read(&path).unwrap(), soter::canonical_bytes(enabled));
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.uid(), uid);
            assert_eq!(metadata.gid(), gid);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        }
    }

    #[test]
    fn only_changed_beta_modes_require_host_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert!(!save_to(&path, false, uid, gid).unwrap());
        assert!(save_to(&path, true, uid, gid).unwrap());
        assert!(!save_to(&path, true, uid, gid).unwrap());
        assert!(save_to(&path, false, uid, gid).unwrap());
        assert!(!save_to(&path, false, uid, gid).unwrap());
    }

    #[test]
    fn rejects_symlink_and_directory_targets_without_changing_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        let target = directory.path().join("target");
        fs::write(&target, b"0").unwrap();
        symlink(&target, &path).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert!(save_to(&path, true, uid, gid).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"0");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(save_to(&path, true, uid, gid).is_err());
        assert!(path.is_dir());
    }
}
