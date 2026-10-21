use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub const STATE_PATH: &str = "/data/misc/keystore/omk/data/soter_beta.conf";

pub const MAX_APP_TARGETS: usize = 128;
pub const MAX_APP_TARGET_BYTES: usize = 8192;

/// A Soter opt-in always names one package in one Android user, never a wildcard.
pub fn parse_app_target(target: &str) -> Option<(&str, u32)> {
    let (package, user) = target.split_once('@')?;
    if package.len() > 255 || !package.contains('.') {
        return None;
    }
    for component in package.split('.') {
        let mut bytes = component.bytes();
        if !bytes
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == b'_')
            || !bytes.all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
        {
            return None;
        }
    }
    let id = user.parse::<u32>().ok()?;
    if id > (i32::MAX as u32 - 99999) / 100000 || id.to_string() != user {
        return None;
    }
    Some((package, id))
}

pub fn validate_app_targets(targets: &[String]) -> Result<(), String> {
    if targets.len() > MAX_APP_TARGETS
        || targets.iter().map(String::len).sum::<usize>() > MAX_APP_TARGET_BYTES
    {
        return Err("Soter application selection exceeds its size limit".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    if targets
        .iter()
        .any(|target| parse_app_target(target).is_none() || !seen.insert(target))
    {
        return Err("Soter application selection contains an invalid or duplicate target".into());
    }
    Ok(())
}

pub fn canonical_bytes(enabled: bool) -> &'static [u8] {
    if enabled {
        b"1"
    } else {
        b"0"
    }
}

pub fn parse(contents: &[u8]) -> io::Result<bool> {
    match contents {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Soter Beta state must contain exactly 0 or 1",
        )),
    }
}

pub fn read() -> io::Result<bool> {
    read_from(Path::new(STATE_PATH))
}

pub fn read_from(path: &Path) -> io::Result<bool> {
    // Open nonblocking before checking the descriptor so a FIFO cannot stall
    // the privileged helper or the Zygisk companion.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Soter Beta state must be a one-byte regular file",
        ));
    }

    let mut contents = Vec::with_capacity(2);
    file.take(2).read_to_end(&mut contents)?;
    parse(&contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::{ffi::OsStrExt, fs::symlink};

    #[test]
    fn app_targets_require_an_explicit_canonical_android_user() {
        assert_eq!(
            parse_app_target("com.example.wallet@0"),
            Some(("com.example.wallet", 0))
        );
        assert_eq!(
            parse_app_target("com.example.wallet@10"),
            Some(("com.example.wallet", 10))
        );
        for target in [
            "com.example",
            "com.example@01",
            "com.example@-1",
            "com.example@21475",
            "com..example@0",
            "*.example@0",
            "com.example@0@1",
            "com.example@+1",
        ] {
            assert_eq!(parse_app_target(target), None, "{target}");
        }
        assert!(validate_app_targets(&[]).is_ok());
        assert!(validate_app_targets(&["com.example@0".into(), "com.example@0".into()]).is_err());
    }

    #[test]
    fn state_accepts_only_canonical_boolean_bytes() {
        for enabled in [false, true] {
            assert_eq!(parse(canonical_bytes(enabled)).unwrap(), enabled);
        }
        for invalid in [b"".as_slice(), b"true", b"2", b" 1", b"1\n", b"0\0"] {
            assert_eq!(
                parse(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn missing_state_is_disabled_without_creating_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        assert!(!read_from(&path).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn reads_enabled_and_disabled_states() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        for enabled in [false, true, false] {
            fs::write(&path, canonical_bytes(enabled)).unwrap();
            assert_eq!(read_from(&path).unwrap(), enabled);
        }
    }

    #[test]
    fn rejects_invalid_oversized_and_non_regular_states() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        for contents in [b"".as_slice(), b"2", b"1\n", &[b'1'; 4096]] {
            fs::write(&path, contents).unwrap();
            assert!(read_from(&path).is_err());
        }
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(read_from(&path).is_err());
    }

    #[test]
    fn rejects_symlink_even_when_target_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let path = directory.path().join("state");
        symlink(&target, &path).unwrap();
        assert!(read_from(&path).is_err());
        fs::write(&target, b"1").unwrap();
        assert!(read_from(&path).is_err());
    }

    #[test]
    fn rejects_fifo_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(read_from(&path).is_err());
    }
}
