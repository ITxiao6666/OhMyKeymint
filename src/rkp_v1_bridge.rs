//! Bounded Android AIDL V1 bridge runner.
//!
//! The bridge exchanges only the public RKP request data and HAL response. It
//! does not create keys, contact a server, or persist issuance artifacts.

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
use std::{
    ffi::{CStr, CString, OsString},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Instant,
};

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const DATA_DIR: &str = crate::root_path!("data");
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const APP_PROCESS: &str = "/system/bin/app_process";
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const MAIN_CLASS: &str = "duck.rkp.RkpV1Bridge";
const MAX_FIELD: usize = 0xa000;
const MAX_REQUEST: usize = 4 * (4 + MAX_FIELD);
#[cfg(any(all(target_os = "android", target_arch = "aarch64"), test))]
const MAX_REPLY: usize = 4 + 3 * (4 + MAX_FIELD);
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const BRIDGE_JAR: &[u8] = include_bytes!(env!("OMK_RKP_V1_BRIDGE_JAR"));

/// Run one pre-encoded V1 bridge exchange and return its bounded wire response.
/// The caller owns request construction and all subsequent RKP signing logic.
pub fn exchange(encoded_request: &[u8]) -> Result<Vec<u8>> {
    validate_request(encoded_request)?;

    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        if unsafe { libc::geteuid() } != 0 {
            bail!("RKP V1 bridge requires root");
        }
        run_android(encoded_request)
    }

    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
    {
        let _ = encoded_request;
        bail!("RKP V1 bridge is available only on Android arm64");
    }
}

/// A read-only resource check, not proof that this firmware accepts a CSR.
pub fn available() -> bool {
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        Path::new(APP_PROCESS).is_file() && find_aidl_apk().is_ok()
    }
    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
    {
        false
    }
}

fn validate_request(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_REQUEST {
        bail!("RKP V1 bridge request exceeds its size limit");
    }

    let mut offset = 0usize;
    let mut lengths = [0usize; 4];
    for length in &mut lengths {
        let header_end = offset
            .checked_add(4)
            .ok_or_else(|| anyhow!("invalid RKP V1 request length"))?;
        let header = bytes
            .get(offset..header_end)
            .ok_or_else(|| anyhow!("truncated RKP V1 request header"))?;
        let encoded_length = u32::from_be_bytes(header.try_into()?) as usize;
        if encoded_length > MAX_FIELD {
            bail!("RKP V1 bridge request field exceeds its size limit");
        }
        offset = header_end;
        let field_end = offset
            .checked_add(encoded_length)
            .ok_or_else(|| anyhow!("invalid RKP V1 request length"))?;
        if field_end > bytes.len() {
            bail!("truncated RKP V1 request field");
        }
        *length = encoded_length;
        offset = field_end;
    }

    if offset != bytes.len() {
        bail!("trailing RKP V1 request data");
    }
    if !(1..=64).contains(&lengths[0]) || lengths[1] == 0 {
        bail!("invalid RKP V1 challenge or MacedPublicKey");
    }
    Ok(())
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
fn run_android(encoded_request: &[u8]) -> Result<Vec<u8>> {
    let mut exchange = ExchangeDir::create()?;
    let result = run_exchange(&exchange.path, encoded_request);
    let cleanup = exchange.cleanup();
    match (result, cleanup) {
        (Ok(reply), Ok(())) => Ok(reply),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("remove temporary RKP V1 exchange files"),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "also failed to remove temporary RKP V1 exchange files: {cleanup_error}"
        ))),
    }
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
fn run_exchange(directory: &Path, encoded_request: &[u8]) -> Result<Vec<u8>> {
    let jar_path = directory.join("bridge.jar");
    write_private_file(&jar_path, BRIDGE_JAR, 0o600)?;
    fs::set_permissions(&jar_path, fs::Permissions::from_mode(0o400))?;
    write_private_file(&directory.join("request.bin"), encoded_request, 0o600)?;

    let apk = find_aidl_apk()?;
    let mut child = bridge_command(directory, &jar_path, &apk)
        .spawn()
        .context("start Android RKP V1 bridge")?;
    let status = wait_bounded(&mut child)?;
    if !status.success() {
        bail!("Android RKP V1 bridge exited with {status}");
    }
    read_bounded_reply(&directory.join("reply.bin"))
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
pub(crate) fn write_private_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("create temporary RKP V1 file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write temporary RKP V1 file {}", path.display()))
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
fn bridge_command(directory: &Path, jar: &Path, apk: &Path) -> Command {
    let mut command = Command::new(APP_PROCESS);
    command
        .env("CLASSPATH", format!("{}:{}", jar.display(), apk.display()))
        .args(["/system/bin", MAIN_CLASS])
        .arg(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
pub(crate) fn wait_bounded(child: &mut Child) -> Result<std::process::ExitStatus> {
    let started = Instant::now();
    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("wait for Android RKP bridge");
            }
        };
        if let Some(status) = status {
            return Ok(status);
        }
        if started.elapsed() >= TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "Android RKP V1 bridge timed out after {} seconds",
                TIMEOUT.as_secs()
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
pub(crate) fn read_bounded_reply(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open Android RKP V1 reply")?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_REPLY as u64 {
        bail!("Android RKP V1 reply must be a regular file under its size limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REPLY as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read Android RKP V1 reply")?;
    if bytes.len() > MAX_REPLY {
        bail!("Android RKP V1 reply exceeded its size limit while reading");
    }
    Ok(bytes)
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
fn find_aidl_apk() -> Result<PathBuf> {
    let apex = Path::new("/apex/com.android.rkpd");
    for directory in ["priv-app", "app"] {
        let root = apex.join(directory);
        let mut entries = fs::read_dir(&root)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path().join("rkpdapp.apk"))
            .collect::<Vec<_>>();
        entries.sort();
        if let Some(apk) = entries.into_iter().find(|path| trusted_system_apk(path)) {
            return Ok(apk);
        }
    }

    for root in ["/system/priv-app", "/system/app", "/system_ext/priv-app"] {
        let apk = Path::new(root).join("RemoteProvisioner/RemoteProvisioner.apk");
        if trusted_system_apk(&apk) {
            return Ok(apk);
        }
    }
    bail!("no trusted system RKP AIDL APK was found")
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
fn trusted_system_apk(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
    })
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
pub(crate) struct ExchangeDir {
    pub(crate) path: PathBuf,
    cleaned: bool,
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
impl ExchangeDir {
    pub(crate) fn create() -> Result<Self> {
        let data = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(DATA_DIR)
            .context("open OMK data directory for temporary RKP V1 exchange")?;
        let metadata = data.metadata()?;
        let acceptable_owner =
            metadata.uid() == 0 || metadata.uid() == kmr_common::consts::KEYSTORE_UID;
        if !metadata.is_dir()
            || !acceptable_owner
            || metadata.mode() & 0o007 != 0
            || metadata.mode() & 0o002 != 0
        {
            bail!("OMK data directory permissions are unsafe for RKP V1 exchange");
        }

        let mut template = CString::new(format!("{DATA_DIR}/rkp-v1-XXXXXX"))?.into_bytes_with_nul();
        // SAFETY: `template` is a mutable, NUL-terminated buffer and remains alive
        // while mkdtemp writes the generated directory name into it.
        let created = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        if created.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("create private RKP V1 exchange directory");
        }
        // SAFETY: mkdtemp returned a pointer into the still-live NUL-terminated buffer.
        let path_bytes = unsafe { CStr::from_ptr(created) }.to_bytes().to_vec();
        let path = PathBuf::from(OsString::from_vec(path_bytes));
        let mut exchange = Self {
            path,
            cleaned: false,
        };
        let setup = (|| -> Result<()> {
            let metadata = fs::symlink_metadata(&exchange.path)?;
            if !metadata.is_dir() || metadata.uid() != 0 {
                bail!("temporary RKP V1 exchange directory is not root-owned");
            }
            fs::set_permissions(&exchange.path, fs::Permissions::from_mode(0o700))?;
            Ok(())
        })();
        if let Err(error) = setup {
            let _ = exchange.cleanup();
            return Err(error);
        }
        Ok(exchange)
    }

    pub(crate) fn cleanup(&mut self) -> Result<()> {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) => Err(error).context("remove private RKP V1 exchange directory"),
        }
    }
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
impl Drop for ExchangeDir {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(fields: [&[u8]; 4]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        bytes
    }

    #[test]
    fn accepts_a_bounded_four_field_exchange() {
        validate_request(&request([b"challenge", b"maced", b"p256", b""])).unwrap();
    }

    #[test]
    fn rejects_truncated_oversized_and_trailing_request_data() {
        for invalid in [
            vec![0, 0, 0],
            request([b"challenge", b"maced", b"p256", b""])
                .into_iter()
                .chain([0])
                .collect(),
            request([b"challenge", b"", b"p256", b""]),
            request([b"", b"maced", b"p256", b""]),
        ] {
            assert!(validate_request(&invalid).is_err());
        }

        let mut oversized = Vec::new();
        oversized.extend_from_slice(&((MAX_FIELD as u32) + 1).to_be_bytes());
        oversized.extend_from_slice(b"challenge");
        assert!(validate_request(&oversized).is_err());
    }

    #[test]
    fn request_and_reply_caps_match_the_bridge_wire_contract() {
        assert_eq!(MAX_REQUEST, 4 * (4 + MAX_FIELD));
        assert_eq!(MAX_REPLY, 4 + 3 * (4 + MAX_FIELD));
    }

    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    #[test]
    fn bridge_command_uses_only_the_fixed_entrypoint() {
        let command = bridge_command(
            Path::new("/data/misc/keystore/omk/data/rkp-v1-test"),
            Path::new("/data/misc/keystore/omk/data/rkp-v1-test/bridge.jar"),
            Path::new("/apex/com.android.rkpd/priv-app/RkpdApp/rkpdapp.apk"),
        );
        assert_eq!(command.get_program(), APP_PROCESS);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("/system/bin"),
                std::ffi::OsStr::new(MAIN_CLASS),
                std::ffi::OsStr::new("/data/misc/keystore/omk/data/rkp-v1-test"),
            ]
        );
        assert_eq!(command.get_envs().count(), 1);
    }
}
