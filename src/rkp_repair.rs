use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};

const TOOL: &str = "/vendor/bin/KmInstallKeybox";
const ARGS: [&str; 4] = ["Keybox_file", "Device_ID", "true", "rkp"];
const LIBRARIES: &str = "/vendor/lib64:/vendor/lib64/hw";
const MAX_OUTPUT: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);

fn command() -> Command {
    let mut command = Command::new(TOOL);
    command.args(ARGS).env("LD_LIBRARY_PATH", LIBRARIES);
    // Never resolve the placeholder Keybox_file against an app-controlled cwd.
    command.current_dir("/vendor/bin").stdin(Stdio::null());
    command
}

/// Explicitly confirmed vendor provisioning, never run at startup or by a test.
/// The vendor tool may persist changes even when it exits with an error.
pub fn run() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("RKP repair requires root");
    }
    let tool = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(TOOL)
        .context("device does not provide a usable /vendor/bin/KmInstallKeybox; unsupported")?;
    let metadata = tool.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        bail!("vendor RKP tool must be a root-owned executable, not writable by apps");
    }
    tool.try_lock()
        .context("another RKP repair is in progress")?;
    let (mut reader, writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    let stderr: OwnedFd = writer.try_clone()?.into();
    let stdout: OwnedFd = writer.into();
    let mut child = command()
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("cannot start vendor RKP tool")?;
    let mut output = Vec::new();
    let result = (|| -> Result<()> {
        let started = Instant::now();
        loop {
            drain_output(&mut reader, &mut output)?;
            if let Some(status) = child.try_wait()? {
                drain_output(&mut reader, &mut output)?;
                let text = String::from_utf8_lossy(&output);
                if !status.success() || !reports_completion(&text) {
                    bail!("vendor RKP tool did not confirm completion ({status}): {}. Persistent changes may already have occurred; do not retry blindly", text.trim());
                }
                return Ok(());
            }
            if started.elapsed() >= TIMEOUT {
                bail!("vendor RKP tool timed out; persistent changes may already have occurred; do not retry blindly");
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

fn drain_output(reader: &mut impl Read, output: &mut Vec<u8>) -> Result<()> {
    let mut buffer = [0u8; 2048];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(size) => {
                if output.len() + size > MAX_OUTPUT {
                    bail!("vendor RKP tool output limit exceeded; persistent changes may already have occurred");
                }
                output.extend_from_slice(&buffer[..size]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn reports_completion(output: &str) -> bool {
    let output = output.to_ascii_lowercase();
    output.contains("is done") || output.contains("provisioning complete")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, io::Cursor};

    #[test]
    fn only_vendor_tool_and_fixed_placeholders_are_used() {
        let command = command();
        assert_eq!(command.get_program(), TOOL);
        assert_eq!(command.get_args().collect::<Vec<_>>(), ARGS);
        assert_eq!(
            command.get_current_dir().unwrap(),
            std::path::Path::new("/vendor/bin")
        );
        assert_eq!(
            command.get_envs().collect::<Vec<_>>(),
            [(OsStr::new("LD_LIBRARY_PATH"), Some(OsStr::new(LIBRARIES)))]
        );
    }

    #[test]
    fn tool_output_is_not_assumed_to_be_success() {
        assert!(reports_completion("Provisioning Complete"));
        assert!(reports_completion("Install is done"));
        for output in ["", "usage: KmInstallKeybox", "error", "exit status 0"] {
            assert!(!reports_completion(output));
        }
    }

    #[test]
    fn collected_output_is_bounded() {
        let mut output = Vec::new();
        drain_output(&mut Cursor::new(b"is done"), &mut output).unwrap();
        assert_eq!(output, b"is done");
        assert!(drain_output(&mut Cursor::new(vec![0; MAX_OUTPUT + 1]), &mut output).is_err());
    }
}
