use anyhow::{Context, Result};
use std::ffi::CString;

pub fn set_sockcreate_con(context: &str) -> Result<()> {
    let context = CString::new(context).context("Invalid context string")?;
    write_sockcreate_con(context.as_bytes_with_nul())
}

pub fn clear_sockcreate_con() -> Result<()> {
    write_sockcreate_con(&[0])
}

/// Set a thread-local socket label for one operation, restoring it on success
/// or error. This does not change the process domain or SELinux policy.
pub fn with_sockcreate_con<T>(context: &str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let previous = std::fs::read("/proc/thread-self/attr/sockcreate")
        .or_else(|_| {
            let tid = unsafe { libc::gettid() };
            std::fs::read(format!("/proc/{tid}/attr/sockcreate"))
        })
        .context("Failed to read previous socket creation context")?;
    set_sockcreate_con(context)?;
    let result = operation();
    let restored = write_sockcreate_con(if previous.is_empty() { &[0] } else { &previous });
    match (result, restored) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error).context("Failed to restore socket creation context"),
        (Err(error), Err(restore)) => {
            Err(error).context(format!("Socket context restore also failed: {restore:#}"))
        }
    }
}

fn write_sockcreate_con(bytes: &[u8]) -> Result<()> {
    if std::fs::write("/proc/thread-self/attr/sockcreate", bytes).is_err() {
        let tid = unsafe { libc::gettid() };
        std::fs::write(format!("/proc/{tid}/attr/sockcreate"), bytes)
            .context("Failed to write sockcreate context via /proc/[tid]/attr/sockcreate")?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;

    #[test]
    fn scoped_socket_context_is_restored_after_success_and_error() {
        let before = std::fs::read("/proc/thread-self/attr/sockcreate").unwrap();
        let label = "u:object_r:system_file:s0:c512,c768";
        let result =
            with_sockcreate_con(label, || Ok(std::fs::read("/proc/thread-self/attr/sockcreate")?))
                .unwrap();
        assert_eq!(String::from_utf8(result).unwrap().trim_end_matches(['\0', '\n']), label);
        assert_eq!(std::fs::read("/proc/thread-self/attr/sockcreate").unwrap(), before);
        let result: Result<()> = with_sockcreate_con(label, || anyhow::bail!("probe failure"));
        assert!(result.is_err());
        assert_eq!(std::fs::read("/proc/thread-self/attr/sockcreate").unwrap(), before);
    }
}
