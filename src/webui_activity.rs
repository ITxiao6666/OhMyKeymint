use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use serde::{Deserialize, Serialize};

use crate::{root_path, security_patch};

const ACTIVITY_LOG_PATH: &str = root_path!("data/webui_activity.json");
const MAX_ACTIVITY_FILE_BYTES: u64 = 16 * 1024;
const MAX_ACTIVITY_ENTRIES: usize = 30;
pub(crate) const MAX_ACTIVITY_DETAIL_BYTES: usize = 256;
const MAX_ACTIVITY_TIMESTAMP: u64 = 253_402_300_799;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ActivityAction {
    TargetsSaved,
    KeyboxChanged,
    WidevineInstalled,
    SecurityPatchSynced,
    SecurityPatchRestored,
    PifEnabled,
    PifDisabled,
}

impl ActivityAction {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "targets_saved" => Ok(Self::TargetsSaved),
            "keybox_changed" => Ok(Self::KeyboxChanged),
            "widevine_installed" => Ok(Self::WidevineInstalled),
            "security_patch_synced" => Ok(Self::SecurityPatchSynced),
            "security_patch_restored" => Ok(Self::SecurityPatchRestored),
            "pif_enabled" => Ok(Self::PifEnabled),
            "pif_disabled" => Ok(Self::PifDisabled),
            _ => bail!("unsupported WebUI activity action"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActivityEntry {
    action: ActivityAction,
    detail: String,
    timestamp: u64,
}

impl ActivityEntry {
    fn validate(&self) -> Result<()> {
        validate_detail(&self.detail)?;
        if self.timestamp == 0 || self.timestamp > MAX_ACTIVITY_TIMESTAMP {
            bail!("WebUI activity timestamp is outside the supported range");
        }
        Ok(())
    }
}

pub fn list_json() -> Result<String> {
    let path = Path::new(ACTIVITY_LOG_PATH);
    let _lock = security_patch::acquire_data_operation_lock(path)?;
    let entries = load_entries(path)?;
    serde_json::to_string(&entries).context("failed to serialize the WebUI activity log")
}

pub fn record(action: &str, detail: &str) -> Result<()> {
    let action = ActivityAction::parse(action)?;
    validate_detail(detail)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is earlier than the Unix epoch")?
        .as_secs();
    if timestamp > MAX_ACTIVITY_TIMESTAMP {
        bail!("system clock is outside the supported range");
    }

    let path = Path::new(ACTIVITY_LOG_PATH);
    let _lock = security_patch::acquire_data_operation_lock(path)?;
    let mut entries = load_entries(path)?;
    entries.push(ActivityEntry {
        action,
        detail: detail.to_string(),
        timestamp,
    });
    if entries.len() > MAX_ACTIVITY_ENTRIES {
        entries.drain(..entries.len() - MAX_ACTIVITY_ENTRIES);
    }
    persist_entries(path, &entries)
}

pub fn clear() -> Result<()> {
    let path = Path::new(ACTIVITY_LOG_PATH);
    let _lock = security_patch::acquire_data_operation_lock(path)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to clear the WebUI activity log"),
    }
}

fn validate_detail(detail: &str) -> Result<()> {
    if detail.len() > MAX_ACTIVITY_DETAIL_BYTES {
        bail!("WebUI activity detail exceeds the byte limit");
    }
    if detail.chars().any(char::is_control) {
        bail!("WebUI activity detail contains control characters");
    }
    Ok(())
}

fn load_entries(path: &Path) -> Result<Vec<ActivityEntry>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("failed to inspect the WebUI activity log"),
    };
    if !metadata.file_type().is_file() {
        bail!("WebUI activity log path is not a regular file");
    }
    if metadata.len() > MAX_ACTIVITY_FILE_BYTES {
        bail!("WebUI activity log exceeds the file-size limit");
    }

    let contents = fs::read(path).context("failed to read the WebUI activity log")?;
    let entries: Vec<ActivityEntry> =
        serde_json::from_slice(&contents).context("invalid WebUI activity log")?;
    if entries.len() > MAX_ACTIVITY_ENTRIES {
        bail!("WebUI activity log contains too many entries");
    }
    for entry in &entries {
        entry.validate()?;
    }
    Ok(entries)
}

fn persist_entries(path: &Path, entries: &[ActivityEntry]) -> Result<()> {
    let contents =
        serde_json::to_vec(entries).context("failed to encode the WebUI activity log")?;
    if contents.len() as u64 > MAX_ACTIVITY_FILE_BYTES {
        bail!("encoded WebUI activity log exceeds the file-size limit");
    }
    let (uid, gid) = if path == Path::new(ACTIVITY_LOG_PATH) {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    };
    atomic_replace_preserving_metadata(path, &contents, 0o600, uid, gid).with_context(|| {
        format!(
            "failed to save the WebUI activity log at {}",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_actions_have_stable_wire_names() {
        for (name, action) in [
            ("targets_saved", ActivityAction::TargetsSaved),
            ("keybox_changed", ActivityAction::KeyboxChanged),
            ("widevine_installed", ActivityAction::WidevineInstalled),
            ("security_patch_synced", ActivityAction::SecurityPatchSynced),
            (
                "security_patch_restored",
                ActivityAction::SecurityPatchRestored,
            ),
            ("pif_enabled", ActivityAction::PifEnabled),
            ("pif_disabled", ActivityAction::PifDisabled),
        ] {
            assert_eq!(ActivityAction::parse(name).unwrap(), action);
            assert_eq!(
                serde_json::to_string(&action).unwrap(),
                format!("\"{name}\"")
            );
        }
        assert!(ActivityAction::parse("unknown").is_err());
    }

    #[test]
    fn activity_entry_rejects_unsafe_details_and_timestamps() {
        assert!(validate_detail("").is_ok());
        assert!(validate_detail("2026-08-01").is_ok());
        assert!(validate_detail("line\nbreak").is_err());
        assert!(validate_detail(&"a".repeat(MAX_ACTIVITY_DETAIL_BYTES + 1)).is_err());

        let mut entry = ActivityEntry {
            action: ActivityAction::TargetsSaved,
            detail: "2".to_string(),
            timestamp: 1,
        };
        assert!(entry.validate().is_ok());
        entry.timestamp = 0;
        assert!(entry.validate().is_err());
    }

    #[test]
    fn activity_json_has_the_expected_shape() {
        let entry = ActivityEntry {
            action: ActivityAction::SecurityPatchSynced,
            detail: "2026-08-01".to_string(),
            timestamp: 1_788_537_600,
        };
        let json = serde_json::to_string(&vec![entry.clone()]).unwrap();
        assert_eq!(
            json,
            r#"[{"action":"security_patch_synced","detail":"2026-08-01","timestamp":1788537600}]"#
        );
        assert_eq!(
            serde_json::from_str::<Vec<ActivityEntry>>(&json).unwrap(),
            vec![entry]
        );
    }
}
