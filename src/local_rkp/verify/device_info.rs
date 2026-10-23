// Adapted from Duck-ToolBox, MIT; see template/THIRD_PARTY_LICENSES/Duck-ToolBox.txt.
use anyhow::{anyhow, Result};
use kmr_wire::cbor::value::Value;

use crate::local_rkp::cbor::{as_bytes, as_i128, as_map, as_text, map_get_text};

use super::checks::{ensure_unique_text_keys, validate_canonical_order};

const ALLOWED_KEYS: &[&str] = &[
    "brand",
    "manufacturer",
    "product",
    "model",
    "device",
    "vb_state",
    "bootloader_state",
    "vbmeta_digest",
    "os_version",
    "system_patch_level",
    "boot_patch_level",
    "vendor_patch_level",
    "security_level",
    "fused",
];

/// Validates the CSR DeviceInfo map and returns its brand.
pub(super) fn validate_device_info(value: &Value) -> Result<String> {
    validate_canonical_order(value, "DeviceInfo")?;

    let entries = as_map(value, "DeviceInfo")?;
    ensure_unique_text_keys(entries, "DeviceInfo")?;

    for (key, _) in entries {
        let key = as_text(key, "DeviceInfo key")?;
        if !ALLOWED_KEYS.contains(&key) {
            return Err(anyhow!("DeviceInfo contains unrecognized key `{key}`"));
        }
    }

    let brand = required_text_field(entries, "brand")?.to_owned();
    for field in ["brand", "manufacturer", "product", "model", "device"] {
        if required_text_field(entries, field)?.is_empty() {
            return Err(anyhow!("DeviceInfo field `{field}` must not be empty"));
        }
    }

    let security_level = required_text_field(entries, "security_level")?;
    validate_choice(
        "vb_state",
        required_text_field(entries, "vb_state")?,
        &["green", "yellow", "orange"],
    )?;
    validate_choice(
        "bootloader_state",
        required_text_field(entries, "bootloader_state")?,
        &["locked", "unlocked"],
    )?;
    validate_choice("security_level", security_level, &["tee", "strongbox"])?;

    if let Some(vbmeta_digest) = map_get_text(entries, "vbmeta_digest") {
        let vbmeta_digest = as_bytes(vbmeta_digest, "vbmeta_digest")?;
        if vbmeta_digest.len() != 32 {
            return Err(anyhow!(
                "DeviceInfo field `vbmeta_digest` must be 32 bytes, got {}",
                vbmeta_digest.len()
            ));
        }
    }

    let os_version = map_get_text(entries, "os_version")
        .map(|value| as_text(value, "os_version"))
        .transpose()?;
    match os_version {
        None if security_level == "tee" => {
            return Err(anyhow!("DeviceInfo field `os_version` is required for TEE"));
        }
        Some("") => return Err(anyhow!("DeviceInfo field `os_version` must not be empty")),
        _ => {}
    }

    for field in [
        "system_patch_level",
        "boot_patch_level",
        "vendor_patch_level",
    ] {
        if !crate::local_rkp::is_valid_patch_level(required_uint_field(entries, field)?) {
            return Err(anyhow!(
                "DeviceInfo field `{field}` must be a valid patch level in YYYYMM or YYYYMMDD form"
            ));
        }
    }

    let fused = required_uint_field(entries, "fused")?;
    if fused > 1 {
        return Err(anyhow!(
            "DeviceInfo field `fused` must be 0 or 1, got {fused}"
        ));
    }

    let expected_len = if security_level == "tee" {
        matches!(entries.len(), 13 | 14)
    } else {
        matches!(entries.len(), 12..=14)
    };
    if !expected_len {
        return Err(anyhow!(
            "DeviceInfo has an unexpected field count of {} for security_level `{security_level}`",
            entries.len()
        ));
    }

    Ok(brand)
}

fn required_text_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    as_text(
        map_get_text(entries, key).ok_or_else(|| anyhow!("DeviceInfo field `{key}` is missing"))?,
        key,
    )
}

fn required_uint_field(entries: &[(Value, Value)], key: &str) -> Result<u32> {
    let value = as_i128(
        map_get_text(entries, key).ok_or_else(|| anyhow!("DeviceInfo field `{key}` is missing"))?,
        key,
    )?;
    if value < 0 {
        return Err(anyhow!(
            "DeviceInfo field `{key}` must be an unsigned integer"
        ));
    }

    u32::try_from(value).map_err(|_| anyhow!("DeviceInfo field `{key}` is out of range"))
}

fn validate_choice(field: &str, value: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&value) {
        return Ok(());
    }

    Err(anyhow!(
        "DeviceInfo field `{field}` must be one of {}, got `{value}`",
        allowed.join(", ")
    ))
}
