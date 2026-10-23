// Adapted from Duck-ToolBox, MIT; see template/THIRD_PARTY_LICENSES/Duck-ToolBox.txt.
use std::collections::HashSet;

use anyhow::{anyhow, Context, Result};
use kmr_wire::cbor::{ser::into_writer, value::Value};

use crate::local_rkp::cbor::{as_bytes, as_i128, as_text, encode, map_get};

use super::MAX_CHALLENGE_LEN;

pub(super) fn ensure_array_len(items: &[Value], expected: usize, label: &str) -> Result<()> {
    if items.len() == expected {
        return Ok(());
    }

    Err(anyhow!(
        "{label} must contain {expected} entries, got {}",
        items.len()
    ))
}

pub(super) fn ensure_unique_integer_keys(entries: &[(Value, Value)], label: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for (key, _) in entries {
        let key = as_i128(key, &format!("{label} key"))?;
        if !seen.insert(key) {
            return Err(anyhow!("{label} contains duplicate key `{key}`"));
        }
    }
    Ok(())
}

pub(super) fn ensure_unique_text_keys(entries: &[(Value, Value)], label: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for (key, _) in entries {
        let key = as_text(key, &format!("{label} key"))?;
        if !seen.insert(key.to_owned()) {
            return Err(anyhow!("{label} contains duplicate key `{key}`"));
        }
    }
    Ok(())
}

pub(super) fn ensure_allowed_integer_keys(
    entries: &[(Value, Value)],
    allowed: &[i128],
    label: &str,
) -> Result<()> {
    for (key, _) in entries {
        let key = as_i128(key, &format!("{label} key"))?;
        if !allowed.contains(&key) {
            return Err(anyhow!("{label} contains unsupported key `{key}`"));
        }
    }
    Ok(())
}

pub(super) fn required_int_text<'a>(
    entries: &'a [(Value, Value)],
    key: i128,
    label: &str,
    field: &str,
) -> Result<&'a str> {
    as_text(
        map_get(entries, key).ok_or_else(|| anyhow!("{label} is missing {field}"))?,
        &format!("{label} {field}"),
    )
}

pub(super) fn required_int_bytes<'a>(
    entries: &'a [(Value, Value)],
    key: i128,
    label: &str,
    field: &str,
) -> Result<&'a [u8]> {
    as_bytes(
        map_get(entries, key).ok_or_else(|| anyhow!("{label} is missing {field}"))?,
        &format!("{label} {field}"),
    )
}

pub(super) fn required_int(entries: &[(Value, Value)], key: i128, label: &str) -> Result<i128> {
    as_i128(
        map_get(entries, key).ok_or_else(|| anyhow!("{label} is missing `{key}`"))?,
        &format!("{label} `{key}`"),
    )
}

pub(super) fn required_bytes<'a>(
    entries: &'a [(Value, Value)],
    key: i128,
    label: &str,
    field: &str,
) -> Result<&'a [u8]> {
    as_bytes(
        map_get(entries, key).ok_or_else(|| anyhow!("{label} is missing `{key}`"))?,
        &format!("{label} {field}"),
    )
}

pub(super) fn validate_challenge(challenge: &[u8], label: &str) -> Result<()> {
    if challenge.len() <= MAX_CHALLENGE_LEN {
        return Ok(());
    }

    Err(anyhow!(
        "{label} must be at most {MAX_CHALLENGE_LEN} bytes, got {}",
        challenge.len()
    ))
}

/// DeviceInfo must already be in canonical CBOR order; re-encoding canonically must not
/// change the bytes.
pub(super) fn validate_canonical_order(value: &Value, label: &str) -> Result<()> {
    let mut original = Vec::new();
    into_writer(value, &mut original).context("encode CBOR without canonical reordering")?;
    if original == encode(value)? {
        return Ok(());
    }

    Err(anyhow!("{label} ordering is non-canonical"))
}
