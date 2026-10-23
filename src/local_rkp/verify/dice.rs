// Adapted from Duck-ToolBox, MIT; see template/THIRD_PARTY_LICENSES/Duck-ToolBox.txt.
use std::collections::HashSet;

use anyhow::{anyhow, Result};
use kmr_wire::cbor::value::Value;

use crate::local_rkp::{
    cbor::{as_array, as_bytes, as_map, as_text, decode, map_get},
    cose::{build_sig_structure, CWT_ISSUER, CWT_SUBJECT, DICE_KEY_USAGE, DICE_SUBJECT_PUB_KEY},
};

use super::{
    checks::{ensure_unique_integer_keys, required_int_bytes, required_int_text},
    cose_key::{
        parse_cose_public_key, parse_cose_sign1, verify_signed_data_signature, CosePublicKeyInfo,
    },
    ANDROID_DICE_PROFILE_VERSIONS, DEFAULT_DICE_PROFILE_VERSION, DICE_PROFILE_NAME,
};

/// Open DICE payload fields that must be non-empty byte strings when present.
const OPTIONAL_DICE_BYTE_FIELDS: [(i128, &str); 5] = [
    (-4_670_545, "code hash"),
    (-4_670_546, "code descriptor"),
    (-4_670_547, "configuration hash"),
    (-4_670_549, "authority hash"),
    (-4_670_550, "authority descriptor"),
];
const DICE_CONFIGURATION_DESCRIPTOR: i128 = -4_670_548;
const DICE_SECURITY_VERSION: i128 = -70_005;
/// `mode` is checked separately: the Android Profile for DICE also permits a CBOR integer.
const DICE_MODE: i128 = -4_670_551;

pub(super) fn extract_uds_key(dice_chain: &[Value]) -> Result<CosePublicKeyInfo> {
    let uds_key = dice_chain
        .first()
        .ok_or_else(|| anyhow!("DICE chain is empty"))?;
    parse_cose_public_key(as_map(uds_key, "UDS COSE key")?, "UDS COSE key")
}

pub(super) fn verify_dice_chain_and_extract_leaf_key(
    dice_chain: &[Value],
) -> Result<CosePublicKeyInfo> {
    let mut signer = extract_uds_key(dice_chain)?;
    let mut previous_profile_index = None;

    for (index, item) in dice_chain.iter().enumerate().skip(1) {
        let label = format!("DICE chain entry {index}");
        let entry = parse_cose_sign1(as_array(item, "DICE chain entry")?, &label, Some(&signer))?;
        let signature_input = build_sig_structure("Signature1", entry.protected, entry.payload)?;
        if !verify_signed_data_signature(&signer, entry.signature, &signature_input)? {
            return Err(anyhow!("{label} signature is invalid"));
        }

        let (subject_key, profile_index) =
            parse_dice_entry_payload(&decode(entry.payload)?, &label)?;
        if let Some(previous) = previous_profile_index {
            if profile_index < previous {
                return Err(anyhow!(
                    "{label} profile name `{}` must not precede previous profile `{}`",
                    ANDROID_DICE_PROFILE_VERSIONS[profile_index],
                    ANDROID_DICE_PROFILE_VERSIONS[previous]
                ));
            }
        }
        previous_profile_index = Some(profile_index);
        signer = subject_key;
    }

    Ok(signer)
}

pub(super) fn validate_uds_certs(value: &Value) -> Result<()> {
    let entries = as_map(value, "UDS certs")?;
    let mut seen = HashSet::new();

    for (signer_name, chain) in entries {
        let signer_name = as_text(signer_name, "UDS cert signer")?;
        if signer_name.is_empty() {
            return Err(anyhow!("UDS cert signer name must not be empty"));
        }
        if !seen.insert(signer_name.to_owned()) {
            return Err(anyhow!("duplicate UDS cert signer `{signer_name}`"));
        }

        let certs = as_array(chain, &format!("UDS cert chain `{signer_name}`"))?;
        if certs.is_empty() {
            return Err(anyhow!(
                "UDS cert chain `{signer_name}` must contain at least one certificate"
            ));
        }

        for (index, cert) in certs.iter().enumerate() {
            let cert = as_bytes(cert, &format!("UDS cert `{signer_name}` entry {index}"))?;
            if cert.is_empty() {
                return Err(anyhow!(
                    "UDS cert `{signer_name}` entry {index} must not be empty"
                ));
            }
        }
    }

    Ok(())
}

fn parse_dice_entry_payload(value: &Value, label: &str) -> Result<(CosePublicKeyInfo, usize)> {
    let payload_label = format!("{label} payload");
    let payload_entries = as_map(value, &payload_label)?;
    ensure_unique_integer_keys(payload_entries, &payload_label)?;

    if required_int_text(payload_entries, CWT_ISSUER, label, "issuer")?.is_empty() {
        return Err(anyhow!("{label} issuer must not be empty"));
    }
    if required_int_text(payload_entries, CWT_SUBJECT, label, "subject")?.is_empty() {
        return Err(anyhow!("{label} subject must not be empty"));
    }

    let profile_name = map_get(payload_entries, DICE_PROFILE_NAME)
        .map(|value| as_text(value, &format!("{label} profile name")))
        .transpose()?;
    let effective_profile = effective_profile_name(profile_name);
    let profile_index = ANDROID_DICE_PROFILE_VERSIONS
        .iter()
        .position(|profile| *profile == effective_profile)
        .ok_or_else(|| {
            anyhow!(
                "{label} profile name must be one of {ANDROID_DICE_PROFILE_VERSIONS:?}, got `{effective_profile}`"
            )
        })?;

    if required_int_bytes(payload_entries, DICE_KEY_USAGE, label, "key usage")?.is_empty() {
        return Err(anyhow!("{label} key usage must not be empty"));
    }

    for (field, field_label) in OPTIONAL_DICE_BYTE_FIELDS {
        if let Some(value) = map_get(payload_entries, field) {
            if as_bytes(value, &format!("{label} {field_label}"))?.is_empty() {
                return Err(anyhow!(
                    "{label} {field_label} must not be empty when present"
                ));
            }
        }
    }

    validate_dice_mode(payload_entries, label, profile_name)?;

    if let Some(configuration) = map_get(payload_entries, DICE_CONFIGURATION_DESCRIPTOR) {
        let descriptor_label = format!("{label} configuration descriptor");
        let configuration = decode(as_bytes(configuration, &descriptor_label)?)?;
        let entries = as_map(&configuration, &descriptor_label)?;
        if effective_profile == "android.16" {
            ensure_unique_integer_keys(entries, &descriptor_label)?;
            let security_version = map_get(entries, DICE_SECURITY_VERSION)
                .ok_or_else(|| anyhow!("{descriptor_label} is missing security version"))?;
            if !matches!(security_version, Value::Integer(value) if i128::from(*value) >= 0) {
                return Err(anyhow!(
                    "{descriptor_label} security version must be a CBOR unsigned integer"
                ));
            }
        }
    }

    let subject_key_bytes = required_int_bytes(
        payload_entries,
        DICE_SUBJECT_PUB_KEY,
        label,
        "subject public key",
    )?;
    let subject_key = decode(subject_key_bytes)?;
    parse_cose_public_key(
        as_map(&subject_key, "DICE chain subject COSE key")?,
        "DICE chain subject COSE key",
    )
    .map(|subject_key| (subject_key, profile_index))
}

/// Validates the optional DICE `mode` field.
///
/// The Open Profile for DICE requires a one-byte CBOR byte string. The Android Profile for DICE
/// (`android.14`, see the profile's "Mode" note) additionally permits the mode to be encoded as a
/// CBOR integer, which real bootloaders do emit. AOSP's `hwtrust` applies that relaxation to the
/// `android.14` profile only and treats a certificate without `profileName` as `android.14`, so the
/// same rule is applied here.
fn validate_dice_mode(
    entries: &[(Value, Value)],
    label: &str,
    profile_name: Option<&str>,
) -> Result<()> {
    let Some(mode) = map_get(entries, DICE_MODE) else {
        return Ok(());
    };
    let mode_label = format!("{label} mode");

    match mode {
        Value::Bytes(bytes) => {
            if bytes.len() != 1 {
                return Err(anyhow!(
                    "{mode_label} must be a single byte, got {} bytes",
                    bytes.len()
                ));
            }
            Ok(())
        }
        Value::Integer(_) if allows_integer_mode(profile_name) => Ok(()),
        Value::Integer(_) => Err(anyhow!(
            "{mode_label} is a CBOR integer, which profile `{}` does not allow; only the Open DICE byte string form is accepted",
            effective_profile_name(profile_name)
        )),
        _ => Err(anyhow!(
            "{mode_label} is neither CBOR bytes nor a CBOR integer"
        )),
    }
}

/// The Android Profile for DICE permits an integer `mode` in `android.14` only.
fn allows_integer_mode(profile_name: Option<&str>) -> bool {
    effective_profile_name(profile_name) == "android.14"
}

/// Profile name actually in force, applying the documented `android.14` default.
fn effective_profile_name(profile_name: Option<&str>) -> &str {
    profile_name.unwrap_or(DEFAULT_DICE_PROFILE_VERSION)
}
