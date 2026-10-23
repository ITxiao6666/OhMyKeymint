// Adapted from Duck-ToolBox, MIT; see template/THIRD_PARTY_LICENSES/Duck-ToolBox.txt.
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kmr_wire::cbor::value::Value;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};

use crate::local_rkp::{
    cbor::{as_array, as_bytes, as_i128, as_map, decode, map_get},
    cose::{ALG_EDDSA, ALG_ES256},
};

use super::{
    checks::{
        ensure_allowed_integer_keys, ensure_unique_integer_keys, required_bytes, required_int,
    },
    ALG_ES384, ED25519_CURVE, P256_COORD_LEN, P256_CURVE, P384_COORD_LEN, P384_CURVE,
};

pub(super) struct CosePublicKeyInfo {
    pub(super) public_key_bytes: Vec<u8>,
    pub(super) algorithm: i128,
    verifier: CoseVerifier,
}

enum CoseVerifier {
    Ed25519(VerifyingKey),
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
}

pub(super) fn parse_cose_public_key(
    entries: &[(Value, Value)],
    label: &str,
) -> Result<CosePublicKeyInfo> {
    ensure_unique_integer_keys(entries, label)?;
    let key_type = required_int(entries, 1, label)?;
    let algorithm = required_int(entries, 3, label)?;
    let curve = required_int(entries, -1, label)?;
    validate_key_metadata(entries, label)?;

    match (key_type, algorithm, curve) {
        (1, ALG_EDDSA, ED25519_CURVE) => {
            ensure_allowed_integer_keys(entries, &[1, 2, 3, 4, 5, -1, -2], label)?;
            let public_key = required_bytes(entries, -2, label, "public key")?.to_vec();
            let verifying_key = VerifyingKey::from_bytes(
                &<[u8; 32]>::try_from(public_key.as_slice())
                    .map_err(|_| anyhow!("{label} public key must be 32 bytes"))?,
            )
            .context("build Ed25519 verifying key")?;
            if verifying_key.is_weak() {
                return Err(anyhow!("{label} Ed25519 public key has small order"));
            }

            Ok(CosePublicKeyInfo {
                public_key_bytes: public_key,
                algorithm: ALG_EDDSA,
                verifier: CoseVerifier::Ed25519(verifying_key),
            })
        }
        (2, ALG_ES256, P256_CURVE) => {
            let (sec1, public_key) = ec2_point(entries, label, P256_COORD_LEN, "P-256")?;
            let verifying_key =
                P256VerifyingKey::from_sec1_bytes(&sec1).context("build ES256 verifying key")?;

            Ok(CosePublicKeyInfo {
                public_key_bytes: public_key,
                algorithm: ALG_ES256,
                verifier: CoseVerifier::P256(verifying_key),
            })
        }
        (2, ALG_ES384, P384_CURVE) => {
            let (sec1, public_key) = ec2_point(entries, label, P384_COORD_LEN, "P-384")?;
            let verifying_key =
                P384VerifyingKey::from_sec1_bytes(&sec1).context("build ES384 verifying key")?;

            Ok(CosePublicKeyInfo {
                public_key_bytes: public_key,
                algorithm: ALG_ES384,
                verifier: CoseVerifier::P384(verifying_key),
            })
        }
        _ => Err(anyhow!(
            "unsupported {label} parameters: kty={key_type}, alg={algorithm}, crv={curve}"
        )),
    }
}

/// Returns the uncompressed SEC1 point and the raw `x || y` bytes of an EC2 COSE key.
fn ec2_point(
    entries: &[(Value, Value)],
    label: &str,
    coord_len: usize,
    curve_name: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure_allowed_integer_keys(entries, &[1, 2, 3, 4, 5, -1, -2, -3], label)?;
    let x = required_bytes(entries, -2, label, "x coordinate")?;
    if x.len() != coord_len {
        return Err(anyhow!(
            "{label} {curve_name} x coordinate must be {coord_len} bytes"
        ));
    }
    match map_get(entries, -3).ok_or_else(|| anyhow!("{label} is missing y coordinate"))? {
        Value::Bytes(y) => {
            if y.len() != coord_len {
                return Err(anyhow!(
                    "{label} {curve_name} y coordinate must be {coord_len} bytes"
                ));
            }
            let raw = [x, y].concat();
            Ok(([&[0x04], raw.as_slice()].concat(), raw))
        }
        Value::Bool(odd) => {
            let compressed = [&[if *odd { 0x03 } else { 0x02 }], x].concat();
            let full = match coord_len {
                P256_COORD_LEN => P256VerifyingKey::from_sec1_bytes(&compressed)
                    .context("invalid compressed P-256 public key")?
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
                P384_COORD_LEN => P384VerifyingKey::from_sec1_bytes(&compressed)
                    .context("invalid compressed P-384 public key")?
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
                _ => return Err(anyhow!("unsupported EC2 coordinate width")),
            };
            let raw = full[1..].to_vec();
            Ok((full, raw))
        }
        _ => Err(anyhow!(
            "{label} y coordinate must be CBOR bytes or boolean"
        )),
    }
}

fn validate_key_metadata(entries: &[(Value, Value)], label: &str) -> Result<()> {
    for key in [2, 5] {
        if let Some(value) = map_get(entries, key) {
            as_bytes(value, label)?;
        }
    }
    if let Some(operations) = map_get(entries, 4) {
        let operations = as_array(operations, "COSE key operations")?;
        let mut seen = std::collections::HashSet::new();
        for operation in operations {
            let operation = as_i128(operation, "COSE key operation")?;
            if !matches!(operation, 1 | 2) || !seen.insert(operation) {
                return Err(anyhow!(
                    "{label} has invalid or duplicate signing key operation"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn verify_signed_data_signature(
    key: &CosePublicKeyInfo,
    signature_bytes: &[u8],
    signature_input: &[u8],
) -> Result<bool> {
    Ok(match &key.verifier {
        CoseVerifier::Ed25519(verifying_key) => {
            let signature =
                Signature::from_slice(signature_bytes).context("parse Ed25519 signature")?;
            verifying_key
                .verify_strict(signature_input, &signature)
                .is_ok()
        }
        CoseVerifier::P256(verifying_key) => {
            let signature =
                P256Signature::from_slice(signature_bytes).context("parse ES256 signature")?;
            verifying_key.verify(signature_input, &signature).is_ok()
        }
        CoseVerifier::P384(verifying_key) => {
            let signature =
                P384Signature::from_slice(signature_bytes).context("parse ES384 signature")?;
            verifying_key.verify(signature_input, &signature).is_ok()
        }
    })
}

pub(super) struct ParsedCoseSign1<'a> {
    pub(super) protected: &'a [u8],
    pub(super) payload: &'a [u8],
    pub(super) signature: &'a [u8],
}

pub(super) fn parse_cose_sign1<'a>(
    sign1: &'a [Value],
    label: &str,
    signer: Option<&CosePublicKeyInfo>,
) -> Result<ParsedCoseSign1<'a>> {
    if sign1.len() != 4 {
        return Err(anyhow!("{label} must contain 4 array entries"));
    }

    let protected = as_bytes(&sign1[0], "COSE_Sign1 protected headers")?;
    let unprotected = as_map(&sign1[1], &format!("{label} unprotected headers"))?;
    validate_header_metadata(unprotected, label, false)?;
    let protected_algorithm = parse_protected_algorithm(protected, label)?;
    let protected_value = decode(protected)?;
    let protected_headers = as_map(&protected_value, "protected headers")?;
    if unprotected
        .iter()
        .any(|(key, _)| protected_headers.iter().any(|(other, _)| key == other))
    {
        return Err(anyhow!(
            "{label} repeats a header across protected and unprotected maps"
        ));
    }
    if let Some(signer) = signer {
        if signer.algorithm != protected_algorithm {
            return Err(anyhow!(
            "{label} protected algorithm {protected_algorithm} does not match signer algorithm {}",
            signer.algorithm
        ));
        }
    }
    let payload = as_bytes(&sign1[2], "COSE_Sign1 payload")?;
    let signature = as_bytes(&sign1[3], "COSE_Sign1 signature")?;
    if signature.is_empty() {
        return Err(anyhow!("{label} signature must not be empty"));
    }

    Ok(ParsedCoseSign1 {
        protected,
        payload,
        signature,
    })
}

fn parse_protected_algorithm(protected: &[u8], label: &str) -> Result<i128> {
    let protected_value = decode(protected)?;
    let headers_label = format!("{label} protected headers");
    let headers = as_map(&protected_value, &headers_label)?;
    validate_header_metadata(headers, &headers_label, true)?;

    let algorithm = as_i128(
        map_get(headers, 1).ok_or_else(|| anyhow!("{label} protected headers are missing `1`"))?,
        &format!("{label} algorithm"),
    )?;
    if matches!(algorithm, ALG_EDDSA | ALG_ES256 | ALG_ES384) {
        return Ok(algorithm);
    }

    Err(anyhow!(
        "{label} uses unsupported protected algorithm {algorithm}"
    ))
}

fn validate_header_metadata(
    headers: &[(Value, Value)],
    label: &str,
    protected: bool,
) -> Result<()> {
    ensure_unique_integer_keys(headers, label)?;
    let allowed: &[i128] = if protected { &[1, 2, 3, 4] } else { &[3, 4] };
    ensure_allowed_integer_keys(headers, allowed, label)?;
    if let Some(kid) = map_get(headers, 4) {
        as_bytes(kid, "COSE key identifier")?;
    }
    if let Some(content_type) = map_get(headers, 3) {
        if !matches!(content_type, Value::Text(_) | Value::Integer(_)) {
            return Err(anyhow!("{label} content type must be text or integer"));
        }
    }
    if let Some(critical) = map_get(headers, 2) {
        let critical = as_array(critical, "COSE critical headers")?;
        if critical.is_empty()
            || critical.len() != 1
            || as_i128(&critical[0], "critical label")? != 1
            || map_get(headers, 1).is_none()
        {
            return Err(anyhow!("{label} contains unsupported critical headers"));
        }
    }
    Ok(())
}
