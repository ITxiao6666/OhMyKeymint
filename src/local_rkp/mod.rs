//! Explicit, device-backed RKP issuance. No startup action, automatic import, or retries.
// Protocols adapted from Duck-ToolBox 7567a8e084d31b1a6da3541bf0e8e2692ee45e0a (MIT).
use std::{
    fs::OpenOptions,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine as _,
};
use kmr_wire::cbor::value::Value;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use zeroize::Zeroizing;

use self::cbor::{as_array, as_bytes, as_i128, as_map, bytes, decode, encode, int, map_get};

pub mod cbor;
pub mod cose;
mod native;
mod v1;
pub mod verify;

const SERVER: &str = "https://remoteprovisioning.googleapis.com/v1";
const MAX_HTTP_BODY: usize = 256 * 1024;
pub(super) const BUFFER_SIZE: usize = 0xa000;
const MAX_CHAIN: usize = 0x4000;
const SUBMISSION_UNKNOWN: &str =
    "RKP submission result is uncertain. Do not retry blindly; no Keybox was imported";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Auto,
    V1,
    V2,
    V1Native,
}

impl Protocol {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "v1" => Ok(Self::V1),
            "v2" => Ok(Self::V2),
            "v1-native" => Ok(Self::V1Native),
            _ => bail!("RKP protocol must be auto, v1, v2 or v1-native"),
        }
    }
}

struct Eek {
    challenge: Vec<u8>,
    p256: Vec<u8>,
    x25519: Vec<u8>,
}

/// Called only after the CLI's explicit confirmation. One submission at most per call.
pub fn issue(protocol: Protocol) -> Result<String> {
    if !cfg!(all(target_os = "android", target_arch = "aarch64")) {
        bail!("Local RKP issuance requires Android arm64");
    }
    if unsafe { libc::geteuid() } != 0 {
        bail!("Local RKP issuance requires root");
    }
    let data = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(crate::root_path!("data"))
        .context("open OMK data directory")?;
    let metadata = data.metadata()?;
    if ![0, kmr_common::consts::KEYSTORE_UID].contains(&metadata.uid())
        || metadata.mode() & 0o007 != 0
    {
        bail!("OMK data directory is not private");
    }
    if unsafe { libc::flock(data.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("Another OMK data operation is in progress");
    }
    // Check storage before spending a server challenge. This creates only the approved
    // private result directory, never a seed, identity, device configuration, or key.
    crate::local_rkp_artifacts::prepare()?;
    let fingerprint =
        rsproperties::get::<String>("ro.build.fingerprint").context("read build fingerprint")?;
    if fingerprint.is_empty()
        || fingerprint.len() > 1024
        || fingerprint.chars().any(char::is_control)
    {
        bail!("device build fingerprint is missing or invalid");
    }
    let methods = candidate_methods(protocol)?;
    let random = SystemRandom::new();
    let private = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
        .map_err(|_| anyhow!("cannot generate local P-256 key"))?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private.as_ref(), &random)
        .map_err(|_| anyhow!("cannot load generated P-256 key"))?;
    let point = key.public_key().as_ref();
    let public = Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), bytes(&point[1..33])),
        (int(-3), bytes(&point[33..])),
    ]);
    let eek = fetch_eek(&fingerprint)?;
    let mut last_error = None;
    let mut csr = None;
    // Fallback is allowed only for LOCAL CSR construction failures. Once submitted to
    // Google, every failure is final, including a parse/validation/storage failure.
    for method in methods {
        match build_csr(method, &eek, &public) {
            Ok(value) => {
                csr = Some(value);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let csr = csr.ok_or_else(|| last_error.unwrap_or_else(|| anyhow!("no supported RKP path")))?;
    let signed = submit(&csr, &eek.challenge)?;
    let chain = order_chain(&signed, point).context(SUBMISSION_UNKNOWN)?;
    let xml = keybox_xml(private.as_ref(), &chain);
    validate_issued_xml(xml.as_bytes()).context(SUBMISSION_UNKNOWN)?;
    let id = crate::local_rkp_artifacts::store_issued_keybox(xml.as_bytes()).context(
        "Certificates returned, but saving the local result failed; do not blindly issue again",
    )?;
    crate::local_rkp_artifacts::summary_json(&id)
}

fn candidate_methods(protocol: Protocol) -> Result<Vec<Protocol>> {
    let aidl = crate::rkp_v1_bridge::available();
    let native = native::available();
    let candidates = match protocol {
        Protocol::Auto => [
            (Protocol::V2, native),
            (Protocol::V1, aidl),
            (Protocol::V1Native, native),
        ]
        .into_iter()
        .filter_map(|(method, available)| available.then_some(method))
        .collect(),
        Protocol::V1 if aidl => vec![Protocol::V1],
        Protocol::V2 | Protocol::V1Native if native => vec![protocol],
        _ => Vec::new(),
    };
    if candidates.is_empty() {
        bail!("No compatible RKP interface is available for the selected protocol");
    }
    Ok(candidates)
}

fn build_csr(protocol: Protocol, eek: &Eek, public: &Value) -> Result<Vec<u8>> {
    match protocol {
        Protocol::V1 => v1::aidl(eek, public),
        Protocol::V1Native => v1::native(eek, public),
        Protocol::V2 => {
            let payload = encode(&Value::Map(vec![
                (int(4), bytes(eek.challenge.as_slice())),
                (int(57), bytes(encode(&Value::Array(vec![public.clone()]))?)),
            ]))?;
            let mut request = 0x3122u32.to_le_bytes().to_vec();
            request.extend(payload);
            let reply = native::exchange(&request)?;
            let value = decode(&reply)?;
            let csr = if matches!(value, Value::Array(_)) {
                reply
            } else {
                let fields = as_map(&value, "V2 reply")?;
                if fields.len() != 1 {
                    bail!("invalid V2 reply fields");
                }
                as_bytes(required(fields, 61)?, "V2 CSR")?.to_vec()
            };
            validate_v2(&csr, &eek.challenge, public)?;
            Ok(csr)
        }
        Protocol::Auto => bail!("a concrete RKP method is required"),
    }
}

fn validate_v2(csr: &[u8], challenge: &[u8], public: &Value) -> Result<()> {
    // Never print this report: it includes device/DICE metadata.
    let report = verify::verify_csr(csr)
        .map_err(|_| anyhow!("V2 CSR signature or structure validation failed"))?;
    if !report.signature_valid || report.cert_type != "keymint" || report.keys_to_sign != 1 {
        bail!("V2 CSR is not a signed single-key KeyMint request");
    }
    let request = decode(csr)?;
    let fields = as_array(&request, "V2 CSR")?;
    let signed = as_array(&fields[3], "V2 SignedData")?;
    let payload = decode(as_bytes(&signed[2], "V2 SignedData payload")?)?;
    let parts = as_array(&payload, "V2 signed payload")?;
    if as_bytes(&parts[0], "V2 challenge")? != challenge {
        bail!("V2 challenge binding mismatch");
    }
    let contents = decode(as_bytes(&parts[1], "V2 CSR payload")?)?;
    let contents = as_array(&contents, "V2 CSR payload")?;
    let keys = as_array(&contents[3], "V2 keys")?;
    if encode(&keys[0])? != encode(public)? {
        bail!("V2 public key binding mismatch");
    }
    Ok(())
}

fn post(route: &str, body: &[u8], submission: bool) -> Result<Vec<u8>> {
    // Fresh agent per POST: no pooled stale connection and no automatic redirect or
    // alternate endpoint. A POST is never retried by this feature.
    let client: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut response = client
        .post(format!("{SERVER}:{route}"))
        .header("Content-Type", "application/cbor")
        .header("Accept", "application/cbor")
        .header("Accept-Encoding", "identity")
        .send(body)
        .map_err(|_| {
            anyhow!(if submission {
                SUBMISSION_UNKNOWN
            } else {
                "RKP challenge transport failed"
            })
        })?;
    if !response.status().is_success() {
        // Never echo the server body, headers or URL (which contains the challenge).
        bail!(
            "RKP server returned HTTP {}; no Keybox was imported",
            response.status().as_u16()
        );
    }
    let result = response
        .body_mut()
        .with_config()
        .limit((MAX_HTTP_BODY + 1) as u64)
        .read_to_vec()
        .map_err(|_| anyhow!("cannot read bounded RKP response"))
        .and_then(|bytes| {
            if bytes.len() <= MAX_HTTP_BODY {
                Ok(bytes)
            } else {
                Err(anyhow!("RKP response too large"))
            }
        });
    if submission {
        result.context(SUBMISSION_UNKNOWN)
    } else {
        result
    }
}

fn fetch_eek(fingerprint: &str) -> Result<Eek> {
    let payload = encode(&Value::Map(vec![
        (
            Value::Text("fingerprint".into()),
            Value::Text(fingerprint.into()),
        ),
        (Value::Text("id".into()), int(42)),
    ]))?;
    parse_eek(&post("fetchEekChain", &payload, false)?)
        .map_err(|_| anyhow!("RKP server returned an invalid challenge or EEK chain"))
}

fn parse_eek(body: &[u8]) -> Result<Eek> {
    let value = decode(body)?;
    let fields = as_array(&value, "EEK reply")?;
    if fields.len() < 2 {
        bail!("EEK reply is truncated");
    }
    let challenge = as_bytes(&fields[1], "challenge")?.to_vec();
    if challenge.is_empty() || challenge.len() > 64 {
        bail!("invalid RKP challenge length");
    }
    let mut eek = Eek {
        challenge,
        p256: Vec::new(),
        x25519: Vec::new(),
    };
    for entry in as_array(&fields[0], "EEK chains")? {
        let Ok(pair) = as_array(entry, "EEK pair") else {
            continue;
        };
        if pair.len() != 2 {
            continue;
        }
        let curve = as_i128(&pair[0], "EEK curve")?;
        if curve != 1 && curve != 2 {
            continue;
        }
        let encoded = encode(&pair[1])?;
        v1::validate_eek(&encoded)?;
        let target = if curve == 1 {
            &mut eek.p256
        } else {
            &mut eek.x25519
        };
        if target.is_empty() {
            *target = encoded;
        }
    }
    if eek.p256.is_empty() && eek.x25519.is_empty() {
        bail!("no supported EEK chains");
    }
    Ok(eek)
}

fn submit(csr: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
    // URL-safe base64 has no reserved characters except its padding. Match the
    // upstream URL query encoder without introducing a second URL dependency.
    let encoded = URL_SAFE.encode(challenge).replace('=', "%3D");
    let route = format!("signCertificates?challenge={encoded}");
    parse_signed(&post(&route, csr, true)?).map_err(|_| anyhow!(SUBMISSION_UNKNOWN))
}

fn parse_signed(body: &[u8]) -> Result<Vec<u8>> {
    let value = decode(body)?;
    let top = as_array(&value, "signCertificates reply")?;
    let fields = match top.first() {
        Some(Value::Array(inner)) => inner.as_slice(),
        _ => top,
    };
    if fields.len() < 2 {
        bail!("missing certificate chains");
    }
    let shared = as_bytes(&fields[0], "shared chain")?;
    let unique = as_array(&fields[1], "unique chains")?;
    if unique.len() != 1 {
        bail!("expected exactly one issued chain");
    }
    let unique = as_bytes(&unique[0], "unique chain")?;
    if shared.len() + unique.len() > MAX_CHAIN || unique.is_empty() {
        bail!("invalid issued chain size");
    }
    Ok([shared, unique].concat())
}

fn order_chain(der: &[u8], point: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut remainder = der;
    let mut certs = Vec::new();
    while !remainder.is_empty() {
        let (rest, cert) = x509_parser::parse_x509_certificate(remainder)
            .map_err(|_| anyhow!("invalid issued X.509 chain"))?;
        let consumed = remainder.len() - rest.len();
        if consumed == 0 || certs.len() >= 8 {
            bail!("invalid certificate count");
        }
        certs.push((remainder[..consumed].to_vec(), cert));
        remainder = rest;
    }
    let matching = certs
        .iter()
        .enumerate()
        .filter(|(_, (_, cert))| cert.public_key().subject_public_key.data.as_ref() == point)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let [mut current] = matching.as_slice() else {
        bail!("issued certificate does not uniquely match generated key");
    };
    let mut visited = Vec::new();
    loop {
        if visited.contains(&current) {
            bail!("issued chain contains a cycle");
        }
        visited.push(current);
        let cert = &certs[current].1;
        if cert.subject() == cert.issuer() {
            break;
        }
        let issuers = certs
            .iter()
            .enumerate()
            .filter(|(_, (_, parent))| cert.issuer() == parent.subject())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let [next] = issuers.as_slice() else {
            bail!("issued chain has missing or ambiguous issuer");
        };
        current = *next;
    }
    if visited.len() != certs.len() {
        bail!("issued chain contains unrelated certificates");
    }
    Ok(visited
        .into_iter()
        .map(|index| certs[index].0.clone())
        .collect())
}

fn pem(label: &str, der: &[u8]) -> Zeroizing<String> {
    let encoded = Zeroizing::new(STANDARD.encode(der));
    let mut output = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----"));
    output
}

fn keybox_xml(private: &[u8], chain: &[Vec<u8>]) -> Zeroizing<String> {
    let mut xml = Zeroizing::new(format!("<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes><Keybox DeviceID=\"omk-local-rkp\"><Key algorithm=\"ecdsa\"><PrivateKey format=\"pem\">{}</PrivateKey><CertificateChain><NumberOfCertificates>{}</NumberOfCertificates>", pem("PRIVATE KEY", private).as_str(), chain.len()));
    for cert in chain {
        xml.push_str(&format!(
            "<Certificate format=\"pem\">{}</Certificate>",
            pem("CERTIFICATE", cert).as_str()
        ));
    }
    xml.push_str("</CertificateChain></Key></Keybox></AndroidAttestation>");
    xml
}

pub fn validate_issued_xml(xml: &[u8]) -> Result<()> {
    crate::keybox::validate_issued_rkp_xml(xml)
}

fn required(fields: &[(Value, Value)], key: i128) -> Result<&Value> {
    map_get(fields, key).ok_or_else(|| anyhow!("required RKP field is missing"))
}

pub fn is_valid_patch_level(value: u32) -> bool {
    let digits = value.to_string();
    let digits = match digits.len() {
        6 => format!("{digits}01"),
        8 => digits,
        _ => return false,
    };
    crate::config::is_security_patch_date(&format!(
        "{}-{}-{}",
        &digits[..4],
        &digits[4..6],
        &digits[6..]
    ))
}

pub fn worker(directory: &str) -> Result<()> {
    native::worker(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_selection_rejects_unknown_input() {
        for mode in ["auto", "v1", "v2", "v1-native"] {
            assert!(Protocol::parse(mode).is_ok());
        }
        assert!(Protocol::parse("v3").is_err());
    }
    #[test]
    fn signed_response_requires_exactly_one_nonempty_key_chain() {
        let reply = encode(&Value::Array(vec![
            bytes([1, 2]),
            Value::Array(vec![bytes([3])]),
        ]))
        .unwrap();
        assert_eq!(parse_signed(&reply).unwrap(), vec![1, 2, 3]);
        for value in [
            Value::Array(vec![]),
            Value::Array(vec![bytes([]), Value::Array(vec![])]),
            Value::Array(vec![bytes([]), Value::Array(vec![bytes([])])]),
        ] {
            assert!(parse_signed(&encode(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn invalid_csr_and_challenge_do_not_reach_network() {
        assert!(parse_eek(&[0x80]).is_err());
        assert!(validate_v2(&[0x80], b"challenge", &Value::Null).is_err());
        assert!(order_chain(b"not DER", &[]).is_err());
    }

    fn signed_v2_fixture(public: &Value, challenge: &[u8]) -> Vec<u8> {
        use cose::{
            build_sig_structure, CWT_ISSUER, CWT_SUBJECT, DICE_KEY_USAGE, DICE_SUBJECT_PUB_KEY,
        };
        use ed25519_dalek::{Signer, SigningKey};
        let uds = SigningKey::from_bytes(&[1; 32]);
        let leaf = SigningKey::from_bytes(&[2; 32]);
        let cose_key = |key: &SigningKey| {
            Value::Map(vec![
                (int(1), int(1)),
                (int(3), int(-8)),
                (int(-1), int(6)),
                (int(-2), bytes(key.verifying_key().to_bytes())),
            ])
        };
        let sign = |key: &SigningKey, payload: &Value| {
            let protected = encode(&Value::Map(vec![(int(1), int(-8))])).unwrap();
            let payload = encode(payload).unwrap();
            let input = build_sig_structure("Signature1", &protected, &payload).unwrap();
            Value::Array(vec![
                bytes(protected),
                Value::Map(vec![]),
                bytes(payload),
                bytes(key.sign(&input).to_bytes()),
            ])
        };
        let dice = Value::Map(vec![
            (int(CWT_ISSUER), Value::Text("root".into())),
            (int(CWT_SUBJECT), Value::Text("leaf".into())),
            (int(DICE_KEY_USAGE), bytes([32])),
            (
                int(DICE_SUBJECT_PUB_KEY),
                bytes(encode(&cose_key(&leaf)).unwrap()),
            ),
        ]);
        let mut device = vec![];
        for (name, value) in [
            ("brand", "test"),
            ("manufacturer", "test"),
            ("product", "test"),
            ("model", "test"),
            ("device", "test"),
            ("vb_state", "green"),
            ("bootloader_state", "locked"),
            ("security_level", "tee"),
            ("os_version", "15"),
        ] {
            device.push((Value::Text(name.into()), Value::Text(value.into())));
        }
        for name in [
            "system_patch_level",
            "boot_patch_level",
            "vendor_patch_level",
        ] {
            device.push((Value::Text(name.into()), int(20260101)));
        }
        device.push((Value::Text("fused".into()), int(1)));
        let payload = Value::Array(vec![
            int(3),
            Value::Text("keymint".into()),
            Value::Map(device),
            Value::Array(vec![public.clone()]),
        ]);
        let signed = sign(
            &leaf,
            &Value::Array(vec![bytes(challenge), bytes(encode(&payload).unwrap())]),
        );
        encode(&Value::Array(vec![
            int(1),
            Value::Map(vec![]),
            Value::Array(vec![cose_key(&uds), sign(&uds, &dice)]),
            signed,
        ]))
        .unwrap()
    }

    #[test]
    fn v2_signature_and_challenge_key_binding_are_all_required() {
        let key = p256::SecretKey::from_slice(&[3; 32]).unwrap();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let point = key.public_key().to_encoded_point(false);
        let point = point.as_bytes();
        let public = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), bytes(&point[1..33])),
            (int(-3), bytes(&point[33..])),
        ]);
        let mut csr = signed_v2_fixture(&public, b"one-time-challenge");
        validate_v2(&csr, b"one-time-challenge", &public).unwrap();
        assert!(validate_v2(&csr, b"other-challenge", &public).is_err());
        assert!(validate_v2(&csr, b"one-time-challenge", &Value::Map(vec![])).is_err());
        *csr.last_mut().unwrap() ^= 1;
        assert!(validate_v2(&csr, b"one-time-challenge", &public).is_err());
    }
}
