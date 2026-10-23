use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    str,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock, RwLock,
    },
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::Encode;
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    crypto::{ec, rsa, KeyMaterial, OpaqueOr, Sha256},
    runtime::fs::atomic_replace_preserving_metadata,
    Error,
};
use kmr_crypto_boring::{ec::BoringEc, mldsa::BoringMlDsa, rsa::BoringRsa, sha256::BoringSha256};
use kmr_ta::device::{
    RetrieveCertSigningInfo, SigningAlgorithm, SigningInfoSnapshot, SigningKeyType,
};
use kmr_wire::keymint;
use log::{debug, error, info, warn};
use regex::Regex;
use serde::Deserialize;
use ureq::http::Uri;
use x509_cert::der as x509_der;
use x509_cert::{ext::pkix::name::DirectoryString, Certificate};
use x509_parser::parse_x509_certificate;

use crate::{
    root_path,
    webui_http::{self, DownloadPolicy},
};

pub const KEYBOX_PATH: &str = "/data/misc/keystore/omk/keybox.xml";
pub const MAX_KEYBOX_XML_BYTES: usize = 64 * 1024;
pub const GOOGLE_ATTESTATION_STATUS_CACHE_PATH: &str =
    root_path!("data/google_attestation_status.json");

const GOOGLE_ATTESTATION_STATUS_URL: &str = "https://android.googleapis.com/attestation/status";
const GOOGLE_ATTESTATION_STATUS_HOST: &str = "android.googleapis.com";
const GOOGLE_ATTESTATION_STATUS_PATH: &str = "/attestation/status";
const MAX_ATTESTATION_STATUS_BYTES: usize = 512 * 1024;
const ATTESTATION_STATUS_TIMEOUT: Duration = Duration::from_secs(15);
const ATTESTATION_STATUS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const GOOGLE_ATTESTATION_STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
const BUNDLED_GOOGLE_ATTESTATION_STATUS: &str =
    include_str!("../template/google_attestation_status.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboxFileState {
    Bundled,
    Custom,
    Invalid,
}

/// Origin of the attestation key material represented by a keybox.
///
/// The value is intentionally conservative: a certificate chain is only
/// identified as a Google key when its root public key matches the pinned
/// Google root key.  Certificate subjects alone are not sufficient evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyboxSource {
    GoogleHardware,
    GoogleRemote,
    #[default]
    Unknown,
}

impl KeyboxSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoogleHardware => "google_hardware",
            Self::GoogleRemote => "google_remote",
            Self::Unknown => "unknown",
        }
    }
}

/// Hardware-backed level advertised by the active keybox certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyboxLevel {
    Tee,
    Strongbox,
    #[default]
    Unknown,
}

impl KeyboxLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tee => "tee",
            Self::Strongbox => "strongbox",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboxRevocationStatus {
    NotChecked,
    NotListed,
    Suspended,
    Revoked,
}

impl KeyboxRevocationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::NotListed => "not_listed",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleAttestationStatusList {
    entries: BTreeMap<String, GoogleAttestationStatusEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleAttestationStatusEntry {
    status: String,
    #[serde(default, rename = "expires")]
    _expires: Option<String>,
    #[serde(default, rename = "reason")]
    _reason: Option<String>,
    #[serde(default, rename = "comment")]
    _comment: Option<String>,
}

/// Non-sensitive information derived from the public certificate chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyboxMetadata {
    pub source: KeyboxSource,
    pub level: KeyboxLevel,
}

/// Public, non-sensitive certificate information used by the WebUI inspector.
///
/// Private key material is deliberately excluded.  The inspector only reads
/// the presented certificate chains and is therefore safe to expose as a
/// diagnostic view even when the active Keybox is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyboxInspector {
    pub rsa: Option<KeyboxChainInspector>,
    pub ec: Option<KeyboxChainInspector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyboxChainInspector {
    pub algorithm: &'static str,
    pub chain_length: usize,
    pub serials: Vec<String>,
    pub leaf_subject: String,
    pub leaf_issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    /// Public metadata for every certificate in presentation order.  Keeping
    /// the complete chain here lets the WebUI show the same per-certificate
    /// details as a key-attestation inspector without exposing DER or keys.
    pub certificates: Vec<KeyboxCertificateInspector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyboxCertificateInspector {
    pub serial: String,
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
}

const BUNDLED_KEYBOX_XML: &str = include_str!("../template/keybox.xml");

lazy_static::lazy_static! {
    pub static ref KEYBOX: RwLock<KeyBox> = RwLock::new(KeyBox::new());
    static ref KEYBOX_IO_LOCK: Mutex<()> = Mutex::new(());
    static ref GOOGLE_ATTESTATION_STATUS_IO_LOCK: Mutex<()> = Mutex::new(());
    static ref KEY_BLOCK_RE: Regex =
        Regex::new(r#"(?s)<Key\s+algorithm="([^"]+)">\s*(.*?)\s*</Key>"#).unwrap();
    static ref PRIVATE_KEY_RE: Regex =
        Regex::new(r#"(?s)<PrivateKey[^>]*>\s*(.*?)\s*</PrivateKey>"#).unwrap();
    static ref CERT_COUNT_RE: Regex =
        Regex::new(r#"(?s)<NumberOfCertificates>\s*(\d+)\s*</NumberOfCertificates>"#).unwrap();
    static ref CERT_RE: Regex =
        Regex::new(r#"(?s)<Certificate(?:\s+[^>]*)?>\s*(.*?)\s*</Certificate>"#).unwrap();
    // These are the DER SubjectPublicKeyInfo values published by Google's
    // attestation-root endpoint. Keep all supported roots pinned and compare
    // the complete SPKI, rather than relying on a free-form subject or issuer
    // string.
    static ref GOOGLE_HARDWARE_ROOT_SPKI_DER: Vec<u8> = STANDARD
        .decode(GOOGLE_HARDWARE_ROOT_SPKI_B64)
        .expect("pinned Google root SPKI must be valid base64");
    static ref GOOGLE_EC_ROOT_SPKI_DER: Vec<u8> = STANDARD
        .decode(GOOGLE_EC_ROOT_SPKI_B64)
        .expect("pinned Google EC root SPKI must be valid base64");
}

static KEYBOX_WATCHER: OnceLock<()> = OnceLock::new();
static KEYBOX_DB_RETIRE_ALLOWED: AtomicBool = AtomicBool::new(false);
static KEYBOX_RUNTIME_LOADED: AtomicBool = AtomicBool::new(false);

const RKP_PROVISIONING_OID: x509_der::asn1::ObjectIdentifier =
    x509_der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.30");
const TITLE_OID: x509_der::asn1::ObjectIdentifier =
    x509_der::asn1::ObjectIdentifier::new_unwrap("2.5.4.12");
const SERIAL_NUMBER_OID: x509_der::asn1::ObjectIdentifier =
    x509_der::asn1::ObjectIdentifier::new_unwrap("2.5.4.5");

const GOOGLE_HARDWARE_ROOT_SPKI_B64: &str = concat!(
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU",
    "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j",
    "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y",
    "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X",
    "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI",
    "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB",
    "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q",
    "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp",
    "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7",
    "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82",
    "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+",
    "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==",
);

// Google added this EC attestation root during the 2025 root-certificate
// rotation. It can anchor both factory- and remotely-provisioned chains, so
// the ProvisioningInfo extension, rather than the root algorithm, determines
// the provisioning source.
const GOOGLE_EC_ROOT_SPKI_B64: &str = concat!(
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV",
    "9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObf",
    "gDkU2KNXezT9/RQ+XvNslxPHrHCowhGr",
);

#[derive(Clone)]
pub struct CertSignAlgoInfo {
    key: KeyMaterial,
    key_der: Vec<u8>,
    chain: Vec<keymint::Certificate>,
}

#[derive(Clone)]
pub struct KeyBox {
    // Accept dual-algorithm, RSA-only, and EC-only (including RKP-extracted) keyboxes.
    // Construction guarantees that at least one entry is present.
    rsa_info: Option<CertSignAlgoInfo>,
    ec_info: Option<CertSignAlgoInfo>,
    identity_digest: [u8; 32],
}

#[derive(Clone, Copy)]
enum KeyAlgorithm {
    Ec,
    Rsa,
}

struct ParsedKeyEntry {
    key_der: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

impl KeyBox {
    pub fn new() -> Self {
        Self::from_xml_str(BUNDLED_KEYBOX_XML).expect("bundled keybox.xml must be valid")
    }

    pub fn from_xml_str(xml: &str) -> Result<Self> {
        let mut rsa_entry = None;
        let mut ec_entry = None;

        for captures in KEY_BLOCK_RE.captures_iter(xml) {
            let algorithm = match captures.get(1).map(|m| m.as_str().trim()) {
                Some("ecdsa") | Some("ec") => KeyAlgorithm::Ec,
                Some("rsa") => KeyAlgorithm::Rsa,
                Some(other) => bail!("unsupported key algorithm `{other}` in keybox.xml"),
                None => bail!("missing key algorithm in keybox.xml"),
            };
            let body = captures
                .get(2)
                .map(|m| m.as_str())
                .ok_or_else(|| anyhow!("missing key block body"))?;
            let entry = ParsedKeyEntry::from_xml_block(body).with_context(|| {
                format!("failed to parse {:?} key entry", algorithm_name(algorithm))
            })?;
            match algorithm {
                KeyAlgorithm::Ec => ec_entry = Some(entry),
                KeyAlgorithm::Rsa => rsa_entry = Some(entry),
            }
        }

        let rsa_info = rsa_entry.map(Self::build_rsa_info).transpose()?;
        let ec_info = ec_entry.map(Self::build_ec_info).transpose()?;
        if rsa_info.is_none() && ec_info.is_none() {
            bail!("keybox.xml contains neither an RSA nor an EC key entry");
        }
        let identity_digest = Self::compute_identity_digest(rsa_info.as_ref(), ec_info.as_ref())?;

        Ok(Self {
            rsa_info,
            ec_info,
            identity_digest,
        })
    }

    fn build_rsa_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("RSA certificate chain is empty");
        }
        let key = rsa::import_pkcs1_key(&entry.key_der)
            .or_else(|_| rsa::import_pkcs8_key(&entry.key_der))
            .map(|(key, _, _)| key)
            .map_err(|e| anyhow!("failed to import RSA private key: {e:?}"))?;
        // Both importers return the inner PKCS#1 key. Keep that canonical
        // encoding for XML export and identity hashing, so rewrapping the same
        // key in PKCS#8 cannot retire its existing attestation entries.
        let key_der = match &key {
            KeyMaterial::Rsa(OpaqueOr::Explicit(key)) => key.0.clone(),
            _ => bail!("RSA private key import returned unexpected key material"),
        };
        let chain: Vec<keymint::Certificate> = entry
            .chain
            .into_iter()
            .map(|encoded_certificate| keymint::Certificate {
                encoded_certificate,
            })
            .collect();
        validate_chain_matches_key(&key, &chain, KeyAlgorithm::Rsa)?;
        Ok(CertSignAlgoInfo {
            key,
            key_der,
            chain,
        })
    }

    fn build_ec_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("EC certificate chain is empty");
        }
        let key = ec::import_sec1_private_key(&entry.key_der)
            .or_else(|_| ec::import_pkcs8_key(&entry.key_der))
            .map_err(|e| anyhow!("failed to import EC private key: {e:?}"))?;
        // Both importers return SEC1 key material with the named curve present.
        // Keep that encoding for XML export and identity hashing, so a PKCS#8
        // wrapper cannot retire entries bound to the same keybox.
        let key_der = match &key {
            KeyMaterial::Ec(
                _,
                _,
                OpaqueOr::Explicit(
                    ec::Key::P224(key)
                    | ec::Key::P256(key)
                    | ec::Key::P384(key)
                    | ec::Key::P521(key),
                ),
            ) => key.0.clone(),
            _ => bail!("EC private key import returned non-NIST key material"),
        };
        let chain: Vec<keymint::Certificate> = entry
            .chain
            .into_iter()
            .map(|encoded_certificate| keymint::Certificate {
                encoded_certificate,
            })
            .collect();
        validate_chain_matches_key(&key, &chain, KeyAlgorithm::Ec)?;
        Ok(CertSignAlgoInfo {
            key,
            key_der,
            chain,
        })
    }

    fn compute_identity_digest(
        rsa_info: Option<&CertSignAlgoInfo>,
        ec_info: Option<&CertSignAlgoInfo>,
    ) -> Result<[u8; 32]> {
        let mut material = Vec::new();
        if let Some(rsa_info) = rsa_info {
            append_labeled_bytes(&mut material, b"rsa-key", &rsa_info.key_der);
            append_labeled_chain(&mut material, b"rsa-chain", &rsa_info.chain);
        }
        if let Some(ec_info) = ec_info {
            append_labeled_bytes(&mut material, b"ec-key", &ec_info.key_der);
            append_labeled_chain(&mut material, b"ec-chain", &ec_info.chain);
        }

        BoringSha256 {}
            .hash(&material)
            .map_err(|e| anyhow!("failed to hash keybox identity: {e:?}"))
    }

    fn refresh_identity_digest(&mut self) -> Result<()> {
        self.identity_digest =
            Self::compute_identity_digest(self.rsa_info.as_ref(), self.ec_info.as_ref())?;
        Ok(())
    }

    pub fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }

    /// Returns non-sensitive metadata derived from the keybox certificate
    /// chains.  Parsing failures are treated as unknown metadata because the
    /// keybox itself has already passed the normal private-key/leaf check and
    /// this informational path must never prevent KeyMint startup.
    pub fn metadata(&self) -> KeyboxMetadata {
        let chains = [self.ec_info.as_ref(), self.rsa_info.as_ref()];
        combine_chain_metadata(
            chains
                .into_iter()
                .flatten()
                .map(|info| metadata_for_chain(&info.chain)),
        )
    }

    /// Return certificate-only details for the optional RSA and EC chains.
    /// Parsing errors are represented as an empty diagnostic entry by the
    /// caller; they never affect KeyMint startup or key generation.
    pub fn inspector(&self) -> KeyboxInspector {
        KeyboxInspector {
            rsa: self
                .rsa_info
                .as_ref()
                .and_then(|info| inspector_for_chain("RSA", &info.chain)),
            ec: self
                .ec_info
                .as_ref()
                .and_then(|info| inspector_for_chain("EC", &info.chain)),
        }
    }

    fn certificate_serials(&self) -> Result<Vec<String>> {
        let mut serials = BTreeSet::new();
        for info in [self.ec_info.as_ref(), self.rsa_info.as_ref()]
            .into_iter()
            .flatten()
        {
            for encoded in &info.chain {
                serials.insert(canonical_certificate_serial(&encoded.encoded_certificate)?);
            }
        }
        if serials.is_empty() {
            bail!("keybox contains no certificate serial numbers");
        }
        Ok(serials.into_iter().collect())
    }

    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        // Prefer the subject key's algorithm, but use the sole available key for a single-algorithm
        // keybox. The TA derives the leaf signature algorithm from this returned key material.
        let (preferred, fallback) = match key_type.algo_hint {
            SigningAlgorithm::Rsa => (&self.rsa_info, &self.ec_info),
            SigningAlgorithm::Ec => (&self.ec_info, &self.rsa_info),
        };
        let info = preferred.as_ref().or(fallback.as_ref()).ok_or_else(|| {
            kmr_common::km_err!(KeymintNotConfigured, "keybox contains no signing key")
        })?;

        Ok(SigningInfoSnapshot {
            signing_key: info.key.clone(),
            cert_chain: info.chain.clone(),
            identity_digest: self.identity_digest,
        })
    }

    pub fn update_rsa_keybox(
        &mut self,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        self.update_keybox(KeyAlgorithm::Rsa, key_der, chain)
    }

    pub fn update_ec_keybox(
        &mut self,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        self.update_keybox(KeyAlgorithm::Ec, key_der, chain)
    }

    fn update_keybox(
        &mut self,
        algorithm: KeyAlgorithm,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        let entry = ParsedKeyEntry {
            key_der,
            chain: chain
                .into_iter()
                .map(|certificate| certificate.encoded_certificate)
                .collect(),
        };
        match algorithm {
            KeyAlgorithm::Ec => self.ec_info = Some(Self::build_ec_info(entry)?),
            KeyAlgorithm::Rsa => self.rsa_info = Some(Self::build_rsa_info(entry)?),
        }
        self.refresh_identity_digest()
    }

    pub fn to_xml_string(&self) -> String {
        let key_blocks = [
            self.ec_info
                .as_ref()
                .map(|info| Self::to_xml_block(KeyAlgorithm::Ec, info)),
            self.rsa_info
                .as_ref()
                .map(|info| Self::to_xml_block(KeyAlgorithm::Rsa, info)),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");

        format!(
            concat!(
                "<?xml version=\"1.0\"?>\n",
                "<AndroidAttestation>\n",
                "<NumberOfKeyboxes>1</NumberOfKeyboxes>\n",
                "<Keybox DeviceID=\"sw\">\n",
                "{}\n",
                "</Keybox>\n",
                "</AndroidAttestation>\n"
            ),
            key_blocks,
        )
    }

    fn to_xml_block(algorithm: KeyAlgorithm, info: &CertSignAlgoInfo) -> String {
        let (name, private_label) = match algorithm {
            KeyAlgorithm::Ec => ("ecdsa", "EC PRIVATE KEY"),
            KeyAlgorithm::Rsa => ("rsa", "RSA PRIVATE KEY"),
        };
        let certificates = info
            .chain
            .iter()
            .map(|certificate| {
                format!(
                    "<Certificate format=\"pem\">\n{}\n</Certificate>",
                    encode_pem_block("CERTIFICATE", &certificate.encoded_certificate)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            concat!(
                "<Key algorithm=\"{name}\">\n",
                "<PrivateKey format=\"pem\">\n",
                "{private_key}\n",
                "</PrivateKey>\n",
                "<CertificateChain>\n",
                "<NumberOfCertificates>{cert_count}</NumberOfCertificates>\n",
                "{certificates}\n",
                "</CertificateChain>\n",
                "</Key>"
            ),
            name = name,
            private_key = encode_pem_block(private_label, &info.key_der),
            cert_count = info.chain.len(),
            certificates = certificates,
        )
    }
}

fn canonical_certificate_serial(encoded_certificate: &[u8]) -> Result<String> {
    let certificate = <Certificate as x509_der::Decode>::from_der(encoded_certificate)
        .context("failed to parse a certificate while reading its serial number")?;
    let bytes = certificate.tbs_certificate().serial_number().as_bytes();
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map(|offset| &bytes[offset..])
        .unwrap_or_default();
    if significant.is_empty() {
        return Ok("0".to_string());
    }
    Ok(hex::encode(significant))
}

fn inspector_for_chain(
    algorithm: &'static str,
    chain: &[keymint::Certificate],
) -> Option<KeyboxChainInspector> {
    let certificates = chain
        .iter()
        .map(|certificate| {
            let (_, parsed) = parse_x509_certificate(&certificate.encoded_certificate).ok()?;
            Some(KeyboxCertificateInspector {
                serial: canonical_certificate_serial(&certificate.encoded_certificate).ok()?,
                subject: parsed.subject().to_string(),
                issuer: parsed.issuer().to_string(),
                valid_from: parsed.validity().not_before.to_rfc2822().ok()?,
                valid_until: parsed.validity().not_after.to_rfc2822().ok()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let leaf = certificates.first()?;
    let serials = certificates
        .iter()
        .map(|certificate| certificate.serial.clone())
        .collect();
    Some(KeyboxChainInspector {
        algorithm,
        chain_length: chain.len(),
        serials,
        leaf_subject: leaf.subject.clone(),
        leaf_issuer: leaf.issuer.clone(),
        valid_from: leaf.valid_from.clone(),
        valid_until: leaf.valid_until.clone(),
        certificates,
    })
}

fn combine_chain_metadata(chains: impl IntoIterator<Item = ChainMetadata>) -> KeyboxMetadata {
    let mut source = None;
    let mut source_unknown = false;
    let mut level = KeyboxLevel::Unknown;
    let mut saw_level = false;
    let mut conflicting_levels = false;

    for chain_metadata in chains {
        // The keybox can contain independent RSA and EC chains.  Do not
        // let one chain hide an unknown or contradictory result from the
        // other chain: the label describes the complete keybox, not just
        // whichever algorithm happens to be queried first.
        match chain_metadata.source {
            KeyboxSource::Unknown => source_unknown = true,
            known => match source {
                None => source = Some(known),
                Some(existing) if existing != known => source_unknown = true,
                Some(_) => {}
            },
        }

        if chain_metadata.level != KeyboxLevel::Unknown {
            if !saw_level {
                level = chain_metadata.level;
                saw_level = true;
            } else if level != chain_metadata.level {
                conflicting_levels = true;
            }
        }
    }

    if conflicting_levels {
        level = KeyboxLevel::Unknown;
    }

    KeyboxMetadata {
        source: if source_unknown {
            KeyboxSource::Unknown
        } else {
            source.unwrap_or_default()
        },
        level,
    }
}

impl Default for KeyBox {
    fn default() -> Self {
        Self::new()
    }
}

impl ParsedKeyEntry {
    fn from_xml_block(block: &str) -> Result<Self> {
        let private_key_pem = PRIVATE_KEY_RE
            .captures(block)
            .and_then(|captures| captures.get(1))
            .map(|m| m.as_str())
            .context("missing <PrivateKey> block")?;
        let key_der = decode_pem(private_key_pem)?;

        let expected_cert_count = CERT_COUNT_RE
            .captures(block)
            .and_then(|captures| captures.get(1))
            .map(|m| m.as_str())
            .context("missing <NumberOfCertificates> in certificate chain")?
            .parse::<usize>()
            .context("invalid certificate count in keybox.xml")?;

        let chain = CERT_RE
            .captures_iter(block)
            .filter_map(|captures| captures.get(1).map(|m| m.as_str()))
            .map(decode_pem)
            .collect::<Result<Vec<_>>>()?;

        if chain.len() != expected_cert_count {
            bail!(
                "certificate count mismatch: declared {}, parsed {}",
                expected_cert_count,
                chain.len()
            );
        }

        Ok(Self { key_der, chain })
    }
}

fn append_labeled_bytes(buffer: &mut Vec<u8>, label: &[u8], data: &[u8]) {
    buffer.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buffer.extend_from_slice(data);
}

fn append_labeled_chain(buffer: &mut Vec<u8>, label: &[u8], chain: &[keymint::Certificate]) {
    buffer.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(&(chain.len() as u32).to_be_bytes());
    for certificate in chain {
        buffer.extend_from_slice(&(certificate.encoded_certificate.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&certificate.encoded_certificate);
    }
}

fn algorithm_name(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Ec => "EC",
        KeyAlgorithm::Rsa => "RSA",
    }
}

fn validate_chain_matches_key(
    key: &KeyMaterial,
    chain: &[keymint::Certificate],
    algorithm: KeyAlgorithm,
) -> Result<()> {
    let first_cert = chain
        .first()
        .context("certificate chain must contain a leaf certificate")?;
    let certificate = <Certificate as x509_der::Decode>::from_der(&first_cert.encoded_certificate)
        .with_context(|| {
            format!(
                "failed to parse {} leaf certificate from keybox chain",
                algorithm_name(algorithm)
            )
        })?;
    let mut spki_buf = Vec::new();
    let derived_spki = key
        .subject_public_key_info(
            &mut spki_buf,
            &BoringEc::default(),
            &BoringRsa::default(),
            &BoringMlDsa,
        )
        .map_err(|e| {
            anyhow!(
                "failed to derive {} public key info from private key: {e:?}",
                algorithm_name(algorithm)
            )
        })?
        .context("symmetric key cannot back an attestation certificate")?
        .to_der()
        .with_context(|| {
            format!(
                "failed to encode {} public key info from private key",
                algorithm_name(algorithm)
            )
        })?;
    let certificate_spki =
        x509_der::Encode::to_der(certificate.tbs_certificate().subject_public_key_info())
            .with_context(|| {
                format!(
                    "failed to encode {} public key info from certificate chain",
                    algorithm_name(algorithm)
                )
            })?;
    if derived_spki != certificate_spki {
        bail!(
            "{} certificate chain does not match the supplied private key",
            algorithm_name(algorithm)
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct ChainMetadata {
    source: KeyboxSource,
    level: KeyboxLevel,
}

fn metadata_for_chain(chain: &[keymint::Certificate]) -> ChainMetadata {
    metadata_for_chain_with_roots(
        chain,
        &[
            GOOGLE_HARDWARE_ROOT_SPKI_DER.as_slice(),
            GOOGLE_EC_ROOT_SPKI_DER.as_slice(),
        ],
    )
}

fn metadata_for_chain_with_roots(
    chain: &[keymint::Certificate],
    pinned_root_spkis: &[&[u8]],
) -> ChainMetadata {
    // Keep certificate positions intact. Silently dropping a malformed middle
    // certificate could turn an invalid chain into a plausible leaf/root pair
    // and produce misleading metadata in the WebUI.
    let mut parsed_chain = Vec::with_capacity(chain.len());
    for certificate in chain {
        let Ok(parsed) =
            <Certificate as x509_der::Decode>::from_der(&certificate.encoded_certificate)
        else {
            return ChainMetadata::default();
        };
        parsed_chain.push(parsed);
    }
    let Some(leaf) = parsed_chain.first() else {
        return ChainMetadata::default();
    };
    let Some(root) = parsed_chain.last() else {
        return ChainMetadata::default();
    };

    let has_pinned_root =
        x509_der::Encode::to_der(root.tbs_certificate().subject_public_key_info())
            .ok()
            .is_some_and(|spki| pinned_root_spkis.contains(&spki.as_slice()));

    // A pinned root key alone is not enough: an unrelated leaf can otherwise
    // be followed by a copied Google root certificate and look authentic in
    // the WebUI. Verify every child signature with the next certificate's
    // public key before reporting a Google source. This is intentionally kept
    // in the informational metadata path; KeyMint's existing key/leaf
    // validation remains unchanged.
    if has_pinned_root && !chain_signatures_are_valid(chain) {
        return ChainMetadata {
            level: keybox_level_from_subject(leaf.tbs_certificate().subject()),
            ..ChainMetadata::default()
        };
    }

    let has_rkp_extension = leaf
        .tbs_certificate()
        .extensions()
        .is_some_and(|extensions| {
            extensions
                .iter()
                .any(|extension| extension.extn_id == RKP_PROVISIONING_OID)
        });
    let root_adjacent = parsed_chain.iter().rev().nth(1);
    let has_factory_serial = root_adjacent.is_some_and(|certificate| {
        certificate
            .tbs_certificate()
            .subject()
            .iter()
            .any(|attribute| attribute.oid == SERIAL_NUMBER_OID)
    });
    let has_droid_ca2 = root_adjacent.is_some_and(|certificate| {
        let subject = certificate.tbs_certificate().subject();
        let common_name = subject.common_name().ok().flatten();
        let organization = subject.organization().ok().flatten();
        common_name.is_some_and(|value| value.value().as_ref() == "Droid CA2")
            && organization.is_some_and(|value| value.value().as_ref() == "Google LLC")
    });

    // Google attestation roots can anchor both factory- and remotely-
    // provisioned keys. Match the factory serial-number and remote Droid CA2
    // structures used by Android's official verifier. ProvisioningInfo is an
    // additional positive indication for extracted RKP chains.
    let source = if has_pinned_root && has_factory_serial {
        KeyboxSource::GoogleHardware
    } else if has_pinned_root && (has_rkp_extension || has_droid_ca2) {
        KeyboxSource::GoogleRemote
    } else {
        KeyboxSource::Unknown
    };

    let level = keybox_level_from_subject(leaf.tbs_certificate().subject());

    ChainMetadata { source, level }
}

/// Verify the signatures linking a leaf-first certificate chain.
///
/// The verifier supports the RSA PKCS#1, RSA-PSS, ECDSA, and Ed25519
/// algorithms used by Android attestation chains. Unsupported algorithms are
/// rejected conservatively so a future chain is shown as unknown until the
/// verifier supports it.
fn chain_signatures_are_valid(chain: &[keymint::Certificate]) -> bool {
    chain.windows(2).all(|pair| {
        certificate_signature_is_valid(&pair[0].encoded_certificate, &pair[1].encoded_certificate)
    })
}

fn certificate_signature_is_valid(child_der: &[u8], issuer_der: &[u8]) -> bool {
    let Ok((child_remainder, child)) = parse_x509_certificate(child_der) else {
        return false;
    };
    let Ok((issuer_remainder, issuer)) = parse_x509_certificate(issuer_der) else {
        return false;
    };
    if !child_remainder.is_empty() || !issuer_remainder.is_empty() {
        return false;
    }
    child.verify_signature(Some(issuer.public_key())).is_ok()
}

fn keybox_level_from_subject(subject: &x509_cert::name::Name) -> KeyboxLevel {
    // Newer RKP certificates use O=TEE/StrongBox. Older factory keyboxes
    // commonly encode the same value as the X.520 title attribute (T=TEE),
    // so use title only as a compatibility fallback when O is absent or
    // contains an unrelated value.
    let parse_value = |value: &str| match value.trim().to_ascii_lowercase().as_str() {
        "tee" => KeyboxLevel::Tee,
        "strongbox" => KeyboxLevel::Strongbox,
        _ => KeyboxLevel::Unknown,
    };

    if let Ok(Some(organization)) = subject.organization() {
        let level = parse_value(organization.value().as_ref());
        if level != KeyboxLevel::Unknown {
            return level;
        }
    }

    subject
        .by_oid::<DirectoryString>(TITLE_OID)
        .ok()
        .flatten()
        .map(|title| parse_value(title.value().as_ref()))
        .unwrap_or(KeyboxLevel::Unknown)
}

fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let base64_body = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .collect::<String>();

    if base64_body.is_empty() {
        bail!("empty PEM payload");
    }

    STANDARD
        .decode(base64_body.as_bytes())
        .context("failed to decode PEM payload")
}

fn encode_pem_block(label: &str, der: &[u8]) -> String {
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {label}-----\n"));
    let base64 = STANDARD.encode(der);
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is valid UTF-8"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----"));
    pem
}

fn write_keybox_xml(path: &str, xml: &str) -> Result<()> {
    atomic_replace_preserving_metadata(
        Path::new(path),
        xml.as_bytes(),
        0o600,
        KEYSTORE_UID,
        KEYSTORE_GID,
    )
    .with_context(|| format!("failed to atomically replace keybox.xml at {path}"))
}

fn validate_keybox_xml(contents: &[u8]) -> Result<()> {
    if contents.len() > MAX_KEYBOX_XML_BYTES {
        bail!("keybox.xml exceeds the {} byte limit", MAX_KEYBOX_XML_BYTES);
    }
    let xml = str::from_utf8(contents).context("keybox.xml is not valid UTF-8")?;
    KeyBox::from_xml_str(xml).context("keybox.xml validation failed")?;
    Ok(())
}

fn classify_keybox_xml(contents: &[u8]) -> KeyboxFileState {
    if validate_keybox_xml(contents).is_err() {
        return KeyboxFileState::Invalid;
    }
    let xml = str::from_utf8(contents).expect("validated keybox.xml is UTF-8");
    if is_bundled_keybox_xml(xml) {
        KeyboxFileState::Bundled
    } else {
        KeyboxFileState::Custom
    }
}

pub fn installed_keybox_state() -> Result<KeyboxFileState> {
    let contents = fs::read(KEYBOX_PATH)
        .with_context(|| format!("failed to read keybox.xml from {KEYBOX_PATH}"))?;
    Ok(classify_keybox_xml(&contents))
}

/// Reads the installed keybox once and returns its validation state, public
/// metadata, and the canonical serial numbers from every presented chain.
/// Invalid XML is represented as `Invalid` with unknown metadata so an
/// informational WebUI query cannot prevent the rest of the service from
/// starting. A missing serial list means that at least one presented
/// certificate could not be parsed, so an online revocation result must not
/// be reported for that keybox.
pub fn installed_keybox_state_and_metadata(
) -> Result<(KeyboxFileState, KeyboxMetadata, Option<Vec<String>>)> {
    let contents = fs::read(KEYBOX_PATH)
        .with_context(|| format!("failed to read keybox.xml from {KEYBOX_PATH}"))?;
    if contents.len() > MAX_KEYBOX_XML_BYTES {
        return Ok((KeyboxFileState::Invalid, KeyboxMetadata::default(), None));
    }
    let Ok(xml) = str::from_utf8(&contents) else {
        return Ok((KeyboxFileState::Invalid, KeyboxMetadata::default(), None));
    };
    let Ok(keybox) = KeyBox::from_xml_str(xml) else {
        return Ok((KeyboxFileState::Invalid, KeyboxMetadata::default(), None));
    };
    let state = if is_bundled_keybox_xml(xml) {
        KeyboxFileState::Bundled
    } else {
        KeyboxFileState::Custom
    };
    let metadata = keybox.metadata();
    let serials = keybox.certificate_serials().ok();
    Ok((state, metadata, serials))
}

/// Read certificate-only details from the installed keybox without changing
/// the active KeyMint state or rewriting an invalid file.  This is used by the
/// read-only WebUI inspector, so malformed input is represented as an invalid
/// result rather than being repaired as a side effect of a diagnostic query.
pub fn installed_keybox_inspector() -> Result<(KeyboxFileState, KeyboxInspector)> {
    let contents = fs::read(KEYBOX_PATH)
        .with_context(|| format!("failed to read keybox.xml from {KEYBOX_PATH}"))?;
    if contents.len() > MAX_KEYBOX_XML_BYTES {
        return Ok((KeyboxFileState::Invalid, KeyboxInspector::default()));
    }
    let Ok(xml) = str::from_utf8(&contents) else {
        return Ok((KeyboxFileState::Invalid, KeyboxInspector::default()));
    };
    let Ok(keybox) = KeyBox::from_xml_str(xml) else {
        return Ok((KeyboxFileState::Invalid, KeyboxInspector::default()));
    };
    let state = if is_bundled_keybox_xml(xml) {
        KeyboxFileState::Bundled
    } else {
        KeyboxFileState::Custom
    };
    Ok((state, keybox.inspector()))
}

/// Ensure a validated copy of Google's status list exists in the persistent
/// OMK data directory.  The copy is seeded from the build-time snapshot only
/// when no local file exists; an existing file is never replaced merely
/// because it is old or temporarily unreachable.
pub fn ensure_google_attestation_status_cache() -> Result<()> {
    let path = Path::new(GOOGLE_ATTESTATION_STATUS_CACHE_PATH);
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            bail!(
                "Google attestation status cache is not a regular file: {}",
                path.display()
            )
        }
        Ok(metadata) => {
            if metadata.len() <= MAX_ATTESTATION_STATUS_BYTES as u64 {
                if let Ok(contents) = fs::read_to_string(path) {
                    if parse_google_attestation_status(&contents).is_ok() {
                        return Ok(());
                    }
                }
            }
            warn!(
                "existing Google attestation status cache is invalid; replacing it with the bundled snapshot"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect the Google attestation status cache {}",
                    path.display()
                )
            })
        }
    }

    parse_google_attestation_status(BUNDLED_GOOGLE_ATTESTATION_STATUS)
        .context("bundled Google attestation status snapshot failed validation")?;
    persist_google_attestation_status_cache(BUNDLED_GOOGLE_ATTESTATION_STATUS)
}

pub fn check_google_attestation_status(serials: &[String]) -> Result<KeyboxRevocationStatus> {
    if serials.is_empty() {
        bail!("cannot check an empty certificate serial-number set");
    }

    // A successful download updates the cache mtime through the atomic replace
    // path below. Reuse a validated cache for twelve hours, then refresh it
    // from Google on the next status check. An expired cache remains a valid
    // offline fallback if the endpoint is unavailable.
    if google_attestation_status_cache_is_fresh() {
        if let Ok(status) = read_and_classify_google_attestation_status_cache(serials) {
            info!("using the validated Google attestation status cache");
            return Ok(status);
        }
        warn!("fresh Google attestation status cache failed validation; refreshing it");
    }

    let online_error = match fetch_google_attestation_status() {
        Ok(contents) => match classify_google_attestation_status(&contents, serials) {
            Ok(status) => {
                if let Err(error) = persist_google_attestation_status_cache(&contents) {
                    warn!("Google attestation status was valid but could not be cached: {error:#}");
                }
                info!("checked Keybox certificate status using Google's live list");
                return Ok(status);
            }
            Err(error) => {
                anyhow!("downloaded Google attestation status list is invalid: {error:#}")
            }
        },
        Err(error) => error,
    };

    match read_and_classify_google_attestation_status_cache(serials) {
        Ok(status) => {
            info!("Google status endpoint unavailable; using the validated local status cache");
            Ok(status)
        }
        Err(cache_error) => {
            match classify_google_attestation_status(BUNDLED_GOOGLE_ATTESTATION_STATUS, serials) {
                Ok(status) => {
                    if let Err(error) =
                        persist_google_attestation_status_cache(BUNDLED_GOOGLE_ATTESTATION_STATUS)
                    {
                        warn!(
                            "using bundled Google attestation status snapshot; could not seed local cache: {error:#}"
                        );
                    } else {
                        info!(
                            "Google status endpoint and local cache unavailable; using bundled status snapshot"
                        );
                    }
                    Ok(status)
                }
                Err(snapshot_error) => {
                    bail!(
                        "Google attestation status lookup failed; live list: {online_error:#}; local cache: {cache_error:#}; bundled snapshot: {snapshot_error:#}"
                    );
                }
            }
        }
    }
}

fn google_attestation_status_cache_is_fresh() -> bool {
    let path = Path::new(GOOGLE_ATTESTATION_STATUS_CACHE_PATH);
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return false;
    }
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age < GOOGLE_ATTESTATION_STATUS_REFRESH_INTERVAL
}

fn fetch_google_attestation_status() -> Result<String> {
    let requested_uri: Uri = GOOGLE_ATTESTATION_STATUS_URL
        .parse()
        .context("Google attestation status URL is invalid")?;
    webui_http::download_https_utf8(
        requested_uri,
        &DownloadPolicy {
            resource: "Google attestation status list",
            redirect_allowlist: "the fixed Google attestation status endpoint",
            max_bytes: MAX_ATTESTATION_STATUS_BYTES,
            max_size_label: "512 KiB",
            max_redirects: 0,
            timeout: ATTESTATION_STATUS_TIMEOUT,
            connect_timeout: ATTESTATION_STATUS_CONNECT_TIMEOUT,
        },
        is_allowed_attestation_status_uri,
    )
}

fn read_and_classify_google_attestation_status_cache(
    serials: &[String],
) -> Result<KeyboxRevocationStatus> {
    let contents = read_google_attestation_status_cache()?;
    classify_google_attestation_status(&contents, serials)
}

fn read_google_attestation_status_cache() -> Result<String> {
    let path = Path::new(GOOGLE_ATTESTATION_STATUS_CACHE_PATH);
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect the Google attestation status cache {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!(
            "Google attestation status cache is not a regular file: {}",
            path.display()
        );
    }
    if metadata.len() > MAX_ATTESTATION_STATUS_BYTES as u64 {
        bail!("Google attestation status cache exceeds the 512 KiB limit");
    }
    let contents = fs::read(path).with_context(|| {
        format!(
            "failed to read the Google attestation status cache {}",
            path.display()
        )
    })?;
    String::from_utf8(contents).context("Google attestation status cache is not UTF-8")
}

fn persist_google_attestation_status_cache(contents: &str) -> Result<()> {
    if contents.len() > MAX_ATTESTATION_STATUS_BYTES {
        bail!("Google attestation status cache exceeds the 512 KiB limit");
    }
    parse_google_attestation_status(contents)
        .context("refusing to cache an invalid Google attestation status list")?;

    let _io_guard = GOOGLE_ATTESTATION_STATUS_IO_LOCK.lock().unwrap();
    let path = Path::new(GOOGLE_ATTESTATION_STATUS_CACHE_PATH);
    validate_google_attestation_status_cache_target(path)?;
    atomic_replace_preserving_metadata(
        path,
        contents.as_bytes(),
        0o600,
        KEYSTORE_UID,
        KEYSTORE_GID,
    )
    .with_context(|| {
        format!(
            "failed to atomically replace Google attestation status cache {}",
            path.display()
        )
    })?;

    let saved = read_google_attestation_status_cache()?;
    if saved != contents {
        bail!("Google attestation status cache read-back does not match the downloaded list");
    }
    Ok(())
}

fn validate_google_attestation_status_cache_target(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Google attestation status cache has no parent directory"))?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            bail!(
                "Google attestation status cache parent is not a real directory: {}",
                parent.display()
            )
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect Google attestation status cache parent {}",
                    parent.display()
                )
            })
        }
    }

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!(
                "Google attestation status cache is not a regular file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn is_allowed_attestation_status_uri(uri: &Uri) -> bool {
    if uri.scheme_str() != Some("https")
        || uri.query().is_some()
        || uri.path() != GOOGLE_ATTESTATION_STATUS_PATH
    {
        return false;
    }
    let Some(authority) = uri.authority() else {
        return false;
    };
    let authority = authority.as_str();
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_suffix(":443") {
        Some(host) if !host.contains(':') => host,
        Some(_) => return false,
        None if authority.contains(':') => return false,
        None => authority,
    };
    host.eq_ignore_ascii_case(GOOGLE_ATTESTATION_STATUS_HOST)
}

fn classify_google_attestation_status(
    contents: &str,
    serials: &[String],
) -> Result<KeyboxRevocationStatus> {
    let list = parse_google_attestation_status(contents)?;

    let mut result = KeyboxRevocationStatus::NotListed;
    for serial in serials {
        let Some(entry) = certificate_status_entry(&list.entries, serial) else {
            continue;
        };
        match entry.status.as_str() {
            "REVOKED" => return Ok(KeyboxRevocationStatus::Revoked),
            "SUSPENDED" => result = KeyboxRevocationStatus::Suspended,
            status => bail!("unsupported Google attestation status `{status}`"),
        }
    }
    Ok(result)
}

fn parse_google_attestation_status(contents: &str) -> Result<GoogleAttestationStatusList> {
    if contents.len() > MAX_ATTESTATION_STATUS_BYTES {
        bail!("Google attestation status list exceeds the 512 KiB limit");
    }
    let list: GoogleAttestationStatusList = serde_json::from_str(contents)
        .context("failed to parse the Google attestation status list")?;
    if list.entries.is_empty() {
        bail!("Google attestation status list contains no entries");
    }
    let mut entries = BTreeMap::new();
    for (serial, entry) in list.entries {
        if !is_canonical_attestation_status_serial(&serial) {
            bail!("Google attestation status list contains a non-canonical serial number");
        }
        match entry.status.as_str() {
            "REVOKED" | "SUSPENDED" => {}
            status => bail!("unsupported Google attestation status `{status}`"),
        }
        let normalized_serial = serial.to_ascii_lowercase();
        if entries.insert(normalized_serial, entry).is_some() {
            bail!("Google attestation status list contains duplicate serial numbers");
        }
    }
    Ok(GoogleAttestationStatusList { entries })
}

fn certificate_status_entry<'a>(
    entries: &'a BTreeMap<String, GoogleAttestationStatusEntry>,
    serial: &str,
) -> Option<&'a GoogleAttestationStatusEntry> {
    // Google's verifier formats X.509 serial numbers in base 16 before the
    // lookup. Entries containing only decimal digits are still hexadecimal
    // strings and must not be treated as base-10 aliases.
    entries.get(&serial.to_ascii_lowercase())
}

fn is_canonical_attestation_status_serial(serial: &str) -> bool {
    !serial.is_empty()
        && !serial.starts_with('0')
        && serial.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) || (b'A'..=b'F').contains(&byte)
        })
}

pub fn install_keybox_xml(contents: &[u8]) -> Result<()> {
    validate_keybox_xml(contents)?;
    let xml = str::from_utf8(contents).expect("validated keybox.xml is UTF-8");
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    write_keybox_xml(KEYBOX_PATH, xml)
}

/// Strict acceptance for a newly issued local RKP artifact. Ordinary Keybox import
/// keeps its existing compatibility semantics; only the new issuer uses this gate.
pub(crate) fn validate_issued_rkp_xml(contents: &[u8]) -> Result<()> {
    validate_issued_rkp_xml_with_roots(
        contents,
        &[
            GOOGLE_HARDWARE_ROOT_SPKI_DER.as_slice(),
            GOOGLE_EC_ROOT_SPKI_DER.as_slice(),
        ],
    )
}

fn validate_issued_rkp_xml_with_roots(contents: &[u8], roots: &[&[u8]]) -> Result<()> {
    validate_keybox_xml(contents)
        .map_err(|_| anyhow!("issued RKP Keybox failed private-key/leaf validation"))?;
    let text = str::from_utf8(contents).context("issued RKP Keybox is not UTF-8")?;
    let keybox = KeyBox::from_xml_str(text).map_err(|_| anyhow!("invalid issued RKP Keybox"))?;
    if keybox.rsa_info.is_some() {
        bail!("issued RKP result must contain only its generated EC key");
    }
    let info = keybox
        .ec_info
        .as_ref()
        .context("issued RKP result has no EC key")?;
    if !(2..=8).contains(&info.chain.len()) {
        bail!("invalid issued RKP certificate count");
    }
    let mut certificates = Vec::new();
    for item in &info.chain {
        let (rest, cert) = parse_x509_certificate(&item.encoded_certificate)
            .map_err(|_| anyhow!("invalid issued RKP X.509 certificate"))?;
        if !rest.is_empty() || !cert.validity().is_valid() {
            bail!("issued RKP certificate is expired, not yet valid or malformed");
        }
        certificates.push(cert);
    }
    let root = certificates.last().context("missing RKP root")?;
    if root.subject() != root.issuer()
        || root.verify_signature(None).is_err()
        || !roots.contains(&root.public_key().raw)
    {
        bail!("issued RKP chain has no valid pinned Google root");
    }
    for (index, pair) in certificates.windows(2).enumerate() {
        let child = &pair[0];
        let issuer = &pair[1];
        if child.issuer() != issuer.subject()
            || child.verify_signature(Some(issuer.public_key())).is_err()
        {
            bail!("issued RKP certificate signature or issuer mismatch");
        }
        let constraints = issuer
            .basic_constraints()
            .map_err(|_| anyhow!("invalid RKP CA constraints"))?
            .context("issued RKP issuer is not a CA")?;
        if !constraints.value.ca {
            bail!("issued RKP issuer is not a CA");
        }
        if let Some(limit) = constraints.value.path_len_constraint {
            // RFC 5280 path length excludes the target certificate, including
            // an attestation-signing target with its CA bit set.
            let intermediate_cas = certificates[1..=index]
                .iter()
                .filter(|cert| {
                    cert.subject() != cert.issuer()
                        && cert
                            .basic_constraints()
                            .ok()
                            .flatten()
                            .is_some_and(|bc| bc.value.ca)
                })
                .count();
            if intermediate_cas > limit as usize {
                bail!("issued RKP chain exceeds CA path length");
            }
        }
        if let Some(usage) = issuer
            .key_usage()
            .map_err(|_| anyhow!("invalid RKP key usage"))?
        {
            if !usage.value.key_cert_sign() {
                bail!("RKP issuer is not permitted to sign certificates");
            }
        }
    }
    Ok(())
}

fn write_bundled_keybox(path: &str) -> Result<()> {
    write_keybox_xml(path, BUNDLED_KEYBOX_XML)
}

pub fn ensure_keybox_file(path: &str) -> Result<()> {
    if Path::new(path).exists() {
        return Ok(());
    }
    info!("keybox.xml missing at {}; seeding bundled template", path);
    write_bundled_keybox(path)
}

fn is_bundled_keybox_xml(xml: &str) -> bool {
    xml.trim() == BUNDLED_KEYBOX_XML.trim()
}

fn retire_stale_keybox_bound_entries(current_identity: [u8; 32]) {
    if !db_retirement_allowed() {
        warn!("skipping stale keybox-bound DB retirement while active keybox came from fallback");
        return;
    }

    match crate::global::DB.with(|db| {
        db.borrow_mut()
            .retire_stale_keybox_bound_entries(current_identity)
    }) {
        Ok(0) => debug!("no stale keybox-bound key entries needed retirement"),
        Ok(retired) => info!("retired {retired} stale keybox-bound key entries"),
        Err(error) => error!("failed to retire stale keybox-bound key entries: {error:#}"),
    }
}

fn install_keybox(
    new_keybox: KeyBox,
    retire_db_entries: bool,
    db_retirement_allowed: bool,
) -> bool {
    let new_identity = new_keybox.identity_digest();
    let changed = {
        let mut keybox = KEYBOX.write().unwrap();
        let changed = keybox.identity_digest() != new_identity;
        *keybox = new_keybox;
        changed
    };
    KEYBOX_DB_RETIRE_ALLOWED.store(db_retirement_allowed, Ordering::Release);
    KEYBOX_RUNTIME_LOADED.store(true, Ordering::Release);

    if changed {
        crate::keymaster::keymint_device::clear_initialized_attestation_caches();
    }

    if retire_db_entries {
        retire_stale_keybox_bound_entries(new_identity);
    }

    changed
}

pub fn db_retirement_allowed() -> bool {
    KEYBOX_DB_RETIRE_ALLOWED.load(Ordering::Acquire)
}

fn is_fallback_continuation(keybox: &KeyBox, contents: &str) -> bool {
    let current_identity = KEYBOX
        .read()
        .map(|current| current.identity_digest())
        .unwrap_or([0u8; 32]);
    is_fallback_continuation_with_state(
        keybox,
        contents,
        KEYBOX_RUNTIME_LOADED.load(Ordering::Acquire),
        db_retirement_allowed(),
        current_identity,
    )
}

fn is_fallback_continuation_with_state(
    keybox: &KeyBox,
    contents: &str,
    runtime_loaded: bool,
    retirement_allowed: bool,
    current_identity: [u8; 32],
) -> bool {
    runtime_loaded
        && !retirement_allowed
        && is_bundled_keybox_xml(contents)
        && current_identity == keybox.identity_digest()
}

fn load_keybox_with_fallback(path: &str) -> Result<(KeyBox, bool)> {
    match fs::read_to_string(path) {
        Ok(contents) => match KeyBox::from_xml_str(&contents) {
            Ok(keybox) => {
                let fallback_origin = is_fallback_continuation(&keybox, &contents);
                Ok((keybox, fallback_origin))
            }
            Err(error) => {
                warn!(
                    "invalid keybox.xml at {}: {:#}; rewriting bundled template",
                    path, error
                );
                write_bundled_keybox(path)?;
                Ok((KeyBox::new(), true))
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!("keybox.xml missing at {}; writing bundled template", path);
            write_bundled_keybox(path)?;
            Ok((KeyBox::new(), true))
        }
        Err(error) => Err(error).with_context(|| format!("failed to read keybox.xml from {path}")),
    }
}

pub fn reload_from_disk() -> Result<bool> {
    reload_from_disk_inner(true)
}

fn reload_from_disk_inner(retire_db_entries: bool) -> Result<bool> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let (keybox, used_fallback) = load_keybox_with_fallback(KEYBOX_PATH)?;
    let changed = install_keybox(keybox, retire_db_entries, !used_fallback);
    if changed {
        info!(
            "active keybox identity updated from {} (fallback={})",
            KEYBOX_PATH, used_fallback
        );
    } else {
        debug!(
            "keybox reload completed without identity change (fallback={})",
            used_fallback
        );
    }
    Ok(changed)
}

pub fn initialize() -> Result<()> {
    ensure_keybox_file(KEYBOX_PATH)?;
    reload_from_disk_inner(false)?;
    KEYBOX_WATCHER.get_or_init(|| {
        if let Err(error) = kmr_common::runtime::file_watch::spawn_path_watcher(
            "omk-keybox-watch",
            PathBuf::from(KEYBOX_PATH),
            |_trigger| {
                if let Err(reload_error) = reload_from_disk() {
                    error!("failed to reload keybox.xml after change: {reload_error:#}");
                }
            },
        ) {
            error!("failed to watch keybox.xml: {error:#}");
        }
    });
    Ok(())
}

pub fn update_rsa_keybox(key_der: Vec<u8>, chain: Vec<keymint::Certificate>) -> Result<bool> {
    update_keybox_file(KeyAlgorithm::Rsa, key_der, chain)
}

pub fn update_ec_keybox(key_der: Vec<u8>, chain: Vec<keymint::Certificate>) -> Result<bool> {
    update_keybox_file(KeyAlgorithm::Ec, key_der, chain)
}

fn update_keybox_file(
    algorithm: KeyAlgorithm,
    key_der: Vec<u8>,
    chain: Vec<keymint::Certificate>,
) -> Result<bool> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let mut keybox = KEYBOX.read().unwrap().clone();
    keybox.update_keybox(algorithm, key_der, chain)?;
    write_keybox_xml(KEYBOX_PATH, &keybox.to_xml_string())?;
    Ok(install_keybox(keybox, true, true))
}

pub fn current_identity_digest() -> [u8; 32] {
    KEYBOX.read().unwrap().identity_digest()
}

pub(crate) fn signing_certificate_ders_from_disk() -> Result<Vec<Vec<u8>>> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let (keybox, _) = load_keybox_with_fallback(KEYBOX_PATH)?;
    Ok([keybox.rsa_info.as_ref(), keybox.ec_info.as_ref()]
        .into_iter()
        .flatten()
        .map(|info| info.chain[0].encoded_certificate.clone())
        .collect())
}

pub struct KeyboxManager;

impl RetrieveCertSigningInfo for KeyboxManager {
    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        let keybox = KEYBOX
            .read()
            .map_err(|_| kmr_common::km_err!(UnknownError, "failed to lock KEYBOX"))?;
        keybox.signing_info(key_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_ta::device::SigningKey;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
        SerialNumber,
    };

    fn write_temp_keybox(name: &str, contents: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("omk-keybox-{name}-{}.xml", std::process::id()));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_bundled_template() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        assert_eq!(keybox.ec_info.as_ref().unwrap().chain.len(), 2);
        assert_eq!(keybox.rsa_info.as_ref().unwrap().chain.len(), 2);
        assert_ne!(keybox.identity_digest(), [0u8; 32]);
    }

    #[test]
    fn rejects_invalid_xml() {
        assert!(KeyBox::from_xml_str("<AndroidAttestation/>").is_err());
    }

    #[test]
    fn webui_import_accepts_bundled_keybox() {
        validate_keybox_xml(BUNDLED_KEYBOX_XML.as_bytes()).unwrap();
    }

    #[test]
    fn webui_import_rejects_invalid_utf8() {
        let error = validate_keybox_xml(&[0xff]).unwrap_err();
        assert!(error.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn webui_import_rejects_oversized_xml_before_parsing() {
        let oversized = vec![b' '; MAX_KEYBOX_XML_BYTES + 1];
        let error = validate_keybox_xml(&oversized).unwrap_err();
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn certificate_serial_is_lowercase_hex_without_der_sign_padding() {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.serial_number = Some(SerialNumber::from_slice(&[0x80, 0x01]));
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();

        assert_eq!(
            canonical_certificate_serial(certificate.der()).unwrap(),
            "8001"
        );
    }

    #[test]
    fn keybox_serials_cover_every_algorithm_chain_and_are_deduplicated() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let expected = [keybox.ec_info.as_ref(), keybox.rsa_info.as_ref()]
            .into_iter()
            .flatten()
            .flat_map(|info| &info.chain)
            .map(|certificate| {
                canonical_certificate_serial(&certificate.encoded_certificate).unwrap()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        assert_eq!(keybox.certificate_serials().unwrap(), expected);
    }

    #[test]
    fn inspector_preserves_each_certificate_metadata_and_chain_order() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        for (algorithm, info) in [
            ("RSA", keybox.rsa_info.as_ref().unwrap()),
            ("EC", keybox.ec_info.as_ref().unwrap()),
        ] {
            let inspected = inspector_for_chain(algorithm, &info.chain).unwrap();
            assert_eq!(inspected.algorithm, algorithm);
            assert_eq!(inspected.chain_length, info.chain.len());
            assert_eq!(inspected.certificates.len(), info.chain.len());
            assert_eq!(
                inspected.serials,
                info.chain
                    .iter()
                    .map(|certificate| {
                        canonical_certificate_serial(&certificate.encoded_certificate).unwrap()
                    })
                    .collect::<Vec<_>>()
            );

            for (certificate, actual) in info.chain.iter().zip(inspected.certificates.iter()) {
                let (_, parsed) = parse_x509_certificate(&certificate.encoded_certificate).unwrap();
                assert_eq!(
                    actual.serial,
                    canonical_certificate_serial(&certificate.encoded_certificate).unwrap()
                );
                assert_eq!(actual.subject, parsed.subject().to_string());
                assert_eq!(actual.issuer, parsed.issuer().to_string());
                assert_eq!(
                    actual.valid_from,
                    parsed.validity().not_before.to_rfc2822().unwrap()
                );
                assert_eq!(
                    actual.valid_until,
                    parsed.validity().not_after.to_rfc2822().unwrap()
                );
            }
            let leaf = &inspected.certificates[0];
            assert_eq!(inspected.leaf_subject, leaf.subject);
            assert_eq!(inspected.leaf_issuer, leaf.issuer);
            assert_eq!(inspected.valid_from, leaf.valid_from);
            assert_eq!(inspected.valid_until, leaf.valid_until);
        }
    }

    #[test]
    fn inspector_rejects_a_chain_with_any_malformed_certificate() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        for (algorithm, info) in [
            ("RSA", keybox.rsa_info.as_ref().unwrap()),
            ("EC", keybox.ec_info.as_ref().unwrap()),
        ] {
            for index in 0..info.chain.len() {
                let mut chain = info.chain.clone();
                chain[index].encoded_certificate = vec![0xff, 0x00];

                // A malformed leaf or root must invalidate the entire view,
                // rather than leave the UI displaying a partial chain.
                assert!(inspector_for_chain(algorithm, &chain).is_none());
            }
        }
        assert!(inspector_for_chain("RSA", &[]).is_none());
    }

    #[test]
    fn keybox_serials_fail_when_any_presented_certificate_is_malformed() {
        let mut keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        keybox.ec_info.as_mut().unwrap().chain[1].encoded_certificate = vec![0x01, 0x02];

        assert!(keybox.certificate_serials().is_err());
    }

    #[test]
    fn attestation_status_reports_not_listed_suspended_and_revoked() {
        let contents = r#"{"entries":{"abc":{"status":"SUSPENDED"},"def":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"#;

        assert_eq!(
            classify_google_attestation_status(contents, &["123".to_string()]).unwrap(),
            KeyboxRevocationStatus::NotListed
        );
        assert_eq!(
            classify_google_attestation_status(contents, &["abc".to_string()]).unwrap(),
            KeyboxRevocationStatus::Suspended
        );
        assert_eq!(
            classify_google_attestation_status(contents, &["abc".to_string(), "def".to_string()])
                .unwrap(),
            KeyboxRevocationStatus::Revoked
        );
    }

    #[test]
    fn attestation_status_rejects_unknown_status_even_when_unmatched() {
        let contents = r#"{"entries":{"abc":{"status":"UNKNOWN"}}}"#;
        assert!(classify_google_attestation_status(contents, &["def".to_string()]).is_err());
    }

    #[test]
    fn attestation_status_rejects_malformed_or_out_of_schema_responses() {
        assert!(classify_google_attestation_status("not-json", &["abc".to_string()]).is_err());
        assert!(
            classify_google_attestation_status(r#"{"entries":{}}"#, &["abc".to_string()]).is_err()
        );
        assert!(classify_google_attestation_status(
            r#"{"entries":{},"unexpected":true}"#,
            &["abc".to_string()]
        )
        .is_err());
    }

    #[test]
    fn attestation_status_rejects_non_canonical_serial_numbers() {
        for serial in ["", "0abc", "GABC", "ab-c", "\u{4e32}\u{53f7}"] {
            let contents = format!(r#"{{"entries":{{"{serial}":{{"status":"REVOKED"}}}}}}"#);
            assert!(classify_google_attestation_status(&contents, &["abc".to_string()]).is_err());
        }
    }

    #[test]
    fn attestation_status_normalizes_uppercase_hex_and_keeps_digit_keys_hexadecimal() {
        let uppercase = r#"{"entries":{"ABCD":{"status":"REVOKED"}}}"#;
        assert_eq!(
            classify_google_attestation_status(uppercase, &["abcd".to_string()]).unwrap(),
            KeyboxRevocationStatus::Revoked
        );

        let digit_only_hex = r#"{"entries":{"4660":{"status":"SUSPENDED"}}}"#;
        assert_eq!(
            classify_google_attestation_status(digit_only_hex, &["4660".to_string()]).unwrap(),
            KeyboxRevocationStatus::Suspended
        );
        assert_eq!(
            classify_google_attestation_status(digit_only_hex, &["1234".to_string()]).unwrap(),
            KeyboxRevocationStatus::NotListed
        );
    }

    #[test]
    fn attestation_status_uri_is_exactly_scoped() {
        for allowed in [
            "https://android.googleapis.com/attestation/status",
            "https://android.googleapis.com:443/attestation/status",
        ] {
            assert!(is_allowed_attestation_status_uri(&allowed.parse().unwrap()));
        }
        for denied in [
            "http://android.googleapis.com/attestation/status",
            "https://android.googleapis.com/attestation/status?x=1",
            "https://android.googleapis.com/attestation/status/",
            "https://android.googleapis.com.evil.example/attestation/status",
            "https://user@android.googleapis.com/attestation/status",
            "https://android.googleapis.com:444/attestation/status",
        ] {
            assert!(!is_allowed_attestation_status_uri(&denied.parse().unwrap()));
        }
    }

    #[test]
    fn metadata_reads_tee_and_strongbox_from_leaf_organization() {
        let tee = metadata_for_chain(&[keymint::Certificate {
            encoded_certificate: certificate_with_organization("TEE", false),
        }]);
        assert_eq!(tee.source, KeyboxSource::Unknown);
        assert_eq!(tee.level, KeyboxLevel::Tee);

        let strongbox = metadata_for_chain(&[keymint::Certificate {
            encoded_certificate: certificate_with_organization("StrongBox", false),
        }]);
        assert_eq!(strongbox.source, KeyboxSource::Unknown);
        assert_eq!(strongbox.level, KeyboxLevel::Strongbox);
    }

    #[test]
    fn metadata_rejects_unknown_leaf_organization() {
        let metadata = metadata_for_chain(&[keymint::Certificate {
            encoded_certificate: certificate_with_organization("Google LLC", false),
        }]);
        assert_eq!(metadata.level, KeyboxLevel::Unknown);
    }

    #[test]
    fn metadata_accepts_legacy_title_level_when_organization_is_absent() {
        let metadata = metadata_for_chain(&[keymint::Certificate {
            encoded_certificate: certificate_with_title("TEE"),
        }]);
        assert_eq!(metadata.level, KeyboxLevel::Tee);
    }

    #[test]
    fn rkp_extension_without_pinned_google_root_is_not_remote() {
        let metadata = metadata_for_chain(&[keymint::Certificate {
            // A matching name and the RKP OID are not sufficient to establish
            // that this is a Google-issued chain.
            encoded_certificate: certificate_with_organization("Google LLC", true),
        }]);
        assert_eq!(metadata.source, KeyboxSource::Unknown);
        assert_eq!(metadata.level, KeyboxLevel::Unknown);
    }

    #[test]
    fn rejects_spliced_google_ec_root() {
        let leaf = certificate_with_organization("TEE", true);
        let root = decode_pem(GOOGLE_EC_ROOT_CERT_PEM).unwrap();
        let metadata = metadata_for_chain(&[
            keymint::Certificate {
                encoded_certificate: leaf,
            },
            keymint::Certificate {
                encoded_certificate: root,
            },
        ]);
        assert_eq!(metadata.source, KeyboxSource::Unknown);
        assert_eq!(metadata.level, KeyboxLevel::Tee);
    }

    #[test]
    fn recognizes_signed_chain_anchored_by_pinned_root() {
        let (hardware_chain, hardware_root_spki) = generated_signed_chain("StrongBox", false, true);
        let hardware =
            metadata_for_chain_with_roots(&hardware_chain, &[hardware_root_spki.as_slice()]);
        assert_eq!(hardware.source, KeyboxSource::GoogleHardware);
        assert_eq!(hardware.level, KeyboxLevel::Strongbox);

        let (remote_chain, remote_root_spki) = generated_signed_chain("TEE", true, false);
        let remote = metadata_for_chain_with_roots(&remote_chain, &[remote_root_spki.as_slice()]);
        assert_eq!(remote.source, KeyboxSource::GoogleRemote);
        assert_eq!(remote.level, KeyboxLevel::Tee);

        let (unknown_chain, unknown_root_spki) = generated_signed_chain("TEE", false, false);
        let unknown =
            metadata_for_chain_with_roots(&unknown_chain, &[unknown_root_spki.as_slice()]);
        assert_eq!(unknown.source, KeyboxSource::Unknown);
    }

    #[test]
    fn recognizes_droid_ca2_chain_without_provisioning_extension() {
        let (chain, root_spki) = generated_droid_ca2_chain();
        let metadata = metadata_for_chain_with_roots(&chain, &[root_spki.as_slice()]);
        assert_eq!(metadata.source, KeyboxSource::GoogleRemote);
        assert_eq!(metadata.level, KeyboxLevel::Tee);
    }

    #[test]
    fn rejects_tampered_chain_anchored_by_pinned_root() {
        let (mut chain, root_spki) = generated_signed_chain("TEE", true, false);
        let signature_byte = chain[0].encoded_certificate.last_mut().unwrap();
        *signature_byte ^= 1;

        let metadata = metadata_for_chain_with_roots(&chain, &[root_spki.as_slice()]);
        assert_eq!(metadata.source, KeyboxSource::Unknown);
        assert_eq!(metadata.level, KeyboxLevel::Tee);
    }

    #[test]
    fn pinned_google_ec_root_without_provisioning_cert_is_unknown() {
        let root = decode_pem(GOOGLE_EC_ROOT_CERT_PEM).unwrap();
        let metadata = metadata_for_chain(&[keymint::Certificate {
            encoded_certificate: root,
        }]);
        assert_eq!(metadata.source, KeyboxSource::Unknown);
    }

    #[test]
    fn pinned_legacy_google_root_without_provisioning_cert_is_unknown() {
        let root = decode_pem(GOOGLE_HARDWARE_ROOT_CERT_PEM).unwrap();
        let metadata = metadata_for_chain(&[keymint::Certificate {
            encoded_certificate: root,
        }]);
        assert_eq!(metadata.source, KeyboxSource::Unknown);
    }

    #[test]
    fn rejects_spliced_legacy_google_root() {
        let leaf = certificate_with_organization("TEE", true);
        let root = decode_pem(GOOGLE_HARDWARE_ROOT_CERT_PEM).unwrap();
        let metadata = metadata_for_chain(&[
            keymint::Certificate {
                encoded_certificate: leaf,
            },
            keymint::Certificate {
                encoded_certificate: root,
            },
        ]);
        assert_eq!(metadata.source, KeyboxSource::Unknown);
        assert_eq!(metadata.level, KeyboxLevel::Tee);
    }

    #[test]
    fn verifies_pinned_google_root_self_signatures() {
        for root_pem in [GOOGLE_EC_ROOT_CERT_PEM, GOOGLE_HARDWARE_ROOT_CERT_PEM] {
            let root_der = decode_pem(root_pem).unwrap();
            assert!(certificate_signature_is_valid(&root_der, &root_der));
        }
    }

    #[test]
    fn mixed_or_unknown_algorithm_sources_are_unknown() {
        let hardware = ChainMetadata {
            source: KeyboxSource::GoogleHardware,
            level: KeyboxLevel::Tee,
        };
        let remote = ChainMetadata {
            source: KeyboxSource::GoogleRemote,
            level: KeyboxLevel::Tee,
        };
        let unknown = ChainMetadata {
            source: KeyboxSource::Unknown,
            level: KeyboxLevel::Tee,
        };

        assert_eq!(
            combine_chain_metadata([hardware, remote]).source,
            KeyboxSource::Unknown
        );
        assert_eq!(
            combine_chain_metadata([hardware, unknown]).source,
            KeyboxSource::Unknown
        );
        assert_eq!(
            combine_chain_metadata([hardware, hardware]).source,
            KeyboxSource::GoogleHardware
        );
        assert_eq!(
            combine_chain_metadata([remote]).source,
            KeyboxSource::GoogleRemote
        );
        assert_eq!(
            combine_chain_metadata([remote, remote]).source,
            KeyboxSource::GoogleRemote
        );
    }

    const GOOGLE_EC_ROOT_CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----";

    const GOOGLE_HARDWARE_ROOT_CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----";

    fn certificate_with_organization(organization: &str, rkp_extension: bool) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::OrganizationName, organization);
        if rkp_extension {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 30],
                    Vec::new(),
                ));
        }
        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    fn certificate_with_title(title: &str) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CustomDnType(vec![2, 5, 4, 12]), title);
        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    fn generated_signed_chain(
        organization: &str,
        rkp_extension: bool,
        factory_serial: bool,
    ) -> (Vec<keymint::Certificate>, Vec<u8>) {
        let mut root_params = CertificateParams::new(Vec::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Metadata test root");
        let root_key = KeyPair::generate().unwrap();
        let root_certificate = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, root_key);

        let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationName, organization);
        if factory_serial {
            leaf_params
                .distinguished_name
                .push(DnType::CustomDnType(vec![2, 5, 4, 5]), "factory-key-id");
        }
        if rkp_extension {
            leaf_params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 30],
                    Vec::new(),
                ));
        }
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_certificate = leaf_params.signed_by(&leaf_key, &root_issuer).unwrap();
        let root_der = root_certificate.der().to_vec();
        let parsed_root = <Certificate as x509_der::Decode>::from_der(&root_der).unwrap();
        let root_spki = parsed_root
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();

        (
            vec![
                keymint::Certificate {
                    encoded_certificate: leaf_certificate.der().to_vec(),
                },
                keymint::Certificate {
                    encoded_certificate: root_der,
                },
            ],
            root_spki,
        )
    }

    fn issued_fixture(root_ca: bool, expired: bool, signing_usage: bool) -> (String, Vec<u8>) {
        let mut root_params = CertificateParams::new(Vec::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Issuance test root");
        root_params.is_ca = if root_ca {
            IsCa::Ca(BasicConstraints::Constrained(0))
        } else {
            IsCa::NoCa
        };
        root_params.key_usages = vec![if signing_usage {
            rcgen::KeyUsagePurpose::KeyCertSign
        } else {
            rcgen::KeyUsagePurpose::DigitalSignature
        }];
        let root_key = KeyPair::generate().unwrap();
        let root = root_params.self_signed(&root_key).unwrap();
        let (_, parsed) = parse_x509_certificate(root.der()).unwrap();
        let root_spki = parsed.public_key().raw.to_vec();
        let issuer = Issuer::new(root_params, root_key);
        let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Issued attestation key");
        leaf_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        if expired {
            leaf_params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            leaf_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let xml = format!(
            "<AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes><Keybox DeviceID=\"test\"><Key algorithm=\"ecdsa\"><PrivateKey format=\"pem\">{}</PrivateKey><CertificateChain><NumberOfCertificates>2</NumberOfCertificates><Certificate format=\"pem\">{}</Certificate><Certificate format=\"pem\">{}</Certificate></CertificateChain></Key></Keybox></AndroidAttestation>",
            leaf_key.serialize_pem(), leaf.pem(), root.pem(),
        );
        (xml, root_spki)
    }

    #[test]
    fn issued_chain_accepts_matching_key_and_trusted_ca() {
        let (xml, root) = issued_fixture(true, false, true);
        validate_issued_rkp_xml_with_roots(xml.as_bytes(), &[&root]).unwrap();
        // Tests never add their generated root to the production trust set.
        assert!(validate_issued_rkp_xml(xml.as_bytes()).is_err());
    }

    #[test]
    fn issued_chain_rejects_expired_non_ca_and_wrong_usage() {
        for (ca, expired, usage) in [
            (true, true, true),
            (false, false, true),
            (true, false, false),
        ] {
            let (xml, root) = issued_fixture(ca, expired, usage);
            assert!(validate_issued_rkp_xml_with_roots(xml.as_bytes(), &[&root]).is_err());
        }
    }

    #[test]
    fn issued_chain_rejects_signature_tampering_and_key_mismatch() {
        let (xml, root) = issued_fixture(true, false, true);
        let mut keybox = KeyBox::from_xml_str(&xml).unwrap();
        let leaf = &mut keybox.ec_info.as_mut().unwrap().chain[0].encoded_certificate;
        *leaf.last_mut().unwrap() ^= 1;
        assert!(
            validate_issued_rkp_xml_with_roots(keybox.to_xml_string().as_bytes(), &[&root])
                .is_err()
        );
        let other_key = KeyPair::generate().unwrap().serialize_pem();
        let start = xml.find("-----BEGIN PRIVATE KEY-----").unwrap();
        let end =
            xml.find("-----END PRIVATE KEY-----").unwrap() + "-----END PRIVATE KEY-----".len();
        let mismatch = format!("{}{}{}", &xml[..start], other_key, &xml[end..]);
        assert!(validate_issued_rkp_xml_with_roots(mismatch.as_bytes(), &[&root]).is_err());
    }

    fn generated_droid_ca2_chain() -> (Vec<keymint::Certificate>, Vec<u8>) {
        let mut root_params = CertificateParams::new(Vec::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Metadata test root");
        let root_key = KeyPair::generate().unwrap();
        let root_certificate = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, root_key);

        let mut ca2_params = CertificateParams::new(Vec::new()).unwrap();
        ca2_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca2_params
            .distinguished_name
            .push(DnType::CommonName, "Droid CA2");
        ca2_params
            .distinguished_name
            .push(DnType::OrganizationName, "Google LLC");
        let ca2_key = KeyPair::generate().unwrap();
        let ca2_certificate = ca2_params.signed_by(&ca2_key, &root_issuer).unwrap();
        let ca2_issuer = Issuer::new(ca2_params, ca2_key);

        let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationName, "TEE");
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_certificate = leaf_params.signed_by(&leaf_key, &ca2_issuer).unwrap();
        let root_der = root_certificate.der().to_vec();
        let parsed_root = <Certificate as x509_der::Decode>::from_der(&root_der).unwrap();
        let root_spki = parsed_root
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();

        (
            vec![
                keymint::Certificate {
                    encoded_certificate: leaf_certificate.der().to_vec(),
                },
                keymint::Certificate {
                    encoded_certificate: ca2_certificate.der().to_vec(),
                },
                keymint::Certificate {
                    encoded_certificate: root_der,
                },
            ],
            root_spki,
        )
    }

    #[test]
    fn classifies_installed_keybox_contents_without_modifying_them() {
        assert_eq!(
            classify_keybox_xml(BUNDLED_KEYBOX_XML.as_bytes()),
            KeyboxFileState::Bundled
        );
        let custom = format!("{BUNDLED_KEYBOX_XML}\n<!-- selected by user -->\n");
        assert_eq!(
            classify_keybox_xml(custom.as_bytes()),
            KeyboxFileState::Custom
        );
        assert_eq!(
            classify_keybox_xml(b"<AndroidAttestation/>"),
            KeyboxFileState::Invalid
        );
    }

    #[test]
    fn identity_changes_when_chain_changes() {
        let original = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let mut changed = original.clone();
        let ec_info = changed.ec_info.as_mut().unwrap();
        ec_info.chain.push(ec_info.chain[0].clone());
        changed.refresh_identity_digest().unwrap();

        let modified = KeyBox::from_xml_str(&changed.to_xml_string()).unwrap();
        assert_ne!(original.identity_digest(), modified.identity_digest());
    }

    #[test]
    fn rejects_mismatched_private_key_and_certificate_chain() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let rsa_cert = encode_pem_block(
            "CERTIFICATE",
            &keybox.rsa_info.as_ref().unwrap().chain[0].encoded_certificate,
        );
        let ec_cert = encode_pem_block(
            "CERTIFICATE",
            &keybox.ec_info.as_ref().unwrap().chain[0].encoded_certificate,
        );
        let modified_xml = BUNDLED_KEYBOX_XML.replacen(&rsa_cert, &ec_cert, 1);
        assert!(KeyBox::from_xml_str(&modified_xml).is_err());
    }

    fn single_algorithm_keybox(algorithm: KeyAlgorithm) -> KeyBox {
        let mut keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        match algorithm {
            KeyAlgorithm::Ec => keybox.rsa_info = None,
            KeyAlgorithm::Rsa => keybox.ec_info = None,
        }
        keybox.refresh_identity_digest().unwrap();
        keybox
    }

    fn pkcs8_private_key(info: &CertSignAlgoInfo, key_der: &[u8]) -> Vec<u8> {
        #[derive(der::Sequence)]
        struct PrivateKeyInfo {
            version: u8,
            algorithm: x509_cert::spki::AlgorithmIdentifierOwned,
            private_key: der::asn1::OctetString,
        }

        let certificate =
            <Certificate as x509_der::Decode>::from_der(&info.chain[0].encoded_certificate)
                .unwrap();
        PrivateKeyInfo {
            version: 0,
            algorithm: certificate
                .tbs_certificate()
                .subject_public_key_info()
                .algorithm
                .clone(),
            private_key: der::asn1::OctetString::new(key_der).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn ec_only_keybox_signs_rsa_and_ec_attestations_with_ec_key() {
        let ec_only = single_algorithm_keybox(KeyAlgorithm::Ec);
        let xml = ec_only.to_xml_string();
        assert!(xml.contains("<NumberOfKeyboxes>1</NumberOfKeyboxes>"));
        assert!(!xml.contains("algorithm=\"rsa\""));

        let parsed = KeyBox::from_xml_str(&xml).unwrap();
        assert!(parsed.rsa_info.is_none());
        assert!(parsed.ec_info.is_some());
        assert_eq!(parsed.identity_digest(), ec_only.identity_digest());

        for algo_hint in [SigningAlgorithm::Rsa, SigningAlgorithm::Ec] {
            let snapshot = parsed
                .signing_info(SigningKeyType {
                    which: SigningKey::Batch,
                    algo_hint,
                })
                .unwrap();
            assert!(matches!(&snapshot.signing_key, KeyMaterial::Ec(_, _, _)));
            validate_chain_matches_key(
                &snapshot.signing_key,
                &snapshot.cert_chain,
                KeyAlgorithm::Ec,
            )
            .unwrap();
        }
    }

    #[test]
    fn ec_pkcs8_import_preserves_identity_and_sec1_export() {
        #[derive(der::Sequence)]
        struct EcPrivateKey {
            version: u8,
            private_key: der::asn1::OctetString,
            #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
            parameters: Option<der::asn1::ObjectIdentifier>,
            #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
            public_key: Option<der::asn1::BitString>,
        }

        for keybox in [KeyBox::new(), single_algorithm_keybox(KeyAlgorithm::Ec)] {
            let ec_info = keybox.ec_info.as_ref().unwrap();
            let sec1_xml = keybox.to_xml_string();
            let mut inner = <EcPrivateKey as der::Decode>::from_der(&ec_info.key_der).unwrap();
            assert!(inner.parameters.take().is_some());
            let without_parameters = inner.to_der().unwrap();

            // PKCS#8 may carry the curve only in its outer AlgorithmIdentifier.
            for inner_der in [ec_info.key_der.as_slice(), without_parameters.as_slice()] {
                let pkcs8 = pkcs8_private_key(ec_info, inner_der);
                let pkcs8_xml = sec1_xml.replacen(
                    &encode_pem_block("EC PRIVATE KEY", &ec_info.key_der),
                    &encode_pem_block("PRIVATE KEY", &pkcs8),
                    1,
                );
                assert_ne!(pkcs8_xml, sec1_xml);
                validate_keybox_xml(pkcs8_xml.as_bytes()).unwrap();
                let parsed = KeyBox::from_xml_str(&pkcs8_xml).unwrap();
                assert_eq!(parsed.rsa_info.is_some(), keybox.rsa_info.is_some());
                assert_eq!(parsed.identity_digest(), keybox.identity_digest());
                assert_eq!(parsed.to_xml_string(), sec1_xml);
                assert_eq!(
                    parsed.certificate_serials().unwrap(),
                    keybox.certificate_serials().unwrap()
                );
                for algo_hint in [SigningAlgorithm::Rsa, SigningAlgorithm::Ec] {
                    let snapshot = parsed
                        .signing_info(SigningKeyType {
                            which: SigningKey::Batch,
                            algo_hint,
                        })
                        .unwrap();
                    let algorithm = if keybox.rsa_info.is_some()
                        && matches!(algo_hint, SigningAlgorithm::Rsa)
                    {
                        assert!(matches!(&snapshot.signing_key, KeyMaterial::Rsa(_)));
                        KeyAlgorithm::Rsa
                    } else {
                        assert!(matches!(&snapshot.signing_key, KeyMaterial::Ec(_, _, _)));
                        KeyAlgorithm::Ec
                    };
                    validate_chain_matches_key(
                        &snapshot.signing_key,
                        &snapshot.cert_chain,
                        algorithm,
                    )
                    .unwrap();
                }
            }
        }
    }

    #[test]
    fn ec_pkcs8_import_rejects_invalid_keys_and_mismatched_certificates() {
        let ec_only = single_algorithm_keybox(KeyAlgorithm::Ec);
        let ec_info = ec_only.ec_info.as_ref().unwrap();
        let sec1_xml = ec_only.to_xml_string();
        let sec1_pem = encode_pem_block("EC PRIVATE KEY", &ec_info.key_der);
        let pkcs8 = pkcs8_private_key(ec_info, &ec_info.key_der);
        let bundled = KeyBox::new();
        let rsa_info = bundled.rsa_info.as_ref().unwrap();
        for invalid_key in [
            vec![0x30, 0x00],
            pkcs8[..pkcs8.len() - 1].to_vec(),
            pkcs8_private_key(rsa_info, &rsa_info.key_der),
        ] {
            let invalid_xml =
                sec1_xml.replacen(&sec1_pem, &encode_pem_block("PRIVATE KEY", &invalid_key), 1);
            assert!(validate_keybox_xml(invalid_xml.as_bytes()).is_err());
        }

        let pkcs8_xml = sec1_xml.replacen(&sec1_pem, &encode_pem_block("PRIVATE KEY", &pkcs8), 1);
        let other_key = KeyPair::generate().unwrap();
        let other_certificate = CertificateParams::new(Vec::new())
            .unwrap()
            .self_signed(&other_key)
            .unwrap();
        let mismatch = pkcs8_xml.replacen(
            &encode_pem_block("CERTIFICATE", &ec_info.chain[0].encoded_certificate),
            &encode_pem_block("CERTIFICATE", other_certificate.der()),
            1,
        );
        let error = validate_keybox_xml(mismatch.as_bytes()).unwrap_err();
        assert!(format!("{error:#}").contains("does not match the supplied private key"));

        let wrong_count = pkcs8_xml.replacen(
            &format!(
                "<NumberOfCertificates>{}</NumberOfCertificates>",
                ec_info.chain.len()
            ),
            &format!(
                "<NumberOfCertificates>{}</NumberOfCertificates>",
                ec_info.chain.len() + 1
            ),
            1,
        );
        let error = validate_keybox_xml(wrong_count.as_bytes()).unwrap_err();
        assert!(format!("{error:#}").contains("certificate count mismatch"));
    }

    #[test]
    fn rsa_only_keybox_signs_rsa_and_ec_attestations_with_rsa_key() {
        let rsa_only = single_algorithm_keybox(KeyAlgorithm::Rsa);
        let xml = rsa_only.to_xml_string();
        assert!(xml.contains("<NumberOfKeyboxes>1</NumberOfKeyboxes>"));
        assert!(!xml.contains("algorithm=\"ecdsa\""));
        validate_keybox_xml(xml.as_bytes()).unwrap();

        let parsed = KeyBox::from_xml_str(&xml).unwrap();
        assert!(parsed.rsa_info.is_some());
        assert!(parsed.ec_info.is_none());
        assert_eq!(parsed.identity_digest(), rsa_only.identity_digest());
        assert_eq!(
            parsed.certificate_serials().unwrap(),
            rsa_only.certificate_serials().unwrap()
        );

        for algo_hint in [SigningAlgorithm::Rsa, SigningAlgorithm::Ec] {
            let snapshot = parsed
                .signing_info(SigningKeyType {
                    which: SigningKey::Batch,
                    algo_hint,
                })
                .unwrap();
            assert!(matches!(&snapshot.signing_key, KeyMaterial::Rsa(_)));
            validate_chain_matches_key(
                &snapshot.signing_key,
                &snapshot.cert_chain,
                KeyAlgorithm::Rsa,
            )
            .unwrap();
        }
    }

    #[test]
    fn rsa_only_pkcs8_import_preserves_identity_and_pkcs1_export() {
        let rsa_only = single_algorithm_keybox(KeyAlgorithm::Rsa);
        let rsa_info = rsa_only.rsa_info.as_ref().unwrap();
        let pkcs8 = pkcs8_private_key(rsa_info, &rsa_info.key_der);
        let pkcs1_xml = rsa_only.to_xml_string();
        let pkcs8_xml = pkcs1_xml.replace(
            &encode_pem_block("RSA PRIVATE KEY", &rsa_info.key_der),
            &encode_pem_block("PRIVATE KEY", &pkcs8),
        );
        assert_ne!(pkcs8_xml, pkcs1_xml);
        validate_keybox_xml(pkcs8_xml.as_bytes()).unwrap();
        let parsed = KeyBox::from_xml_str(&pkcs8_xml).unwrap();
        assert!(parsed.ec_info.is_none());
        assert_eq!(parsed.identity_digest(), rsa_only.identity_digest());
        assert_eq!(parsed.to_xml_string(), pkcs1_xml);
        for algo_hint in [SigningAlgorithm::Rsa, SigningAlgorithm::Ec] {
            let snapshot = parsed
                .signing_info(SigningKeyType {
                    which: SigningKey::Batch,
                    algo_hint,
                })
                .unwrap();
            assert!(matches!(&snapshot.signing_key, KeyMaterial::Rsa(_)));
            validate_chain_matches_key(
                &snapshot.signing_key,
                &snapshot.cert_chain,
                KeyAlgorithm::Rsa,
            )
            .unwrap();
        }

        // Accepting another encoding must not bypass private-key/leaf checks.
        let bundled = KeyBox::new();
        let mismatch = pkcs8_xml.replace(
            &encode_pem_block("CERTIFICATE", &rsa_info.chain[0].encoded_certificate),
            &encode_pem_block(
                "CERTIFICATE",
                &bundled.ec_info.as_ref().unwrap().chain[0].encoded_certificate,
            ),
        );
        assert!(validate_keybox_xml(mismatch.as_bytes()).is_err());
    }

    #[test]
    fn rsa_only_keybox_produces_verifiable_rsa_and_ec_attestations() {
        assert_keybox_produces_verifiable_rsa_and_ec_attestations(
            single_algorithm_keybox(KeyAlgorithm::Rsa),
            KeyAlgorithm::Rsa,
        );
    }

    #[test]
    fn ec_only_pkcs8_keybox_produces_verifiable_rsa_and_ec_attestations() {
        let ec_only = single_algorithm_keybox(KeyAlgorithm::Ec);
        let ec_info = ec_only.ec_info.as_ref().unwrap();
        let pkcs8 = pkcs8_private_key(ec_info, &ec_info.key_der);
        let sec1_xml = ec_only.to_xml_string();
        let pkcs8_xml = sec1_xml.replacen(
            &encode_pem_block("EC PRIVATE KEY", &ec_info.key_der),
            &encode_pem_block("PRIVATE KEY", &pkcs8),
            1,
        );
        assert_ne!(pkcs8_xml, sec1_xml);
        let imported = KeyBox::from_xml_str(&pkcs8_xml).unwrap();
        assert!(imported.rsa_info.is_none());
        assert_keybox_produces_verifiable_rsa_and_ec_attestations(imported, KeyAlgorithm::Ec);
    }

    fn assert_keybox_produces_verifiable_rsa_and_ec_attestations(
        keybox: KeyBox,
        signer: KeyAlgorithm,
    ) {
        use crate::keymaster::keymint_device::tests::{set_boot_info, test_ta};
        use crate::plat::attestation::{
            ensure_sequence, parse_tlv, TlvClass, ANDROID_ATTESTATION_OID,
        };
        use kmr_wire::{
            keymint::{Algorithm, DateTime, Digest, EcCurve, KeyParam, KeyPurpose, PaddingMode},
            GenerateKeyRequest, KeySizeInBits, PerformOpReq, PerformOpRsp, RsaExponent,
            SetHalInfoRequest,
        };
        use x509_der::Decode;

        struct TestSigningInfo(KeyBox);
        impl RetrieveCertSigningInfo for TestSigningInfo {
            fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
                self.0.signing_info(key_type)
            }
        }

        let (expected_chain, expected_signature_oid) = match signer {
            KeyAlgorithm::Rsa => (
                keybox.rsa_info.as_ref().unwrap().chain.clone(),
                "1.2.840.113549.1.1.11",
            ),
            KeyAlgorithm::Ec => (
                keybox.ec_info.as_ref().unwrap().chain.clone(),
                "1.2.840.10045.4.3.2",
            ),
        };
        let mut ta = test_ta();
        assert_eq!(set_boot_info(&mut ta), 0);
        assert_eq!(
            ta.process_req(PerformOpReq::SetHalInfo(SetHalInfoRequest {
                os_version: 150000,
                os_patchlevel: 202609,
                vendor_patchlevel: 20260901,
            }))
            .error_code,
            0
        );
        ta.set_sign_info(Some(Box::new(TestSigningInfo(keybox))));

        let attestation_oid = ANDROID_ATTESTATION_OID.to_string();
        for (profile, expected_patchlevels) in [
            (None, [202609, 20260901, 20250605]),
            (
                Some(kmr_ta::RequestPatchLevels {
                    os_patchlevel: 202604,
                    vendor_patchlevel: 20260405,
                    boot_patchlevel: 20260405,
                }),
                [202604, 20260405, 20260405],
            ),
            (
                Some(kmr_ta::RequestPatchLevels {
                    os_patchlevel: 202605,
                    vendor_patchlevel: 20260505,
                    boot_patchlevel: 20260505,
                }),
                [202605, 20260505, 20260505],
            ),
            (None, [202609, 20260901, 20250605]),
        ] {
            for algorithm in [Algorithm::Rsa, Algorithm::Ec] {
                let mut key_params = vec![
                    KeyParam::Algorithm(algorithm),
                    KeyParam::Purpose(KeyPurpose::Sign),
                    KeyParam::Digest(Digest::Sha256),
                    KeyParam::NoAuthRequired,
                    KeyParam::AttestationChallenge(b"single-algorithm-keybox".to_vec()),
                    KeyParam::AttestationApplicationId(b"test".to_vec()),
                    KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: 0 }),
                    KeyParam::CertificateNotAfter(DateTime {
                        ms_since_epoch: 2_000_000_000_000,
                    }),
                ];
                if algorithm == Algorithm::Rsa {
                    key_params.extend([
                        KeyParam::KeySize(KeySizeInBits(2048)),
                        KeyParam::RsaPublicExponent(RsaExponent(65537)),
                        KeyParam::Padding(PaddingMode::RsaPkcs115Sign),
                    ]);
                } else {
                    key_params.push(KeyParam::EcCurve(EcCurve::P256));
                }
                let response = ta.process_req_with_patchlevels(
                    PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
                        key_params,
                        attestation_key: None,
                    }),
                    profile,
                );
                assert_eq!(
                    response.error_code, 0,
                    "{algorithm:?}, profile {profile:?}: {response:?}"
                );
                let Some(PerformOpRsp::DeviceGenerateKey(response)) = response.rsp else {
                    panic!("unexpected generate response")
                };
                let chain = response.ret.certificate_chain;
                assert_eq!(chain.len(), expected_chain.len() + 1);
                assert_eq!(&chain[1..], &expected_chain);
                let (_, leaf) = parse_x509_certificate(&chain[0].encoded_certificate).unwrap();
                let (_, issuer) = parse_x509_certificate(&chain[1].encoded_certificate).unwrap();
                assert_eq!(
                    leaf.signature_algorithm.algorithm.to_id_string(),
                    expected_signature_oid
                );
                assert_eq!(leaf.issuer(), issuer.subject());
                match signer {
                    KeyAlgorithm::Rsa => {
                        // The bundled RSA signer is 1024-bit; x509-parser's default
                        // verifier requires 2048 bits. Verify this fixture explicitly
                        // without changing production certificate-validation policy.
                        ring::signature::UnparsedPublicKey::new(
                            &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                            issuer.public_key().subject_public_key.data.as_ref(),
                        )
                        .verify(
                            leaf.tbs_certificate.as_ref(),
                            leaf.signature_value.data.as_ref(),
                        )
                        .unwrap();
                    }
                    KeyAlgorithm::Ec => leaf.verify_signature(Some(issuer.public_key())).unwrap(),
                }
                let subject_oid = leaf.public_key().algorithm.algorithm.to_id_string();
                assert_eq!(
                    subject_oid,
                    if algorithm == Algorithm::Rsa {
                        "1.2.840.113549.1.1.1"
                    } else {
                        "1.2.840.10045.2.1"
                    }
                );

                // Inspect the signed extension rather than the returned characteristics.
                let extension = leaf
                    .extensions()
                    .iter()
                    .find(|extension| extension.oid.to_id_string() == attestation_oid)
                    .expect("Android attestation extension missing");
                let (attestation, rest) = parse_tlv(extension.value).unwrap();
                ensure_sequence(attestation, "attestation extension").unwrap();
                assert!(rest.is_empty());
                let mut fields = attestation.value;
                for _ in 0..7 {
                    let (_, next) = parse_tlv(fields).unwrap();
                    fields = next;
                }
                let (hardware_enforced, rest) = parse_tlv(fields).unwrap();
                ensure_sequence(hardware_enforced, "hardwareEnforced").unwrap();
                assert!(rest.is_empty());
                let mut authorizations = hardware_enforced.value;
                let mut signed_patchlevels = [None; 3];
                while !authorizations.is_empty() {
                    let (field, rest) = parse_tlv(authorizations).unwrap();
                    authorizations = rest;
                    let index = match field.tag_number {
                        706 => 0,
                        718 => 1,
                        719 => 2,
                        _ => continue,
                    };
                    assert_eq!(field.class, TlvClass::ContextSpecific);
                    assert!(field.constructed);
                    let patchlevel = u32::from_der(field.value).unwrap();
                    assert!(signed_patchlevels[index].replace(patchlevel).is_none());
                }
                assert_eq!(
                    signed_patchlevels,
                    expected_patchlevels.map(Some),
                    "{algorithm:?}, profile {profile:?}"
                );
            }
        }
    }

    #[test]
    fn signing_snapshot_keeps_key_chain_and_digest_in_sync() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        let rsa_snapshot = keybox
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Rsa,
            })
            .unwrap();
        assert_eq!(rsa_snapshot.identity_digest, keybox.identity_digest());
        assert!(matches!(&rsa_snapshot.signing_key, KeyMaterial::Rsa(_)));
        validate_chain_matches_key(
            &rsa_snapshot.signing_key,
            &rsa_snapshot.cert_chain,
            KeyAlgorithm::Rsa,
        )
        .unwrap();

        let ec_snapshot = keybox
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Ec,
            })
            .unwrap();
        assert_eq!(ec_snapshot.identity_digest, keybox.identity_digest());
        assert!(matches!(&ec_snapshot.signing_key, KeyMaterial::Ec(_, _, _)));
        validate_chain_matches_key(
            &ec_snapshot.signing_key,
            &ec_snapshot.cert_chain,
            KeyAlgorithm::Ec,
        )
        .unwrap();
    }

    #[test]
    fn invalid_file_falls_back_to_bundled_template() {
        let path = write_temp_keybox("invalid", "<not-xml>");
        let (keybox, used_fallback) = load_keybox_with_fallback(path.to_str().unwrap()).unwrap();
        assert!(used_fallback);
        assert_eq!(keybox.identity_digest(), KeyBox::new().identity_digest());
        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("<AndroidAttestation>"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn explicit_bundled_template_is_retirement_eligible_before_runtime_fallback() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        assert!(!is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            false,
            false,
            keybox.identity_digest(),
        ));
    }

    #[test]
    fn non_bundled_keybox_is_retirement_eligible() {
        let modified_xml = format!("{BUNDLED_KEYBOX_XML}\n<!-- explicit local keybox -->\n");
        let path = write_temp_keybox("modified", &modified_xml);

        let (_, used_fallback) = load_keybox_with_fallback(path.to_str().unwrap()).unwrap();

        assert!(!used_fallback);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rewritten_bundled_template_can_continue_runtime_fallback() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        assert!(is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            true,
            false,
            keybox.identity_digest(),
        ));
        assert!(!is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            true,
            true,
            keybox.identity_digest(),
        ));
    }
}
