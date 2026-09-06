use std::{
    fs,
    path::{Path, PathBuf},
    str,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock, RwLock,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::Encode;
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    crypto::{ec, rsa, KeyMaterial, Sha256},
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
use x509_cert::der as x509_der;
use x509_cert::{ext::pkix::name::DirectoryString, Certificate};
use x509_parser::parse_x509_certificate;

pub const KEYBOX_PATH: &str = "/data/misc/keystore/omk/keybox.xml";
pub const MAX_KEYBOX_XML_BYTES: usize = 64 * 1024;

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

/// Non-sensitive information derived from the public certificate chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyboxMetadata {
    pub source: KeyboxSource,
    pub level: KeyboxLevel,
}

const BUNDLED_KEYBOX_XML: &str = include_str!("../template/keybox.xml");

lazy_static::lazy_static! {
    pub static ref KEYBOX: RwLock<KeyBox> = RwLock::new(KeyBox::new());
    static ref KEYBOX_IO_LOCK: Mutex<()> = Mutex::new(());
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
    // Factory keyboxes commonly carry both algorithms, while RKP-extracted keyboxes are EC-only.
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
            .map(|(key, _, _)| key)
            .map_err(|e| anyhow!("failed to import RSA private key: {e:?}"))?;
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
            key_der: entry.key_der,
            chain,
        })
    }

    fn build_ec_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("EC certificate chain is empty");
        }
        let key = ec::import_sec1_private_key(&entry.key_der)
            .map_err(|e| anyhow!("failed to import EC private key: {e:?}"))?;
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
            key_der: entry.key_der,
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

/// Reads the installed keybox once and returns both its validation state and
/// the non-sensitive metadata derived from its certificate chains. Invalid
/// XML is represented as `Invalid` with unknown metadata so an informational
/// WebUI query cannot prevent the rest of the service from starting.
pub fn installed_keybox_state_and_metadata() -> Result<(KeyboxFileState, KeyboxMetadata)> {
    let contents = fs::read(KEYBOX_PATH)
        .with_context(|| format!("failed to read keybox.xml from {KEYBOX_PATH}"))?;
    if contents.len() > MAX_KEYBOX_XML_BYTES {
        return Ok((KeyboxFileState::Invalid, KeyboxMetadata::default()));
    }
    let Ok(xml) = str::from_utf8(&contents) else {
        return Ok((KeyboxFileState::Invalid, KeyboxMetadata::default()));
    };
    let Ok(keybox) = KeyBox::from_xml_str(xml) else {
        return Ok((KeyboxFileState::Invalid, KeyboxMetadata::default()));
    };
    let state = if is_bundled_keybox_xml(xml) {
        KeyboxFileState::Bundled
    } else {
        KeyboxFileState::Custom
    };
    Ok((state, keybox.metadata()))
}

pub fn install_keybox_xml(contents: &[u8]) -> Result<()> {
    validate_keybox_xml(contents)?;
    let xml = str::from_utf8(contents).expect("validated keybox.xml is UTF-8");
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    write_keybox_xml(KEYBOX_PATH, xml)
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
    fn rsa_only_keybox_signs_rsa_and_ec_attestations_with_rsa_key() {
        let rsa_only = single_algorithm_keybox(KeyAlgorithm::Rsa);
        let xml = rsa_only.to_xml_string();
        assert!(xml.contains("<NumberOfKeyboxes>1</NumberOfKeyboxes>"));
        assert!(!xml.contains("algorithm=\"ecdsa\""));

        let parsed = KeyBox::from_xml_str(&xml).unwrap();
        assert!(parsed.rsa_info.is_some());
        assert!(parsed.ec_info.is_none());
        assert_eq!(parsed.identity_digest(), rsa_only.identity_digest());

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
        let written = fs::read_to_string(path).unwrap();
        assert!(written.contains("<AndroidAttestation>"));
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
