//! Soter blob codec: `[u32 le jsonLen][json][rsa-pss signature]`.
//!
//! The shape was taken from the vendor HAL library pulled off the OnePlus 13
//! (`vendor.qti.hardware.soter-V1-ndk.so`, method `SoterBufferReturn::writeToParcel`)
//! and from captures of a working device: JSON key order is
//! `pub_key, cpu_id, counter, uid`, and the tail is RSA-PSS/SHA-256 with a
//! 20-byte salt over the exact JSON bytes.

use openssl::{
    hash::MessageDigest,
    pkey::{HasPublic, PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer, Verifier},
};
use serde::Serialize;

/// Salt length used by the real device on every stage of the chain.
pub const PSS_SALT_LEN: usize = 20;

/// Signature size for the RSA-2048 keys the TA uses.
pub const SIGNATURE_LEN: usize = 256;

/// Values the stock TA reports for its own environment. They are constants here
/// because the local TA has no secure world to ask.
pub const TEE_NAME: &str = "QSEE";
pub const TEE_VERSION: &str = "5";
pub const FINGERPRINT_NAME: &str = "fingerprint";
pub const FINGERPRINT_VERSION: &str = "1";

#[derive(Serialize)]
struct KeyJson<'a> {
    pub_key: &'a str,
    cpu_id: &'a str,
    counter: u64,
    uid: String,
}

#[derive(Serialize)]
struct SignedJson<'a> {
    raw: &'a str,
    fid: &'a str,
    counter: u64,
    tee_n: &'a str,
    tee_v: &'a str,
    fp_n: &'a str,
    fp_v: &'a str,
    cpu_id: &'a str,
    uid: String,
}

/// JSON body of an ASK or AuthKey blob. `uid` is a string on the wire, the
/// counter is a number, and there is no certificate array (the Qualcomm backend
/// never returns one).
pub fn key_json(public_pem: &str, cpu_id: &str, counter: u64, uid: u32) -> Vec<u8> {
    let json = KeyJson { pub_key: public_pem, cpu_id, counter, uid: uid.to_string() };
    serde_json::to_vec(&json).expect("key JSON is serializable")
}

/// JSON body of a `finishSign` result.
pub fn result_json(challenge: &str, fid: &str, counter: u64, cpu_id: &str, uid: u32) -> Vec<u8> {
    let json = SignedJson {
        raw: challenge,
        fid,
        counter,
        tee_n: TEE_NAME,
        tee_v: TEE_VERSION,
        fp_n: FINGERPRINT_NAME,
        fp_v: FINGERPRINT_VERSION,
        cpu_id,
        uid: uid.to_string(),
    };
    serde_json::to_vec(&json).expect("result JSON is serializable")
}

/// Wrap a JSON body and its signature into the blob the HAL hands out.
pub fn encode(json: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + json.len() + signature.len());
    blob.extend_from_slice(&(json.len() as u32).to_le_bytes());
    blob.extend_from_slice(json);
    blob.extend_from_slice(signature);
    blob
}

/// Split a blob back into its JSON body and signature.
pub fn parse(blob: &[u8]) -> Option<(&[u8], &[u8])> {
    if blob.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(blob[..4].try_into().ok()?) as usize;
    let json = blob.get(4..4 + len)?;
    let signature = blob.get(4 + len..)?;
    if signature.is_empty() {
        return None;
    }
    Some((json, signature))
}

/// RSA-PSS/SHA-256 with the device's 20-byte salt, over the JSON bytes.
pub fn sign(key: &Rsa<Private>, data: &[u8]) -> Option<Vec<u8>> {
    let key = PKey::from_rsa(key.clone()).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).ok()?;
    signer.set_rsa_padding(Padding::PKCS1_PSS).ok()?;
    signer.set_rsa_mgf1_md(MessageDigest::sha256()).ok()?;
    signer.set_rsa_pss_saltlen(RsaPssSaltlen::custom(PSS_SALT_LEN as i32)).ok()?;
    signer.update(data).ok()?;
    signer.sign_to_vec().ok()
}

/// Verify a blob tail produced by [`sign`].
pub fn verify(key: &Rsa<Public>, data: &[u8], signature: &[u8]) -> bool {
    let result = || -> Result<bool, openssl::error::ErrorStack> {
        let key = PKey::from_rsa(key.clone())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(PSS_SALT_LEN as i32))?;
        verifier.update(data)?;
        verifier.verify(signature)
    };
    result().unwrap_or(false)
}

/// SPKI/PEM encoding of a public key, the spelling the blobs use.
pub fn public_key_pem<T: HasPublic>(key: &Rsa<T>) -> Option<String> {
    String::from_utf8(key.public_key_to_pem().ok()?).ok()
}

/// Parse an SPKI/PEM public key out of a blob's `pub_key` field.
pub fn public_key_from_pem(pem: &str) -> Option<Rsa<Public>> {
    Rsa::public_key_from_pem(pem.as_bytes()).ok()
}

/// Read the existing unencrypted PKCS#8 ledger keys and reject invalid RSA material.
pub fn private_key_from_pem(pem: &str) -> Option<Rsa<Private>> {
    let key = PKey::private_key_from_pem(pem.as_bytes()).ok()?.rsa().ok()?;
    key.check_key().ok()?.then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs8_and_spki_round_trip_keep_the_same_signing_identity() {
        let original = Rsa::generate(2048).unwrap();
        let pem = PKey::from_rsa(original.clone()).unwrap().private_key_to_pem_pkcs8().unwrap();
        let pem = String::from_utf8(pem).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let key = private_key_from_pem(&pem).unwrap();
        let crlf = private_key_from_pem(&pem.replace('\n', "\r\n")).unwrap();
        assert_eq!(key.n(), original.n());
        assert_eq!(key.n(), crlf.n());
        assert_eq!(key.e().to_vec(), [1, 0, 1]);
        let public_pem = public_key_pem(&key).unwrap();
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let public = public_key_from_pem(&public_pem).unwrap();
        let data = key_json(&public_pem, "device", 1, 10001);
        let signature = sign(&key, &data).unwrap();
        assert_eq!(signature.len(), SIGNATURE_LEN);
        assert!(verify(&public, &data, &signature));
        assert!(!verify(&public, b"different JSON", &signature));
        assert!(!verify(&public, &data, &signature[..signature.len() - 1]));
        let mut changed = signature.clone();
        changed[0] ^= 1;
        assert!(!verify(&public, &data, &changed));
        assert!(private_key_from_pem(&public_pem).is_none());
        assert!(private_key_from_pem("invalid PEM").is_none());
    }

    #[test]
    fn verifier_rejects_wrong_pss_salt_and_pkcs1_padding() {
        let rsa = Rsa::generate(2048).unwrap();
        let public = public_key_from_pem(&public_key_pem(&rsa).unwrap()).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        let data = b"SOTER wire-format compatibility";
        for salt_len in [0, 20, 32] {
            let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
            signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            signer.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
            signer.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len)).unwrap();
            signer.update(data).unwrap();
            assert_eq!(verify(&public, data, &signer.sign_to_vec().unwrap()), salt_len == 20);
        }
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();
        signer.update(data).unwrap();
        assert!(!verify(&public, data, &signer.sign_to_vec().unwrap()));
    }
}
