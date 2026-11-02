//! RSA-2048 RSASSA-PSS signing for the forged Soter key exports.
//!
//! The reference ATTK signs ASK exports, and each ASK signs its AuthKey exports.
//! ASK and AuthKey subjects use independent runtime-generated RSA key pairs. The parameters mirror
//! the D-Soter reference implementation: SHA-256 with MGF1-SHA256, a 20-byte salt, and
//! `emBits = 2047` over a 2048-bit modulus.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use jni::{
    JNIEnv, JavaVM,
    objects::{JByteArray, JValue},
};
use num_bigint_dig::BigUint;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Reference ATTK public half used to verify ASK signatures in tests.
#[cfg(test)]
pub(crate) const ATTK_PUBLIC_B64: &str = concat!(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2cJFTNvNSzXRZyD9qKWo",
    "DRWj/Np/a6MXIfzFKWBMBWbavCnrsxqHcEC1phAqibQ5HW+yNPWcbRGyHfrDsTw9",
    "WdYJ+NmAtTEEO4/OS2LvIfMkiPA4SpaMVDM5WXXdmRKcCPG/LKFx6Qb5SPlulDC0",
    "uuPFGDaqorYDUyeDZuRFDxUDNPs1UR05GcCY/zu6Od+/Zry9DW5JMS/HjfLc2EZT",
    "53ydfG/mXJYBil3UEr0bv2y8mv8rENPXo7HWO3RK2TGkWBtrj1xzskficfBi1ZRa",
    "SHR7r9ccbnJrSL53JiptsyqTsn9FrHWnJ542hdp9LjS7TDJqKNSS/kpC0BkIWEKD",
    "wQIDAQAB",
);

/// Reference ATTK private half. It signs ASK exports; ASK keys sign AuthKey exports.
const ATTK_PRIVATE_B64: &str = concat!(
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZwkVM281LNdFn",
    "IP2opagNFaP82n9roxch/MUpYEwFZtq8KeuzGodwQLWmECqJtDkdb7I09ZxtEbId",
    "+sOxPD1Z1gn42YC1MQQ7j85LYu8h8ySI8DhKloxUMzlZdd2ZEpwI8b8soXHpBvlI",
    "+W6UMLS648UYNqqitgNTJ4Nm5EUPFQM0+zVRHTkZwJj/O7o5379mvL0NbkkxL8eN",
    "8tzYRlPnfJ18b+ZclgGKXdQSvRu/bLya/ysQ09ejsdY7dErZMaRYG2uPXHOyR+Jx",
    "8GLVlFpIdHuv1xxucmtIvncmKm2zKpOyf0WsdacnnjaF2n0uNLtMMmoo1JL+SkLQ",
    "GQhYQoPBAgMBAAECggEAAN/PodhK1NRZ7/5qmt4jA7To/PKKMqmA/MWu6Hwqj67l",
    "PuwaWstG+QXaoQlclEOSwbOR1sJzTPfxxFcYCl+rzZOOGu6wPOh37IZXfpIJO+Ov",
    "CeQWuTJR3xoZQsYv9uHppjkprLuN3ltssQfoSjLtGX8VIZyvJWkvVJDTsHGEIGpk",
    "KXwdX2VJ8Qoa7eaXKDKABtuD8rkWzhgliTe4l4c1O9WhdPahBn74EqW12+T3/uFp",
    "W34EyZcrugLv/cm3PsOW5FPi5GWHdYFFNY+bBL6RaWTMeC8pCxX+RPrSIk6D/gYH",
    "1HzlTFwNNilVrrRHxOzcxrnMTFl7d74brRsv9oVD6QKBgQD8inu/Q4xa8vDVQkDs",
    "WuPRwM7pVhlt2iNthStgydm51cAP0D2YGU99ahNuwmnaBlhP/WRmGXlbh36kHBV2",
    "Go8VKkaTJortxtFO1/Kmx4eDNysuq6Ql9i6mh5VCWqNpv3882qwuXtvkeOP0MpVq",
    "t0c4jO5sJf5ZYxaXhgDh1w4MzQKBgQDcvdOS+fMteX1NorbTxrdTh2EUC8GLW2dt",
    "QSsYb0PC6i+t91qZ5E2VhqMurj4wy/r3POThj9JngEDoKwGgvCeza7ab82CX+o1k",
    "/q+LNMqBQQip5x26/xkB0kjyplcqh8QhLJk5Pyz59MfkpzX4kv3smKtbD8Sijtm0",
    "WNgrg71SxQKBgBVwvGjUl0nxbjjs0w49+TGJqQduY+JLrs5RjAk/mdiJKTEugMw0",
    "+eav5s50ewAjocPIw4lXiFIZAst0Bu5r+tHVMQC1OP5O7t4+vz8hmYOuX2Aq+liu",
    "ue8xe56Si2Ui+O51skCNlSWkjdXhpYXV4ZoPfP55i0qTewuKOPDzjSHRAoGBAI0k",
    "ExP3HbYF6EirsZrXhIC0Hy5iFe61EvyYnqWQ/xKyCqqBbjzX7YOeAtjmMH2i72UG",
    "WpKfEzl6mAXa+b98jyX5yVkN1MVYPvBEqJmpt5HNs2xvimL2mVbAzkPYeAOJq65K",
    "he5Eps1r5iQdhjTaR+Hv/CDNhD0seacG57FrGrLBAoGAUU33iVKZdjBg78/LJknc",
    "XHxRYdj6MdS7Wk+y476SjcHiAu77AAtPW4rfnd1v44/mBelguOEFVqAvNSZ8rqNo",
    "qG+O+9COZEsNfKpMDExpwj2YhsNSm3qGCNN1Wa60Km2NdB+O+KVHBGeoPzuXmFSO",
    "5y3G0apc5G+MHqfA0jITAIs=",
);

/// Only owned DER bytes cross the JNI local frame; Java objects are never cached.
pub(crate) struct KeyPair {
    pub(crate) public_der: Vec<u8>,
    pub(crate) private_der: Vec<u8>,
}

static VM: OnceLock<JavaVM> = OnceLock::new();

pub(crate) fn initialize_vm(env: &JNIEnv<'_>) -> bool {
    match env.get_java_vm() {
        Ok(vm) => VM.set(vm).is_ok() || VM.get().is_some(),
        Err(_) => false,
    }
}

/// Use Android's RSA provider, with no dependency on a platform libcrypto ABI.
pub(crate) fn generate_keypair() -> Option<KeyPair> {
    let mut env = VM.get()?.attach_current_thread().ok()?;
    // Do not clear an exception belonging to the caller.
    if env.exception_check().ok()? {
        return None;
    }
    let result = env.with_local_frame(16, |env| -> jni::errors::Result<KeyPair> {
        let algorithm = env.new_string("RSA")?;
        let generator = env
            .call_static_method(
                "java/security/KeyPairGenerator",
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[JValue::Object(algorithm.as_ref())],
            )?
            .l()?;
        env.call_method(&generator, "initialize", "(I)V", &[JValue::Int(2048)])?;
        let pair = env
            .call_method(&generator, "generateKeyPair", "()Ljava/security/KeyPair;", &[])?
            .l()?;
        let public =
            env.call_method(&pair, "getPublic", "()Ljava/security/PublicKey;", &[])?.l()?;
        let private =
            env.call_method(&pair, "getPrivate", "()Ljava/security/PrivateKey;", &[])?.l()?;
        let public = JByteArray::from(env.call_method(public, "getEncoded", "()[B", &[])?.l()?);
        let private = JByteArray::from(env.call_method(private, "getEncoded", "()[B", &[])?.l()?);
        Ok(KeyPair {
            public_der: env.convert_byte_array(public)?,
            private_der: env.convert_byte_array(private)?,
        })
    });
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    result.ok().filter(|key| !key.public_der.is_empty() && !key.private_der.is_empty())
}

pub(crate) fn attk_private_der() -> Option<Vec<u8>> {
    BASE64.decode(ATTK_PRIVATE_B64).ok()
}

const MODULUS_BYTES: usize = 256;
const HASH_BYTES: usize = 32;
const SALT_BYTES: usize = 20;
const EM_BITS: usize = 2047;

/// Read one DER tag-length-value triple from `buffer`, advancing `offset`.
fn der_tlv<'a>(buffer: &'a [u8], offset: &mut usize) -> Option<(u8, &'a [u8])> {
    let tag = *buffer.get(*offset)?;
    let first = *buffer.get(*offset + 1)?;
    *offset += 2;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > size_of::<usize>() {
            return None;
        }
        let bytes = buffer.get(*offset..*offset + count)?;
        *offset += count;
        bytes.iter().try_fold(0usize, |value, byte| {
            value.checked_mul(256)?.checked_add(usize::from(*byte))
        })?
    };
    let value = buffer.get(*offset..*offset + length)?;
    *offset += length;
    Some((tag, value))
}

/// Parse a PKCS#8 RSAPrivateKey and return its modulus, public exponent and private exponent.
fn parse_pkcs8_private(der: &[u8]) -> Option<(BigUint, BigUint, BigUint)> {
    let mut offset = 0;
    let (outer_tag, outer) = der_tlv(der, &mut offset)?;
    if outer_tag != 0x30 || offset != der.len() {
        return None;
    }
    let mut inner = 0;
    let (_, _) = der_tlv(outer, &mut inner)?;
    let (algorithm_tag, _) = der_tlv(outer, &mut inner)?;
    if algorithm_tag != 0x30 {
        return None;
    }
    let (octet_tag, octets) = der_tlv(outer, &mut inner)?;
    if octet_tag != 0x04 {
        return None;
    }
    let mut key = 0;
    let (key_tag, sequence) = der_tlv(octets, &mut key)?;
    if key_tag != 0x30 || key != octets.len() {
        return None;
    }
    let mut field = 0;
    let (_, _) = der_tlv(sequence, &mut field)?;
    let read_integer = |field: &mut usize| -> Option<BigUint> {
        let (tag, bytes) = der_tlv(sequence, field)?;
        if tag != 0x02 || bytes.is_empty() {
            return None;
        }
        let stripped = bytes.iter().skip_while(|byte| **byte == 0).copied().collect::<Vec<_>>();
        (!stripped.is_empty()).then(|| BigUint::from_bytes_be(&stripped))
    };
    let modulus = read_integer(&mut field)?;
    let public = read_integer(&mut field)?;
    let private = read_integer(&mut field)?;
    Some((modulus, public, private))
}

/// MGF1 with SHA-256, as used by RSASSA-PSS.
fn mgf1(seed: &[u8], length: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(length + HASH_BYTES);
    let mut counter = 0u32;
    while mask.len() < length {
        let mut hash = Sha256::new();
        hash.update(seed);
        hash.update(counter.to_be_bytes());
        mask.extend_from_slice(&hash.finalize());
        counter += 1;
    }
    mask.truncate(length);
    mask
}

/// Sample a fresh PSS salt. A failure here leaves the export blob unsigned, which the caller logs.
fn random_salt() -> Option<[u8; SALT_BYTES]> {
    let mut salt = [0u8; SALT_BYTES];
    let mut file = std::fs::File::open("/dev/urandom").ok()?;
    std::io::Read::read_exact(&mut file, &mut salt).ok()?;
    Some(salt)
}

/// RSASSA-PSS encode the SHA-256 of `message_hash` with `salt`.
fn encode_pss(message_hash: &[u8], salt: &[u8; SALT_BYTES]) -> Option<Vec<u8>> {
    if message_hash.len() != HASH_BYTES {
        return None;
    }
    let mut hash_input = Vec::with_capacity(8 + HASH_BYTES + SALT_BYTES);
    hash_input.extend_from_slice(&[0u8; 8]);
    hash_input.extend_from_slice(message_hash);
    hash_input.extend_from_slice(salt);
    let hash = Sha256::digest(&hash_input);

    let mut block = Vec::with_capacity(MODULUS_BYTES);
    block.resize(MODULUS_BYTES - SALT_BYTES - HASH_BYTES - 2, 0);
    block.push(0x01);
    block.extend_from_slice(salt);

    let mask = mgf1(&hash, MODULUS_BYTES - HASH_BYTES - 1);
    for (byte, mask_byte) in block.iter_mut().zip(mask) {
        *byte ^= mask_byte;
    }
    let unused_bits = 8 * MODULUS_BYTES - EM_BITS;
    *block.first_mut()? &= 0xFF >> unused_bits;

    block.extend_from_slice(&hash);
    block.push(0xbc);
    Some(block)
}

/// Sign the exact bytes of an export JSON, mirroring the D-Soter reference parameters.
pub(crate) fn sign_export_json(private_der: &[u8], json: &[u8]) -> Option<[u8; MODULUS_BYTES]> {
    let salt = random_salt()?;
    sign_export_json_with_salt(private_der, json, &salt)
}

fn sign_export_json_with_salt(
    private_der: &[u8],
    json: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Option<[u8; MODULUS_BYTES]> {
    let (modulus, _, private) = parse_pkcs8_private(private_der)?;
    if modulus.bits() != MODULUS_BYTES * 8 {
        return None;
    }
    let encoded = encode_pss(&Sha256::digest(json), salt)?;
    let signature = BigUint::from_bytes_be(&encoded).modpow(&private, &modulus);
    let bytes = signature.to_bytes_be();
    if bytes.len() > MODULUS_BYTES {
        return None;
    }
    let mut out = [0u8; MODULUS_BYTES];
    out[MODULUS_BYTES - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Fixed-salt signature over a fixed export JSON, produced by the D-Soter C++ reference
    /// implementation (`soter_attk.h`, salt forced to `0x11 * (index + 1)`). Any change to the
    /// key pair, the JSON layout, the hash, the mask generation, `emBits`, or the salt length
    /// breaks this test.
    const KNOWN_JSON: &str = concat!(
        "{\"pub_key\":\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2cJFTNvNSzXRZyD9qKWo",
        "DRWj/Np/a6MXIfzFKWBMBWbavCnrsxqHcEC1phAqibQ5HW+yNPWcbRGyHfrDsTw9",
        "WdYJ+NmAtTEEO4/OS2LvIfMkiPA4SpaMVDM5WXXdmRKcCPG/LKFx6Qb5SPlulDC0",
        "uuPFGDaqorYDUyeDZuRFDxUDNPs1UR05GcCY/zu6Od+/Zry9DW5JMS/HjfLc2EZT",
        "53ydfG/mXJYBil3UEr0bv2y8mv8rENPXo7HWO3RK2TGkWBtrj1xzskficfBi1ZRa",
        "SHR7r9ccbnJrSL53JiptsyqTsn9FrHWnJ542hdp9LjS7TDJqKNSS/kpC0BkIWEKD",
        "wQIDAQAB\",\"counter\":1,\"cpu_id\":\"0123456789abcdef0123456789abcdef\",\"uid\":10123}",
    );
    const KNOWN_SIGNATURE: &str = concat!(
        "c8c08a0c10dd9a45dad1a3decdb9002d0ca2e069ce8f0b66da2ff30c1b832927",
        "a79dd171fcc38f472728b7145c581b400ec95bbc90788561974812f05b41159a",
        "42e3a98d8e2faa967cae06c6b63c34f154d15a5f75dae44b6ee209652d791fc9",
        "f3bbc0a55da878dcd73c56f3dfd505f04a9988d6f8366e548cf91ce3e7103a62",
        "237bd1ed82ad897423324546a581a73874f72548173a7cb6f77806cb92e0f9c6",
        "5daeb4bb2d12d79285770d5a88b22a450eadebaf76c1ea7ec6b0615c74ffbf73",
        "6863d04827ff88ce976256888fe51b23d08756803c82cc0c06e5b12531b54a91",
        "2b0c2ecf0ced3846674ca3859f16db7349fad67a10ea4c015393749be2c0b061",
    );

    #[test]
    fn matches_the_reference_implementation_byte_for_byte() {
        let salt = std::array::from_fn(|index| (0x11u32 * (index as u32 + 1)) as u8);
        let signature =
            sign_export_json_with_salt(&attk_private_der().unwrap(), KNOWN_JSON.as_bytes(), &salt)
                .unwrap();
        assert_eq!(hex(&signature), KNOWN_SIGNATURE);
    }

    #[test]
    fn embedded_pair_is_consistent_and_signs_new_salts() {
        let der = BASE64.decode(ATTK_PRIVATE_B64).unwrap();
        let (modulus, public, _) = parse_pkcs8_private(&der).unwrap();
        assert_eq!(modulus.bits(), MODULUS_BYTES * 8);
        let signature = sign_export_json(&der, KNOWN_JSON.as_bytes()).unwrap();
        assert!(verifies(&signature, KNOWN_JSON.as_bytes(), &modulus, &public));
    }

    #[test]
    fn rejects_a_different_message() {
        let der = BASE64.decode(ATTK_PRIVATE_B64).unwrap();
        let (modulus, public, _) = parse_pkcs8_private(&der).unwrap();
        let signature = sign_export_json(&der, KNOWN_JSON.as_bytes()).unwrap();
        assert!(!verifies(&signature, b"{}", &modulus, &public));
    }

    pub(crate) fn verifies_export(blob: &[u8], private_der: &[u8]) -> bool {
        let length = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
        let json = &blob[4..4 + length];
        let signature = blob[4 + length..].try_into().unwrap();
        let (modulus, public, _) = parse_pkcs8_private(private_der).unwrap();
        verifies(signature, json, &modulus, &public)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Textbook RSASSA-PSS verification, used only to prove the embedded pair is self-consistent.
    pub(crate) fn verifies(
        signature: &[u8; MODULUS_BYTES],
        json: &[u8],
        modulus: &BigUint,
        public: &BigUint,
    ) -> bool {
        let message = BigUint::from_bytes_be(signature).modpow(public, modulus).to_bytes_be();
        if message.len() > MODULUS_BYTES {
            return false;
        }
        let mut encoded = vec![0u8; MODULUS_BYTES - message.len()];
        encoded.extend_from_slice(&message);
        if encoded.last() != Some(&0xbc) {
            return false;
        }
        let hash = &encoded[MODULUS_BYTES - HASH_BYTES - 1..MODULUS_BYTES - 1];
        let mask = mgf1(hash, MODULUS_BYTES - HASH_BYTES - 1);
        let mut block = encoded[..MODULUS_BYTES - HASH_BYTES - 1]
            .iter()
            .zip(mask)
            .map(|(byte, mask_byte)| byte ^ mask_byte)
            .collect::<Vec<_>>();
        block[0] &= 0xFF >> (8 * MODULUS_BYTES - EM_BITS);
        let separator = block.iter().position(|byte| *byte == 0x01);
        let Some(separator) = separator else {
            return false;
        };
        if block[..separator].iter().any(|byte| *byte != 0) {
            return false;
        }
        let salt = &block[separator + 1..];
        if salt.len() != SALT_BYTES {
            return false;
        }
        let mut hash_input = Vec::with_capacity(8 + HASH_BYTES + SALT_BYTES);
        hash_input.extend_from_slice(&[0u8; 8]);
        hash_input.extend_from_slice(&Sha256::digest(json));
        hash_input.extend_from_slice(salt);
        Sha256::digest(&hash_input)[..] == hash[..]
    }
}
