// Adapted from Duck-ToolBox and rkp-v1-oracle (MIT); see THIRD_PARTY_LICENSES.
use anyhow::{anyhow, Result};
use kmr_wire::cbor::value::Value;
use ring::{hkdf, hmac};

use super::cbor::{bytes, encode, int};

pub const ALG_ES256: i128 = -7;
pub const ALG_EDDSA: i128 = -8;
pub const CWT_ISSUER: i128 = 1;
pub const CWT_SUBJECT: i128 = 2;
pub const DICE_SUBJECT_PUB_KEY: i128 = -4_670_552;
pub const DICE_KEY_USAGE: i128 = -4_670_553;

pub fn build_sig_structure(context: &str, protected: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    encode(&Value::Array(vec![
        Value::Text(context.into()),
        bytes(protected),
        bytes([]),
        bytes(payload),
    ]))
}

pub(super) fn maced_key(public: &Value) -> Result<Vec<u8>> {
    let extracted = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&[0; 32]);
    let mut key = [0; 32];
    extracted
        .expand(&[b"Key to MAC public keys"], hkdf::HKDF_SHA256)
        .map_err(|_| anyhow!("cannot derive PureSoft public-key MAC key"))?
        .fill(&mut key)
        .map_err(|_| anyhow!("cannot derive PureSoft public-key MAC key"))?;
    let protected = encode(&Value::Map(vec![(int(1), int(5))]))?;
    let payload = encode(public)?;
    let input = build_sig_structure("MAC0", &protected, &payload)?;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &input);
    encode(&Value::Array(vec![
        bytes(protected),
        Value::Map(vec![]),
        bytes(payload),
        bytes(tag.as_ref()),
    ]))
}

pub(super) fn keys_mac_tag(key: &[u8], public: &Value) -> Result<[u8; 32]> {
    let protected = encode(&Value::Map(vec![(int(1), int(5))]))?;
    let payload = encode(&Value::Array(vec![public.clone()]))?;
    let input = build_sig_structure("MAC0", &protected, &payload)?;
    Ok(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &input)
        .as_ref()
        .try_into()?)
}

pub(super) fn maced_keys(public: &Value, tag: &[u8]) -> Result<Vec<u8>> {
    encode(&Value::Array(vec![
        bytes(encode(&Value::Map(vec![(int(1), int(5))]))?),
        Value::Map(vec![]),
        bytes(encode(&Value::Array(vec![public.clone()]))?),
        bytes(tag),
    ]))
}
