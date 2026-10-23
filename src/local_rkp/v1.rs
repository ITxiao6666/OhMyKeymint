// Adapted from Duck-ToolBox / rkp-v1-oracle (MIT); see THIRD_PARTY_LICENSES.
use super::{
    cbor::{as_array, as_bytes, as_map, bytes, decode, encode, int},
    cose, required, Eek, BUFFER_SIZE,
};
use anyhow::{anyhow, bail, Result};
use kmr_wire::cbor::value::Value;
use ring::rand::{SecureRandom, SystemRandom};

pub(super) fn aidl(eek: &Eek, public: &Value) -> Result<Vec<u8>> {
    let maced = cose::maced_key(public)?;
    let mut request = Vec::new();
    for field in [&eek.challenge, &maced, &eek.p256, &eek.x25519] {
        request.extend_from_slice(&(field.len() as u32).to_be_bytes());
        request.extend_from_slice(field);
    }
    let reply = crate::rkp_v1_bridge::exchange(&request)?;
    parse_bridge(&reply, &eek.challenge, public)
}

fn parse_bridge(reply: &[u8], challenge: &[u8], public: &Value) -> Result<Vec<u8>> {
    let mut rest = reply;
    let status = read_int(&mut rest)?;
    if status != 0 {
        if status == 1 {
            let code = read_int(&mut rest)? as i32;
            bail!("Device rejected V1 AIDL CSR (code {code}); firmware may not support this path");
        }
        // Do not expose arbitrary HAL/JVM exception strings in WebUI or logs.
        bail!("V1 AIDL bridge failed (status {status}); firmware/interface may not be compatible");
    }
    let mac = read_bytes(&mut rest)?;
    let device = read_bytes(&mut rest)?;
    let protected = read_bytes(&mut rest)?;
    if !rest.is_empty() {
        bail!("trailing V1 bridge response");
    }
    assemble(mac, device, protected, challenge, public)
}

fn read_int(rest: &mut &[u8]) -> Result<u32> {
    let (head, tail) = rest
        .split_at_checked(4)
        .ok_or_else(|| anyhow!("truncated V1 bridge reply"))?;
    *rest = tail;
    Ok(u32::from_be_bytes(head.try_into()?))
}

fn read_bytes<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let length = read_int(rest)? as usize;
    if length > BUFFER_SIZE {
        bail!("oversized V1 reply field");
    }
    let (field, tail) = rest
        .split_at_checked(length)
        .ok_or_else(|| anyhow!("truncated V1 reply field"))?;
    *rest = tail;
    Ok(field)
}

pub(super) fn native(eek: &Eek, public: &Value) -> Result<Vec<u8>> {
    let chain = if !eek.x25519.is_empty() {
        &eek.x25519
    } else {
        &eek.p256
    };
    let mut mac_key = [0; 32];
    SystemRandom::new()
        .fill(&mut mac_key)
        .map_err(|_| anyhow!("cannot generate native V1 MAC key"))?;
    let tag = cose::keys_mac_tag(&mac_key, public)?;
    let payload = encode(&Value::Map(vec![
        (int(4), bytes(eek.challenge.as_slice())),
        (int(55), int(0)),
        (int(56), bytes(mac_key)),
        (int(57), bytes(tag)),
        (int(58), bytes(chain.as_slice())),
    ]))?;
    let mut request = 0x311eu32.to_le_bytes().to_vec();
    request.extend(payload);
    let reply = super::native::exchange(&request)?;
    let value = decode(&reply)?;
    let fields = as_map(&value, "native V1 response")?;
    if fields.len() != 2 {
        bail!("native V1 response must contain DeviceInfo and ProtectedData only");
    }
    assemble(
        &tag,
        as_bytes(required(fields, 59)?, "DeviceInfo")?,
        as_bytes(required(fields, 60)?, "ProtectedData")?,
        &eek.challenge,
        public,
    )
}

pub(super) fn validate_eek(encoded: &[u8]) -> Result<()> {
    if encoded.is_empty() || encoded.len() > BUFFER_SIZE {
        bail!("invalid EEK size");
    }
    let value = decode(encoded)?;
    let entries = as_array(&value, "EEK chain")?;
    if entries.is_empty() || entries.len() > 8 {
        bail!("invalid EEK certificate count");
    }
    for entry in entries {
        let fields = as_array(entry, "EEK certificate")?;
        if fields.len() != 4 {
            bail!("EEK must contain COSE_Sign1 certificates");
        }
        as_bytes(&fields[0], "EEK headers")?;
        as_map(&fields[1], "EEK unprotected headers")?;
        as_bytes(&fields[2], "EEK payload")?;
        as_bytes(&fields[3], "EEK signature")?;
    }
    Ok(())
}

fn assemble(
    mac: &[u8],
    device: &[u8],
    protected: &[u8],
    challenge: &[u8],
    public: &Value,
) -> Result<Vec<u8>> {
    if mac.len() != 32 || device.len() > BUFFER_SIZE || protected.len() > BUFFER_SIZE {
        bail!("invalid V1 response field sizes");
    }
    if as_map(&decode(device)?, "V1 DeviceInfo")?.is_empty() {
        bail!("empty V1 DeviceInfo");
    }
    let protected_value = decode(protected)?;
    let encrypted = as_array(&protected_value, "ProtectedData")?;
    if encrypted.len() != 4 {
        bail!("V1 ProtectedData must be COSE_Encrypt");
    }
    let headers = decode(as_bytes(&encrypted[0], "ProtectedData headers")?)?;
    if required(as_map(&headers, "encryption headers")?, 1)? != &int(3) {
        bail!("V1 ProtectedData must use A256GCM");
    }
    if as_bytes(
        required(as_map(&encrypted[1], "unprotected headers")?, 5)?,
        "IV",
    )?
    .len()
        != 12
        || as_bytes(&encrypted[2], "ciphertext")?.len() < 16
    {
        bail!("invalid V1 encrypted fields");
    }
    let recipients = as_array(&encrypted[3], "recipients")?;
    if recipients.len() != 1 {
        bail!("invalid V1 recipient count");
    }
    let recipient = as_array(&recipients[0], "recipient")?;
    if recipient.len() != 3 || recipient[2] != Value::Null {
        bail!("invalid V1 recipient");
    }
    let recipient_headers = as_bytes(&recipient[0], "recipient headers")?;
    if !recipient_headers.is_empty() {
        as_map(&decode(recipient_headers)?, "recipient headers")?;
    }
    as_map(&recipient[1], "recipient unprotected headers")?;
    // The HAL authenticates the EXACT DeviceInfo bytes in SignedMac AAD. Never
    // canonicalize these or the encrypted evidence. The server alone can decrypt it.
    let mut csr = vec![0x84, 0x82];
    csr.extend_from_slice(device);
    csr.push(0xa0);
    csr.extend(encode(&bytes(challenge))?);
    csr.extend_from_slice(protected);
    csr.extend(cose::maced_keys(public, mac)?);
    if csr.len() > BUFFER_SIZE {
        bail!("V1 CSR exceeds size limit");
    }
    Ok(csr)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bridge_errors_are_redacted_and_bounded() {
        let mut reply = 1u32.to_be_bytes().to_vec();
        reply.extend((-18i32).to_be_bytes());
        reply.extend(b"SECRET HAL MESSAGE");
        let error = parse_bridge(&reply, b"challenge", &Value::Null)
            .unwrap_err()
            .to_string();
        assert!(error.contains("-18"));
        assert!(!error.contains("SECRET"));
        assert!(parse_bridge(&[], &[], &Value::Null).is_err());
    }
    #[test]
    fn opaque_device_and_encrypted_bytes_are_preserved() {
        // Deliberately noncanonical integer width in DeviceInfo.
        let device = [0xa1, 0x61, b'x', 0x18, 0x01];
        let protected = encode(&Value::Array(vec![
            bytes([0xa1, 1, 3]),
            Value::Map(vec![(int(5), bytes([0; 12]))]),
            bytes([0; 16]),
            Value::Array(vec![Value::Array(vec![
                bytes([]),
                Value::Map(vec![]),
                Value::Null,
            ])]),
        ]))
        .unwrap();
        let csr = assemble(&[7; 32], &device, &protected, b"test", &Value::Map(vec![])).unwrap();
        assert_eq!(&csr[2..2 + device.len()], &device);
        assert!(csr.windows(protected.len()).any(|part| part == protected));
        assert!(assemble(&[7; 31], &device, &protected, b"test", &Value::Null).is_err());
    }
}
