// Adapted from Duck-ToolBox 75f78866071287ecc749dcbbf53dbd2fc47b4e67 (MIT).
//! Optional host metadata outside authenticated RKP evidence.
use super::cbor::{array_items_raw, as_array, as_i128, as_map, as_text, decode, encode, text};
use anyhow::{ensure, Result};
use kmr_wire::cbor::value::Value;

pub(super) fn validate_fingerprint(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control),
        "build fingerprint must contain 1..1024 bytes without control characters"
    );
    Ok(())
}

pub(super) fn unverified_device_info(fingerprint: Option<&str>) -> Result<Value> {
    let entries = match fingerprint {
        Some(value) => {
            validate_fingerprint(value)?;
            vec![(text("fingerprint"), text(value))]
        }
        None => vec![],
    };
    Ok(Value::Map(entries))
}

pub(super) fn validate_unverified_device_info(value: &Value) -> Result<()> {
    let entries = as_map(value, "unverified device info")?;
    ensure!(entries.len() <= 1, "unsupported unverified device info fields");
    for (key, value) in entries {
        ensure!(as_text(key, "metadata key")? == "fingerprint", "unsupported metadata field");
        validate_fingerprint(as_text(value, "fingerprint")?)?;
    }
    Ok(())
}

/// Preserve all original fields, including noncanonical HAL encodings.
pub(super) fn with_fingerprint(csr: &[u8], fingerprint: Option<&str>) -> Result<Vec<u8>> {
    let value = decode(csr)?;
    let items = as_array(&value, "AuthenticatedRequest")?;
    ensure!(items.len() == 4, "expected four-item AuthenticatedRequest");
    ensure!(as_i128(&items[0], "version")? == 1, "unsupported AuthenticatedRequest version");
    let Some(fingerprint) = fingerprint else { return Ok(csr.to_vec()) };
    let metadata = encode(&unverified_device_info(Some(fingerprint))?)?;
    let mut result = vec![0x85];
    for item in array_items_raw(csr)? {
        result.extend_from_slice(item);
    }
    result.extend(metadata);
    ensure!(result.len() <= super::BUFFER_SIZE, "CSR with metadata exceeds device buffer limit");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_preserves_noncanonical_and_indefinite_evidence() {
        for csr in [
            vec![0x84, 0x18, 1, 0xa0, 0x9f, 0x18, 1, 0xff, 0x58, 1, 0],
            vec![0x9f, 0x18, 1, 0xa0, 0x9f, 0x18, 1, 0xff, 0x58, 1, 0, 0xff],
        ] {
            assert_eq!(with_fingerprint(&csr, None).unwrap(), csr);
            let added = with_fingerprint(&csr, Some("source/device/build")).unwrap();
            let before = array_items_raw(&csr).unwrap();
            let after = array_items_raw(&added).unwrap();
            assert_eq!(&after[..4], before);
            assert_eq!(
                decode(after[4]).unwrap(),
                unverified_device_info(Some("source/device/build")).unwrap()
            );
            assert!(with_fingerprint(&added, Some("replacement/build")).is_err());
        }
    }

    #[test]
    fn invalid_metadata_and_oversized_requests_are_rejected() {
        for fingerprint in ["".to_string(), "  ".into(), "a\nb".into(), "x".repeat(1025)] {
            assert!(unverified_device_info(Some(&fingerprint)).is_err());
        }
        for value in [
            Value::Map(vec![(text("other"), text("build"))]),
            Value::Map(vec![(text("fingerprint"), Value::Null)]),
            Value::Array(vec![]),
        ] {
            assert!(validate_unverified_device_info(&value).is_err());
        }
        let csr = encode(&Value::Array(vec![
            super::super::cbor::int(1),
            Value::Null,
            Value::Null,
            Value::Bytes(vec![0; super::super::BUFFER_SIZE - 7]),
        ]))
        .unwrap();
        assert!(with_fingerprint(&csr, Some("source/build")).is_err());
        assert!(with_fingerprint(&[0x84], Some("source/build")).is_err());
    }
}
