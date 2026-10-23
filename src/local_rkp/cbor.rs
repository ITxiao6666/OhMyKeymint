// Adapted from Duck-ToolBox, MIT; see template/THIRD_PARTY_LICENSES/Duck-ToolBox.txt.
use anyhow::{bail, ensure, Context, Result};
use kmr_wire::cbor::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};

pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let value = canonicalize(value)?;
    let mut bytes = Vec::new();
    into_writer(&value, &mut bytes).context("encode CBOR")?;
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Value> {
    preflight(bytes)?;
    let mut reader = bytes;
    let value: Value = from_reader(&mut reader).context("decode CBOR")?;
    ensure!(reader.is_empty(), "trailing data after CBOR item");
    validate_unique_maps(&value)?;
    Ok(value)
}

pub const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_CONTAINER_ITEMS: u64 = 64;

// inspect lengths and nesting before the general decoder can allocate containers
fn preflight(bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_INPUT_BYTES,
        "CBOR input must contain 1..262144 bytes"
    );
    let mut scanner = Scanner { bytes, position: 0 };
    scanner.item(0)?;
    ensure!(
        scanner.position == bytes.len(),
        "trailing data after CBOR item"
    );
    Ok(())
}

struct Scanner<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Scanner<'_> {
    fn byte(&mut self) -> Result<u8> {
        let byte = *self.bytes.get(self.position).context("truncated CBOR")?;
        self.position += 1;
        Ok(byte)
    }

    fn argument(&mut self, additional: u8) -> Result<Option<u64>> {
        let count = match additional {
            0..=23 => return Ok(Some(u64::from(additional))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Ok(None),
            _ => bail!("reserved CBOR additional information"),
        };
        let mut value = 0;
        for _ in 0..count {
            value = (value << 8) | u64::from(self.byte()?);
        }
        Ok(Some(value))
    }

    fn item(&mut self, depth: usize) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "CBOR nesting exceeds 16 levels");
        let initial = self.byte()?;
        let major = initial >> 5;
        let argument = self.argument(initial & 31)?;
        match major {
            0 | 1 | 7 => ensure!(argument.is_some(), "unexpected CBOR break"),
            2 | 3 => match argument {
                Some(length) => {
                    let length = usize::try_from(length).context("CBOR length overflow")?;
                    self.position = self
                        .position
                        .checked_add(length)
                        .context("CBOR length overflow")?;
                    ensure!(self.position <= self.bytes.len(), "truncated CBOR string");
                }
                None => {
                    while self.bytes.get(self.position) != Some(&0xff) {
                        let chunk = *self
                            .bytes
                            .get(self.position)
                            .context("truncated CBOR string")?;
                        ensure!(
                            chunk >> 5 == major && chunk & 31 != 31,
                            "invalid indefinite CBOR string chunk"
                        );
                        self.item(depth + 1)?;
                    }
                    self.position += 1;
                }
            },
            4 | 5 => {
                if let Some(length) = argument {
                    ensure!(
                        length <= MAX_CONTAINER_ITEMS,
                        "CBOR container exceeds 64 entries"
                    );
                    for _ in 0..length {
                        self.item(depth + 1)?;
                        if major == 5 {
                            self.item(depth + 1)?;
                        }
                    }
                } else {
                    let mut count = 0;
                    while self.bytes.get(self.position) != Some(&0xff) {
                        count += 1;
                        ensure!(
                            count <= MAX_CONTAINER_ITEMS,
                            "CBOR container exceeds 64 entries"
                        );
                        self.item(depth + 1)?;
                        if major == 5 {
                            self.item(depth + 1)?;
                        }
                    }
                    self.position += 1;
                }
            }
            6 => {
                ensure!(argument.is_some(), "invalid CBOR tag");
                self.item(depth + 1)?;
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

fn validate_unique_maps(value: &Value) -> Result<()> {
    match value {
        Value::Map(entries) => {
            let mut seen = std::collections::HashSet::new();
            for (key, value) in entries {
                if !seen.insert(encode(key)?) {
                    // HAL/server data can include device metadata. Keep errors
                    // suitable for the WebUI without reflecting response keys.
                    bail!("CBOR map contains a duplicate key");
                }
                validate_unique_maps(key)?;
                validate_unique_maps(value)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                validate_unique_maps(item)?;
            }
        }
        Value::Tag(_, inner) => validate_unique_maps(inner)?,
        _ => {}
    }
    Ok(())
}

pub fn int(value: i128) -> Value {
    if value >= 0 {
        Value::Integer(Integer::from(value as u64))
    } else {
        Value::Integer(Integer::from(value as i64))
    }
}

pub fn text(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

pub fn bytes(value: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(value.into())
}

pub fn empty_map() -> Value {
    Value::Map(Vec::new())
}

pub fn as_array<'a>(value: &'a Value, label: &str) -> Result<&'a [Value]> {
    match value {
        Value::Array(items) => Ok(items),
        _ => bail!("{label} is not a CBOR array"),
    }
}

pub fn as_map<'a>(value: &'a Value, label: &str) -> Result<&'a [(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => bail!("{label} is not a CBOR map"),
    }
}

pub fn as_bytes<'a>(value: &'a Value, label: &str) -> Result<&'a [u8]> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => bail!("{label} is not CBOR bytes"),
    }
}

pub fn as_text<'a>(value: &'a Value, label: &str) -> Result<&'a str> {
    match value {
        Value::Text(text) => Ok(text),
        _ => bail!("{label} is not CBOR text"),
    }
}

pub fn as_i128(value: &Value, label: &str) -> Result<i128> {
    match value {
        Value::Integer(number) => Ok((*number).into()),
        _ => bail!("{label} is not a CBOR integer"),
    }
}

pub fn map_get(entries: &[(Value, Value)], key: i128) -> Option<&Value> {
    entries
        .iter()
        .find(|(candidate, _)| matches!(candidate, Value::Integer(value) if i128::from(*value) == key))
        .map(|(_, value)| value)
}

pub fn map_get_text<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(candidate, _)| matches!(candidate, Value::Text(value) if value == key))
        .map(|(_, value)| value)
}

fn canonicalize(value: &Value) -> Result<Value> {
    match value {
        Value::Array(items) => Ok(Value::Array(
            items.iter().map(canonicalize).collect::<Result<Vec<_>>>()?,
        )),
        Value::Map(entries) => {
            let mut sorted = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let key = canonicalize(key)?;
                let value = canonicalize(value)?;
                let key_bytes = encode_preserving_order(&key)?;
                sorted.push((key_bytes, key, value));
            }

            sorted.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });

            Ok(Value::Map(
                sorted
                    .into_iter()
                    .map(|(_, key, value)| (key, value))
                    .collect(),
            ))
        }
        Value::Tag(tag, inner) => Ok(Value::Tag(*tag, Box::new(canonicalize(inner)?))),
        other => Ok(other.clone()),
    }
}

fn encode_preserving_order(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    into_writer(value, &mut bytes).context("encode CBOR")?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, int, text};
    use kmr_wire::cbor::value::Value;

    #[test]
    fn decode_requires_exactly_one_complete_cbor_item() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0x81]).is_err());
        assert_eq!(decode(&[0x81, 0]).unwrap(), Value::Array(vec![int(0)]));
        for trailing in [0, 0xff] {
            assert!(decode(&[0x81, 0, trailing]).is_err());
        }
    }

    #[test]
    fn decode_rejects_resource_exhaustion_before_decoding() {
        let mut nested = vec![0x81; 17];
        nested.push(0);
        assert!(decode(&nested).is_err());
        assert!(decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]).is_err());
        let mut wide = vec![0xb8, 65];
        wide.extend(vec![0; 130]);
        assert!(decode(&wide).is_err());
        assert!(decode(&vec![0; 262_145]).is_err());
    }

    #[test]
    fn encode_sorts_map_keys_canonically() {
        let value = Value::Map(vec![
            (text("manufacturer"), text("google")),
            (text("brand"), text("google")),
            (text("device"), text("husky")),
        ]);

        let encoded = encode(&value).unwrap();
        let decoded = decode(&encoded).unwrap();
        let Value::Map(entries) = decoded else {
            panic!("encoded device info must decode as a map");
        };

        let keys = entries
            .into_iter()
            .map(|(key, _)| match key {
                Value::Text(key) => key,
                other => panic!("unexpected key type: {other:?}"),
            })
            .collect::<Vec<_>>();

        assert_eq!(keys, vec!["brand", "device", "manufacturer"]);
    }

    #[test]
    fn encode_sorts_integer_map_keys_canonically() {
        let value = Value::Map(vec![
            (int(-1), text("minus-one")),
            (int(3), text("three")),
            (int(1), text("one")),
        ]);

        let encoded = encode(&value).unwrap();
        let decoded = decode(&encoded).unwrap();
        let Value::Map(entries) = decoded else {
            panic!("encoded map must decode as a map");
        };

        let keys = entries.into_iter().map(|(key, _)| key).collect::<Vec<_>>();

        assert_eq!(keys, vec![int(1), int(3), int(-1)]);
    }
}
