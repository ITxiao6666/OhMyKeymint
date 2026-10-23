// Adapted from Duck-ToolBox, MIT; see template/THIRD_PARTY_LICENSES/Duck-ToolBox.txt.
use anyhow::{anyhow, Result};
use kmr_wire::cbor::value::Value;

use crate::local_rkp::{
    cbor::{as_map, map_get},
    cose::ALG_ES256,
};

use super::{
    checks::{
        ensure_allowed_integer_keys, ensure_unique_integer_keys, required_bytes, required_int,
    },
    P256_COORD_LEN, P256_CURVE, TEST_KEY_LABEL,
};

/// Every `keysToSign` entry must be an ES256 P-256 COSE_Key (optionally carrying the
/// null test-key marker).
pub(super) fn validate_keys_to_sign(keys_to_sign: &[Value]) -> Result<()> {
    for (index, item) in keys_to_sign.iter().enumerate() {
        let label = format!("keysToSign entry {index}");
        let entries = as_map(item, &label)?;
        ensure_unique_integer_keys(entries, &label)?;
        ensure_allowed_integer_keys(entries, &[1, 3, -1, -2, -3, TEST_KEY_LABEL], &label)?;

        let key_type = required_int(entries, 1, &label)?;
        if key_type != 2 {
            return Err(anyhow!("{label} key type must be 2, got {key_type}"));
        }

        let algorithm = required_int(entries, 3, &label)?;
        if algorithm != ALG_ES256 {
            return Err(anyhow!(
                "{label} algorithm must be {ALG_ES256}, got {algorithm}"
            ));
        }

        let curve = required_int(entries, -1, &label)?;
        if curve != P256_CURVE {
            return Err(anyhow!("{label} curve must be {P256_CURVE}, got {curve}"));
        }

        for (key, name) in [(-2, "x coordinate"), (-3, "y coordinate")] {
            let coordinate = required_bytes(entries, key, &label, name)?;
            if coordinate.len() != P256_COORD_LEN {
                return Err(anyhow!(
                    "{label} {name} must be {P256_COORD_LEN} bytes, got {}",
                    coordinate.len()
                ));
            }
        }

        if let Some(test_key) = map_get(entries, TEST_KEY_LABEL) {
            if !matches!(test_key, Value::Null) {
                return Err(anyhow!("{label} test-key marker `-70000` must be null"));
            }
        }
    }

    Ok(())
}
