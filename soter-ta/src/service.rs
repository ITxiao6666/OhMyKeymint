//! `ISoterService` replies built from a local identity ledger.
//!
//! The vendor-HAL path in [`crate::hal`] needs the vendor's own parcel contract; a device whose
//! contract is unknown never reaches it. These builders answer the four transactions a health
//! check needs directly at the service boundary, with real ledger material instead of constants:
//! the ASK/AuthKey blobs are the same signed blobs the HAL path returns, the device id is the
//! identity's `cpu_id` bytes, and `hasAskAlready` follows the ledger.

use crate::error::{SOTER_ERR_BAD_VALUE, SOTER_ERR_NO_KEY, SOTER_OK};
use crate::state::TaState;

pub const TX_GET_APP_SECURE_KEY: u32 = 2;
pub const TX_HAS_ASK: u32 = 3;
pub const TX_GET_AUTH_KEY: u32 = 6;
pub const TX_GET_DEVICE_ID: u32 = 11;

/// Transactions this module can answer from the ledger alone.
pub fn handles(tx: u32) -> bool {
    matches!(tx, TX_GET_APP_SECURE_KEY | TX_HAS_ASK | TX_GET_AUTH_KEY | TX_GET_DEVICE_ID)
}

fn push_i32(buffer: &mut Vec<u8>, value: i32) {
    buffer.extend_from_slice(&value.to_ne_bytes());
}

fn push_no_exception(buffer: &mut Vec<u8>) {
    push_i32(buffer, 0);
}

fn push_byte_array(buffer: &mut Vec<u8>, bytes: &[u8]) {
    push_i32(buffer, bytes.len() as i32);
    buffer.extend_from_slice(bytes);
    while !buffer.len().is_multiple_of(4) {
        buffer.push(0);
    }
}

/// `SoterExportResult` / `SoterDeviceResult`: a non-null parcelable, its result code, the byte
/// array and the length field the Java class carries beside it.
fn push_result(buffer: &mut Vec<u8>, code: i32, bytes: &[u8]) {
    push_i32(buffer, 1);
    push_i32(buffer, code);
    push_byte_array(buffer, bytes);
    push_i32(buffer, bytes.len() as i32);
}

/// Read one AIDL `String` at `offset`: length, UTF-16 units, NUL, 4-byte padding.
fn read_string16_at(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let raw = data.get(offset..offset + 4)?;
    let length = i32::from_ne_bytes(raw.try_into().ok()?);
    if !(-1..=4096).contains(&length) {
        return None;
    }
    let start = offset + 4;
    if length < 0 {
        return Some((String::new(), start));
    }
    let length = length as usize;
    let units = data.get(start..start + length * 2)?;
    let mut text = String::with_capacity(length);
    for chunk in units.as_chunks::<2>().0 {
        text.push(char::from_u32(u16::from_ne_bytes(*chunk) as u32)?);
    }
    let mut end = start + length * 2;
    if end + 2 > data.len() {
        return None;
    }
    end += 2;
    while !end.is_multiple_of(4) {
        end += 1;
    }
    Some((text, end))
}

/// Name carried by a call whose prefix layering varies by SDK generation.
///
/// An AIDL proxy writes `writeInterfaceToken` before the arguments, older
/// callers may omit it, and the argument itself is the last string on the wire.
/// Scan aligned offsets for printable strings and keep the last one: that is the
/// key name regardless of how many decoration strings precede it.
fn read_argument_string(data: &[u8]) -> Option<String> {
    let mut found = None;
    let limit = data.len().min(512);
    let mut offset = 0;
    while offset + 4 <= limit {
        if let Some((value, end)) = read_string16_at(data, offset) {
            let printable = !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
            if printable {
                found = Some(value);
                offset = end.max(offset + 4);
                continue;
            }
        }
        offset += 4;
    }
    found
}

/// Build the reply parcel for one `ISoterService` transaction.
///
/// `Ok(None)` means the transaction is not one of the four this module answers; the caller must
/// keep the request on its normal path. The request bytes are only examined for `getAuthKey`.
pub fn reply(
    state: &mut TaState,
    uid: u32,
    tx: u32,
    request: &[u8],
) -> Option<Result<Vec<u8>, ()>> {
    if !handles(tx) {
        return None;
    }
    let mut reply = Vec::new();
    push_no_exception(&mut reply);
    Some(match tx {
        TX_HAS_ASK => {
            push_i32(&mut reply, if state.has_ask(uid) == SOTER_OK { 1 } else { 0 });
            Ok(reply)
        }
        TX_GET_APP_SECURE_KEY => {
            let (code, blob) = if state.has_ask(uid) == SOTER_OK {
                state.export_ask(uid)
            } else {
                (SOTER_ERR_NO_KEY, Vec::new())
            };
            push_result(&mut reply, code, &blob);
            Ok(reply)
        }
        TX_GET_AUTH_KEY => {
            let Some(kname) = read_argument_string(request) else {
                return Some(Err(()));
            };
            if kname.is_empty() {
                push_result(&mut reply, SOTER_ERR_BAD_VALUE, &[]);
                return Some(Ok(reply));
            }
            let (code, blob) = state.export_auth(uid, &kname);
            push_result(&mut reply, code, &blob);
            Ok(reply)
        }
        TX_GET_DEVICE_ID => {
            let (code, bytes) = state.device_id();
            push_result(&mut reply, code, &bytes);
            Ok(reply)
        }
        _ => unreachable!("handles() only admits the four transactions above"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blob, error::SOTER_ERR_NO_AUTH_KEY, state::TaState};

    fn seeded() -> (TaState, u32) {
        let uid = 10_123;
        let mut state = TaState::generate_local().expect("local material");
        assert_eq!(state.generate_ask(uid), SOTER_OK);
        assert_eq!(state.generate_auth(uid, "kname"), SOTER_OK);
        (state, uid)
    }

    fn int_at(bytes: &[u8], at: usize) -> i32 {
        i32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn only_the_four_service_transactions_are_answered() {
        let mut state = TaState::generate_local().unwrap();
        for tx in [1u32, 4, 5, 7, 8, 9, 10, 12, 13] {
            assert!(reply(&mut state, 10_123, tx, &[]).is_none(), "tx {tx}");
        }
        for tx in [2u32, 3, 6, 11] {
            assert!(handles(tx), "tx {tx}");
        }
    }

    #[test]
    fn has_ask_reports_the_ledger() {
        let (mut state, uid) = seeded();
        let present = reply(&mut state, uid, TX_HAS_ASK, &[]).unwrap().unwrap();
        assert_eq!(int_at(&present, 0), 0, "no exception");
        assert_eq!(int_at(&present, 4), 1, "ASK exists");
        assert_eq!(state.remove_all_uid(uid), SOTER_OK);
        let after_removal = reply(&mut state, uid, TX_HAS_ASK, &[]).unwrap().unwrap();
        assert_eq!(int_at(&after_removal, 4), 0, "ASK removed");
    }

    #[test]
    fn export_results_carry_a_verifiable_blob() {
        let (mut state, uid) = seeded();
        let reply = reply(&mut state, uid, TX_GET_APP_SECURE_KEY, &[]).unwrap().unwrap();
        assert_eq!(int_at(&reply, 0), 0);
        assert_eq!(int_at(&reply, 4), 1, "non-null parcelable");
        assert_eq!(int_at(&reply, 8), SOTER_OK);
        let length = int_at(&reply, 12) as usize;
        let blob_bytes = &reply[16..16 + length];
        assert_eq!(int_at(&reply, 16 + length.next_multiple_of(4)), length as i32);
        let (json, signature) = blob::parse(blob_bytes).expect("blob layout");
        let key = state.attk.public().expect("device public key");
        assert!(blob::verify(&key, json, signature), "signature must verify");
    }

    #[test]
    fn device_id_is_the_identity_bytes() {
        let (mut state, _uid) = seeded();
        let expected = hex::decode(&state.cpu_id).unwrap();
        let reply = reply(&mut state, 10_123, TX_GET_DEVICE_ID, &[]).unwrap().unwrap();
        let length = int_at(&reply, 12) as usize;
        assert_eq!(length, expected.len());
        assert_eq!(&reply[16..16 + length], expected.as_slice());
    }

    #[test]
    fn auth_key_request_decodes_the_string16_name() {
        let (mut state, uid) = seeded();
        // AIDL call layout: interface token first, then the method argument.
        fn push_string16(buffer: &mut Vec<u8>, value: &str) {
            let units: Vec<u16> = value.encode_utf16().collect();
            buffer.extend_from_slice(&(units.len() as i32).to_ne_bytes());
            for unit in units {
                buffer.extend_from_slice(&unit.to_ne_bytes());
            }
            buffer.extend_from_slice(&[0, 0]);
            while !buffer.len().is_multiple_of(4) {
                buffer.push(0);
            }
        }
        let mut request = Vec::new();
        push_string16(&mut request, "com.tencent.soter.soterserver.ISoterService");
        push_string16(&mut request, "kname");
        let exported = reply(&mut state, uid, TX_GET_AUTH_KEY, &request).unwrap().unwrap();
        assert_eq!(int_at(&exported, 8), SOTER_OK);
        let length = int_at(&exported, 12) as usize;
        assert!(length > 0, "exported AuthKey blob");

        let mut unknown = Vec::new();
        push_string16(&mut unknown, "com.tencent.soter.soterserver.ISoterService");
        push_string16(&mut unknown, "other");
        let missing = reply(&mut state, uid, TX_GET_AUTH_KEY, &unknown).unwrap().unwrap();
        assert_eq!(int_at(&missing, 8), SOTER_ERR_NO_AUTH_KEY);
    }
}
