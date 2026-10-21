use super::{wire::Writer, *};
use rsa::{
    Pss, RsaPublicKey,
    pkcs8::DecodePublicKey,
    sha2::{Digest, Sha256},
    traits::PublicKeyParts,
};

#[derive(Default)]
struct Buffer(Vec<u8>);

impl Buffer {
    fn align(&mut self) {
        self.0.resize((self.0.len() + 3) & !3, 0);
    }

    fn string(&mut self, value: &str) -> Result<(), i32> {
        self.int32(value.encode_utf16().count() as i32)?;
        for unit in value.encode_utf16().chain([0]) {
            self.0.extend_from_slice(&unit.to_le_bytes());
        }
        self.align();
        Ok(())
    }
}

impl Writer for Buffer {
    fn int32(&mut self, value: i32) -> Result<(), i32> {
        self.0.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn int64(&mut self, value: i64) -> Result<(), i32> {
        self.0.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), i32> {
        self.int32(value.len() as i32)?;
        self.0.extend_from_slice(value);
        self.align();
        Ok(())
    }
}

fn request(code: u32) -> Vec<u8> {
    request_for(code, 10001, "key", "challenge", 123)
}

pub(super) fn request_for(
    code: u32,
    uid: i32,
    key: &str,
    challenge: &str,
    session: i64,
) -> Vec<u8> {
    let mut output = Buffer::default();
    output.int32(0x8000_0000u32 as i32).unwrap();
    output.int32(-1).unwrap();
    output.int32(0x5359_5354).unwrap();
    output.string(DESCRIPTOR.to_str().unwrap()).unwrap();
    match code {
        1..=3 | 7 => output.int32(uid).unwrap(),
        4..=6 | 8 => {
            output.int32(uid).unwrap();
            output.string(key).unwrap();
        }
        9 => {
            output.int32(uid).unwrap();
            output.string(key).unwrap();
            output.string(challenge).unwrap();
        }
        10 => output.int64(session).unwrap(),
        13 => output.string("type").unwrap(),
        _ => {}
    }
    output.0
}

fn transaction(code: u32, bytes: &[u8]) -> Transaction {
    Transaction {
        target: 0x1234,
        cookie: 0x5678,
        code,
        flags: 0x10,
        sender_pid: 42,
        sender_euid: 10001,
        data_size: bytes.len() as u64,
        buffer: bytes.as_ptr() as u64,
        ..Default::default()
    }
}

#[test]
fn accepts_all_tencent_aidl_requests_and_oem_argument_extensions() {
    for code in 1..=13 {
        let bytes = request(code);
        assert!(wire::valid_request(code, &bytes), "code {code}");
        let mut trailing = bytes;
        trailing.extend_from_slice(&[0xff; 17]);
        assert!(wire::valid_request(code, &trailing));
        // Interface routing is independent of argument validation. The reply
        // handler must reject missing arguments before writing a response.
        assert!(wire::valid_request(code, &request(12)));
    }
    for code in [0, 14, u32::MAX] {
        assert!(!wire::valid_request(code, &request(code)));
    }
}

#[test]
fn accepts_aligned_string16_header_variants_without_arbitrary_descriptor_scan() {
    let valid = request(12);
    let token = &valid[12..];
    for prefix in [0, 4, 8, 12] {
        let mut bytes = vec![0xff; prefix];
        bytes.extend_from_slice(token);
        bytes.extend_from_slice(&[0xff; 19]);
        for code in 1..=13 {
            assert!(
                wire::valid_request(code, &bytes),
                "code {code} prefix {prefix}"
            );
        }
    }
    for prefix in [1, 2, 3, 16, 31] {
        let mut bytes = vec![0xff; prefix];
        bytes.extend_from_slice(token);
        assert!(!wire::valid_request(12, &bytes), "prefix {prefix}");
    }
    let descriptor = &valid[16..16 + DESCRIPTOR.to_bytes().len() * 2];
    assert!(!wire::valid_request(12, descriptor));
}

#[test]
fn rejects_missing_corrupt_truncated_or_oversized_descriptors() {
    let valid = request(12);
    let descriptor = &valid[16..16 + DESCRIPTOR.to_bytes().len() * 2];
    for length in 0..descriptor.len() {
        assert!(!wire::valid_request(12, &descriptor[..length]));
    }
    for index in 0..descriptor.len() {
        let mut bytes = valid.clone();
        bytes[16 + index] ^= 1;
        assert!(!wire::valid_request(12, &bytes));
    }
    assert!(!wire::valid_request(12, DESCRIPTOR.to_bytes()));
    let mut larger = valid;
    larger.resize(MAX_REQUEST_BYTES, 0);
    assert!(wire::valid_request(12, &larger));
    larger.push(0);
    assert!(!wire::valid_request(12, &larger));
}

#[test]
fn preserves_all_transaction_fields_except_selected_target() {
    let destination = Target {
        ptr: 0x8000,
        cookie: 0x9000,
    };
    for code in 1..=13 {
        let bytes = request(code);
        let before = transaction(code, &bytes);
        let mut after = before;
        assert!(retarget(&mut after, &bytes, destination, false, |_| false));
        assert_eq!(
            after,
            Transaction {
                target: destination.ptr,
                cookie: destination.cookie,
                ..before
            }
        );
    }
}

#[test]
fn per_app_routing_leaves_unselected_and_capability_requests_stock() {
    let destination = Target {
        ptr: 0x8000,
        cookie: 0x9000,
    };
    for code in 1..=13 {
        // Deliberately make the argument UID differ from the kernel sender.
        let bytes = request_for(code, 10199, "key", "challenge", 123);
        for uid in [10001, 10002, 1010001] {
            let before = Transaction {
                sender_euid: uid,
                ..transaction(code, &bytes)
            };
            let mut after = before;
            let changed = retarget(&mut after, &bytes, destination, true, |sender| {
                sender == 10001
            });
            assert_eq!(changed, uid == 10001 && code <= 11);
            assert_eq!(
                after,
                if changed {
                    Transaction {
                        target: destination.ptr,
                        cookie: destination.cookie,
                        ..before
                    }
                } else {
                    before
                }
            );
        }
    }
    let mut malformed = request(3);
    malformed[16] ^= 1;
    let mut original = transaction(3, &malformed);
    assert!(!retarget(
        &mut original,
        &malformed,
        destination,
        true,
        |_| panic!("unrelated Binder interface queried Soter authorization")
    ));
}

#[test]
fn preserves_oem_flags_and_argument_objects_when_redirecting() {
    let bytes = request(3);
    for flags in [0, 1, 8, 0x10, 0x30, 0x40, 0x100] {
        let before = Transaction {
            cookie: 0,
            flags,
            offsets_size: 8,
            offsets: 0x12345678,
            ..transaction(3, &bytes)
        };
        let mut after = before;
        assert!(retarget(
            &mut after,
            &bytes,
            Target { ptr: 1, cookie: 2 },
            false,
            |_| false
        ));
        assert_eq!(
            after,
            Transaction {
                target: 1,
                cookie: 2,
                ..before
            }
        );
    }
}

#[test]
fn leaves_unrelated_unsupported_or_malformed_transactions_unchanged() {
    let bytes = request(3);
    let base = transaction(3, &bytes);
    for before in [
        Transaction { target: 0, ..base },
        Transaction { code: 14, ..base },
        Transaction {
            data_size: MAX_REQUEST_BYTES as u64 + 1,
            ..base
        },
        Transaction { buffer: 0, ..base },
        Transaction {
            buffer: u64::MAX,
            ..base
        },
        Transaction {
            data_size: base.data_size - 1,
            ..base
        },
    ] {
        let mut after = before;
        assert!(!retarget(
            &mut after,
            &bytes,
            Target { ptr: 1, cookie: 2 },
            false,
            |_| false
        ));
        assert_eq!(after, before);
    }
    let mut malformed = bytes.clone();
    malformed[16] ^= 1;
    let mut after = base;
    assert!(!retarget(
        &mut after,
        &malformed,
        Target { ptr: 1, cookie: 2 },
        false,
        |_| false
    ));
    assert_eq!(after, base);
}

fn append_command(buffer: &mut Vec<u8>, command: u32, transaction: Transaction) {
    buffer.extend_from_slice(&command.to_ne_bytes());
    let data = unsafe {
        std::slice::from_raw_parts(
            (&transaction as *const Transaction).cast::<u8>(),
            size_of::<Transaction>(),
        )
    };
    buffer.extend_from_slice(data);
    if command == BR_TRANSACTION_SEC_CTX {
        buffer.extend_from_slice(&0x1234u64.to_ne_bytes());
    }
}

#[test]
fn validates_full_command_buffer_before_visiting_and_handles_secctx() {
    assert_eq!(size_of::<Transaction>(), 64);
    assert_eq!(size_of::<WriteRead>(), 48);
    let mut commands = Vec::new();
    append_command(
        &mut commands,
        BR_TRANSACTION,
        Transaction {
            code: 2,
            ..Default::default()
        },
    );
    commands.extend_from_slice(&0x720cu32.to_ne_bytes()); // BR_NOOP
    append_command(
        &mut commands,
        BR_TRANSACTION_SEC_CTX,
        Transaction {
            code: 6,
            ..Default::default()
        },
    );
    assert!(valid_read_commands(&commands));
    let mut visited = Vec::new();
    visit_transactions(&mut commands, |transaction| {
        visited.push(transaction.code);
        transaction.target = 0x8888;
    });
    assert_eq!(visited, [2, 6]);
    assert_eq!(&commands[commands.len() - 8..], &0x1234u64.to_ne_bytes());
    for length in 1..68 {
        assert!(!valid_read_commands(&commands[..length]));
    }
    let complete = commands.len();
    for extra in 1..4 {
        commands.resize(complete + extra, 0);
        assert!(!valid_read_commands(&commands));
    }
    assert!(!valid_pointer_range(u64::MAX - 2, 4));
    assert!(!valid_pointer_range(0, 1));
}

#[test]
fn only_exact_transaction_commands_are_visited() {
    for command in [0x8040_7203u32, 0x8038_7202, 0x4040_7202, 0x8040_6302] {
        let mut bytes = command.to_ne_bytes().to_vec();
        bytes.resize(4 + ((command >> 16) & 0x3fff) as usize, 0);
        assert!(valid_read_commands(&bytes));
        visit_transactions(&mut bytes, |_| panic!("unrelated command was visited"));
    }
}

#[test]
fn rejects_invalid_binder_carriers() {
    let mut carrier = vec![0; 28];
    carrier[..4].copy_from_slice(&BINDER_TYPE_BINDER.to_ne_bytes());
    carrier[8..16].copy_from_slice(&0x1000u64.to_ne_bytes());
    carrier[16..24].copy_from_slice(&0x2000u64.to_ne_bytes());
    assert_eq!(
        parse_carrier(&carrier),
        Some(Target {
            ptr: 0x1000,
            cookie: 0x2000
        })
    );
    for length in 0..28 {
        assert!(parse_carrier(&carrier[..length]).is_none());
    }
    carrier[0] ^= 1;
    assert!(parse_carrier(&carrier).is_none());
    carrier[0] ^= 1;
    carrier[8..16].fill(0);
    assert!(parse_carrier(&carrier).is_none());
}

fn int32(bytes: &[u8], position: usize) -> i32 {
    i32::from_le_bytes(bytes[position..position + 4].try_into().unwrap())
}

fn reply(state: &mut wire::SoftwareState, code: u32, request: &[u8]) -> Vec<u8> {
    let mut output = Buffer::default();
    state.write_reply(code, request, &mut output).unwrap();
    assert_eq!(int32(&output.0, 0), 0, "Java exception header");
    output.0
}

fn call(state: &mut wire::SoftwareState, code: u32, uid: i32, key: &str) -> Vec<u8> {
    reply(state, code, &request_for(code, uid, key, "challenge", 123))
}

fn buffer_payload(bytes: &[u8], expected_code: i32) -> &[u8] {
    assert_eq!(int32(bytes, 0), 0);
    assert_eq!(int32(bytes, 4), 1, "buffer return present");
    assert_eq!(int32(bytes, 8), expected_code, "Soter return code");
    let length: usize = int32(bytes, 12)
        .try_into()
        .expect("nonnegative array length");
    let padded = (length + 3) & !3;
    assert_eq!(bytes.len(), 20 + padded);
    assert_eq!(int32(bytes, 16 + padded), length as i32);
    assert!(
        bytes[16 + length..16 + padded]
            .iter()
            .all(|byte| *byte == 0)
    );
    &bytes[16..16 + length]
}

fn export_blob(state: &mut wire::SoftwareState, code: u32, uid: i32, key: &str) -> Vec<u8> {
    buffer_payload(&call(state, code, uid, key), 0).to_vec()
}

fn split_blob(bytes: &[u8]) -> (&[u8], &[u8]) {
    let json_length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 4 + json_length + 256);
    (&bytes[4..4 + json_length], &bytes[4 + json_length..])
}

fn blob_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(split_blob(bytes).0).unwrap()
}

fn verifies(key: &RsaPublicKey, json: &[u8], signature: &[u8]) -> bool {
    key.verify(
        Pss::new_with_salt::<Sha256>(20),
        &Sha256::digest(json),
        signature,
    )
    .is_ok()
}

// Independent public half of the published RustCrypto RSA 0.9.10 fixture.
const EXPECTED_TEST_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtsQsUV8QpqrygsY+2+JC
Q6Fw8/omM71IM2N/R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04
LHb2HJAYlz25+lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ/wcBOnyCgb3yLcvJrX
yrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0N
fFdfsZhTT8YbxBvA8FdODgEwx7u/vf3J9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejI
n04APPKIjpMyQdnWlby7rNyQtE4+CV+jcFjqJbE/Xilcvqxt6DirjFCvYeKYl1uH
LwIDAQAB
-----END PUBLIC KEY-----
";

#[test]
fn exported_public_fixture_signs_exact_json_and_rejects_all_field_tampering() {
    let mut state = wire::SoftwareState::default();
    assert_eq!(int32(&call(&mut state, 1, 10001, "alias"), 4), 0);
    assert_eq!(int32(&call(&mut state, 4, 10001, "alias"), 4), 0);
    let expected = RsaPublicKey::from_public_key_pem(EXPECTED_TEST_PUBLIC).unwrap();
    for code in [2, 6] {
        let bytes = export_blob(&mut state, code, 10001, "alias");
        let (json, signature) = split_blob(&bytes);
        let value: serde_json::Value = serde_json::from_slice(json).unwrap();
        let exported = RsaPublicKey::from_public_key_pem(value["pub_key"].as_str().unwrap())
            .expect("valid SPKI public key");
        assert_eq!(exported, expected, "matches independent upstream fixture");
        assert_eq!(exported.n().bits(), 2048);
        assert_eq!(exported.e(), &rsa::BigUint::from(65537u32));
        assert_eq!(value["uid"], "10001");
        assert_eq!(value["cpu_id"], "4f4d4b2d534f46542d544553542d3031");
        assert_eq!(value["software_test"], true);
        assert_eq!(value["key_source"], "public_test_fixture");
        assert!(value["counter"].as_u64().unwrap() > 0);
        assert!(!value.as_object().unwrap().contains_key("certs"));
        if code == 6 {
            assert_eq!(value["key_name"], "alias");
        } else {
            assert!(!value.as_object().unwrap().contains_key("key_name"));
        }
        assert!(signature.iter().any(|byte| *byte != 0));
        assert!(verifies(&expected, json, signature));
        for (field, replacement) in [
            ("uid", serde_json::json!("10002")),
            ("cpu_id", serde_json::json!("different-software-id")),
            (
                "counter",
                serde_json::json!(value["counter"].as_u64().unwrap() + 1),
            ),
            ("pub_key", serde_json::json!("changed public key")),
            ("key_name", serde_json::json!("changed alias")),
        ] {
            let mut altered = value.clone();
            altered[field] = replacement;
            assert!(
                !verifies(&expected, &serde_json::to_vec(&altered).unwrap(), signature),
                "signature must bind {field}"
            );
        }
        let mut altered_signature = signature.to_vec();
        altered_signature[0] ^= 1;
        assert!(!verifies(&expected, json, &altered_signature));
    }
    let device_reply = call(&mut state, 11, 0, "");
    let device = buffer_payload(&device_reply, 0);
    assert_eq!(device, b"OMK-SOFT-TEST-01");
    let mut device_hex = String::new();
    for byte in device {
        use std::fmt::Write as _;
        write!(device_hex, "{byte:02x}").unwrap();
    }
    assert_eq!(
        device_hex,
        blob_json(&export_blob(&mut state, 2, 10001, ""))["cpu_id"]
    );
}

#[test]
fn isolates_uid_alias_lifecycle_and_preserves_counter_after_recreation() {
    let mut state = wire::SoftwareState::default();
    assert_eq!(int32(&call(&mut state, 3, 10001, ""), 4), 0);
    assert!(buffer_payload(&call(&mut state, 2, 10001, ""), -5).is_empty());
    assert_eq!(int32(&call(&mut state, 4, 10001, "alpha"), 4), -5);
    for uid in [10001, 10002] {
        assert_eq!(int32(&call(&mut state, 1, uid, ""), 4), 0);
        for alias in ["alpha", "beta"] {
            assert_eq!(int32(&call(&mut state, 4, uid, alias), 4), 0);
            assert_eq!(int32(&call(&mut state, 8, uid, alias), 4), 1);
        }
    }
    let first = blob_json(&export_blob(&mut state, 6, 10001, "alpha"));
    let second = blob_json(&export_blob(&mut state, 6, 10001, "beta"));
    let other_uid = blob_json(&export_blob(&mut state, 6, 10002, "alpha"));
    assert_eq!(first["counter"], 1);
    assert_eq!(second["counter"], 2);
    assert_eq!(other_uid["counter"], 1);
    assert_eq!(other_uid["uid"], "10002");
    assert_eq!(
        first["pub_key"], other_uid["pub_key"],
        "public test fixture is intentionally shared"
    );
    assert_eq!(int32(&call(&mut state, 5, 10001, "alpha"), 4), 0);
    assert_eq!(int32(&call(&mut state, 8, 10001, "alpha"), 4), 0);
    assert_eq!(int32(&call(&mut state, 5, 10001, "alpha"), 4), -6);
    assert!(buffer_payload(&call(&mut state, 6, 10001, "alpha"), -6).is_empty());
    assert_eq!(int32(&call(&mut state, 8, 10001, "beta"), 4), 1);
    assert_eq!(int32(&call(&mut state, 8, 10002, "alpha"), 4), 1);
    assert_eq!(int32(&call(&mut state, 7, 10001, ""), 4), 0);
    assert_eq!(int32(&call(&mut state, 3, 10001, ""), 4), 0);
    assert_eq!(int32(&call(&mut state, 8, 10001, "beta"), 4), 0);
    assert_eq!(int32(&call(&mut state, 7, 10001, ""), 4), -5);
    assert_eq!(int32(&call(&mut state, 3, 10002, ""), 4), 1);
    assert_eq!(int32(&call(&mut state, 1, 10001, ""), 4), 0);
    let recreated = blob_json(&export_blob(&mut state, 2, 10001, ""));
    assert_eq!(recreated["counter"], 3);
    assert_eq!(recreated["pub_key"], first["pub_key"]);
    assert_eq!(recreated["cpu_id"], first["cpu_id"]);
}

fn init_session(state: &mut wire::SoftwareState, uid: i32, key: &str, expected_code: i32) -> i64 {
    let bytes = call(state, 9, uid, key);
    assert_eq!(bytes.len(), 20);
    assert_eq!(int32(&bytes, 4), 1);
    assert_eq!(int32(&bytes, 16), expected_code);
    i64::from_le_bytes(bytes[8..16].try_into().unwrap())
}

fn finish_session(state: &mut wire::SoftwareState, id: i64, expected_code: i32) {
    let bytes = reply(state, 10, &request_for(10, 0, "", "", id));
    assert!(buffer_payload(&bytes, expected_code).is_empty());
}

#[test]
fn sign_sessions_are_unique_consumed_and_never_fabricate_biometrics() {
    let mut state = wire::SoftwareState::default();
    assert_eq!(init_session(&mut state, 10001, "key", -6), 0);
    finish_session(&mut state, 0, -1000);
    assert_eq!(int32(&call(&mut state, 1, 10001, ""), 4), 0);
    assert_eq!(int32(&call(&mut state, 4, 10001, "key"), 4), 0);
    let first = init_session(&mut state, 10001, "key", 0);
    let second = init_session(&mut state, 10001, "key", 0);
    assert!(first > 0 && second > first);
    finish_session(&mut state, first, -26);
    finish_session(&mut state, first, -1000);
    finish_session(&mut state, second, -26);
    finish_session(&mut state, i64::MAX, -1000);
    finish_session(&mut state, -1, -1000);
    let removed_alias = init_session(&mut state, 10001, "key", 0);
    assert_eq!(int32(&call(&mut state, 5, 10001, "key"), 4), 0);
    finish_session(&mut state, removed_alias, -1000);
    assert_eq!(int32(&call(&mut state, 4, 10001, "key"), 4), 0);
    let removed_uid = init_session(&mut state, 10001, "key", 0);
    assert_eq!(int32(&call(&mut state, 7, 10001, ""), 4), 0);
    finish_session(&mut state, removed_uid, -1000);
    assert_eq!(call(&mut state, 12, 0, ""), [0, 0, 0, 0, 1, 0, 0, 0]);
    let extra = call(&mut state, 13, 0, "");
    assert_eq!(extra.len(), 12);
    assert_eq!(
        [int32(&extra, 0), int32(&extra, 4), int32(&extra, 8)],
        [0, 1, -1]
    );
}

#[test]
fn bounded_alias_and_session_tables_recover_capacity_after_removal() {
    let mut state = wire::SoftwareState::default();
    assert_eq!(int32(&call(&mut state, 1, 10001, ""), 4), 0);
    for index in 0..64 {
        assert_eq!(
            int32(&call(&mut state, 4, 10001, &format!("alias-{index}")), 4),
            0
        );
    }
    assert_eq!(int32(&call(&mut state, 4, 10001, "alias-0"), 4), 0);
    assert_eq!(int32(&call(&mut state, 4, 10001, "alias-64"), 4), -20);
    assert_eq!(int32(&call(&mut state, 8, 10001, "alias-64"), 4), 0);
    assert_eq!(int32(&call(&mut state, 5, 10001, "alias-63"), 4), 0);
    assert_eq!(int32(&call(&mut state, 4, 10001, "alias-64"), 4), 0);
    let sessions = (0..64)
        .map(|_| init_session(&mut state, 10001, "alias-0", 0))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(sessions.len(), 64, "all allocated session IDs are distinct");
    assert_eq!(init_session(&mut state, 10001, "alias-0", -20), 0);
    finish_session(&mut state, *sessions.first().unwrap(), -26);
    let replacement = init_session(&mut state, 10001, "alias-0", 0);
    assert!(replacement > *sessions.last().unwrap());
    finish_session(&mut state, replacement, -26);
}

#[test]
fn rejects_malformed_arguments_before_output_and_null_aliases_as_business_errors() {
    let mut state = wire::SoftwareState::default();
    for code in [1, 2, 3, 7, 4, 5, 6, 8, 9, 10, 13] {
        let mut output = Buffer::default();
        assert_eq!(
            state.write_reply(code, &request(12), &mut output),
            Err(BAD_VALUE)
        );
        assert!(output.0.is_empty(), "missing argument for code {code}");
    }
    for code in [1, 2, 3, 4, 5, 6, 7, 8, 9] {
        let mut output = Buffer::default();
        assert_eq!(
            state.write_reply(code, &request_for(code, -1, "key", "", 0), &mut output),
            Err(BAD_VALUE)
        );
        assert!(output.0.is_empty(), "negative UID for code {code}");
    }
    let key_request = request(4);
    let args_start = request(12).len();
    for length in args_start..key_request.len() {
        let mut output = Buffer::default();
        assert_eq!(
            state.write_reply(4, &key_request[..length], &mut output),
            Err(BAD_VALUE)
        );
        assert!(output.0.is_empty(), "truncated key length {length}");
    }
    let mut unterminated = key_request.clone();
    let terminator = args_start + 4 + 4 + "key".encode_utf16().count() * 2;
    unterminated[terminator] = 1;
    let mut output = Buffer::default();
    assert_eq!(
        state.write_reply(4, &unterminated, &mut output),
        Err(BAD_VALUE)
    );
    assert!(output.0.is_empty());
    let mut invalid_utf16 = key_request;
    invalid_utf16[args_start + 8..args_start + 10].copy_from_slice(&0xd800u16.to_le_bytes());
    let mut output = Buffer::default();
    assert_eq!(
        state.write_reply(4, &invalid_utf16, &mut output),
        Err(BAD_VALUE)
    );
    assert!(output.0.is_empty());
    let mut null_descriptor = vec![0; 12];
    null_descriptor.extend_from_slice(&(-1i32).to_le_bytes());
    let mut output = Buffer::default();
    assert_eq!(
        state.write_reply(12, &null_descriptor, &mut output),
        Err(BAD_VALUE)
    );
    assert!(output.0.is_empty());

    assert_eq!(int32(&call(&mut state, 1, 10001, ""), 4), 0);
    let mut null_key = Buffer(request(12));
    null_key.int32(10001).unwrap();
    null_key.int32(-1).unwrap();
    assert_eq!(int32(&reply(&mut state, 4, &null_key.0), 4), BAD_VALUE);
    assert_eq!(int32(&call(&mut state, 4, 10001, ""), 4), BAD_VALUE);
    assert!(buffer_payload(&reply(&mut state, 6, &null_key.0), BAD_VALUE).is_empty());
    let mut null_challenge = Buffer(request(12));
    null_challenge.int32(10001).unwrap();
    null_challenge.string("key").unwrap();
    null_challenge.int32(-1).unwrap();
    let rejected_init = reply(&mut state, 9, &null_challenge.0);
    assert_eq!(int32(&rejected_init, 16), BAD_VALUE);
    assert_eq!(
        i64::from_le_bytes(rejected_init[8..16].try_into().unwrap()),
        0
    );
}

#[cfg(target_os = "android")]
#[test]
fn android_local_binder_round_trip_uses_native_parcels_without_enabling_module() {
    type Prepare = unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> i32;
    type Transact =
        unsafe extern "C" fn(*mut c_void, u32, *mut *mut c_void, *mut *mut c_void, u32) -> i32;
    type WriteString = unsafe extern "C" fn(*mut c_void, *const c_char, i32) -> i32;

    // RAII releases test parcels even if a codec or transaction assertion fails.
    struct Parcel {
        pointer: *mut c_void,
        delete: ParcelDelete,
    }
    impl Drop for Parcel {
        fn drop(&mut self) {
            if !self.pointer.is_null() {
                unsafe { (self.delete)(self.pointer) };
            }
        }
    }

    let ndk = library(c"libbinder_ndk.so").expect("load Android NDK Binder");
    let binder = library(c"libbinder.so").expect("load Android platform Binder");
    let native = NATIVE
        .get_or_init(|| load_native(ndk, binder))
        .as_ref()
        .expect("construct test-local native Binder");
    let prepare: Prepare = symbol(ndk, c"AIBinder_prepareTransaction").unwrap();
    let transact: Transact = symbol(ndk, c"AIBinder_transact").unwrap();
    let write_string: WriteString = symbol(ndk, c"AParcel_writeString").unwrap();
    let delete: ParcelDelete = symbol(ndk, c"AParcel_delete").unwrap();
    let write_text = |parcel, value: &CStr| {
        assert_eq!(
            unsafe { write_string(parcel, value.as_ptr(), value.to_bytes().len() as i32) },
            0
        );
    };
    let invoke = |code: u32, session: i64| {
        let mut input = Parcel {
            pointer: ptr::null_mut(),
            delete,
        };
        let mut output = Parcel {
            pointer: ptr::null_mut(),
            delete,
        };
        assert_eq!(
            unsafe { prepare(native.binder as *mut c_void, &mut input.pointer) },
            0
        );
        assert!(!input.pointer.is_null());
        // prepareTransaction writes the class header on Android 12. The class
        // disables that header on Android 13+, so supply the Java AIDL header
        // explicitly when the prepared parcel is empty.
        if unsafe { (native.api.parcel_size)(input.pointer) } == 0 {
            for value in [0x8000_0000u32 as i32, -1, 0x5359_5354] {
                assert_eq!(unsafe { (native.api.write_i32)(input.pointer, value) }, 0);
            }
            write_text(input.pointer, DESCRIPTOR);
        }
        match code {
            1..=3 | 7 => {
                assert_eq!(unsafe { (native.api.write_i32)(input.pointer, 10501) }, 0);
            }
            4..=6 | 8 | 9 => {
                assert_eq!(unsafe { (native.api.write_i32)(input.pointer, 10501) }, 0);
                write_text(input.pointer, c"omk-native-test");
                if code == 9 {
                    write_text(input.pointer, c"local-binder-challenge");
                }
            }
            10 => {
                assert_eq!(unsafe { (native.api.write_i64)(input.pointer, session) }, 0);
            }
            13 => write_text(input.pointer, c"type"),
            _ => {}
        }
        assert_eq!(
            unsafe {
                transact(
                    native.binder as *mut c_void,
                    code,
                    &mut input.pointer,
                    &mut output.pointer,
                    0,
                )
            },
            0,
            "local transaction {code}"
        );
        assert!(
            input.pointer.is_null(),
            "transact consumes the input parcel"
        );
        // No hook is installed and no service is registered: only this local
        // Binder instance and its in-memory software-test state are exercised.
        unsafe {
            native.api.bytes(
                output.pointer,
                native.binder as *const c_void,
                true,
                Some(0),
            )
        }
        .expect("read native reply bytes")
        .to_vec()
    };

    assert_eq!(int32(&invoke(3, 0), 4), 0);
    assert_eq!(int32(&invoke(1, 0), 4), 0);
    assert_eq!(int32(&invoke(3, 0), 4), 1);
    assert_eq!(int32(&invoke(4, 0), 4), 0);
    assert_eq!(int32(&invoke(8, 0), 4), 1);
    let expected = RsaPublicKey::from_public_key_pem(EXPECTED_TEST_PUBLIC).unwrap();
    for code in [2, 6] {
        let reply = invoke(code, 0);
        let (json, signature) = split_blob(buffer_payload(&reply, 0));
        assert!(verifies(&expected, json, signature), "native export {code}");
        let value: serde_json::Value = serde_json::from_slice(json).unwrap();
        assert_eq!(value["uid"], "10501");
        assert_eq!(value["software_test"], true);
    }
    let opened = invoke(9, 0);
    assert_eq!(int32(&opened, 16), 0);
    let session = i64::from_le_bytes(opened[8..16].try_into().unwrap());
    assert!(session > 0);
    assert!(buffer_payload(&invoke(10, session), -26).is_empty());
    assert!(buffer_payload(&invoke(10, session), -1000).is_empty());
    assert_eq!(buffer_payload(&invoke(11, 0), 0), b"OMK-SOFT-TEST-01");
    let extras = invoke(13, 0);
    assert_eq!(
        [int32(&extras, 0), int32(&extras, 4), int32(&extras, 8)],
        [0, 1, -1]
    );
    assert_eq!(int32(&invoke(7, 0), 4), 0);
    assert_eq!(int32(&invoke(3, 0), 4), 0);
    assert!(
        !ACTIVE.load(Ordering::Acquire),
        "test does not activate Zygisk interception"
    );
}

#[test]
fn initial_native_write_failure_stops_without_mutating_ledger_or_sessions() {
    struct Reject;
    impl Writer for Reject {
        fn int32(&mut self, _: i32) -> Result<(), i32> {
            Err(-12)
        }
        fn int64(&mut self, _: i64) -> Result<(), i32> {
            panic!("write after failure")
        }
        fn bytes(&mut self, _: &[u8]) -> Result<(), i32> {
            panic!("write after failure")
        }
    }
    let mut state = wire::SoftwareState::default();
    for code in 1..=13 {
        assert_eq!(
            state.write_reply(code, &request(code), &mut Reject),
            Err(-12)
        );
    }
    assert_eq!(
        int32(&call(&mut state, 3, 10001, ""), 4),
        0,
        "rejected ASK generation has no side effect"
    );
    assert_eq!(int32(&call(&mut state, 1, 10001, ""), 4), 0);
    assert_eq!(int32(&call(&mut state, 4, 10001, "key"), 4), 0);
    let session = init_session(&mut state, 10001, "key", 0);
    for code in [2, 5, 6, 7, 9] {
        assert_eq!(
            state.write_reply(code, &request(code), &mut Reject),
            Err(-12)
        );
    }
    assert_eq!(
        state.write_reply(10, &request_for(10, 0, "", "", session), &mut Reject),
        Err(-12)
    );
    assert_eq!(int32(&call(&mut state, 8, 10001, "key"), 4), 1);
    assert_eq!(
        blob_json(&export_blob(&mut state, 2, 10001, ""))["counter"],
        1
    );
    let next = init_session(&mut state, 10001, "key", 0);
    assert_eq!(
        next,
        session + 1,
        "rejected init did not allocate a session"
    );
    finish_session(&mut state, session, -26);
    for code in [0, 14, u32::MAX] {
        let mut output = Buffer::default();
        assert_eq!(
            state.write_reply(code, &request(code), &mut output),
            Err(UNKNOWN_TRANSACTION)
        );
        assert!(output.0.is_empty());
    }
}
