use super::{wire::Writer, *};

#[derive(Default)]
pub(super) struct Buffer(pub(super) Vec<u8>);

impl Buffer {
    fn align(&mut self) {
        self.0.resize((self.0.len() + 3) & !3, 0);
    }

    /// Append a Java `writeString` value while building a request fixture.
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
    let mut output = Buffer::default();
    output.int32(0x8000_0000u32 as i32).unwrap();
    output.int32(-1).unwrap();
    output.int32(0x5359_5354).unwrap();
    output.string(DESCRIPTOR.to_str().unwrap()).unwrap();
    match code {
        1..=3 | 7 => output.int32(10001).unwrap(),
        4..=6 | 8 => {
            output.int32(10001).unwrap();
            output.string("key").unwrap();
        }
        9 => {
            output.int32(10001).unwrap();
            output.string("key").unwrap();
            output.string("challenge").unwrap();
        }
        10 => output.int64(123).unwrap(),
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
        // Routing scans the descriptor; argument validation happens in the callback.
        assert!(wire::valid_request(code, &request(12)));
    }
    for code in [0, 14, u32::MAX] {
        assert!(!wire::valid_request(code, &request(code)));
    }
}

#[test]
fn matches_upstream_descriptor_scan_across_header_layouts() {
    let valid = request(12);
    let descriptor = &valid[16..16 + DESCRIPTOR.to_bytes().len() * 2];
    for prefix in [0, 1, 8, 12, 16, 31] {
        let mut bytes = vec![0xff; prefix];
        bytes.extend_from_slice(descriptor);
        bytes.extend_from_slice(&[0xff; 19]);
        for code in 1..=13 {
            assert!(wire::valid_request(code, &bytes), "code {code} prefix {prefix}");
        }
    }
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
    let destination = Target { ptr: 0x8000, cookie: 0x9000 };
    for code in 1..=13 {
        let bytes = request(code);
        let before = transaction(code, &bytes);
        let mut after = before;
        assert!(retarget(&mut after, &bytes, destination));
        assert_eq!(
            after,
            Transaction { target: destination.ptr, cookie: destination.cookie, ..before }
        );
    }
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
        assert!(retarget(&mut after, &bytes, Target { ptr: 1, cookie: 2 }));
        assert_eq!(after, Transaction { target: 1, cookie: 2, ..before });
    }
}

#[test]
fn leaves_unrelated_unsupported_or_malformed_transactions_unchanged() {
    let bytes = request(3);
    let base = transaction(3, &bytes);
    for before in [
        Transaction { target: 0, ..base },
        Transaction { code: 14, ..base },
        Transaction { data_size: MAX_REQUEST_BYTES as u64 + 1, ..base },
        Transaction { buffer: 0, ..base },
        Transaction { buffer: u64::MAX, ..base },
        Transaction { data_size: base.data_size - 1, ..base },
    ] {
        let mut after = before;
        assert!(!retarget(&mut after, &bytes, Target { ptr: 1, cookie: 2 }));
        assert_eq!(after, before);
    }
    let mut malformed = bytes.clone();
    malformed[16] ^= 1;
    let mut after = base;
    assert!(!retarget(&mut after, &malformed, Target { ptr: 1, cookie: 2 }));
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
    append_command(&mut commands, BR_TRANSACTION, Transaction { code: 2, ..Default::default() });
    commands.extend_from_slice(&0x720cu32.to_ne_bytes()); // BR_NOOP
    append_command(
        &mut commands,
        BR_TRANSACTION_SEC_CTX,
        Transaction { code: 6, ..Default::default() },
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
    assert_eq!(parse_carrier(&carrier), Some(Target { ptr: 0x1000, cookie: 0x2000 }));
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

#[test]
fn encodes_non_key_reply_shapes() {
    const UID: u32 = 10123;
    for code in [5, 7, 10, 11, 12, 9, 13] {
        let mut output = Buffer::default();
        let mut arguments = wire::Arguments::default();
        if code == 10 {
            // `finishSign` always carries a session; zero is one no `initSigh` opened.
            arguments.session = Some(0);
        }
        wire::write_reply(code, UID, &arguments, &mut output).unwrap();
        let bytes = output.0;
        assert_eq!(int32(&bytes, 0), 0);
        match code {
            5 => assert_eq!(int32(&bytes, 4), -6),
            7 => assert_eq!(bytes, [0; 8]),
            12 => assert_eq!(bytes, [0, 0, 0, 0, 1, 0, 0, 0]),
            13 => assert_eq!(bytes, [0; 8]),
            9 => {
                // No AuthKey exists yet: a zero session and the vendor's missing-key code.
                assert_eq!(bytes.len(), 20);
                assert_eq!(i64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0);
                assert_eq!(int32(&bytes, 16), -6);
            }
            10 => {
                // No session was opened: the vendor's unknown-session code, empty result.
                assert_eq!(int32(&bytes, 4), 1);
                assert_eq!(int32(&bytes, 8), -1000);
                assert_eq!(int32(&bytes, 12), 0);
                assert_eq!(int32(&bytes, 16), 0);
                assert_eq!(bytes.len(), 20);
            }
            11 => {
                assert_eq!(int32(&bytes, 4), 1);
                assert_eq!(int32(&bytes, 8), 0);
                let length = int32(&bytes, 12) as usize;
                let padded = (length + 3) & !3;
                assert_eq!(int32(&bytes, 16 + padded), length as i32);
                assert_eq!(bytes.len(), 20 + padded);
                let payload = &bytes[16..16 + length];
                assert_eq!(payload.len(), 16);
                assert_ne!(payload, b"TEESIM-SOTER-0001");
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn stops_on_native_write_errors_and_rejects_unknown_codes_without_output() {
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
    const UID: u32 = 10123;
    for code in 1..=13 {
        assert_eq!(
            wire::write_reply(code, UID, &wire::Arguments::default(), &mut Reject),
            Err(-12)
        );
    }
    for code in [0, 14, u32::MAX] {
        let mut output = Buffer::default();
        assert_eq!(
            wire::write_reply(code, UID, &wire::Arguments::default(), &mut output),
            Err(UNKNOWN_TRANSACTION)
        );
        assert!(output.0.is_empty());
    }
}

#[test]
fn parses_arguments_after_the_platform_header_and_preserves_utf16_aliases() {
    let alias: [u16; 7] = [0x61, 0, 0x62, 0x4e2d, 0xd83d, 0xdd11, 0xd800];
    for prefix in [0, 8, 12, 16] {
        let mut bytes = Buffer(vec![0; prefix]);
        bytes.int32(-123).unwrap(); // A declared UID never supplies the caller identity.
        bytes.int32(alias.len() as i32).unwrap();
        for unit in alias.into_iter().chain([0]) {
            bytes.0.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.align();
        let end = bytes.0.len();
        for code in [4, 5, 6, 8] {
            let parsed = wire::request_arguments(code, &bytes.0, prefix).unwrap();
            assert_eq!(parsed.alias, alias);
            assert_eq!(parsed.challenge, None);
            for length in prefix..end {
                assert_eq!(
                    wire::request_arguments(code, &bytes.0[..length], prefix),
                    Err(BAD_VALUE)
                );
            }
        }
        // `initSigh` carries the challenge after the alias.
        bytes.string("challenge").unwrap();
        let parsed = wire::request_arguments(9, &bytes.0, prefix).unwrap();
        assert_eq!(parsed.alias, alias);
        assert_eq!(parsed.challenge.as_deref(), Some("challenge"));
        let end = bytes.0.len();
        for length in prefix..end {
            assert_eq!(wire::request_arguments(9, &bytes.0[..length], prefix), Err(BAD_VALUE));
        }
        bytes.0.extend_from_slice(&[0xff; 17]);
        let trailing = wire::request_arguments(9, &bytes.0, prefix).unwrap();
        assert_eq!(trailing.alias, alias);
        assert_eq!(trailing.challenge.as_deref(), Some("challenge"));
    }
    for length in [-1, 0, i32::MAX] {
        let mut bytes = Buffer::default();
        bytes.int32(1).unwrap();
        bytes.int32(length).unwrap();
        assert_eq!(wire::request_arguments(4, &bytes.0, 0), Err(BAD_VALUE));
    }
    let mut bytes = Buffer::default();
    bytes.int32(1).unwrap();
    bytes.string("a").unwrap();
    bytes.0[10] = 1; // Missing UTF-16 terminator.
    assert_eq!(wire::request_arguments(4, &bytes.0, 0), Err(BAD_VALUE));
    assert_eq!(wire::request_arguments(1, &[0; 3], 0), Err(BAD_VALUE));
    assert_eq!(wire::request_arguments(1, &[0; 4], 0).unwrap(), wire::Arguments::default());
    assert_eq!(wire::request_arguments(4, &bytes.0, 1), Err(BAD_VALUE));
    assert_eq!(wire::request_arguments(12, &[], 0).unwrap(), wire::Arguments::default());
}

#[test]
fn parses_signing_sessions_and_extra_parameter_keys() {
    let mut session = Buffer::default();
    session.int64(-7).unwrap();
    let parsed = wire::request_arguments(10, &session.0, 0).unwrap();
    assert_eq!(parsed.session, Some(-7));
    assert_eq!(parsed.alias, Vec::<u16>::new());
    assert_eq!(wire::request_arguments(10, &session.0[..7], 0), Err(BAD_VALUE));

    for key in ["fingerprint_type", "sotercheck_unknown_param", ""] {
        let mut bytes = Buffer::default();
        bytes.string(key).unwrap();
        let parsed = wire::request_arguments(13, &bytes.0, 0).unwrap();
        assert_eq!(parsed.key.as_deref(), Some(key));
    }
    let mut null_key = Buffer::default();
    null_key.int32(-1).unwrap();
    assert_eq!(wire::request_arguments(13, &null_key.0, 0).unwrap().key, None);
    // A null challenge is the Java `writeString(null)` spelling.
    let mut null_challenge = Buffer::default();
    null_challenge.int32(1).unwrap();
    null_challenge.string("k").unwrap();
    null_challenge.int32(-1).unwrap();
    let parsed = wire::request_arguments(9, &null_challenge.0, 0).unwrap();
    assert_eq!(parsed.alias, vec![0x6b]);
    assert_eq!(parsed.challenge.as_deref(), Some(""));
}
