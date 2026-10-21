//! Host-side tests for the software TA.
//!
//! Two of these are anchored to bytes captured from the live HAL of the OnePlus 13
//! (`getDeviceId` and `hasAskAlready` while its TA was dead), so any drift in the
//! reply encoder away from the vendor wire format fails here.

use crate::blob;
use crate::dispatch;
use crate::error::{
    SOTER_ERR_NO_AUTH_KEY, SOTER_ERR_NO_FINGERPRINT, SOTER_ERR_NO_KEY, SOTER_ERR_TA_UNAVAILABLE,
    SOTER_OK,
};
use crate::parcel::{self, Args, Reply};
use crate::platform::Platform;
use crate::state::{TaState, BIO_WINDOW_MS};

const UID: u32 = 10503;
const KNAME: &str = "ommega_default_key";

/// Builds a request parcel the way the generated client stubs do: strict-mode
/// policy word, interface token, then the arguments.
struct RequestBuilder {
    buf: Vec<u8>,
}

impl RequestBuilder {
    fn new(token: &str) -> Self {
        let mut builder = Self { buf: Vec::new() };
        builder.buf.extend_from_slice(&0i32.to_le_bytes());
        builder.string16(token)
    }

    fn i32(mut self, value: i32) -> Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn i64(mut self, value: i64) -> Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn string16(mut self, value: &str) -> Self {
        let units: Vec<u16> = value.encode_utf16().collect();
        self.buf
            .extend_from_slice(&(units.len() as i32).to_le_bytes());
        for unit in &units {
            self.buf.extend_from_slice(&unit.to_le_bytes());
        }
        self.buf.extend_from_slice(&0u16.to_le_bytes());
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        self
    }

    fn build(self) -> Vec<u8> {
        self.buf
    }
}

fn state() -> TaState {
    TaState::generate_local().expect("local TA state")
}

fn call(state: &mut TaState, tx: u32, request: &[u8]) -> Vec<u8> {
    let (token, mut args) = Args::parse_request(request).expect("request parses");
    assert!(Args::is_soter_token(&token), "unexpected token: {token}");
    dispatch::handle(state, tx, &mut args, Platform::default())
        .expect("transaction belongs to the software TA")
}

fn word(bytes: &[u8], index: usize) -> i32 {
    let start = index * 4;
    i32::from_le_bytes(bytes[start..start + 4].try_into().expect("word"))
}

/// Reads `[status][rc][presence][size][byte[] buffer][int32 field]`.
fn parse_buffer_return(reply: &[u8]) -> Vec<u8> {
    let mut args = Args::new(reply);
    assert_eq!(args.read_i32(), Some(0), "status header");
    assert_eq!(args.read_i32(), Some(SOTER_OK), "return code");
    assert_eq!(args.read_i32(), Some(1), "out parameter is present");
    let size = args.read_i32().expect("size");
    let buffer = args.read_byte_array().expect("buffer");
    assert_eq!(
        args.read_i32(),
        Some(buffer.len() as i32),
        "buffer field carries the export length"
    );
    assert_eq!(size as usize, 4 + 4 + ((buffer.len() + 3) & !3) + 4);
    buffer
}

fn counter_of(blob_bytes: &[u8]) -> u64 {
    let (json, _) = blob::parse(blob_bytes).expect("blob structure");
    let value: serde_json::Value = serde_json::from_slice(json).expect("blob JSON");
    value["counter"].as_u64().expect("counter")
}

fn json_field(blob_bytes: &[u8], field: &str) -> String {
    let (json, _) = blob::parse(blob_bytes).expect("blob structure");
    let value: serde_json::Value = serde_json::from_slice(json).expect("blob JSON");
    value[field].as_str().expect("string field").to_string()
}

#[test]
fn reply_bytes_match_captured_hal_failures() {
    // getDeviceId with a dead TA: status ok, rc -20, a present but empty
    // SoterBufferReturn.
    let mut reply = Reply::ok();
    reply.i32(SOTER_ERR_TA_UNAVAILABLE);
    reply.buffer_return(&[], 0);
    assert_eq!(
        hex::encode(reply.into_bytes()),
        "00000000ecffffff010000000c0000000000000000000000"
    );

    // hasAskAlready for a uid with no ASK: status ok, rc -5.
    let mut reply = Reply::ok();
    reply.i32(SOTER_ERR_NO_KEY);
    assert_eq!(hex::encode(reply.into_bytes()), "00000000fbffffff");
}

#[test]
fn request_parsing_matches_client_layout() {
    let request = RequestBuilder::new(parcel::SOTER_INTERFACE)
        .i32(UID as i32)
        .string16(KNAME)
        .build();
    let (token, mut args) = Args::parse_request(&request).expect("parse");
    assert_eq!(token, parcel::SOTER_INTERFACE);
    assert!(Args::is_soter_token(&token));
    assert_eq!(args.read_u32(), Some(UID));
    assert_eq!(args.read_string16().as_deref(), Some(KNAME));

    // the `<descriptor>/default` spelling is accepted too
    let request = RequestBuilder::new(parcel::SOTER_INTERFACE_INSTANCE).build();
    let (token, _) = Args::parse_request(&request).expect("parse");
    assert!(Args::is_soter_token(&token));
}

#[test]
fn ask_blob_signature_verifies_under_the_device_key() {
    let mut state = state();
    assert_eq!(state.generate_ask(UID), SOTER_OK);
    let (code, blob_bytes) = state.export_ask(UID);
    assert_eq!(code, SOTER_OK);

    let (json, signature) = blob::parse(&blob_bytes).expect("blob structure");
    assert_eq!(signature.len(), blob::SIGNATURE_LEN);
    let device_key = blob::public_key_from_pem(&state.attk.public_pem).expect("device key");
    assert!(blob::verify(&device_key, json, signature));

    let text = String::from_utf8(json.to_vec()).expect("utf8 json");
    let position = |needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("{needle} in {text}"))
    };
    assert!(position("\"pub_key\"") < position("\"cpu_id\""));
    assert!(position("\"cpu_id\"") < position("\"counter\""));
    assert!(position("\"counter\"") < position("\"uid\""));
    assert!(!text.contains("certs"), "{text}");
}

#[test]
fn auth_blob_and_sign_result_verify_along_the_chain() {
    let mut state = state();
    assert_eq!(state.generate_ask(UID), SOTER_OK);
    assert_eq!(state.generate_auth(UID, KNAME), SOTER_OK);

    let (code, auth_blob) = state.export_auth(UID, KNAME);
    assert_eq!(code, SOTER_OK);
    let (auth_json, auth_signature) = blob::parse(&auth_blob).expect("auth blob");
    let ask_public =
        blob::public_key_from_pem(&state.uids[&UID].ask.as_ref().expect("ask").public_pem)
            .expect("ask public key");
    assert!(blob::verify(&ask_public, auth_json, auth_signature));

    let (code, session) = state.init_sign(UID, KNAME, "challenge-1", Platform::default());
    assert_eq!(code, SOTER_OK);
    assert!(session > 0);

    let (code, result_blob) = state.finish_sign(session, Platform::default());
    assert_eq!(code, SOTER_OK);
    let (result_json, result_signature) = blob::parse(&result_blob).expect("result blob");
    let auth_public =
        blob::public_key_from_pem(&state.uids[&UID].auth[KNAME].public_pem).expect("auth key");
    assert!(blob::verify(&auth_public, result_json, result_signature));

    let text = String::from_utf8(result_json.to_vec()).expect("utf8 json");
    for field in [
        "raw", "fid", "counter", "tee_n", "tee_v", "fp_n", "fp_v", "cpu_id", "uid",
    ] {
        assert!(text.contains(&format!("\"{field}\"")), "{text}");
    }
    assert!(text.contains("\"raw\":\"challenge-1\""), "{text}");
}

#[test]
fn counters_are_strictly_increasing_per_uid() {
    let mut state = state();
    let other = 10349;
    assert_eq!(state.generate_ask(UID), SOTER_OK);
    assert_eq!(state.generate_ask(other), SOTER_OK);

    let (_, first) = state.export_ask(UID);
    let (_, second) = state.export_ask(UID);
    let (_, independent) = state.export_ask(other);
    assert_eq!(counter_of(&second), counter_of(&first) + 1);
    assert!(counter_of(&independent) > 0);
    assert_ne!(counter_of(&independent), counter_of(&second));
}

#[test]
fn ledger_tracks_presence_and_removal() {
    let mut state = state();
    assert_eq!(state.has_ask(UID), SOTER_ERR_NO_KEY);
    assert_eq!(state.export_ask(UID).0, SOTER_ERR_NO_KEY);
    assert_eq!(
        state.generate_auth(UID, KNAME),
        SOTER_ERR_NO_KEY,
        "no ASK yet"
    );

    assert_eq!(state.generate_ask(UID), SOTER_OK);
    assert_eq!(state.has_ask(UID), SOTER_OK);
    assert_eq!(state.generate_auth(UID, KNAME), SOTER_OK);
    assert_eq!(state.has_auth(UID, KNAME), SOTER_OK);

    assert_eq!(state.remove_auth(UID, KNAME), SOTER_OK);
    // A missing AuthKey answers -6 on a live vendor TA even while the ASK is
    // still there (PHB110 capture, 2026-09-26); -5 is the dead-TA spelling.
    assert_eq!(state.has_auth(UID, KNAME), SOTER_ERR_NO_AUTH_KEY);
    assert_eq!(state.remove_auth(UID, KNAME), SOTER_ERR_NO_AUTH_KEY);
    assert_eq!(
        state.remove_auth(999_999, KNAME),
        SOTER_ERR_NO_AUTH_KEY,
        "AuthKey-scoped lookups answer -6 even with no ledger entry at all"
    );
    assert_eq!(state.export_auth(UID, KNAME).0, SOTER_ERR_NO_AUTH_KEY);
    assert_eq!(
        state
            .init_sign(UID, KNAME, "challenge", Platform::default())
            .0,
        SOTER_ERR_NO_AUTH_KEY
    );

    assert_eq!(state.remove_all_uid(UID), SOTER_OK);
    assert_eq!(state.has_ask(UID), SOTER_ERR_NO_KEY);
    assert_eq!(state.remove_all_uid(UID), SOTER_ERR_NO_KEY);
    assert_eq!(state.has_ask(999_999), SOTER_ERR_NO_KEY);
}

#[test]
fn sign_sessions_are_single_use() {
    let mut state = state();
    assert_eq!(state.generate_ask(UID), SOTER_OK);
    assert_eq!(state.generate_auth(UID, KNAME), SOTER_OK);

    let (code, session) = state.init_sign(UID, KNAME, "challenge", Platform::default());
    assert_eq!(code, SOTER_OK);
    assert_eq!(state.finish_sign(session, Platform::default()).0, SOTER_OK);
    assert_ne!(
        state.finish_sign(session, Platform::default()).0,
        SOTER_OK,
        "session is consumed"
    );
    assert_ne!(
        state.finish_sign(4242, Platform::default()).0,
        SOTER_OK,
        "unknown session"
    );
    assert_ne!(
        state
            .init_sign(UID, "missing", "challenge", Platform::default())
            .0,
        SOTER_OK
    );

    // removing the key invalidates a session that was already opened
    let (_, session) = state.init_sign(UID, KNAME, "challenge", Platform::default());
    assert_eq!(state.remove_all_uid(UID), SOTER_OK);
    assert_ne!(state.finish_sign(session, Platform::default()).0, SOTER_OK);
}

/// A fingerprint mark the gate tests can move: the high bits are one boot tag.
const BOOT_TAG: u64 = 0x5A17_0000_0000;

fn platform_at(boot_ms: u64, accepted: u64) -> Platform {
    Platform {
        boot_ms: Some(boot_ms),
        bio_mark: Some(BOOT_TAG | accepted),
    }
}

fn signable_state() -> TaState {
    let mut state = state();
    assert_eq!(state.generate_ask(UID), SOTER_OK);
    assert_eq!(state.generate_auth(UID, KNAME), SOTER_OK);
    state
}

#[test]
fn finish_sign_without_a_fingerprint_answers_minus_26() {
    let mut state = signable_state();
    let (code, session) = state.init_sign(UID, KNAME, "challenge", platform_at(1_000, 7));
    assert_eq!(code, SOTER_OK);

    // Nothing was accepted since the session opened: the answer is the one a
    // stock TA gives, and the session stays open for a later press.
    let (code, data) = state.finish_sign(session, platform_at(1_400, 7));
    assert_eq!(code, SOTER_ERR_NO_FINGERPRINT);
    assert!(data.is_empty());

    let (code, data) = state.finish_sign(session, platform_at(1_800, 8));
    assert_eq!(code, SOTER_OK, "a press after the refusal still signs");
    assert!(!data.is_empty());
}

#[test]
fn one_accepted_fingerprint_pays_for_one_signature() {
    let mut state = signable_state();
    let (_, first) = state.init_sign(UID, KNAME, "first", platform_at(1_000, 10));
    let (_, second) = state.init_sign(UID, KNAME, "second", platform_at(1_100, 10));

    assert_eq!(state.finish_sign(first, platform_at(1_200, 11)).0, SOTER_OK);
    let (code, data) = state.finish_sign(second, platform_at(1_300, 11));
    assert_eq!(
        code, SOTER_ERR_NO_FINGERPRINT,
        "the match was already spent"
    );
    assert!(data.is_empty());
}

#[test]
fn stale_and_cross_boot_sessions_have_no_evidence() {
    let mut state = signable_state();

    let (_, old) = state.init_sign(UID, KNAME, "old", platform_at(1_000, 3));
    let late = platform_at(1_000 + BIO_WINDOW_MS + 1, 4);
    assert_eq!(state.finish_sign(old, late).0, SOTER_ERR_NO_FINGERPRINT);

    // The counter restarts with the boot; a mark from the previous boot is not
    // evidence even when it carries a larger number.
    let (_, crossed) = state.init_sign(UID, KNAME, "crossed", platform_at(5_000, 9));
    let next_boot = Platform {
        boot_ms: Some(6_000),
        bio_mark: Some((BOOT_TAG + (1 << 40)) | 2),
    };
    assert_eq!(
        state.finish_sign(crossed, next_boot).0,
        SOTER_ERR_NO_FINGERPRINT
    );
}

#[test]
fn a_missing_platform_hook_keeps_signing() {
    let mut state = signable_state();
    let (_, session) = state.init_sign(UID, KNAME, "challenge", Platform::default());
    assert_eq!(
        state.finish_sign(session, Platform::default()).0,
        SOTER_OK,
        "no hooks: answer like the revision before the biometric gate"
    );
}

#[test]
fn device_id_matches_the_cpu_id_inside_the_blobs() {
    let mut state = state();
    let (code, id) = state.device_id();
    assert_eq!(code, SOTER_OK);
    // Raw bytes, not the hex spelling: that is what a device with a working TA
    // answers, and their hex is the `cpu_id` inside every blob.
    assert_eq!(id.len(), 16, "16 raw bytes");
    assert_eq!(hex::encode(&id), state.cpu_id);
    assert!(state.cpu_id.starts_with("00000000"));

    assert_eq!(state.generate_ask(UID), SOTER_OK);
    let (_, ask_blob) = state.export_ask(UID);
    assert_eq!(json_field(&ask_blob, "cpu_id"), hex::encode(&id));
}

#[test]
fn state_json_round_trip_preserves_the_ledger() {
    let mut state = state();
    assert_eq!(state.generate_ask(UID), SOTER_OK);
    assert_eq!(state.generate_auth(UID, KNAME), SOTER_OK);
    let (_, before) = state.export_auth(UID, KNAME);

    let encoded = state.to_json();
    let mut restored = TaState::from_json(&encoded).expect("round trip");
    assert_eq!(restored.cpu_id, state.cpu_id);
    assert_eq!(restored.has_ask(UID), SOTER_OK);
    assert_eq!(restored.has_auth(UID, KNAME), SOTER_OK);
    let (code, after) = restored.export_auth(UID, KNAME);
    assert_eq!(code, SOTER_OK);
    assert_eq!(
        json_field(&before, "pub_key"),
        json_field(&after, "pub_key")
    );
    assert!(counter_of(&after) > counter_of(&before));
}

/// The ledger has to survive a truncated file, and an unreadable one must never
/// be replaced by a fresh identity behind the operator's back: clients (and the
/// relay-era registration) remember the old device id.
#[test]
fn the_ledger_is_written_atomically_and_never_silently_replaced() {
    let dir = std::env::temp_dir().join(format!("soterta-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("state.json");
    let backup = path.with_file_name("state.json.bak");

    // No identity yet: the caller may mint one.
    assert!(TaState::load_or_error(&path)
        .expect("a missing file is not an error")
        .is_none());

    let mut state = state();
    assert_eq!(state.generate_ask(UID), SOTER_OK);
    state.store(&path).expect("first revision");
    let kept_id = state.cpu_id.clone();
    assert!(!backup.exists(), "nothing to keep yet");

    // A second revision keeps the previous one beside the ledger.
    assert_eq!(state.generate_auth(UID, KNAME), SOTER_OK);
    state.store(&path).expect("second revision");
    assert!(backup.exists(), "the previous revision is kept");
    let older = TaState::load(&backup).expect("the backup parses");
    assert_eq!(older.cpu_id, kept_id);
    assert_eq!(older.has_ask(UID), SOTER_OK);
    assert_ne!(older.has_auth(UID, KNAME), SOTER_OK, "the backup is older");

    // A truncated ledger falls back to the kept revision, same identity.
    std::fs::write(&path, b"{\"cpu_id\": \"0000").expect("truncate");
    let recovered = TaState::load_or_error(&path)
        .expect("the backup recovers")
        .expect("state");
    assert_eq!(recovered.cpu_id, kept_id, "the identity is preserved");
    assert_eq!(recovered.has_ask(UID), SOTER_OK);
    assert_eq!(
        TaState::load(&path)
            .expect("the main file is restored")
            .cpu_id,
        kept_id
    );

    // With both files broken it is an error, not a new identity.
    std::fs::write(&path, b"not json").expect("break the main file");
    std::fs::write(&backup, b"not json either").expect("break the backup");
    assert!(
        TaState::load_or_error(&path).is_err(),
        "unreadable must not become a new identity"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn dispatch_serves_the_java_layer_and_the_attk_trio() {
    let mut state = state();
    let token = parcel::SOTER_INTERFACE;

    assert!(dispatch::handles(dispatch::TX_GENERATE_ASK));
    // Answered since 2026-09-25: the vendor engineering-mode key check reads
    // verifyAttkKeyPair through cryptoeng, and with a dead TA that item failed.
    assert!(dispatch::handles(dispatch::TX_VERIFY_ATTK));
    assert!(dispatch::handles(dispatch::TX_EXPORT_ATTK));
    assert!(dispatch::handles(dispatch::TX_GENERATE_ATTK));

    let reply = call(
        &mut state,
        dispatch::TX_HAS_ASK,
        &RequestBuilder::new(token).i32(UID as i32).build(),
    );
    assert_eq!(word(&reply, 1), SOTER_ERR_NO_KEY, "no ASK yet");

    let reply = call(
        &mut state,
        dispatch::TX_GENERATE_ASK,
        &RequestBuilder::new(token).i32(UID as i32).build(),
    );
    assert_eq!(word(&reply, 0), 0);
    assert_eq!(word(&reply, 1), SOTER_OK);

    let reply = call(
        &mut state,
        dispatch::TX_EXPORT_ASK,
        &RequestBuilder::new(token).i32(UID as i32).build(),
    );
    assert_eq!(word(&reply, 2), 1, "out parameter present");
    let exported = parse_buffer_return(&reply);
    let (json, signature) = blob::parse(&exported).expect("blob");
    let device_key = blob::public_key_from_pem(&state.attk.public_pem).expect("device key");
    assert!(blob::verify(&device_key, json, signature));

    let reply = call(
        &mut state,
        dispatch::TX_GENERATE_AUTH,
        &RequestBuilder::new(token)
            .i32(UID as i32)
            .string16(KNAME)
            .build(),
    );
    assert_eq!(word(&reply, 1), SOTER_OK);

    let reply = call(
        &mut state,
        dispatch::TX_INIT_SIGN,
        &RequestBuilder::new(token)
            .i32(UID as i32)
            .string16(KNAME)
            .string16("challenge")
            .build(),
    );
    assert_eq!(word(&reply, 0), 0, "status header");
    assert_eq!(word(&reply, 1), 1, "return value present");
    assert_eq!(word(&reply, 2), 16, "SoterInitReturn size");
    assert_eq!(word(&reply, 3), SOTER_OK);
    let session = i64::from_le_bytes(reply[16..24].try_into().expect("session"));
    assert!(session > 0);

    let reply = call(
        &mut state,
        dispatch::TX_FINISH_SIGN,
        &RequestBuilder::new(token).i64(session).build(),
    );
    let result = parse_buffer_return(&reply);
    let (json, signature) = blob::parse(&result).expect("result blob");
    let auth_key =
        blob::public_key_from_pem(&state.uids[&UID].auth[KNAME].public_pem).expect("auth key");
    assert!(blob::verify(&auth_key, json, signature));

    let reply = call(
        &mut state,
        dispatch::TX_GET_DEVICE_ID,
        &RequestBuilder::new(token).build(),
    );
    let id = parse_buffer_return(&reply);
    assert_eq!(id.len(), 16, "the device id is raw bytes");
    assert_eq!(hex::encode(&id), state.cpu_id);

    let reply = call(
        &mut state,
        dispatch::TX_REMOVE_ALL_UID_KEY,
        &RequestBuilder::new(token).i32(UID as i32).build(),
    );
    assert_eq!(word(&reply, 1), SOTER_OK);
    let reply = call(
        &mut state,
        dispatch::TX_HAS_ASK,
        &RequestBuilder::new(token).i32(UID as i32).build(),
    );
    assert_eq!(word(&reply, 1), SOTER_ERR_NO_KEY);

    // a truncated request must not be passed through in silence
    let reply = call(
        &mut state,
        dispatch::TX_HAS_ASK,
        &RequestBuilder::new(token).build(),
    );
    assert_ne!(word(&reply, 0), 0, "exception status");
}

/// Every reply the live HAL of the OnePlus 13 produced while its TA was dead,
/// captured on 2026-09-24 with `service call vendor.qti.hardware.soter.ISoter/default`,
/// once per transaction code. `soterta-svc --mode=dead` answers exactly this,
/// so a client cannot tell the daemon apart from the stock HAL it replaces.
#[test]
fn dead_replies_match_captured_hal_failures() {
    let cases: [(u32, &str); 14] = [
        (
            dispatch::TX_EXPORT_ASK,
            "00000000fbffffff010000000c0000000000000000000000",
        ),
        (
            dispatch::TX_EXPORT_ATTK,
            "00000000ecffffff010000000c0000000000000000000000",
        ),
        (
            dispatch::TX_EXPORT_AUTH,
            "00000000fbffffff010000000c0000000000000000000000",
        ),
        (
            dispatch::TX_FINISH_SIGN,
            "0000000018fcffff010000000c0000000000000000000000",
        ),
        (dispatch::TX_GENERATE_ASK, "00000000ecffffff"),
        (dispatch::TX_GENERATE_ATTK, "00000000ecffffff"),
        (dispatch::TX_GENERATE_AUTH, "00000000fbffffff"),
        (
            dispatch::TX_GET_DEVICE_ID,
            "00000000ecffffff010000000c0000000000000000000000",
        ),
        (dispatch::TX_HAS_ASK, "00000000fbffffff"),
        (dispatch::TX_HAS_AUTH, "00000000fbffffff"),
        (
            dispatch::TX_INIT_SIGN,
            "000000000100000010000000fbffffff0000000000000000",
        ),
        (dispatch::TX_REMOVE_ALL_UID_KEY, "00000000fbffffff"),
        (dispatch::TX_REMOVE_AUTH, "00000000fbffffff"),
        (dispatch::TX_VERIFY_ATTK, "00000000ecffffff"),
    ];
    for (tx, expected) in cases {
        let outcome = dispatch::dead_reply(tx).unwrap_or_else(|| panic!("code {tx} has a reply"));
        assert_eq!(hex::encode(outcome.to_reply_bytes()), expected, "code {tx}");
    }

    // the AIDL metadata codes and anything unknown are not TA traffic
    assert!(dispatch::dead_reply(0x00ff_ffff).is_none());
    assert!(dispatch::dead_reply(99).is_none());
}

/// The path `soterta-svc` uses: arguments in, structured answer out, ledger on
/// disk. Everything the daemon needs must work without a parcel.
#[test]
fn ffi_serves_the_daemon_path_end_to_end() {
    use crate::ffi::{self, SotertaReply};
    use std::ffi::{c_char, CStr, CString};
    use std::ptr;
    use std::slice;

    fn empty_reply() -> SotertaReply {
        SotertaReply {
            kind: -1,
            code: 0,
            field: 0,
            session: 0,
            buffer: ptr::null_mut(),
            buffer_len: 0,
        }
    }

    let dir = std::env::temp_dir().join(format!("soterta-ffi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Exercise the local FFI ledger even on a device with a live remote relay.
    // Never read or send requests using that device's production configuration.
    let _remote_config = crate::remote::test_config_path(dir.join("remote.conf"));
    let path = dir.join("state.json");
    let path_arg = CString::new(path.to_str().expect("utf-8 temp path")).expect("no NUL");
    let kname_arg = CString::new(KNAME).expect("no NUL");
    let challenge_arg = CString::new("challenge-ffi").expect("no NUL");

    assert_eq!(
        unsafe { ffi::soterta_init(path_arg.as_ptr()) },
        1,
        "fresh state is generated"
    );
    assert_eq!(
        unsafe { ffi::soterta_init(path_arg.as_ptr()) },
        0,
        "an existing state is loaded"
    );
    assert!(path.exists(), "the state file is persisted");

    let mut reply = empty_reply();
    assert_eq!(
        unsafe {
            ffi::soterta_handle(
                dispatch::TX_GET_DEVICE_ID,
                0,
                ptr::null(),
                ptr::null(),
                0,
                &mut reply,
            )
        },
        ffi::SOTERTA_HANDLED
    );
    assert_eq!(reply.kind, ffi::SOTERTA_KIND_BUFFER);
    assert_eq!(reply.code, SOTER_OK);
    let id = unsafe { slice::from_raw_parts(reply.buffer, reply.buffer_len) }.to_vec();
    assert_eq!(id.len(), 16, "the device id is raw bytes");
    assert_eq!(
        reply.field, 16,
        "the buffer field carries the export length"
    );
    unsafe { ffi::soterta_free(&mut reply) };
    assert!(reply.buffer.is_null(), "the reply buffer is released");

    let mut reply = empty_reply();
    assert_eq!(
        unsafe {
            ffi::soterta_handle(
                dispatch::TX_HAS_ASK,
                UID,
                ptr::null(),
                ptr::null(),
                0,
                &mut reply,
            )
        },
        ffi::SOTERTA_HANDLED
    );
    assert_eq!(reply.kind, ffi::SOTERTA_KIND_CODE);
    assert_eq!(reply.code, SOTER_ERR_NO_KEY, "no ASK yet");
    unsafe { ffi::soterta_free(&mut reply) };

    let mut reply = empty_reply();
    assert_eq!(
        unsafe {
            ffi::soterta_handle(
                dispatch::TX_GENERATE_ASK,
                UID,
                ptr::null(),
                ptr::null(),
                0,
                &mut reply,
            )
        },
        ffi::SOTERTA_HANDLED
    );
    assert_eq!(reply.code, SOTER_OK);
    unsafe { ffi::soterta_free(&mut reply) };

    let mut reply = empty_reply();
    assert_eq!(
        unsafe {
            ffi::soterta_handle(
                dispatch::TX_EXPORT_ASK,
                UID,
                ptr::null(),
                ptr::null(),
                0,
                &mut reply,
            )
        },
        ffi::SOTERTA_HANDLED
    );
    let ask_blob = unsafe { slice::from_raw_parts(reply.buffer, reply.buffer_len) }.to_vec();
    unsafe { ffi::soterta_free(&mut reply) };
    let device_pem = TaState::load(&path)
        .expect("the ledger reloads from disk")
        .attk
        .public_pem;
    let (json, signature) = blob::parse(&ask_blob).expect("blob structure");
    let device_key = blob::public_key_from_pem(&device_pem).expect("device key");
    assert!(blob::verify(&device_key, json, signature));

    let mut reply = empty_reply();
    assert_eq!(
        unsafe {
            ffi::soterta_handle(
                dispatch::TX_GENERATE_AUTH,
                UID,
                kname_arg.as_ptr(),
                ptr::null(),
                0,
                &mut reply,
            )
        },
        ffi::SOTERTA_HANDLED
    );
    assert_eq!(reply.code, SOTER_OK);
    unsafe { ffi::soterta_free(&mut reply) };

    // Runtime probe failure must never be mistaken for --bio-gate=off.
    unsafe extern "C" fn unavailable_probe() -> i64 {
        -1
    }
    crate::platform::install(Some(unavailable_probe), Some(unavailable_probe));
    assert_eq!(
        ffi::answer(
            dispatch::TX_INIT_SIGN,
            dispatch::Request::InitSign {
                uid: UID,
                kname: KNAME.into(),
                challenge: "not-signed".into(),
            }
        )
        .unwrap(),
        Some(dispatch::Outcome::Init {
            code: SOTER_ERR_NO_FINGERPRINT,
            session: 0
        }),
    );
    assert_eq!(
        ffi::answer(dispatch::TX_FINISH_SIGN, dispatch::Request::Session(1)).unwrap(),
        Some(dispatch::Outcome::Buffer {
            code: SOTER_ERR_NO_FINGERPRINT,
            data: Vec::new(),
            field: 0
        }),
    );
    crate::platform::install(None, None);

    let mut reply = empty_reply();
    assert_eq!(
        unsafe {
            ffi::soterta_handle(
                dispatch::TX_INIT_SIGN,
                UID,
                kname_arg.as_ptr(),
                challenge_arg.as_ptr(),
                0,
                &mut reply,
            )
        },
        ffi::SOTERTA_HANDLED
    );
    assert_eq!(reply.kind, ffi::SOTERTA_KIND_INIT);
    assert_eq!(reply.code, SOTER_OK);
    let session = reply.session;
    assert!(session > 0, "initSign opens a session");
    unsafe { ffi::soterta_free(&mut reply) };

    let mut reply = empty_reply();
    assert_eq!(
        unsafe {
            ffi::soterta_handle(
                dispatch::TX_FINISH_SIGN,
                0,
                ptr::null(),
                ptr::null(),
                session,
                &mut reply,
            )
        },
        ffi::SOTERTA_HANDLED
    );
    let result_blob = unsafe { slice::from_raw_parts(reply.buffer, reply.buffer_len) }.to_vec();
    unsafe { ffi::soterta_free(&mut reply) };
    let (json, signature) = blob::parse(&result_blob).expect("result blob");
    let persisted = TaState::load(&path).expect("the ledger reloads after the AuthKey");
    let auth_key =
        blob::public_key_from_pem(&persisted.uids[&UID].auth[KNAME].public_pem).expect("auth key");
    assert!(blob::verify(&auth_key, json, signature));

    let reloaded = TaState::load(&path).expect("the ledger reloads after signing");
    assert_eq!(reloaded.has_ask(UID), SOTER_OK);
    assert_eq!(reloaded.has_auth(UID, KNAME), SOTER_OK);

    // the ATTK trio is answered now; unknown codes still belong to the stock HAL
    let mut reply = empty_reply();
    for tx in dispatch::ATTK_TRANSACTIONS {
        assert_eq!(
            unsafe { ffi::soterta_handle(tx, UID, kname_arg.as_ptr(), ptr::null(), 0, &mut reply) },
            ffi::SOTERTA_HANDLED,
            "code {tx}"
        );
    }
    // verifyAttkKeyPair is the one the engineering-mode key check reads
    assert_eq!(reply.code, SOTER_OK, "verifyAttkKeyPair");
    assert_eq!(
        unsafe { ffi::soterta_handle(99, UID, ptr::null(), ptr::null(), 0, &mut reply) },
        ffi::SOTERTA_UNHANDLED
    );

    // a request that is missing an argument is an error, not an answer
    assert_eq!(
        unsafe {
            ffi::soterta_handle(
                dispatch::TX_GENERATE_AUTH,
                UID,
                ptr::null(),
                ptr::null(),
                0,
                &mut reply,
            )
        },
        ffi::SOTERTA_ERROR
    );
    let mut message = [0 as c_char; 128];
    let len = unsafe { ffi::soterta_last_error(message.as_mut_ptr(), message.len() as i32) };
    assert!(len > 0, "the error is recorded");
    let text = unsafe { CStr::from_ptr(message.as_ptr()) }
        .to_string_lossy()
        .to_string();
    assert!(text.contains("key name"), "{text}");

    assert_eq!(ffi::soterta_save(), ffi::SOTERTA_HANDLED);

    // An identity file that exists but cannot be read is not a fresh device: the
    // previous revision is restored when possible, and a real failure refuses to
    // start instead of minting keys behind the operator's back.
    let broken_dir = std::env::temp_dir().join(format!("soterta-broken-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&broken_dir);
    std::fs::create_dir_all(&broken_dir).expect("temp dir");
    let broken_path = broken_dir.join("state.json");
    let broken_arg = CString::new(broken_path.to_str().expect("utf-8 path")).expect("no NUL");
    let mut seeded = TaState::generate_local().expect("state");
    assert_eq!(seeded.generate_ask(UID), SOTER_OK);
    seeded.store(&broken_path).expect("seed");
    assert_eq!(seeded.generate_auth(UID, KNAME), SOTER_OK);
    seeded.store(&broken_path).expect("second revision");
    let kept_id = seeded.cpu_id.clone();

    std::fs::write(&broken_path, b"{\"cpu_id\": \"trunc").expect("truncate");
    assert_eq!(
        unsafe { ffi::soterta_init(broken_arg.as_ptr()) },
        0,
        "the backup recovers"
    );
    let restored = TaState::load(&broken_path).expect("the main file is restored");
    assert_eq!(restored.cpu_id, kept_id, "the identity is preserved");

    std::fs::write(&broken_path, b"not json").expect("break the main file");
    std::fs::write(
        broken_path.with_file_name("state.json.bak"),
        b"not json either",
    )
    .expect("break the backup");
    assert!(
        unsafe { ffi::soterta_init(broken_arg.as_ptr()) } < 0,
        "an unreadable ledger must not become a new identity"
    );
    let mut broken_message = [0 as c_char; 160];
    let broken_len = unsafe {
        ffi::soterta_last_error(broken_message.as_mut_ptr(), broken_message.len() as i32)
    };
    assert!(broken_len > 0);
    let broken_text = unsafe { CStr::from_ptr(broken_message.as_ptr()) }
        .to_string_lossy()
        .to_string();
    assert!(broken_text.contains("unreadable"), "{broken_text}");
    let _ = std::fs::remove_dir_all(&broken_dir);

    let _ = std::fs::remove_dir_all(&dir);
}
