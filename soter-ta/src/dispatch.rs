//! Transaction dispatch: `(transaction code, request arguments)` to an answer.
//!
//! Codes come from the vendor AIDL stubs in `vendor.qti.hardware.soter-V1-ndk.so`.
//! Everything the Java `SoterService` and its clients use is answered here, as is
//! the ATTK trio (`exportAttkPublicKey`, `generateAttkKeyPair`,
//! `verifyAttkKeyPair`): no Soter client declares those, but the vendor
//! engineering-mode key check reaches `verifyAttkKeyPair` through cryptoeng. The
//! AIDL metadata codes are left to the stock HAL.
//!
//! The wire tests use [`handle`] with canonical transaction numbers. The device
//! daemon first resolves the complete argument layout with [`resolve_request`]
//! and then uses [`handle_request`]. Both paths share the same argument codec.

use crate::error::{
    SOTER_ERR_BAD_VALUE, SOTER_ERR_NO_KEY, SOTER_ERR_NO_SESSION, SOTER_ERR_TA_UNAVAILABLE,
};
use crate::parcel::{Args, Reply};
use crate::platform::Platform;
use crate::state::TaState;

pub const TX_EXPORT_ASK: u32 = 1;
pub const TX_EXPORT_ATTK: u32 = 2;
pub const TX_EXPORT_AUTH: u32 = 3;
pub const TX_FINISH_SIGN: u32 = 4;
pub const TX_GENERATE_ASK: u32 = 5;
pub const TX_GENERATE_ATTK: u32 = 6;
pub const TX_GENERATE_AUTH: u32 = 7;
pub const TX_GET_DEVICE_ID: u32 = 8;
pub const TX_HAS_ASK: u32 = 9;
pub const TX_HAS_AUTH: u32 = 10;
pub const TX_INIT_SIGN: u32 = 11;
pub const TX_REMOVE_ALL_UID_KEY: u32 = 12;
pub const TX_REMOVE_AUTH: u32 = 13;
pub const TX_VERIFY_ATTK: u32 = 14;

/// The ATTK transactions: no Soter client on this ROM calls them, but the vendor
/// engineering-mode key check reaches `verifyAttkKeyPair` through cryptoeng.
pub const ATTK_TRANSACTIONS: [u32; 3] = [TX_EXPORT_ATTK, TX_GENERATE_ATTK, TX_VERIFY_ATTK];

/// Maximum argument payload accepted at the Binder boundary.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_STRING_BYTES: usize = 8192;

const COMPACT_TRANSACTIONS: [u32; 11] = [
    TX_EXPORT_ASK,
    TX_EXPORT_AUTH,
    TX_FINISH_SIGN,
    TX_GENERATE_ASK,
    TX_GENERATE_AUTH,
    TX_GET_DEVICE_ID,
    TX_HAS_ASK,
    TX_HAS_AUTH,
    TX_INIT_SIGN,
    TX_REMOVE_ALL_UID_KEY,
    TX_REMOVE_AUTH,
];

/// Transactions this TA answers.
///
/// The APK's Java stubs do not declare the ATTK trio, so no Soter client on this
/// ROM reaches them; the vendor engineering-mode key check does, through
/// cryptoeng, and with the stock TA dead it reads a failed key there.
pub fn handles(tx: u32) -> bool {
    matches!(
        tx,
        TX_EXPORT_ASK
            | TX_EXPORT_ATTK
            | TX_EXPORT_AUTH
            | TX_FINISH_SIGN
            | TX_GENERATE_ASK
            | TX_GENERATE_ATTK
            | TX_GENERATE_AUTH
            | TX_GET_DEVICE_ID
            | TX_HAS_ASK
            | TX_HAS_AUTH
            | TX_INIT_SIGN
            | TX_REMOVE_ALL_UID_KEY
            | TX_REMOVE_AUTH
            | TX_VERIFY_ATTK
    )
}

/// Whether `tx` reads platform facts (the boot clock and the fingerprint mark).
/// Every other transaction is answered from the ledger alone.
pub fn consults_platform(tx: u32) -> bool {
    matches!(tx, TX_INIT_SIGN | TX_FINISH_SIGN)
}

/// Arguments of one request, as the client wrote them on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// No arguments, `getDeviceId`.
    None,
    /// `int32 uid`.
    Uid(u32),
    /// `int32 uid, string kname`.
    UidKey { uid: u32, kname: String },
    /// `int32 uid, string kname, string challenge`.
    InitSign {
        uid: u32,
        kname: String,
        challenge: String,
    },
    /// `int64 session`.
    Session(u64),
    /// One byte, the magic `generateAttkKeyPair` passes.
    Magic(i8),
}

/// What one handled transaction answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A bare `SoterErrorCode`.
    Code(i32),
    /// A `SoterErrorCode` plus the `SoterBufferReturn` out parameter.
    ///
    /// `field` is the trailing `int32` of that out parameter. A device with a
    /// working TA writes the length of `data` there and the Java layer reports
    /// it to applications as `exportDataLength` (B-side capture of a live TA,
    /// 2026-09-24: 809 for a 809-byte ASK blob, 16 for the 16-byte device id).
    Buffer {
        code: i32,
        data: Vec<u8>,
        field: i32,
    },
    /// The `SoterInitReturn` parcelable `initSign` returns by value.
    Init { code: i32, session: u64 },
    /// A binder-level exception: status header plus message.
    Exception { code: i32, message: String },
}

impl Outcome {
    /// Encode the legacy native-client buffer result, without a Parcelable.
    /// Callers must positively identify that client contract; Java/unknown
    /// clients continue to use [`Self::to_reply_bytes`].
    pub fn to_native_reply_bytes(&self) -> Vec<u8> {
        if let Outcome::Buffer { code, data, .. } = self {
            let mut reply = Reply::ok();
            reply.i32(*code);
            reply.byte_array(data);
            reply.into_bytes()
        } else {
            self.to_reply_bytes()
        }
    }

    /// Render the reply payload the way the generated stubs expect it.
    ///
    /// The status header is part of the payload because the AIDL server side
    /// writes it: a `0` word first, then the return value, then the out
    /// parameters.
    pub fn to_reply_bytes(&self) -> Vec<u8> {
        match self {
            Outcome::Code(code) => {
                let mut reply = Reply::ok();
                reply.i32(*code);
                reply.into_bytes()
            }
            Outcome::Buffer { code, data, field } => {
                let mut reply = Reply::ok();
                reply.i32(*code);
                reply.buffer_return(data, *field);
                reply.into_bytes()
            }
            Outcome::Init { code, session } => {
                let mut reply = Reply::ok();
                reply.init_return(*code, *session as i64);
                reply.into_bytes()
            }
            Outcome::Exception { code, message } => Reply::exception(*code, message).into_bytes(),
        }
    }
}

fn malformed() -> Vec<u8> {
    Reply::exception(SOTER_ERR_BAD_VALUE, "malformed Soter request").into_bytes()
}

/// Read the arguments of `tx` out of a request parcel.
fn parse_request(tx: u32, args: &mut Args) -> Option<Request> {
    let string = |args: &mut Args| {
        let value = args.read_string16()?;
        (value.len() <= MAX_STRING_BYTES && !value.contains('\0')).then_some(value)
    };
    Some(match tx {
        TX_GET_DEVICE_ID => Request::None,
        TX_HAS_ASK | TX_GENERATE_ASK | TX_EXPORT_ASK | TX_REMOVE_ALL_UID_KEY => {
            Request::Uid(args.read_u32()?)
        }
        TX_GENERATE_AUTH | TX_HAS_AUTH | TX_EXPORT_AUTH | TX_REMOVE_AUTH => Request::UidKey {
            uid: args.read_u32()?,
            kname: string(args)?,
        },
        TX_INIT_SIGN => Request::InitSign {
            uid: args.read_u32()?,
            kname: string(args)?,
            challenge: string(args)?,
        },
        TX_FINISH_SIGN => Request::Session(args.read_i64()? as u64),
        TX_GENERATE_ATTK => Request::Magic(args.read_byte()?),
        TX_EXPORT_ATTK | TX_VERIFY_ATTK => Request::None,
        _ => return None,
    })
}

/// Resolve either the standard 14-method or compact 11-method wire contract.
///
/// The complete argument payload must match exactly one canonical operation.
/// No first-call guess or process-global layout is retained: interleaved Java
/// and native callers cannot change each other's dispatch. A malformed request
/// that also happens to be a complete request in the other contract cannot be
/// distinguished from that valid contract without an explicit caller contract.
pub fn resolve_request(wire_tx: u32, bytes: &[u8]) -> Option<(u32, Request)> {
    if bytes.len() > MAX_REQUEST_BYTES || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let parse = |tx| {
        let mut args = Args::new(bytes);
        let request = parse_request(tx, &mut args)?;
        (args.remaining() == 0).then_some((tx, request))
    };
    let standard = parse(wire_tx);
    let compact = wire_tx
        .checked_sub(1)
        .and_then(|index| COMPACT_TRANSACTIONS.get(index as usize))
        .and_then(|tx| parse(*tx));
    match (standard, compact) {
        (Some(left), Some(right)) if left == right => Some(left),
        (Some(result), None) | (None, Some(result)) => Some(result),
        _ => None,
    }
}

/// Answer one transaction from arguments that are already parsed.
///
/// `None` means the transaction is not this TA's business; the caller decides
/// what to do with it.
pub fn handle_request(
    state: &mut TaState,
    tx: u32,
    request: Request,
    platform: Platform,
) -> Option<Outcome> {
    Some(match (tx, request) {
        (TX_GET_DEVICE_ID, Request::None) => {
            let (code, data) = state.device_id();
            Outcome::Buffer {
                field: data.len() as i32,
                code,
                data,
            }
        }
        (TX_HAS_ASK, Request::Uid(uid)) => Outcome::Code(state.has_ask(uid)),
        (TX_GENERATE_ASK, Request::Uid(uid)) => Outcome::Code(state.generate_ask(uid)),
        (TX_EXPORT_ASK, Request::Uid(uid)) => {
            let (code, data) = state.export_ask(uid);
            Outcome::Buffer {
                field: data.len() as i32,
                code,
                data,
            }
        }
        (TX_GENERATE_AUTH, Request::UidKey { uid, kname }) => {
            Outcome::Code(state.generate_auth(uid, &kname))
        }
        (TX_HAS_AUTH, Request::UidKey { uid, kname }) => Outcome::Code(state.has_auth(uid, &kname)),
        (TX_EXPORT_AUTH, Request::UidKey { uid, kname }) => {
            let (code, data) = state.export_auth(uid, &kname);
            Outcome::Buffer {
                field: data.len() as i32,
                code,
                data,
            }
        }
        (TX_REMOVE_AUTH, Request::UidKey { uid, kname }) => {
            Outcome::Code(state.remove_auth(uid, &kname))
        }
        (TX_REMOVE_ALL_UID_KEY, Request::Uid(uid)) => Outcome::Code(state.remove_all_uid(uid)),
        (
            TX_INIT_SIGN,
            Request::InitSign {
                uid,
                kname,
                challenge,
            },
        ) => {
            let (code, session) = state.init_sign(uid, &kname, &challenge, platform);
            Outcome::Init { code, session }
        }
        (TX_FINISH_SIGN, Request::Session(session)) => {
            let (code, data) = state.finish_sign(session, platform);
            Outcome::Buffer {
                field: data.len() as i32,
                code,
                data,
            }
        }
        (TX_EXPORT_ATTK, Request::None) => {
            let (code, data) = state.export_attk();
            Outcome::Buffer {
                field: data.len() as i32,
                code,
                data,
            }
        }
        (TX_GENERATE_ATTK, Request::Magic(magic)) => Outcome::Code(state.generate_attk(magic)),
        (TX_VERIFY_ATTK, Request::None) => Outcome::Code(state.verify_attk()),
        _ => return None,
    })
}

/// Build the reply for one transaction, or `None` when the transaction belongs
/// to the stock HAL and must be passed through untouched.
pub fn handle(
    state: &mut TaState,
    tx: u32,
    args: &mut Args,
    platform: Platform,
) -> Option<Vec<u8>> {
    match parse_request(tx, args) {
        Some(request) if args.remaining() == 0 => {
            handle_request(state, tx, request, platform).map(|outcome| outcome.to_reply_bytes())
        }
        Some(_) => Some(malformed()),
        None if handles(tx) => Some(malformed()),
        None => None,
    }
}

/// What the stock HAL answers while its TA is dead, per transaction code.
///
/// Captured on the OnePlus 13 on 2026-09-24 by calling the live HAL with
/// `service call vendor.qti.hardware.soter.ISoter/default <code> ...` for every
/// code; `tests::dead_replies_match_captured_hal_failures` pins them byte for
/// byte. `soterta-svc --mode=dead` answers exactly this, so a client that talks
/// to the daemon sees what it saw with a dead TA: no key (-5), no device id
/// (-20), no sign session (-1000), and an empty `SoterBufferReturn` out
/// parameter wherever the reply carries one.
///
/// `None` means the code is not part of this interface.
pub fn dead_reply(tx: u32) -> Option<Outcome> {
    let empty = |code: i32| Outcome::Buffer {
        code,
        data: Vec::new(),
        field: 0,
    };
    Some(match tx {
        TX_EXPORT_ASK | TX_EXPORT_AUTH => empty(SOTER_ERR_NO_KEY),
        TX_EXPORT_ATTK | TX_GET_DEVICE_ID => empty(SOTER_ERR_TA_UNAVAILABLE),
        TX_FINISH_SIGN => empty(SOTER_ERR_NO_SESSION),
        TX_GENERATE_ASK | TX_GENERATE_ATTK | TX_VERIFY_ATTK => {
            Outcome::Code(SOTER_ERR_TA_UNAVAILABLE)
        }
        TX_HAS_ASK | TX_HAS_AUTH | TX_GENERATE_AUTH | TX_REMOVE_ALL_UID_KEY | TX_REMOVE_AUTH => {
            Outcome::Code(SOTER_ERR_NO_KEY)
        }
        TX_INIT_SIGN => Outcome::Init {
            code: SOTER_ERR_NO_KEY,
            session: 0,
        },
        _ => return None,
    })
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn argument_bytes(request: &Request) -> Vec<u8> {
        let mut bytes = Reply::ok();
        match request {
            Request::None => {}
            Request::Uid(uid) => bytes.i32(*uid as i32),
            Request::UidKey { uid, kname } => {
                bytes.i32(*uid as i32);
                bytes.string16(kname);
            }
            Request::InitSign {
                uid,
                kname,
                challenge,
            } => {
                bytes.i32(*uid as i32);
                bytes.string16(kname);
                bytes.string16(challenge);
            }
            Request::Session(session) => bytes.i64(*session as i64),
            Request::Magic(value) => bytes.i32(i32::from(*value)),
        }
        bytes.into_bytes()[4..].to_vec()
    }

    fn request_for(tx: u32) -> Request {
        match tx {
            TX_EXPORT_ATTK | TX_GET_DEVICE_ID | TX_VERIFY_ATTK => Request::None,
            TX_EXPORT_ASK | TX_GENERATE_ASK | TX_HAS_ASK | TX_REMOVE_ALL_UID_KEY => {
                Request::Uid(10503)
            }
            TX_EXPORT_AUTH | TX_GENERATE_AUTH | TX_HAS_AUTH | TX_REMOVE_AUTH => Request::UidKey {
                uid: 10503,
                kname: "test-alias".into(),
            },
            TX_FINISH_SIGN => Request::Session(0x1234_5678_9abc_def0),
            TX_GENERATE_ATTK => Request::Magic(0),
            TX_INIT_SIGN => Request::InitSign {
                uid: 10503,
                kname: "test-alias".into(),
                challenge: "challenge".into(),
            },
            _ => panic!("unknown test transaction"),
        }
    }

    #[test]
    fn standard_and_compact_contracts_resolve_when_interleaved() {
        for standard in 1..=14 {
            let request = request_for(standard);
            assert_eq!(
                resolve_request(standard, &argument_bytes(&request)),
                Some((standard, request)),
                "standard transaction {standard}"
            );
            for (index, canonical) in COMPACT_TRANSACTIONS.iter().enumerate().rev() {
                let request = request_for(*canonical);
                assert_eq!(
                    resolve_request(index as u32 + 1, &argument_bytes(&request)),
                    Some((*canonical, request)),
                    "compact transaction {}",
                    index + 1
                );
            }
        }
    }

    #[test]
    fn incomplete_strings_and_trailing_arguments_are_rejected() {
        let bytes = argument_bytes(&request_for(TX_REMOVE_AUTH));
        for length in 0..bytes.len() {
            assert!(resolve_request(TX_REMOVE_AUTH, &bytes[..length]).is_none());
        }
        let mut trailing = argument_bytes(&Request::Uid(10503));
        trailing.extend_from_slice(&0i32.to_le_bytes());
        assert!(resolve_request(TX_EXPORT_ASK, &trailing).is_none());

        // A compact delete must not ignore the malformed extra string from a
        // standard hasAuth request and dispatch the four-byte prefix.
        let mut bad_alias = argument_bytes(&Request::Uid(10503));
        bad_alias.extend_from_slice(&(-1i32).to_le_bytes());
        assert!(resolve_request(10, &bad_alias).is_none());

        let mut missing_nul = argument_bytes(&Request::UidKey {
            uid: 10503,
            kname: "a".into(),
        });
        missing_nul[10] = b'x';
        assert!(resolve_request(TX_REMOVE_AUTH, &missing_nul).is_none());
        let mut invalid_utf16 = missing_nul;
        invalid_utf16[8..12].copy_from_slice(&[0x00, 0xd8, 0, 0]);
        assert!(resolve_request(TX_REMOVE_AUTH, &invalid_utf16).is_none());
    }

    #[test]
    fn requests_are_bounded_and_strings_cannot_contain_nul() {
        for alias in ["x".repeat(MAX_STRING_BYTES + 1), "a\0b".into()] {
            let request = Request::UidKey {
                uid: 10503,
                kname: alias,
            };
            assert!(resolve_request(TX_REMOVE_AUTH, &argument_bytes(&request)).is_none());
        }
        assert!(resolve_request(0, &[]).is_none());
        assert!(resolve_request(u32::MAX, &[]).is_none());
        assert!(resolve_request(TX_EXPORT_ASK, &vec![0; MAX_REQUEST_BYTES + 4]).is_none());
    }

    #[test]
    fn attk_magic_uses_one_complete_aidl_word() {
        for value in [i8::MIN, -1, 0, i8::MAX] {
            assert_eq!(
                resolve_request(TX_GENERATE_ATTK, &i32::from(value).to_le_bytes()),
                Some((TX_GENERATE_ATTK, Request::Magic(value)))
            );
        }
        assert!(resolve_request(TX_GENERATE_ATTK, &[0]).is_none());
        assert!(resolve_request(TX_GENERATE_ATTK, &256i32.to_le_bytes()).is_none());
        assert_eq!(
            resolve_request(6, &[]),
            Some((TX_GET_DEVICE_ID, Request::None)),
            "empty compact getDeviceId is distinct from ATTK magic"
        );
    }

    #[test]
    fn native_buffer_format_is_explicit_and_other_replies_match() {
        let result = Outcome::Buffer {
            code: 0,
            data: vec![0xa1, 0xb2, 0xc3],
            field: 3,
        };
        assert_eq!(
            hex::encode(result.to_native_reply_bytes()),
            "000000000000000003000000a1b2c300"
        );
        assert_eq!(
            hex::encode(result.to_reply_bytes()),
            "0000000000000000010000001000000003000000a1b2c30003000000"
        );
        let failed = Outcome::Buffer {
            code: -20,
            data: Vec::new(),
            field: 0,
        };
        assert_eq!(
            hex::encode(failed.to_native_reply_bytes()),
            "00000000ecffffff00000000"
        );
        for result in [
            Outcome::Code(-5),
            Outcome::Init {
                code: 0,
                session: 1234,
            },
            Outcome::Exception {
                code: -1,
                message: "test".into(),
            },
        ] {
            assert_eq!(result.to_reply_bytes(), result.to_native_reply_bytes());
        }
    }
}
