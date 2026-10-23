//! Vendor HAL wire contracts used by the native SoterServer forwarding hook.
//! Contract reference: jiyin004-jpg/ommega, commit c6172dc553543aa8eea1b7e03cd50c2ff6f1efb1,
//! hook/soter.rs and parcel/reply.rs (AGPL-3.0-or-later).
//! This module does not implement the Tencent SDK, a local TA, or a test fixture.

use crate::{
    dispatch::{self, Outcome, Request},
    parcel::{Args, Reply},
};

const QTI: &str = "vendor.qti.hardware.soter.ISoter";
const TRUSTONIC: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter";
const HIDL: [&str; 4] = [
    "vendor.qti.hardware.soter@1.0::ISoter",
    "vendor.trustonic.hardware.soter@1.0::ITrustonicSoter",
    "vendor.xiaomi.hardware.soterservice@1.0::ISoter",
    "vendor.microtrust.hardware.soter@1.0::ISoter",
];
pub const APP: &str = "com.tencent.soter.soterserver.ISoterService";
const HIDL_CODES: [u32; 14] = [6, 14, 2, 8, 5, 1, 12, 9, 7, 3, 13, 10, 11, 4];
const PTR: u32 = 0x7074_2a85;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Contract {
    Qti,
    Trustonic,
    Hidl,
}

/// Only exact interface tokens at a documented Binder header boundary qualify.
pub fn aidl_token(bytes: &[u8]) -> Option<(String, usize)> {
    for prefix in [12, 4, 0, 8] {
        let Some(tail) = bytes.get(prefix..) else {
            continue;
        };
        let mut args = Args::new(tail);
        if let Some(token) = args.read_string16() {
            if token == APP || token == QTI || token == TRUSTONIC {
                return Some((token, prefix + args.position()));
            }
        }
    }
    None
}

impl Contract {
    pub fn identify(bytes: &[u8]) -> Option<(Self, usize)> {
        for token in HIDL {
            let end = (token.len() + 1).next_multiple_of(4);
            if bytes.starts_with(token.as_bytes())
                && bytes.get(token.len()) == Some(&0)
                && bytes.get(token.len() + 1..end)?.iter().all(|b| *b == 0)
            {
                return Some((Self::Hidl, end));
            }
        }
        let (token, end) = aidl_token(bytes)?;
        match token.as_str() {
            QTI => Some((Self::Qti, end)),
            TRUSTONIC => Some((Self::Trustonic, end)),
            _ => None,
        }
    }

    /// A supported wire candidate, not a resolved AIDL operation. This early
    /// check keeps metadata/unknown calls native without reading their objects.
    pub fn candidate(self, wire: u32) -> Option<u32> {
        if self == Self::Hidl {
            let tx = *HIDL_CODES.get(wire.checked_sub(1)? as usize)?;
            (!dispatch::ATTK_TRANSACTIONS.contains(&tx)).then_some(tx)
        } else {
            dispatch::handles(wire).then_some(wire)
        }
    }

    /// Resolve the complete wire request before deciding whether it can be
    /// relayed. Compact AIDL codes overlap the standard ATTK codes, so filtering
    /// by the wire number alone would discard ordinary client operations.
    /// Unknown operations and actual ATTK calls remain on the original HAL.
    pub fn resolve_request(
        self,
        wire: u32,
        bytes: &[u8],
        start: usize,
        offsets: &[usize],
        read: impl Fn(usize, usize) -> Option<Vec<u8>>,
    ) -> Result<Option<(u32, Request)>, &'static str> {
        let Some(tx) = self.candidate(wire) else {
            return Ok(None);
        };
        let (tx, request) = if self == Self::Hidl {
            let request = Self::decode_hidl(tx, bytes, start, offsets, read)
                .ok_or("invalid_hidl_arguments")?;
            (tx, request)
        } else {
            if !offsets.is_empty() {
                return Err("unexpected_aidl_objects");
            }
            let args = bytes.get(start..).ok_or("invalid_argument_offset")?;
            dispatch::resolve_request(wire, args).ok_or("invalid_aidl_arguments")?
        };
        Ok((!dispatch::ATTK_TRANSACTIONS.contains(&tx)).then_some((tx, request)))
    }

    /// Read HIDL indirect buffers through a checked process-memory reader, never
    /// by dereferencing pointers supplied in a Parcel. `offsets` are absolute
    /// parcel offsets, including the interface-token prefix.
    fn decode_hidl(
        tx: u32,
        bytes: &[u8],
        start: usize,
        offsets: &[usize],
        read: impl Fn(usize, usize) -> Option<Vec<u8>>,
    ) -> Option<Request> {
        let mut at = start;
        let mut used = 0;
        let mut args = Vec::new();
        let uid = matches!(tx, 1 | 3 | 5 | 7 | 9 | 10 | 11 | 12 | 13);
        if uid {
            args.extend_from_slice(bytes.get(at..at + 4)?);
            at += 4;
        }
        let strings = match tx {
            3 | 7 | 10 | 13 => 1,
            11 => 2,
            _ => 0,
        };
        for _ in 0..strings {
            if offsets.get(used..used + 2)? != [at, at + 40] {
                return None;
            }
            let parent = Object::read(bytes.get(at..at + 40)?)?;
            let child = Object::read(bytes.get(at + 40..at + 80)?)?;
            if parent.flags != 0
                || parent.length != 16
                || child.flags != 1
                || child.parent != used
                || child.parent_offset != 0
            {
                return None;
            }
            let head = read(parent.buffer, 16)?;
            let pointer = u64_at(&head, 0)? as usize;
            let length = u32_at(&head, 8)? as usize;
            if length > 8192 || pointer != child.buffer || child.length != length + 1 {
                return None;
            }
            let text = read(pointer, length + 1)?;
            if text.last() != Some(&0) || text[..length].contains(&0) {
                return None;
            }
            let text = std::str::from_utf8(&text[..length]).ok()?;
            let mut encoded = Reply::ok();
            encoded.string16(text);
            args.extend_from_slice(&encoded.as_bytes()[4..]);
            at += 80;
            used += 2;
        }
        if tx == dispatch::TX_FINISH_SIGN {
            args.extend_from_slice(bytes.get(at..at + 8)?);
            at += 8;
        }
        if at != bytes.len() || used != offsets.len() {
            return None;
        }
        dispatch::decode_request(tx, &args)
    }

    pub fn reply(self, tx: u32, outcome: Outcome) -> OwnedReply {
        let (code, data, session) = match outcome {
            Outcome::Code(code) => (code, Vec::new(), 0),
            Outcome::Buffer { code, data, .. } => (code, data, 0),
            Outcome::Init { code, session } => (code, Vec::new(), session),
            Outcome::Exception { .. } => (-20, Vec::new(), 0),
        };
        let mut reply = Reply::ok();
        let mut storage = Vec::new();
        let mut offsets = Vec::new();
        match tx {
            dispatch::TX_INIT_SIGN if self == Self::Hidl => {
                reply.i32(code);
                reply.i64(session as i64);
            }
            dispatch::TX_INIT_SIGN => reply.init_return(code, session as i64),
            1 | 3 | 4 | 8 if self == Self::Hidl => {
                reply.i32(code);
                let payload = data.into_boxed_slice();
                let pointer = if payload.is_empty() {
                    0
                } else {
                    payload.as_ptr() as usize
                };
                let mut head = vec![0u8; 16].into_boxed_slice();
                head[..8].copy_from_slice(&(pointer as u64).to_le_bytes());
                head[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
                offsets.push(reply.as_bytes().len());
                Object {
                    flags: 0,
                    buffer: head.as_ptr() as usize,
                    length: 16,
                    parent: 0,
                    parent_offset: 0,
                }
                .write(&mut reply);
                if pointer != 0 {
                    offsets.push(reply.as_bytes().len());
                }
                Object {
                    flags: 1,
                    buffer: pointer,
                    length: payload.len(),
                    parent: 0,
                    parent_offset: 0,
                }
                .write(&mut reply);
                reply.i32(payload.len() as i32);
                storage.extend([head, payload]);
            }
            1 | 3 | 4 | 8 if self == Self::Trustonic => {
                reply.i32(1);
                reply.i32((16 + data.len().next_multiple_of(4)) as i32);
                reply.i32(code);
                reply.byte_array(&data);
                reply.i32(data.len() as i32);
            }
            1 | 3 | 4 | 8 => {
                reply.i32(code);
                reply.buffer_return(&data, data.len() as i32);
            }
            _ => reply.i32(code),
        }
        OwnedReply {
            bytes: reply.into_bytes().into_boxed_slice(),
            offsets: offsets.into_boxed_slice(),
            storage,
        }
    }
}

/// Must remain alive until the host submits BC_FREE_BUFFER. Box allocations
/// keep the embedded HIDL pointers stable when this owner moves between maps.
pub struct OwnedReply {
    pub bytes: Box<[u8]>,
    pub offsets: Box<[usize]>,
    storage: Vec<Box<[u8]>>,
}
impl OwnedReply {
    pub fn allocation_size(&self) -> usize {
        self.bytes.len()
            + self.offsets.len() * size_of::<usize>()
            + self.storage.iter().map(|b| b.len()).sum::<usize>()
    }
}

struct Object {
    flags: u32,
    buffer: usize,
    length: usize,
    parent: usize,
    parent_offset: usize,
}
impl Object {
    fn read(bytes: &[u8]) -> Option<Self> {
        if u32_at(bytes, 0)? != PTR {
            return None;
        }
        Some(Self {
            flags: u32_at(bytes, 4)?,
            buffer: u64_at(bytes, 8)? as usize,
            length: u64_at(bytes, 16)? as usize,
            parent: u64_at(bytes, 24)? as usize,
            parent_offset: u64_at(bytes, 32)? as usize,
        })
    }
    fn write(&self, reply: &mut Reply) {
        reply.i32(PTR as i32);
        reply.i32(self.flags as i32);
        for value in [self.buffer, self.length, self.parent, self.parent_offset] {
            reply.i64(value as i64);
        }
    }
}
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_aidl_headers_and_exact_arguments() {
        for (token, contract) in [(QTI, Contract::Qti), (TRUSTONIC, Contract::Trustonic)] {
            for prefix in [0, 4, 8, 12] {
                let mut parcel = Reply::ok();
                parcel.string16(token);
                parcel.i32(10123);
                let mut bytes = vec![0xff; prefix];
                bytes.extend_from_slice(&parcel.as_bytes()[4..]);
                let (actual, start) = Contract::identify(&bytes).unwrap();
                assert_eq!(actual, contract);
                assert_eq!(
                    contract
                        .resolve_request(5, &bytes, start, &[], |_, _| panic!("AIDL dereference")),
                    Ok(Some((5, Request::Uid(10123))))
                );
                bytes.push(0);
                assert!(contract
                    .resolve_request(5, &bytes, start, &[], |_, _| panic!("AIDL dereference"))
                    .is_err());
            }
        }
    }
    #[test]
    fn hidl_string_graph_requires_matching_parent_child_and_terminator() {
        let mut bytes = HIDL[0].as_bytes().to_vec();
        bytes.push(0);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        let start = bytes.len();
        bytes.extend_from_slice(&10123u32.to_le_bytes());
        let at = bytes.len();
        let mut objects = Reply::ok();
        Object {
            flags: 0,
            buffer: 0x1000,
            length: 16,
            parent: 0,
            parent_offset: 0,
        }
        .write(&mut objects);
        Object {
            flags: 1,
            buffer: 0x2000,
            length: 4,
            parent: 0,
            parent_offset: 0,
        }
        .write(&mut objects);
        bytes.extend_from_slice(&objects.as_bytes()[4..]);
        let mut head = vec![0u8; 16];
        head[..8].copy_from_slice(&0x2000u64.to_le_bytes());
        head[8..12].copy_from_slice(&3u32.to_le_bytes());
        let read = |address, size| match (address, size) {
            (0x1000, 16) => Some(head.clone()),
            (0x2000, 4) => Some(b"key\0".to_vec()),
            _ => None,
        };
        assert_eq!(Contract::identify(&bytes), Some((Contract::Hidl, start)));
        assert_eq!(
            Contract::Hidl.resolve_request(9, &bytes, start, &[at, at + 40], read),
            Ok(Some((
                7,
                Request::UidKey {
                    uid: 10123,
                    kname: "key".into()
                }
            )))
        );
        assert!(Contract::Hidl
            .resolve_request(9, &bytes, start, &[at + 4, at + 40], read)
            .is_err());
        let mut bad = bytes.clone();
        bad[at + 64..at + 72].copy_from_slice(&1u64.to_le_bytes());
        assert!(Contract::Hidl
            .resolve_request(9, &bad, start, &[at, at + 40], read)
            .is_err());
        assert!(Contract::Hidl
            .resolve_request(9, &bytes, start, &[at, at + 40], |address, size| {
                if address == 0x2000 {
                    Some(b"keyx".to_vec())
                } else {
                    read(address, size)
                }
            })
            .is_err());
    }
    #[test]
    fn native_hal_is_not_sdk_or_beta() {
        let mut request = Reply::ok();
        request.string16(APP);
        assert!(Contract::identify(request.as_bytes()).is_none());
        assert_eq!(HIDL_CODES, [6, 14, 2, 8, 5, 1, 12, 9, 7, 3, 13, 10, 11, 4]);
    }

    fn arguments(request: &Request) -> Vec<u8> {
        let mut parcel = Reply::ok();
        match request {
            Request::None => {}
            Request::Uid(uid) => parcel.i32(*uid as i32),
            Request::UidKey { uid, kname } => {
                parcel.i32(*uid as i32);
                parcel.string16(kname);
            }
            Request::InitSign {
                uid,
                kname,
                challenge,
            } => {
                parcel.i32(*uid as i32);
                parcel.string16(kname);
                parcel.string16(challenge);
            }
            Request::Session(session) => parcel.i64(*session as i64),
            Request::Magic(magic) => parcel.i32(i32::from(*magic)),
        }
        parcel.as_bytes()[4..].to_vec()
    }

    #[test]
    fn aidl_relay_resolves_interleaved_layouts_before_attk_filtering() {
        let calls = [
            (1, 1, Request::Uid(10123)),
            (
                3,
                2,
                Request::UidKey {
                    uid: 10123,
                    kname: "auth".into(),
                },
            ),
            (4, 3, Request::Session(0x1234_5678_9abc_def0)),
            (5, 4, Request::Uid(10123)),
            (
                7,
                5,
                Request::UidKey {
                    uid: 10123,
                    kname: "auth".into(),
                },
            ),
            (8, 6, Request::None),
            (9, 7, Request::Uid(10123)),
            (
                10,
                8,
                Request::UidKey {
                    uid: 10123,
                    kname: "auth".into(),
                },
            ),
            (
                11,
                9,
                Request::InitSign {
                    uid: 10123,
                    kname: "auth".into(),
                    challenge: "challenge".into(),
                },
            ),
            (12, 10, Request::Uid(10123)),
            (
                13,
                11,
                Request::UidKey {
                    uid: 10123,
                    kname: "auth".into(),
                },
            ),
        ];
        for contract in [Contract::Qti, Contract::Trustonic] {
            for (standard, compact, request) in &calls {
                let bytes = arguments(request);
                for wire in [*compact, *standard, *compact] {
                    assert_eq!(
                        contract.resolve_request(wire, &bytes, 0, &[], |_, _| panic!(
                            "AIDL dereference"
                        )),
                        Ok(Some((*standard, request.clone()))),
                        "{contract:?} wire={wire}",
                    );
                }
            }
            for (wire, request) in [
                (2, Request::None),
                (6, Request::Magic(0)),
                (14, Request::None),
            ] {
                assert_eq!(
                    contract.resolve_request(wire, &arguments(&request), 0, &[], |_, _| None),
                    Ok(None)
                );
            }
        }
        for wire in [1, 2, 3, 0, 15, u32::MAX] {
            assert_eq!(
                Contract::Hidl
                    .resolve_request(wire, &[], 0, &[], |_, _| panic!("native-only dereference")),
                Ok(None)
            );
        }
    }

    #[test]
    fn aidl_relay_rejects_malformed_requests_without_guessing_a_reply_method() {
        for contract in [Contract::Qti, Contract::Trustonic] {
            for wire in [0, 15, 0x00ff_ffff, 0x00ff_fffe] {
                assert_eq!(
                    contract.resolve_request(wire, &[], 0, &[], |_, _| None),
                    Ok(None)
                );
            }
            let args = arguments(&Request::UidKey {
                uid: 10123,
                kname: "auth".into(),
            });
            for len in 1..args.len() {
                assert!(contract
                    .resolve_request(2, &args[..len], 0, &[], |_, _| None)
                    .is_err());
            }
            let mut extra = arguments(&Request::Uid(10123));
            extra.extend_from_slice(&[0; 4]);
            assert!(contract
                .resolve_request(1, &extra, 0, &[], |_, _| None)
                .is_err());
            assert!(contract
                .resolve_request(2, &args, 0, &[0], |_, _| None)
                .is_err());
            assert!(contract
                .resolve_request(6, &[], 1, &[], |_, _| None)
                .is_err());
            assert!(contract
                .resolve_request(
                    1,
                    &vec![0; dispatch::MAX_REQUEST_BYTES + 4],
                    0,
                    &[],
                    |_, _| None
                )
                .is_err());
            let mut invalid = arguments(&Request::UidKey {
                uid: 10123,
                kname: "a".into(),
            });
            invalid[8..12].copy_from_slice(&[0, 0xd8, 0, 0]);
            assert!(contract
                .resolve_request(2, &invalid, 0, &[], |_, _| None)
                .is_err());
        }
    }

    #[test]
    fn compact_aidl_replies_use_the_resolved_operation() {
        let calls = [
            (
                3,
                Request::Session(42),
                Outcome::Buffer {
                    code: 0,
                    data: vec![1, 2, 3],
                    field: 3,
                },
                4,
            ),
            (
                6,
                Request::None,
                Outcome::Buffer {
                    code: 0,
                    data: vec![5; 16],
                    field: 16,
                },
                8,
            ),
            (
                9,
                Request::InitSign {
                    uid: 10123,
                    kname: "key".into(),
                    challenge: "challenge".into(),
                },
                Outcome::Init {
                    code: 0,
                    session: 123,
                },
                11,
            ),
        ];
        for contract in [Contract::Qti, Contract::Trustonic] {
            for (wire, request, outcome, expected) in &calls {
                let (tx, _) = contract
                    .resolve_request(*wire, &arguments(request), 0, &[], |_, _| None)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    contract.reply(tx, outcome.clone()).bytes,
                    contract.reply(*expected, outcome.clone()).bytes
                );
                assert_eq!(tx, *expected);
            }
        }
    }
    #[test]
    fn aidl_init_has_no_extra_return_code() {
        for contract in [Contract::Qti, Contract::Trustonic] {
            let reply = contract.reply(
                11,
                Outcome::Init {
                    code: 0,
                    session: 123,
                },
            );
            assert_eq!(reply.bytes.len(), 24);
            assert_eq!(u32_at(&reply.bytes, 4), Some(1));
            assert_eq!(u32_at(&reply.bytes, 8), Some(16));
            assert_eq!(u64_at(&reply.bytes, 16), Some(123));
        }
    }
    #[test]
    fn vendor_buffer_error_layouts_are_not_interchangeable() {
        let qti = Contract::Qti.reply(1, Outcome::Code(-20));
        let mtk = Contract::Trustonic.reply(1, Outcome::Code(-20));
        assert_eq!(u32_at(&qti.bytes, 4), Some((-20i32) as u32));
        assert_eq!(u32_at(&mtk.bytes, 4), Some(1));
        assert_eq!(u32_at(&mtk.bytes, 12), Some((-20i32) as u32));
    }
    #[test]
    fn hidl_reply_owns_pointer_graph_even_for_empty_error() {
        for data in [vec![], vec![1, 2, 3]] {
            let reply = Contract::Hidl.reply(
                1,
                Outcome::Buffer {
                    code: 0,
                    field: data.len() as i32,
                    data: data.clone(),
                },
            );
            assert_eq!(reply.bytes.len(), 92);
            assert_eq!(
                reply.offsets.as_ref(),
                if data.is_empty() {
                    &[8][..]
                } else {
                    &[8, 48][..]
                }
            );
            let head = Object::read(&reply.bytes[8..48]).unwrap();
            let child = Object::read(&reply.bytes[48..88]).unwrap();
            assert_eq!(head.buffer, reply.storage[0].as_ptr() as usize);
            assert_eq!(child.buffer, u64_at(&reply.storage[0], 0).unwrap() as usize);
            assert_eq!(child.length, data.len());
            assert!(reply.allocation_size() >= 108);
        }
    }
}
