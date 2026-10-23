//! Tencent AIDL software test replies. No hardware or biometric authentication.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
    time::{Duration, Instant},
};

use pif_common::soter_blob as blob;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey};

use super::{BAD_VALUE, DESCRIPTOR, MAX_REQUEST_BYTES, UNKNOWN_TRANSACTION};

const NO_KEY: i32 = -5;
const NO_AUTH_KEY: i32 = -6;
const UNAVAILABLE: i32 = -20;
const NO_FINGERPRINT: i32 = -26;
const NO_SESSION: i32 = -1000;
const MAX_UIDS: usize = 1024;
const MAX_KEYS_PER_UID: usize = 64;
const MAX_SESSIONS: usize = 64;
const MAX_STRING_UNITS: usize = 16 * 1024;
const SESSION_LIFETIME: Duration = Duration::from_secs(120);

// Deliberately recognizable public software-test identity, never a factory ID.
const DEVICE: &[u8; 16] = b"OMK-SOFT-TEST-01";
const CPU_ID: &str = "4f4d4b2d534f46542d544553542d3031";

// PUBLIC, NON-SECRET test material from RustCrypto RSA 0.9.10:
// tests/examples/pkcs8/rsa2048-priv.pem (MIT OR Apache-2.0).
// Shared by every installation/UID/alias. Never use for authentication or secrets.
const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2xCxRXxCmqvKC
xj7b4kJDoXDz+iYzvUgzY39Hyk9vNuA6XSnvwxkayA85DYdLOeMPQU/Owfyg7YHl
R+3CzTgsdvYckBiXPbn6U3lyp8cB9rd+CYLfwV/AGSfuXnzZS09Zn/BwE6fIKBvf
Ity8mtfKu3xDEcmC9Y7bchOtRVizMiZtdDrtgZLRiEytuLFHOaja2mbclwgG2ces
RQyxPQ18V1+xmFNPxhvEG8DwV04OATDHu7+9/cn2puLj4q/xy+rIm6V4hFKNVc+w
gyeh6MifTgA88oiOkzJB2daVvLus3JC0Tj4JX6NwWOolsT9eKVy+rG3oOKuMUK9h
4piXW4cvAgMBAAECggEAfsyDYsDtsHQRZCFeIvdKudkboGkAcAz2NpDlEU2O5r3P
uy4/lhRpKmd6CD8Wil5S5ZaOZAe52XxuDkBk+C2gt1ihTxe5t9QfX0jijWVRcE9W
5p56qfpjD8dkKMBtJeRV3PxVt6wrT3ZkP97T/hX/eKuyfmWsxKrQvfbbJ+9gppEM
XEoIXtQydasZwdmXoyxu/8598tGTX25gHu3hYaErXMJ8oh+B0smcPR6gjpDjBTqw
m++nJN7w0MOjwel0DA2fdhJqFJ7Aqn2AeCBUhCVNlR2wfEz5H7ZFTAlliP1ZJNur
6zWcogJSaNAE+dZus9b3rcETm61A8W3eY54RZHN2wQKBgQDcwGEkLU6Sr67nKsUT
ymW593A2+b1+Dm5hRhp+92VCJewVPH5cMaYVem5aE/9uF46HWMHLM9nWu+MXnvGJ
mOQi7Ny+149Oz9vl9PzYrsLJ0NyGRzypvRbZ0jjSH7Xd776xQ8ph0L1qqNkfM6CX
eQ6WQNvJEIXcXyY0O6MTj2stZwKBgQDT8xR1fkDpVINvkr4kI2ry8NoEo0ZTwYCv
Z+lgCG2T/eZcsj79nQk3R2L1mB42GEmvaM3XU5T/ak4G62myCeQijbLfpw5A9/l1
ClKBdmR7eI0OV3eiy4si480mf/cLTzsC06r7DhjFkKVksDGIsKpfxIFWsHYiIUJD
vRIn76fy+QKBgQDOaLesGw0QDWNuVUiHU8XAmEP9s5DicF33aJRXyb2Nl2XjCXhh
fi78gEj0wyQgbbhgh7ZU6Xuz1GTn7j+M2D/hBDb33xjpqWPE5kkR1n7eNAQvLibj
06GtNGra1rm39ncIywlOYt7p/01dZmmvmIryJV0c6O0xfGp9hpHaNU0S2wKBgCX2
5ZRCIChrTfu/QjXA7lhD0hmAkYlRINbKeyALgm0+znOOLgBJj6wKKmypacfww8oa
sLxAKXEyvnU4177fTLDvxrmO99ulT1aqmaq85TTEnCeUfUZ4xRxjx4x84WhyMbTI
61h65u8EgMuvT8AXPP1Yen5nr1FfubnedREYOXIpAoGAMZlUBtQGIHyt6uo1s40E
DF+Kmhrggn6e0GsVPYO2ghk1tLNqgr6dVseRtYwnJxpXk9U6HWV8CJl5YLFDPlFx
mH9FLxRKfHIwbWPh0//Atxt1qwjy5FpILpiEUcvkeOEusijQdFbJJLZvbO0EjYU/
Uz4xpoYU8cPObY7JmDznKvc=
-----END PRIVATE KEY-----
";

struct Fixture {
    private: RsaPrivateKey,
    public_pem: String,
}

fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let mut private = RsaPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY).ok()?;
            private.validate().ok()?;
            private.precompute().ok()?;
            let public_pem = blob::public_key_pem(&RsaPublicKey::from(&private))?;
            Some(Fixture {
                private,
                public_pem,
            })
        })
        .as_ref()
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Option<&[u8]> {
        let end = self.position.checked_add(length)?;
        let value = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(value)
    }

    fn int32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn int64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn uid(&mut self) -> Option<u32> {
        self.int32()?.try_into().ok()
    }

    fn string(&mut self) -> Option<Option<String>> {
        let length = self.int32()?;
        if length == -1 {
            return Some(None);
        }
        let length: usize = length.try_into().ok()?;
        if length > MAX_STRING_UNITS {
            return None;
        }
        let raw = self.take((length + 1).checked_mul(2)?)?;
        if raw.get(raw.len() - 2..)? != [0, 0] {
            return None;
        }
        let units = raw[..length * 2]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect::<Vec<_>>();
        let padding = (4 - self.position % 4) % 4;
        self.take(padding)?;
        Some(Some(String::from_utf16(&units).ok()?))
    }
}

fn arguments(bytes: &[u8]) -> Option<Reader<'_>> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return None;
    }
    // Standard Android Java header, and bounded legacy OEM header variants.
    // Never discover a descriptor by scanning arbitrary alias/challenge data.
    for position in [12, 8, 4, 0] {
        let mut reader = Reader { bytes, position };
        if reader.string().flatten().as_deref() == DESCRIPTOR.to_str().ok() {
            return Some(reader);
        }
    }
    None
}

pub(super) fn valid_request(code: u32, bytes: &[u8]) -> bool {
    (1..=13).contains(&code) && arguments(bytes).is_some()
}

pub(super) enum Request {
    Uid(u32),
    Key(u32, Option<String>),
    Init(u32, Option<String>, Option<String>),
    Session(i64),
    None,
}

pub(super) fn parse_request(code: u32, bytes: &[u8]) -> Result<Request, i32> {
    if !(1..=13).contains(&code) {
        return Err(UNKNOWN_TRANSACTION);
    }
    let mut reader = arguments(bytes).ok_or(BAD_VALUE)?;
    let request = match code {
        1..=3 | 7 => Request::Uid(reader.uid().ok_or(BAD_VALUE)?),
        4..=6 | 8 => Request::Key(
            reader.uid().ok_or(BAD_VALUE)?,
            reader.string().ok_or(BAD_VALUE)?,
        ),
        9 => Request::Init(
            reader.uid().ok_or(BAD_VALUE)?,
            reader.string().ok_or(BAD_VALUE)?,
            reader.string().ok_or(BAD_VALUE)?,
        ),
        10 => Request::Session(reader.int64().ok_or(BAD_VALUE)?),
        13 => {
            reader.string().ok_or(BAD_VALUE)?;
            Request::None
        }
        _ => Request::None,
    };
    Ok(request)
}

#[derive(Default)]
struct UidState {
    ask: bool,
    keys: BTreeSet<String>,
    counter: u64,
}

struct Session {
    uid: u32,
    key: String,
    opened: Instant,
}

#[derive(Default)]
pub(super) struct SoftwareState {
    uids: BTreeMap<u32, UidState>,
    sessions: BTreeMap<i64, Session>,
    next_session: i64,
}

pub(super) trait Writer {
    fn int32(&mut self, value: i32) -> Result<(), i32>;
    fn int64(&mut self, value: i64) -> Result<(), i32>;
    fn bytes(&mut self, value: &[u8]) -> Result<(), i32>;
}

pub(super) fn buffer_reply(output: &mut impl Writer, code: i32, data: &[u8]) -> Result<(), i32> {
    output.int32(1)?;
    output.int32(code)?;
    output.bytes(data)?;
    output.int32(data.len() as i32)
}

impl SoftwareState {
    fn generate_ask(&mut self, uid: u32) -> i32 {
        if !self.uids.contains_key(&uid) && self.uids.len() >= MAX_UIDS {
            return UNAVAILABLE;
        }
        self.uids.entry(uid).or_default().ask = true;
        0
    }

    fn has_ask(&self, uid: u32) -> bool {
        self.uids.get(&uid).is_some_and(|state| state.ask)
    }

    fn has_auth(&self, uid: u32, key: &str) -> bool {
        self.uids
            .get(&uid)
            .is_some_and(|state| state.ask && state.keys.contains(key))
    }

    fn key_code(&mut self, code: u32, uid: u32, key: Option<String>) -> i32 {
        let Some(key) = key.filter(|key| !key.is_empty()) else {
            return BAD_VALUE;
        };
        let Some(state) = self.uids.get_mut(&uid).filter(|state| state.ask) else {
            return NO_KEY;
        };
        if code == 4 {
            if !state.keys.contains(&key) && state.keys.len() >= MAX_KEYS_PER_UID {
                return UNAVAILABLE;
            }
            state.keys.insert(key);
            0
        } else if state.keys.remove(&key) {
            self.sessions
                .retain(|_, session| session.uid != uid || session.key != key);
            0
        } else {
            NO_AUTH_KEY
        }
    }

    fn export(&mut self, uid: u32, key: Option<&str>) -> Result<Vec<u8>, i32> {
        if !self.has_ask(uid) {
            return Err(NO_KEY);
        }
        if let Some(key) = key
            && !self.has_auth(uid, key)
        {
            return Err(NO_AUTH_KEY);
        }
        let fixture = fixture().ok_or(UNAVAILABLE)?;
        let state = self.uids.get_mut(&uid).ok_or(NO_KEY)?;
        let counter = state.counter.checked_add(1).ok_or(UNAVAILABLE)?;
        let mut value: serde_json::Value =
            serde_json::from_slice(&blob::key_json(&fixture.public_pem, CPU_ID, counter, uid))
                .map_err(|_| UNAVAILABLE)?;
        value["software_test"] = true.into();
        value["key_source"] = "public_test_fixture".into();
        if let Some(key) = key {
            value["key_name"] = key.into();
        }
        let json = serde_json::to_vec(&value).map_err(|_| UNAVAILABLE)?;
        let signature = blob::sign(&fixture.private, &json).ok_or(UNAVAILABLE)?;
        state.counter = counter;
        Ok(blob::encode(&json, &signature))
    }

    fn init(&mut self, uid: u32, key: Option<String>, challenge: Option<String>) -> (i32, i64) {
        let Some(key) = key.filter(|key| !key.is_empty()) else {
            return (BAD_VALUE, 0);
        };
        if challenge.is_none() {
            return (BAD_VALUE, 0);
        }
        if !self.has_auth(uid, &key) {
            return (NO_AUTH_KEY, 0);
        }
        self.sessions
            .retain(|_, session| session.opened.elapsed() < SESSION_LIFETIME);
        if self.sessions.len() >= MAX_SESSIONS {
            return (UNAVAILABLE, 0);
        }
        let Some(id) = self.next_session.checked_add(1) else {
            return (UNAVAILABLE, 0);
        };
        self.next_session = id;
        self.sessions.insert(
            id,
            Session {
                uid,
                key,
                opened: Instant::now(),
            },
        );
        (0, id)
    }

    fn finish(&mut self, id: i64) -> i32 {
        // This process has no trusted biometric evidence. Never sign challenges
        // or return invented TEE/fingerprint claims from the public test key.
        match self.sessions.remove(&id) {
            Some(session) if session.opened.elapsed() < SESSION_LIFETIME => NO_FINGERPRINT,
            _ => NO_SESSION,
        }
    }

    pub(super) fn write_reply(
        &mut self,
        code: u32,
        request: &[u8],
        output: &mut impl Writer,
    ) -> Result<(), i32> {
        let request = parse_request(code, request)?;
        output.int32(0)?; // Java Parcel.writeNoException()
        match (code, request) {
            (1, Request::Uid(uid)) => output.int32(self.generate_ask(uid)),
            (2, Request::Uid(uid)) => match self.export(uid, None) {
                Ok(bytes) => buffer_reply(output, 0, &bytes),
                Err(code) => buffer_reply(output, code, &[]),
            },
            (3, Request::Uid(uid)) => output.int32(i32::from(self.has_ask(uid))),
            (4 | 5, Request::Key(uid, key)) => output.int32(self.key_code(code, uid, key)),
            (6, Request::Key(uid, key)) => {
                let result = key
                    .filter(|key| !key.is_empty())
                    .ok_or(BAD_VALUE)
                    .and_then(|key| self.export(uid, Some(&key)));
                match result {
                    Ok(bytes) => buffer_reply(output, 0, &bytes),
                    Err(code) => buffer_reply(output, code, &[]),
                }
            }
            (7, Request::Uid(uid)) => {
                self.sessions.retain(|_, session| session.uid != uid);
                match self.uids.get_mut(&uid).filter(|state| state.ask) {
                    Some(state) => {
                        // Preserve the counter even after deletion/recreation.
                        state.ask = false;
                        state.keys.clear();
                        output.int32(0)
                    }
                    None => output.int32(NO_KEY),
                }
            }
            (8, Request::Key(uid, key)) => output.int32(i32::from(
                key.as_deref().is_some_and(|key| self.has_auth(uid, key)),
            )),
            (9, Request::Init(uid, key, challenge)) => {
                let (code, session) = self.init(uid, key, challenge);
                output.int32(1)?;
                output.int64(session)?;
                output.int32(code)
            }
            (10, Request::Session(id)) => buffer_reply(output, self.finish(id), &[]),
            (11, Request::None) => buffer_reply(output, 0, DEVICE),
            (12, Request::None) => output.int32(1),
            (13, Request::None) => {
                output.int32(1)?;
                output.int32(-1) // Parcel.writeValue(null), no biometric capability.
            }
            _ => Err(BAD_VALUE),
        }
    }
}
