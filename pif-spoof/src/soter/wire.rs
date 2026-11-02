use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::{BAD_VALUE, DESCRIPTOR, MAX_REQUEST_BYTES, UNKNOWN_TRANSACTION};
use crate::{attk, ids};

/// The vendor TA's answer for an AuthKey alias it does not hold.
const MISSING_KEY: i32 = -6;
/// The vendor TA's answer for a signing session it did not open.
const UNKNOWN_SESSION: i32 = -1000;
/// A signature result the emulated TA cannot produce (for example, no private key).
const SIGN_FAILED: i32 = -1;

struct Record {
    key: attk::KeyPair,
    blob: Arc<[u8]>,
}

struct Session {
    uid: u32,
    alias: Vec<u16>,
    challenge: String,
}

struct User {
    ask: Record,
    auth: HashMap<Vec<u16>, Record>,
    /// Shared by ASK generation, AuthKey generation and signatures so the exported counters only
    /// move forward, as they do behind a live TA.
    counter: i64,
}

/// All keys live only in this SoterServer process, isolated by UID and exact UTF-16 alias.
struct KeyStore {
    users: HashMap<u32, User>,
    sessions: HashMap<i64, Session>,
    next_session: i64,
    generate: fn() -> Option<attk::KeyPair>,
    attk_private: Vec<u8>,
}

/// The arguments a caller passed after the enforced AIDL interface header.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Arguments {
    /// `kname` for the AIDL methods that carry one.
    pub(super) alias: Vec<u16>,
    /// `challenge` for `initSigh`.
    pub(super) challenge: Option<String>,
    /// `signSession` for `finishSign`.
    pub(super) session: Option<i64>,
    /// `key` for `getExtraParam`.
    pub(super) key: Option<String>,
}

fn make_record(
    generate: fn() -> Option<attk::KeyPair>,
    signer: &[u8],
    uid: u32,
    counter: i64,
) -> Option<Record> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let key = generate()?;
    if key.public_der.is_empty() {
        return None;
    }
    let json = format!(
        "{{\"pub_key\":\"{}\",\"counter\":{},\"cpu_id\":\"{}\",\"uid\":{}}}",
        BASE64.encode(&key.public_der),
        counter,
        ids::cpu_id(),
        uid,
    );
    let signature = attk::sign_export_json(signer, json.as_bytes())?;
    let mut blob = Vec::with_capacity(4 + json.len() + signature.len());
    blob.extend_from_slice(&(json.len() as u32).to_le_bytes());
    blob.extend_from_slice(json.as_bytes());
    blob.extend_from_slice(&signature);
    Some(Record { key, blob: Arc::from(blob) })
}

impl KeyStore {
    fn new(generate: fn() -> Option<attk::KeyPair>, attk_private: Vec<u8>) -> Self {
        Self {
            users: HashMap::new(),
            sessions: HashMap::new(),
            next_session: 1,
            generate,
            attk_private,
        }
    }

    fn generate_ask(&mut self, uid: u32) -> bool {
        let counter = self.users.get(&uid).map_or(1, |user| user.counter.saturating_add(1));
        let Some(ask) = make_record(self.generate, &self.attk_private, uid, counter) else {
            return false;
        };
        // Publish only after generation and signing succeed; replacing ASK invalidates its children.
        self.users.insert(uid, User { ask, auth: HashMap::new(), counter });
        self.sessions.retain(|_, session| session.uid != uid);
        true
    }

    fn generate_auth(&mut self, uid: u32, alias: &[u16]) -> bool {
        if alias.is_empty() {
            return false;
        }
        let Some(user) = self.users.get_mut(&uid) else {
            return false;
        };
        let counter = user.counter.saturating_add(1);
        let Some(auth) = make_record(self.generate, &user.ask.key.private_der, uid, counter) else {
            return false;
        };
        user.counter = counter;
        user.auth.insert(alias.to_vec(), auth);
        true
    }

    fn remove_auth(&mut self, uid: u32, alias: &[u16]) -> i32 {
        let Some(user) = self.users.get_mut(&uid) else {
            return MISSING_KEY;
        };
        if user.auth.remove(alias).is_some() { 0 } else { MISSING_KEY }
    }

    fn remove_user(&mut self, uid: u32) {
        self.users.remove(&uid);
        self.sessions.retain(|_, session| session.uid != uid);
    }

    fn export(&self, code: u32, uid: u32, alias: &[u16]) -> Option<Arc<[u8]>> {
        let user = self.users.get(&uid)?;
        if code == 2 {
            Some(Arc::clone(&user.ask.blob))
        } else {
            user.auth.get(alias).map(|record| Arc::clone(&record.blob))
        }
    }

    fn init_session(&mut self, uid: u32, alias: &[u16], challenge: &str) -> (i64, i32) {
        let Some(user) = self.users.get(&uid) else {
            return (0, MISSING_KEY);
        };
        if !user.auth.contains_key(alias) {
            return (0, MISSING_KEY);
        }
        let session = self.next_session;
        self.next_session = self.next_session.checked_add(1).unwrap_or(1);
        self.sessions.insert(
            session,
            Session { uid, alias: alias.to_vec(), challenge: challenge.to_string() },
        );
        (session, 0)
    }

    /// Consume one session and sign the reference result JSON with that AuthKey.
    fn finish_sign(&mut self, uid: u32, session_id: i64) -> Result<Vec<u8>, i32> {
        let Some(session) = self.sessions.get(&session_id) else {
            return Err(UNKNOWN_SESSION);
        };
        if session.uid != uid {
            return Err(UNKNOWN_SESSION);
        }
        let session = self.sessions.remove(&session_id).expect("session was checked");
        let Some(user) = self.users.get_mut(&uid) else {
            return Err(MISSING_KEY);
        };
        let Some(auth) = user.auth.get(&session.alias) else {
            return Err(MISSING_KEY);
        };
        let private = auth.key.private_der.clone();
        let counter = user.counter.saturating_add(1);
        user.counter = counter;
        let json = sign_json(uid, &session.challenge, counter);
        let Some(signature) = attk::sign_export_json(&private, json.as_bytes()) else {
            return Err(SIGN_FAILED);
        };
        let mut blob = Vec::with_capacity(4 + json.len() + signature.len());
        blob.extend_from_slice(&(json.len() as u32).to_le_bytes());
        blob.extend_from_slice(json.as_bytes());
        blob.extend_from_slice(&signature);
        Ok(blob)
    }
}

/// The stock result layout: `raw fid counter tee_n tee_v fp_n fp_v cpu_id uid`, in that order.
fn sign_json(uid: u32, challenge: &str, counter: i64) -> String {
    format!(
        "{{\"raw\":\"{}\",\"fid\":\"\",\"counter\":{},\"tee_n\":\"QSEE\",\"tee_v\":\"5\",\
         \"fp_n\":\"fingerprint\",\"fp_v\":\"1\",\"cpu_id\":\"{}\",\"uid\":{}}}",
        escape_json(challenge),
        counter,
        ids::cpu_id(),
        uid,
    )
}

fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out
}

fn read_i32(bytes: &[u8], position: usize) -> Result<i32, i32> {
    let end = position.checked_add(4).ok_or(BAD_VALUE)?;
    let value = bytes.get(position..end).ok_or(BAD_VALUE)?;
    Ok(i32::from_le_bytes(value.try_into().expect("four bytes")))
}

fn read_i64(bytes: &[u8], position: usize) -> Result<i64, i32> {
    let end = position.checked_add(8).ok_or(BAD_VALUE)?;
    let value = bytes.get(position..end).ok_or(BAD_VALUE)?;
    Ok(i64::from_le_bytes(value.try_into().expect("eight bytes")))
}

/// Read one Java `writeString` value. `Ok(None)` is its null spelling.
fn read_string(bytes: &[u8], position: usize) -> Result<(Option<Vec<u16>>, String, usize), i32> {
    let length = read_i32(bytes, position)?;
    let start = position.checked_add(4).ok_or(BAD_VALUE)?;
    if length < 0 {
        return Ok((None, String::new(), start));
    }
    let units = usize::try_from(length).map_err(|_| BAD_VALUE)?;
    let end = units
        .checked_add(1)
        .and_then(|units| units.checked_mul(2))
        .and_then(|length| start.checked_add(length))
        .ok_or(BAD_VALUE)?;
    let padded_end = end.checked_add(3).map(|end| end & !3).ok_or(BAD_VALUE)?;
    let name = bytes.get(start..end).filter(|_| padded_end <= bytes.len()).ok_or(BAD_VALUE)?;
    if name[name.len() - 2..] != [0, 0] {
        return Err(BAD_VALUE);
    }
    let units = name[..name.len() - 2]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    let text = String::from_utf16_lossy(&units);
    Ok((Some(units), text, padded_end))
}

/// Read the non-empty alias carried by `generateAuthKey` and friends.
fn read_alias(bytes: &[u8], position: usize) -> Result<(Vec<u16>, usize), i32> {
    let (alias, _, end) = read_string(bytes, position)?;
    let alias = alias.filter(|alias| !alias.is_empty()).ok_or(BAD_VALUE)?;
    Ok((alias, end))
}

/// Parse arguments at the cursor left by Android's enforced AIDL interface header.
/// The caller-supplied UID is consumed but never used as the key-store identity.
pub(super) fn request_arguments(
    code: u32,
    bytes: &[u8],
    position: usize,
) -> Result<Arguments, i32> {
    if position > bytes.len() || !position.is_multiple_of(4) {
        return Err(BAD_VALUE);
    }
    let mut arguments = Arguments::default();
    match code {
        1..=3 | 7 => {
            // The Java layer replaces the passed UID with Binder.getCallingUid().
            read_i32(bytes, position)?;
        }
        4..=6 | 8 => {
            let after_uid = position.checked_add(4).ok_or(BAD_VALUE)?;
            let (alias, _) = read_alias(bytes, after_uid)?;
            arguments.alias = alias;
        }
        9 => {
            let after_uid = position.checked_add(4).ok_or(BAD_VALUE)?;
            let (alias, end) = read_alias(bytes, after_uid)?;
            arguments.alias = alias;
            arguments.challenge = Some(read_string(bytes, end)?.1);
        }
        10 => {
            arguments.session = Some(read_i64(bytes, position)?);
        }
        13 => {
            arguments.key =
                read_string(bytes, position)?.0.map(|units| String::from_utf16_lossy(&units));
        }
        _ => {}
    }
    Ok(arguments)
}

pub(super) fn valid_request(code: u32, bytes: &[u8]) -> bool {
    if !(1..=13).contains(&code) || bytes.len() > MAX_REQUEST_BYTES {
        return false;
    }
    // D-soter identifies the interface by its UTF-16 descriptor anywhere in the
    // driver-validated payload. Android validates the interface header before
    // the native callback parses arguments; trailing OEM fields are preserved.
    let expected = DESCRIPTOR.to_bytes();
    bytes.windows(expected.len() * 2).any(|token| {
        token.as_chunks::<2>().0.iter().zip(expected).all(|(unit, byte)| *unit == [*byte, 0])
    })
}

pub(super) trait Writer {
    fn int32(&mut self, value: i32) -> Result<(), i32>;
    fn int64(&mut self, value: i64) -> Result<(), i32>;
    fn bytes(&mut self, value: &[u8]) -> Result<(), i32>;
}

pub(super) fn write_reply(
    code: u32,
    uid: u32,
    arguments: &Arguments,
    output: &mut impl Writer,
) -> Result<(), i32> {
    static KEYS: OnceLock<Mutex<KeyStore>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        Mutex::new(KeyStore::new(
            attk::generate_keypair,
            attk::attk_private_der().unwrap_or_default(),
        ))
    });
    let mut keys = keys.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    write_reply_with_store(code, uid, arguments, output, &mut keys)
}

fn write_reply_with_store(
    code: u32,
    uid: u32,
    arguments: &Arguments,
    output: &mut impl Writer,
    keys: &mut KeyStore,
) -> Result<(), i32> {
    if !(1..=13).contains(&code) {
        return Err(UNKNOWN_TRANSACTION);
    }
    output.int32(0)?; // Java Parcel.writeNoException()
    match code {
        1 => {
            let ok = keys.generate_ask(uid);
            output.int32(if ok { 0 } else { SIGN_FAILED })
        }
        4 => {
            let ok = keys.generate_auth(uid, &arguments.alias);
            output.int32(if ok { 0 } else { SIGN_FAILED })
        }
        5 => output.int32(keys.remove_auth(uid, &arguments.alias)),
        7 => {
            keys.remove_user(uid);
            output.int32(0)
        }
        3 => output.int32(i32::from(keys.users.contains_key(&uid))),
        8 => output.int32(i32::from(
            keys.users.get(&uid).is_some_and(|user| user.auth.contains_key(&arguments.alias)),
        )),
        12 => output.int32(1),
        9 => {
            let (session, status) = keys.init_session(
                uid,
                &arguments.alias,
                arguments.challenge.as_deref().unwrap_or_default(),
            );
            output.int32(1)?;
            output.int64(session)?;
            output.int32(status)
        }
        2 | 6 => {
            let blob = keys.export(code, uid, &arguments.alias);
            let bytes: &[u8] = blob.as_deref().unwrap_or_default();
            output.int32(1)?;
            output.int32(if blob.is_some() { 0 } else { MISSING_KEY })?;
            output.bytes(bytes)?;
            output.int32(bytes.len() as i32)
        }
        10 => {
            let session = arguments.session.ok_or(BAD_VALUE)?;
            match keys.finish_sign(uid, session) {
                Ok(blob) => {
                    output.int32(1)?;
                    output.int32(0)?;
                    output.bytes(&blob)?;
                    output.int32(blob.len() as i32)
                }
                Err(status) => {
                    output.int32(1)?;
                    output.int32(status)?;
                    output.bytes(&[])?;
                    output.int32(0)
                }
            }
        }
        11 => {
            let bytes = ids::device_blob();
            output.int32(1)?;
            output.int32(0)?;
            output.bytes(bytes)?;
            output.int32(bytes.len() as i32)
        }
        13 => write_extra_param(output, arguments.key.as_deref()),
        _ => Err(UNKNOWN_TRANSACTION),
    }
}

/// `fingerprint_type` is an `Integer`; any other key is an absent result. The stock under-screen
/// sample reports type `2`, and the vendor TA returns null for parameters it does not implement.
fn write_extra_param(output: &mut impl Writer, key: Option<&str>) -> Result<(), i32> {
    if key == Some("fingerprint_type") {
        output.int32(1)?; // non-null SoterExtraParam
        output.int32(1)?; // Parcel VAL_INTEGER
        output.int32(2) // FINGERPRINT_TYPE_UNDER_SCREEN
    } else {
        output.int32(0) // null SoterExtraParam
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soter::tests::Buffer;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    fn root() -> Option<attk::KeyPair> {
        Some(attk::KeyPair {
            public_der: BASE64.decode(attk::ATTK_PUBLIC_B64).ok()?,
            private_der: attk::attk_private_der()?,
        })
    }

    // Independent RSA-2048 fixtures generated by OpenSSL; used only by tests.
    fn second() -> Option<attk::KeyPair> {
        Some(attk::KeyPair {
            public_der: BASE64.decode(concat!(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3CTbIbg8xdGAg5v9TStZ79FX2jGAGRh69cYW",
            "r+lmx8MQfg1oMxIVCyq2ieiRbgMkbwJAqTPhZxU5Gs+pwMweetwa79r//hHYfaQ5xb5z5HCp2z+izLEM",
            "7gt+Y4iyWzIsGXMpOWwbSTLMt94RsqQPuyz5o9PZNnc4Gg9rwwT9bsusAXyTwtSZ6tuDX5XJp1tNKDol",
            "jnaTLwkq/LGc1p5mbR8LlHdNIwl7/qMYCt46vMQuMHAt7Csp07tgQoTCO7k8zj9XvhabtkusfJ0X2wdV",
            "eC4Wa56GO2xmhzTMdNb9dD3+G8OPeJ4JrbT03cgUSGfbG4pTKTKPL4VsBPk8ae9tnwIDAQAB",
        )).ok()?,
            private_der: BASE64.decode(concat!(
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDcJNshuDzF0YCDm/1NK1nv0VfaMYAZ",
            "GHr1xhav6WbHwxB+DWgzEhULKraJ6JFuAyRvAkCpM+FnFTkaz6nAzB563Brv2v/+Edh9pDnFvnPkcKnb",
            "P6LMsQzuC35jiLJbMiwZcyk5bBtJMsy33hGypA+7LPmj09k2dzgaD2vDBP1uy6wBfJPC1Jnq24Nflcmn",
            "W00oOiWOdpMvCSr8sZzWnmZtHwuUd00jCXv+oxgK3jq8xC4wcC3sKynTu2BChMI7uTzOP1e+Fpu2S6x8",
            "nRfbB1V4LhZrnoY7bGaHNMx01v10Pf4bw494ngmttPTdyBRIZ9sbilMpMo8vhWwE+Txp722fAgMBAAEC",
            "ggEACDn0Wlk5JCdFByYAHC8fiD+pacTpxYZNqfuCA4bUSWi3qA42M5pcYPNyqMqhDJxfcyqBYhFHPgPk",
            "A2V5MXQvO2YYN5hWcpcWIPPPGN2aFRJEtqW1HrMLCaYyTePgzlmcnkLYaoXoqx6T2dcZkDRjRhpTJdUX",
            "y9o+pXKoEzyPf+FYww0myin3BD+gUx61ugflzJSyVji5r6+wKe0VX8OOfc1SNsmGHH8OI2x9uEDviVy1",
            "BCT96XV9cgptMqgLAirlO745iVItn3SA9CwyGjWt9EfFlZUH+t+T2yRuGxdg2mY8shxqGps5FDLI4YWX",
            "lZTURZrF4U77yZvNhU4LXwOR2QKBgQD58anIqzoWyv0z0msf09xShUzFqpkywN3tuC35K1zzKYGG6elf",
            "9bHdiyuQe4/tMKAZx3ADyFwcTwgUjusnq9/UdOuzWfLmghRMTXeHEs9HZiqYuJ0fRtdWxO+Ob2ENfXsN",
            "Lwpa725R9TJIOieQt/YICbT7QnFT8zuP4xI9sea6CwKBgQDhelndqn9QnO0y76HzcbFhp8nXlpvYLngw",
            "3lwy/7miyfWIawasDSD8lbARC/HQSVG4iqjFAoaEa7sBlFHTMk2AUxyGOpC9tZ1Ai27rKQnwYyjSwG0D",
            "CEfXIa2/sQ1pI+j7IetA+RtDH306+vd5TUqj4VNb3Xc2XXfXNUlKFKfrPQKBgQCWThiO/0FAgbOAnXIk",
            "QrCEw3qmh+/20HrlQNQMumH8LKKi8jmQplze4JlDGrszpQEyX3fiHnQd5fzy9/s78ST6S5GOWnIy4li4",
            "hgFyLgKOakcFbke2jlBi8q0o15vik+oSxI4Sn1eVW8FwI+C1K5t9u/ClBJDILkZMQf4vMbORfwKBgENy",
            "afdYzQS8LGgULom39KuVmVcYAj5EiEd1/HZ08H61kvDfsvs8YiWsUSKIRCleBUgCkkF8Y+iwoRvz1hYq",
            "8ev08I9mbW2SKhvomaFWgVabEtcYIIPLslG0DVlOCQjuaP7WQp0I5xLJFJjUAbsTV8R13o2YTdTBWNvT",
            "YLz8OM6xAoGBAMIsNfDoHxs91BiI80zX40CnT5Wz/1t3xva1GQkUMiMZ8e40xrfTX1BINW6Nuf1FpF70",
            "LDTXmaDmdZglZa+s/7NrA15PnL4DzMIfK1bO/2qp7Rx0P2q3n85VH3Q/05woP6jr8vcABKtKUcCiVn3l",
            "R0DdOCL5NVT8G/X7BazHWKZo",
        )).ok()?,
        })
    }

    // Independent RSA-2048 fixtures generated by OpenSSL; used only by tests.
    fn third() -> Option<attk::KeyPair> {
        Some(attk::KeyPair {
            public_der: BASE64.decode(concat!(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuhhABKz5U4z7il2J9eQg29HLetrIRDCFHvUB",
            "yYuSTRaXTtp6pa4GxMjziUtoJMriJAlLxgC2xt6Z6+kzYX3KL9tyUBYlkULv99s0kotIicESvLRaPEm7",
            "0qDjROjAhDxpV0wZbBosKa6PhwuKZrA1H/zpv8MFlbEvGE7ZTW7zQ4Ves7fCIBE+OdqKQ6kpFnGY64ft",
            "B9MnQKSsas6KFt+3/fHFotVTfKShjLHx+ksegz6+6KMHfb5FuS18gY9OazAUiAzVZDHABf6hMJE/G5k8",
            "+4+hD1Rma7vfCNIjb3u8gCLLCT7kkv532dHS9PQGCxmnnuxkNuOzYGVuX+Hwp3k3iwIDAQAB",
        )).ok()?,
            private_der: BASE64.decode(concat!(
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6GEAErPlTjPuKXYn15CDb0ct62shE",
            "MIUe9QHJi5JNFpdO2nqlrgbEyPOJS2gkyuIkCUvGALbG3pnr6TNhfcov23JQFiWRQu/32zSSi0iJwRK8",
            "tFo8SbvSoONE6MCEPGlXTBlsGiwpro+HC4pmsDUf/Om/wwWVsS8YTtlNbvNDhV6zt8IgET452opDqSkW",
            "cZjrh+0H0ydApKxqzooW37f98cWi1VN8pKGMsfH6Sx6DPr7oowd9vkW5LXyBj05rMBSIDNVkMcAF/qEw",
            "kT8bmTz7j6EPVGZru98I0iNve7yAIssJPuSS/nfZ0dL09AYLGaee7GQ247NgZW5f4fCneTeLAgMBAAEC",
            "ggEATA70P1T5FEJnXn5rkAG8wkslOKGpv2D7T5NAt0Chu3sTvWlDPmr5nj0peEBHIN6A/cyE2Tjaez5o",
            "t4hY9Swl0liFCKF8mjm6/VjszEY8D/1G7LRjuwdBykzyhmwAnytXvJPAQjQSP7j2NXIsj1rOY7QJT1Rk",
            "eHFx96PmYaUKrNnnNWo1/ihUVIPlJcEK/ZLAzLIHgdx5jtTW8Lu5CNAB9D9LX4NYuylYX50dlPWFuJk4",
            "xPsyARJs986WofEFYapuYhYEnJ6lRx5EEF7kseeHuRoYYYL7pD/PPk0Vo6ctJO5HrxeZFYQSsuecmnoc",
            "QbUkwRnG76/1axJBxKsFUeySDQKBgQDtcpC66Yp+OuWfyM2Txi4kud0MEWcnhoxVhnLzXyEe8r1jArVk",
            "mO29GbSqovqcnfp8Lliy7aT6w+5RoTq7WAeXATmBAQX50cUx4UujBTP0itdhnH7j2qVnX7B7G4n3JBCt",
            "iSIeSfnCReZ8qvPnMOhAYhNg2w1G4LCzKLZmalmNTQKBgQDIooYsTnqbf2a/dyIhAh/jH2GK9hZoh9L2",
            "4KmKi8oixydLlGLaEFeOj9kbVooR6QXzz2rXCcA+/DCOBkp6kpf7WYxYSRYbyvkUB8JN+0KPR1Bgyd/p",
            "a98mMnCMu7/ME9YqUDjo7gQZr+aBdryV65aivpu9fpH6OHpLR6O3CO1MNwKBgGWKiq4D1T/p++x6uL8r",
            "DuyRtx/ECXLzrOueFWZSFh3f/HFs5Rlh9LjbV1FpZPa48DdOsovB6L18MFwkMLORD53Z3jd2spGEzWlp",
            "SSkrvm4jObv6aqESDY3Jc/URb8yKVb+AV2DQjcgwkEJb8PW7CncN+e9/fYwD5kyXankdnbI5AoGBALcI",
            "JVUIJyvyNr7WpOjt8j8VorvNsjWcKyYTYDfHPRkrC7sUXHXI0Md6jTo2YXDjXw3EHBieiaYsFPOL46gc",
            "Uc/4KmNkEWo7aa0PQwA3BsqE6VvS7pUYVpOXEjwhD2DSe99QHgrJEC6K3MMgmfw+1sYTEyr066EUouRI",
            "L59L4odTAoGBAIJaYyDEroDBZCJacrtKYQyY13d7FlLGDuRJe3ej0R5IsnKWYvd6kv+HoEYQA75KlDFt",
            "eZrZP/cj0xsKGda/bDm80fd5PmJ41OTZ5v/wplRymZKgju+gEGTRBDV4SwqXSw2T8m7BEtlq7j4IrowI",
            "YohnR/lkV12xzcdCqROqhqop",
        )).ok()?,
        })
    }

    fn arguments(alias: &[u16]) -> Arguments {
        Arguments { alias: alias.to_vec(), ..Default::default() }
    }

    fn reply_with(keys: &mut KeyStore, code: u32, uid: u32, arguments: &Arguments) -> Vec<u8> {
        let mut output = Buffer::default();
        write_reply_with_store(code, uid, arguments, &mut output, keys).unwrap();
        output.0
    }

    fn reply(keys: &mut KeyStore, code: u32, uid: u32, alias: &[u16]) -> Vec<u8> {
        let mut arguments = arguments(alias);
        if code == 9 {
            arguments.challenge = Some("challenge".to_string());
        }
        reply_with(keys, code, uid, &arguments)
    }

    fn scalar(bytes: &[u8]) -> i32 {
        i32::from_le_bytes(bytes[4..8].try_into().unwrap())
    }

    /// Split a `SoterExportResult` reply into its export JSON and signature.
    fn exported(reply: &[u8]) -> (String, Vec<u8>) {
        assert_eq!(int32(reply, 4), 1, "typed object must be non-null");
        let length = int32(reply, 12) as usize;
        let padded = (length + 3) & !3;
        assert_eq!(int32(reply, 16 + padded), length as i32);
        let blob = &reply[16..16 + length];
        let json_length = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
        (
            String::from_utf8(blob[4..4 + json_length].to_vec()).unwrap(),
            blob[4 + json_length..].to_vec(),
        )
    }

    fn int32(bytes: &[u8], position: usize) -> i32 {
        i32::from_le_bytes(bytes[position..position + 4].try_into().unwrap())
    }

    #[test]
    fn isolates_keys_and_signs_exports_with_their_parent() {
        const UID: u32 = 10123;
        let a = [0x61];
        let b = [0x61, 0, 0x62, 0xd800];
        let mut keys = KeyStore::new(second, attk::attk_private_der().unwrap());
        assert_eq!(scalar(&reply(&mut keys, 3, UID, &[])), 0);
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &a)), -1);
        let missing = reply(&mut keys, 2, UID, &[]);
        assert_eq!(missing, [0, 0, 0, 0, 1, 0, 0, 0, 250, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(int32(&missing, 8), -6);
        assert_eq!(scalar(&reply(&mut keys, 1, UID, &[])), 0);
        let ask = keys.export(2, UID, &[]).unwrap();
        assert_eq!(scalar(&reply(&mut keys, 3, UID, &[])), 1);
        keys.generate = third;
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &a)), 0);
        keys.generate = root;
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &b)), 0);
        let auth_a = keys.export(6, UID, &a).unwrap();
        let auth_b = keys.export(6, UID, &b).unwrap();
        assert_ne!(
            keys.users[&UID].ask.key.public_der,
            keys.users[&UID].auth.get(&a[..]).unwrap().key.public_der
        );
        assert_ne!(
            keys.users[&UID].auth.get(&a[..]).unwrap().key.public_der,
            keys.users[&UID].auth.get(&b[..]).unwrap().key.public_der
        );
        assert!(attk::tests::verifies_export(&ask, &keys.attk_private));
        for blob in [&auth_a, &auth_b] {
            assert!(attk::tests::verifies_export(blob, &keys.users[&UID].ask.key.private_der));
            assert!(!attk::tests::verifies_export(blob, &keys.attk_private));
        }
        let exported = reply(&mut keys, 6, UID, &a);
        assert_eq!(&exported[16..16 + auth_a.len()], &*auth_a);
        assert_eq!(reply(&mut keys, 6, UID, &a), exported);
        assert_eq!(scalar(&reply(&mut keys, 8, UID + 1, &a)), 0);
        assert_eq!(scalar(&reply(&mut keys, 1, UID + 1, &[])), 0);
        keys.generate = root;
        assert_eq!(scalar(&reply(&mut keys, 4, UID + 1, &a)), 0);
        assert_ne!(
            keys.users[&UID].auth.get(&a[..]).unwrap().key.public_der,
            keys.users[&(UID + 1)].auth.get(&a[..]).unwrap().key.public_der
        );

        keys.generate = || None;
        assert_eq!(scalar(&reply(&mut keys, 1, UID, &[])), -1);
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &a)), -1);
        assert_eq!(&*keys.export(2, UID, &[]).unwrap(), &*ask);
        assert_eq!(&*keys.export(6, UID, &a).unwrap(), &*auth_a);
        keys.generate = root;
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &[])), -1);
        assert_eq!(scalar(&reply(&mut keys, 5, UID, &a)), 0);
        assert_eq!(scalar(&reply(&mut keys, 8, UID, &a)), 0);
        assert_eq!(&*keys.export(6, UID, &b).unwrap(), &*auth_b);
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &a)), 0);
        assert_ne!(
            keys.users[&UID].auth.get(&a[..]).unwrap().key.public_der,
            third().unwrap().public_der
        );
        keys.generate = third;
        assert_eq!(scalar(&reply(&mut keys, 1, UID, &[])), 0);
        assert_ne!(keys.users[&UID].ask.key.public_der, second().unwrap().public_der);
        assert_eq!(scalar(&reply(&mut keys, 8, UID, &a)), 0);
        assert_eq!(scalar(&reply(&mut keys, 8, UID, &b)), 0);
        assert_eq!(scalar(&reply(&mut keys, 7, UID, &[])), 0);
        assert_eq!(scalar(&reply(&mut keys, 3, UID, &[])), 0);
        assert_eq!(scalar(&reply(&mut keys, 3, UID + 1, &[])), 1);
        assert_eq!(scalar(&reply(&mut keys, 8, UID + 1, &a)), 1);
        let mut bad_signer = KeyStore::new(root, vec![]);
        assert!(!bad_signer.generate_ask(UID));
        assert!(bad_signer.users.is_empty());
    }

    #[test]
    fn signs_finish_results_and_answers_missing_state_like_the_vendor() {
        const UID: u32 = 10123;
        const ALIAS: [u16; 3] = [0x6b, 0x65, 0x79];
        let mut keys = KeyStore::new(second, attk::attk_private_der().unwrap());

        // No ASK, no AuthKey: every stateful read reports the vendor's missing-key code.
        assert_eq!(int32(&reply(&mut keys, 6, UID, &ALIAS), 8), -6);
        let mut unknown_key = arguments(&ALIAS);
        unknown_key.challenge = Some("challenge".to_string());
        let unopened = reply_with(&mut keys, 9, UID, &unknown_key);
        assert_eq!(int32(&unopened, 16), -6);

        assert_eq!(scalar(&reply(&mut keys, 1, UID, &[])), 0);
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &ALIAS)), 0);
        let mut init = arguments(&ALIAS);
        init.challenge = Some("challenge-1".to_string());
        let opened = reply_with(&mut keys, 9, UID, &init);
        let session = i64::from_le_bytes(opened[8..16].try_into().unwrap());
        assert_ne!(session, 0);
        assert_eq!(int32(&opened, 16), 0);

        init.session = Some(session);
        let signed = reply_with(&mut keys, 10, UID, &init);
        assert_eq!(int32(&signed, 8), 0);
        let (json, signature) = exported(&signed);
        assert!(json.contains("\"raw\":\"challenge-1\""));
        let keys_in_order = [
            "\"raw\"",
            "\"fid\"",
            "\"counter\"",
            "\"tee_n\"",
            "\"tee_v\"",
            "\"fp_n\"",
            "\"fp_v\"",
            "\"cpu_id\"",
            "\"uid\"",
        ];
        let mut previous = 0;
        for key in keys_in_order {
            let at = json.find(key).unwrap();
            assert!(at >= previous, "{key} is out of order");
            previous = at;
        }
        assert_eq!(signature.len(), 256);
        let auth_private = keys.users[&UID].auth.get(&ALIAS[..]).unwrap().key.private_der.clone();
        let signed_blob = &signed[16..16 + int32(&signed, 12) as usize];
        assert!(attk::tests::verifies_export(signed_blob, &auth_private));

        // A session is one-shot, and an unknown or foreign session is the vendor's -1000 answer.
        let replay = reply_with(&mut keys, 10, UID, &init);
        assert_eq!(int32(&replay, 8), -1000);
        assert_eq!(int32(&replay, 12), 0);
        assert_eq!(int32(&replay, 16), 0);
        init.session = Some(session + 1);
        assert_eq!(int32(&reply_with(&mut keys, 10, UID, &init), 8), -1000);
        init.session = Some(session);
        assert_eq!(int32(&reply_with(&mut keys, 10, UID + 1, &init), 8), -1000);

        // Removing the AuthKey makes the vendor report -6 again.
        assert_eq!(scalar(&reply(&mut keys, 5, UID, &ALIAS)), 0);
        let removed = reply_with(&mut keys, 6, UID, &arguments(&ALIAS));
        assert_eq!(int32(&removed, 8), -6);
        assert_eq!(int32(&removed, 12), 0);
        assert_eq!(int32(&removed, 16), 0);
        assert_eq!(scalar(&reply(&mut keys, 5, UID, &ALIAS)), -6);
    }

    #[test]
    fn exports_the_same_unit_identity_through_cpu_id_and_get_device_id() {
        const UID: u32 = 4242;
        let mut keys = KeyStore::new(second, attk::attk_private_der().unwrap());
        assert_eq!(scalar(&reply(&mut keys, 1, UID, &[])), 0);
        let (json, _) = exported(&reply(&mut keys, 2, UID, &[]));
        assert!(json.contains(&format!("\"cpu_id\":\"{}\"", ids::cpu_id())));
        let device = reply(&mut keys, 11, UID, &[]);
        let length = int32(&device, 12) as usize;
        assert_eq!(length, 16);
        let hex =
            device[16..16 + length].iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        assert_eq!(hex, ids::cpu_id());
    }

    #[test]
    fn reports_under_screen_fingerprint_type_and_null_for_other_parameters() {
        let mut keys = KeyStore::new(second, attk::attk_private_der().unwrap());
        let mut arguments =
            Arguments { key: Some("fingerprint_type".to_string()), ..Default::default() };
        assert_eq!(
            reply_with(&mut keys, 13, 1000, &arguments),
            [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]
        );
        arguments.key = Some("sotercheck_unknown_param".to_string());
        assert_eq!(reply_with(&mut keys, 13, 1000, &arguments), [0; 8]);
        arguments.key = None;
        assert_eq!(reply_with(&mut keys, 13, 1000, &arguments), [0; 8]);
    }

    #[test]
    fn counters_advance_from_ask_through_auth_key_to_the_signature() {
        const UID: u32 = 7;
        const ALIAS: [u16; 1] = [0x6b];
        let mut keys = KeyStore::new(second, attk::attk_private_der().unwrap());
        assert_eq!(scalar(&reply(&mut keys, 1, UID, &[])), 0);
        let (ask, _) = exported(&reply(&mut keys, 2, UID, &[]));
        assert!(ask.contains("\"counter\":1"));
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &ALIAS)), 0);
        let (auth, _) = exported(&reply(&mut keys, 6, UID, &ALIAS));
        assert!(auth.contains("\"counter\":2"));
        let mut init = arguments(&ALIAS);
        init.challenge = Some("c".to_string());
        let opened = reply_with(&mut keys, 9, UID, &init);
        init.session = Some(i64::from_le_bytes(opened[8..16].try_into().unwrap()));
        let (sign, _) = exported(&reply_with(&mut keys, 10, UID, &init));
        assert!(sign.contains("\"counter\":3"));
    }

    #[test]
    fn answers_the_soterchecker_transaction_matrix() {
        const UID: u32 = 10279;
        const ALIAS: [u16; 3] = [0x6b, 0x65, 0x79];
        let mut keys = KeyStore::new(second, attk::attk_private_der().unwrap());

        // T1: getVersion.
        assert_eq!(scalar(&reply(&mut keys, 12, UID, &[])), 1);
        // T2/C1/C6a: hasAskAlready -> generateAppSecureKey -> getAppSecureKey.
        assert_eq!(scalar(&reply(&mut keys, 3, UID, &[])), 0);
        assert_eq!(scalar(&reply(&mut keys, 1, UID, &[])), 0);
        let ask_reply = reply(&mut keys, 2, UID, &[]);
        assert_eq!(int32(&ask_reply, 8), 0);
        let (ask_json, ask_signature) = exported(&ask_reply);
        assert_eq!(ask_signature.len(), 256);
        assert!(ask_json.contains("\"counter\":1"));
        assert!(ask_json.contains(&format!("\"uid\":{UID}")));
        // T5/T6/T7/T8: missing key, unknown session, extra parameters.
        let missing = reply(&mut keys, 6, UID, &[0x6e, 0x6f, 0x6e, 0x65]);
        assert_eq!(int32(&missing, 8), -6);
        assert_eq!(int32(&missing, 12), 0);
        assert_eq!(int32(&missing, 16), 0);
        let unknown_session = Arguments { session: Some(424242), ..Default::default() };
        assert_eq!(int32(&reply_with(&mut keys, 10, UID, &unknown_session), 8), -1000);
        let extra = Arguments { key: Some("fingerprint_type".to_string()), ..Default::default() };
        assert_eq!(int32(&reply_with(&mut keys, 13, UID, &extra), 12), 2);
        // T9/C5b: getDeviceId is the same unit identity as the export's cpu_id.
        let device = reply(&mut keys, 11, UID, &[]);
        let length = int32(&device, 12) as usize;
        assert_eq!(length, 16);
        let device_hex =
            device[16..16 + length].iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        assert_eq!(device_hex, ids::cpu_id());
        assert!(ask_json.contains(&format!("\"cpu_id\":\"{device_hex}\"")));
        // T10/C6b: generateAuthKey -> hasAuthKey -> getAuthKey.
        assert_eq!(scalar(&reply(&mut keys, 4, UID, &ALIAS)), 0);
        assert_eq!(scalar(&reply(&mut keys, 8, UID, &ALIAS)), 1);
        let auth_reply = reply(&mut keys, 6, UID, &ALIAS);
        assert_eq!(int32(&auth_reply, 8), 0);
        let (auth_json, auth_signature) = exported(&auth_reply);
        assert_eq!(auth_signature.len(), 256);
        assert!(auth_json.contains("\"counter\":2"));
        // T11/T12/C4/C6c/C6d/C7/C9: one session, one signed result.
        let mut init = Arguments {
            alias: ALIAS.to_vec(),
            challenge: Some("sotercheck-chal".to_string()),
            ..Default::default()
        };
        let opened = reply_with(&mut keys, 9, UID, &init);
        let session = i64::from_le_bytes(opened[8..16].try_into().unwrap());
        assert_ne!(session, 0);
        assert_eq!(int32(&opened, 16), 0);
        init.session = Some(session);
        let signed = reply_with(&mut keys, 10, UID, &init);
        assert_eq!(int32(&signed, 8), 0);
        let (sign_json, sign_signature) = exported(&signed);
        assert_eq!(sign_signature.len(), 256);
        assert_eq!(
            sign_json,
            format!(
                "{{\"raw\":\"sotercheck-chal\",\"fid\":\"\",\"counter\":3,\"tee_n\":\"QSEE\",\
                 \"tee_v\":\"5\",\"fp_n\":\"fingerprint\",\"fp_v\":\"1\",\"cpu_id\":\"{}\",\
                 \"uid\":{UID}}}",
                ids::cpu_id()
            )
        );
        let signed_blob = &signed[16..16 + int32(&signed, 12) as usize];
        let auth_private = keys.users[&UID].auth.get(&ALIAS[..]).unwrap().key.private_der.clone();
        assert!(attk::tests::verifies_export(signed_blob, &auth_private));
        // T13: removal makes the AuthKey absent again.
        assert_eq!(scalar(&reply(&mut keys, 5, UID, &ALIAS)), 0);
        assert_eq!(scalar(&reply(&mut keys, 8, UID, &ALIAS)), 0);
        assert_eq!(int32(&reply(&mut keys, 6, UID, &ALIAS), 8), -6);
    }
}
