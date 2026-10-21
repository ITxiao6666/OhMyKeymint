//! Per-app Soter forwarding. Credentials and network I/O stay in the root
//! companion. The injected host holds only private inherited channels and a
//! bounded, non-secret allowlist snapshot; no filesystem socket is created.

use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    sync::{Arc, Mutex, OnceLock, TryLockError},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use soter_ta::{
    dispatch::{self, Outcome, Request},
    remote,
};
use zygisk_api::api::{V4, ZygiskApi};

use super::{BAD_VALUE, wire};

const MAGIC: &[u8; 8] = b"OMKSOTR1";
const AUTH: u8 = 1;
const CALL: u8 = 2;
const MAX_FRAME: usize = 1024 * 1024 + 32;
const IO_TIMEOUT: Duration = Duration::from_secs(25);
const AUTH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SESSIONS: usize = 64;
const SESSION_TTL: Duration = Duration::from_secs(120);
const GLOBAL_FLAG: &str = "/data/misc/keystore/omk/data/soterta/enabled";
const GLOBAL_MARKER: &str = "/data/misc/keystore/omk/data/soterta/hal-taken-over";
const UNAVAILABLE: i32 = -20;
const NO_SESSION: i32 = -1000;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    uids: Vec<u32>,
}

struct Authorization {
    last: Selection,
    fresh: bool,
}

struct Channels {
    auth: Arc<Mutex<Authorization>>,
    auth_refresh: Mutex<Option<UnixStream>>,
    calls: Mutex<Option<UnixStream>>,
}

static CHANNELS: OnceLock<Channels> = OnceLock::new();

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_frame(stream: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > limit {
        return Err(invalid("Soter companion frame exceeds limit"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err(invalid("Soter companion frame exceeds limit"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

fn connect(api: &mut ZygiskApi<'_, V4>, kind: u8) -> Result<UnixStream, String> {
    let stream = api
        .with_companion(|stream| -> io::Result<UnixStream> {
            // Consume the existing PIF/Beta header without interpreting the PIF profile.
            crate::read_soter_from_companion(stream)?;
            stream.set_write_timeout(Some(AUTH_TIMEOUT))?;
            stream.write_all(MAGIC)?;
            stream.write_all(&[kind])?;
            let mut ack = [0];
            stream.read_exact(&mut ack)?;
            if ack != [1] {
                return Err(invalid("Soter companion refused channel"));
            }
            stream.try_clone()
        })
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    if !api.exempt_fd(stream.as_raw_fd()) {
        return Err("Soter companion descriptor was not exempted".into());
    }
    let timeout = if kind == AUTH {
        AUTH_TIMEOUT
    } else {
        IO_TIMEOUT
    };
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

pub(super) fn prepare(api: &mut ZygiskApi<'_, V4>) -> Result<(), String> {
    let mut auth = connect(api, AUTH)?;
    auth.write_all(&[AUTH]).map_err(|error| error.to_string())?;
    let initial = read_frame(&mut auth, 8192).map_err(|error| error.to_string())?;
    let last = parse_selection(&initial).map_err(|error| error.to_string())?;
    let authorization = Arc::new(Mutex::new(Authorization { last, fresh: true }));
    let calls = connect(api, CALL)?;
    CHANNELS
        .set(Channels {
            auth: Arc::clone(&authorization),
            auth_refresh: Mutex::new(Some(auth)),
            calls: Mutex::new(Some(calls)),
        })
        .map_err(|_| "Soter companion already initialized".to_string())?;

    Ok(())
}

/// Start refreshing the allowlist only after Android has completed app
/// specialization. Creating threads earlier can interfere with the UID and
/// SELinux transition performed by zygote.
pub(super) fn activate() -> Result<(), String> {
    let Some(channels) = CHANNELS.get() else {
        return Ok(());
    };
    let Some(mut auth) = channels
        .auth_refresh
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
    else {
        return Ok(());
    };
    let refresh_authorization = Arc::clone(&channels.auth);
    let result = std::thread::Builder::new()
        .name("omk-soter-auth".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(750));
                let result = auth
                    .write_all(&[AUTH])
                    .and_then(|()| read_frame(&mut auth, 8192))
                    .and_then(|frame| parse_selection(&frame));
                let Ok(selection) = result else {
                    // Keep the last known selection so opted-in calls remain
                    // intercepted, but deny the remote call until the
                    // authorization channel is healthy again.
                    refresh_authorization
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .fresh = false;
                    super::log("Soter authorization refresh stopped; selected calls are denied");
                    break;
                };
                *refresh_authorization
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Authorization {
                    last: selection,
                    fresh: true,
                };
            }
        });
    if let Err(error) = result {
        channels
            .auth
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fresh = false;
        return Err(format!(
            "failed to start Soter authorization refresh: {error}"
        ));
    }
    Ok(())
}

fn parse_selection(bytes: &[u8]) -> io::Result<Selection> {
    let value: Selection =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid Soter selection"))?;
    if value.uids.len() > pif_common::soter::MAX_APP_TARGETS
        || value
            .uids
            .iter()
            .any(|uid| !(10000..20000).contains(&(uid % 100000)))
        || value.uids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("invalid Soter UID selection"));
    }
    Ok(value)
}

pub(super) fn selected(uid: u32) -> bool {
    let Some(channels) = CHANNELS.get() else {
        return false;
    };
    let auth = channels
        .auth
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    auth.last.uids.binary_search(&uid).is_ok()
}

pub(super) fn write_reply(
    uid: u32,
    code: u32,
    bytes: &[u8],
    output: &mut impl wire::Writer,
) -> Result<(), i32> {
    let answer = call(uid, code, bytes)
        .unwrap_or_else(|_| Reply::error(if code == 10 { NO_SESSION } else { UNAVAILABLE }));
    answer.write_sdk(code, output)
}

fn call(uid: u32, code: u32, bytes: &[u8]) -> io::Result<Reply> {
    if bytes.len() > super::MAX_REQUEST_BYTES {
        return Err(invalid("Soter request too large"));
    }
    let channels = CHANNELS
        .get()
        .ok_or_else(|| invalid("Soter companion unavailable"))?;
    let authorization = channels
        .auth
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !authorization.fresh || !authorization.last.uids.binary_search(&uid).is_ok() {
        return Err(invalid(
            "Soter authorization is stale or caller is not selected",
        ));
    }
    drop(authorization);
    // Do not fill SoterServer's Binder thread pool with callers waiting behind
    // a slow remote request. Unselected apps need those threads for stock work.
    let mut guard = match channels.calls.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::Poisoned(error)) => error.into_inner(),
        Err(TryLockError::WouldBlock) => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Soter relay is busy",
            ));
        }
    };
    let stream = guard
        .as_mut()
        .ok_or_else(|| invalid("Soter companion unavailable"))?;
    let mut request = Vec::with_capacity(bytes.len() + 8);
    request.extend_from_slice(&uid.to_be_bytes());
    request.extend_from_slice(&code.to_be_bytes());
    request.extend_from_slice(bytes);
    let result = write_frame(stream, &request)
        .and_then(|()| read_frame(stream, MAX_FRAME))
        .and_then(|raw| Reply::decode(&raw));
    if result.is_err() {
        *guard = None;
    }
    result
}

#[derive(Debug, PartialEq, Eq)]
struct Reply {
    code: i32,
    session: i64,
    data: Vec<u8>,
}

impl Reply {
    fn error(code: i32) -> Self {
        Self {
            code,
            session: 0,
            data: vec![],
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.data.len());
        bytes.extend_from_slice(&self.code.to_be_bytes());
        bytes.extend_from_slice(&self.session.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
    fn decode(raw: &[u8]) -> io::Result<Self> {
        if raw.len() < 12 || raw.len() > MAX_FRAME {
            return Err(invalid("invalid Soter reply"));
        }
        Ok(Self {
            code: i32::from_be_bytes(raw[..4].try_into().unwrap()),
            session: i64::from_be_bytes(raw[4..12].try_into().unwrap()),
            data: raw[12..].to_vec(),
        })
    }
    fn write_sdk(&self, code: u32, output: &mut impl wire::Writer) -> Result<(), i32> {
        output.int32(0)?;
        match code {
            1 | 4 | 5 | 7 => output.int32(self.code),
            2 | 6 | 10 | 11 => wire::buffer_reply(output, self.code, &self.data),
            3 | 8 => output.int32(i32::from(self.code == 0)),
            9 => {
                output.int32(1)?;
                output.int64(self.session)?;
                output.int32(self.code)
            }
            _ => Err(BAD_VALUE),
        }
    }
}

/// Called after the backward-compatible companion frame was sent. A short
/// handshake distinguishes Soter's retained channel from ordinary PIF readers.
pub(crate) fn companion(stream: &UnixStream) {
    let Ok(mut stream) = stream.try_clone() else {
        return;
    };
    let _ = std::thread::Builder::new()
        .name("omk-soter-relay".into())
        .spawn(move || {
            let result = serve(&mut stream);
            if result.is_err_and(|error| {
                !matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                )
            }) {
                super::log("Soter companion channel closed");
            }
        });
}

fn active_config() -> Result<remote::Config, String> {
    let config = remote::Config::load()?;
    if !config.app_enabled
        || !config.enabled
        || Path::new(GLOBAL_FLAG).exists()
        || Path::new(GLOBAL_MARKER).exists()
        || pif_common::soter::read().map_err(|error| error.to_string())?
    {
        return Err("per-app Soter relay is disabled or conflicts with another mode".into());
    }
    Ok(config)
}

fn current_selection_result() -> Result<Selection, String> {
    let config = remote::Config::load()?;
    if !config.app_enabled
        || !config.enabled
        || Path::new(GLOBAL_FLAG).exists()
        || Path::new(GLOBAL_MARKER).exists()
        || pif_common::soter::read().map_err(|error| error.to_string())?
    {
        return Ok(Selection::default());
    }
    remote::app_uids(&config).map(|uids| Selection { uids })
}

fn serve(stream: &mut UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(AUTH_TIMEOUT))?;
    stream.set_write_timeout(Some(AUTH_TIMEOUT))?;
    let mut header = [0; 9];
    stream.read_exact(&mut header)?;
    if &header[..8] != MAGIC || ![AUTH, CALL].contains(&header[8]) {
        return Err(invalid("invalid Soter handshake"));
    }
    stream.write_all(&[1])?;
    // A private channel can remain idle while the phone is asleep. Reads are
    // bounded by frame sizes, not by an arbitrary idle lifetime.
    stream.set_read_timeout(None)?;
    let mut sessions = Sessions::default();
    loop {
        if header[8] == AUTH {
            let mut op = [0];
            stream.read_exact(&mut op)?;
            if op != [AUTH] {
                return Err(invalid("invalid authorization query"));
            }
            // A read failure must not be represented as an empty authorization
            // list: that would silently route previously opted-in apps to stock.
            let selection = current_selection_result().map_err(io::Error::other)?;
            write_frame(
                stream,
                &serde_json::to_vec(&selection).map_err(io::Error::other)?,
            )?;
        } else {
            let frame = read_frame(stream, MAX_FRAME)?;
            if frame.len() < 8 {
                return Err(invalid("invalid Soter call"));
            }
            let uid = u32::from_be_bytes(frame[..4].try_into().unwrap());
            let code = u32::from_be_bytes(frame[4..8].try_into().unwrap());
            let response = sessions.answer(uid, code, &frame[8..]);
            write_frame(stream, &response.encode())?;
        }
    }
}

struct Session {
    uid: u32,
    remote: u64,
    config: remote::Config,
    opened: Instant,
}
#[derive(Default)]
struct Sessions {
    next: i64,
    entries: BTreeMap<i64, Session>,
}

impl Sessions {
    fn answer(&mut self, uid: u32, code: u32, bytes: &[u8]) -> Reply {
        let Ok(config) = active_config() else {
            return Reply::error(UNAVAILABLE);
        };
        if !remote::app_uids(&config).is_ok_and(|uids| uids.binary_search(&uid).is_ok()) {
            return Reply::error(UNAVAILABLE);
        }
        self.answer_with(&config, uid, code, bytes, |tx, request| {
            remote::forward_app(&config, uid, tx, request)
        })
    }

    fn answer_with(
        &mut self,
        config: &remote::Config,
        uid: u32,
        code: u32,
        bytes: &[u8],
        send: impl FnOnce(u32, &Request) -> Result<Outcome, String>,
    ) -> Reply {
        self.entries
            .retain(|_, entry| entry.opened.elapsed() < SESSION_TTL);
        let parsed = match wire::parse_remote_request(code, bytes) {
            Ok(value) => value,
            Err(error) => return Reply::error(error),
        };
        let request = match convert_request(uid, code, parsed) {
            Ok(value) => value,
            Err(error) => return Reply::error(error),
        };
        let (tx, mut request) = request;
        if let Request::Session(id) = request {
            let id = id as i64;
            let Some(entry) = self.entries.get(&id) else {
                return Reply::error(NO_SESSION);
            };
            if entry.uid != uid || entry.config != *config {
                return Reply::error(NO_SESSION);
            }
            let entry = self.entries.remove(&id).unwrap();
            request = Request::Session(entry.remote);
        }
        if code == 9 && self.entries.len() >= MAX_SESSIONS {
            return Reply::error(NO_SESSION);
        }
        let outcome = match send(tx, &request) {
            Ok(value) => value,
            Err(_) => return Reply::error(UNAVAILABLE),
        };
        match outcome {
            Outcome::Code(code) => Reply::error(code),
            Outcome::Buffer { code, data, .. } => Reply {
                code,
                data,
                session: 0,
            },
            Outcome::Init {
                code: status,
                session,
            } => {
                if code != 9 || status != 0 || session == 0 {
                    return Reply::error(if status == 0 { NO_SESSION } else { status });
                }
                self.next = match self.next.checked_add(1) {
                    Some(value) => value,
                    None => return Reply::error(NO_SESSION),
                };
                self.entries.insert(
                    self.next,
                    Session {
                        uid,
                        remote: session,
                        config: config.clone(),
                        opened: Instant::now(),
                    },
                );
                Reply {
                    code: 0,
                    session: self.next,
                    data: vec![],
                }
            }
            Outcome::Exception { .. } => Reply::error(UNAVAILABLE),
        }
    }
}

fn convert_request(uid: u32, code: u32, request: wire::Request) -> Result<(u32, Request), i32> {
    use dispatch::*;
    // Tencent SDK uses 0 as its default namespace argument. It is not caller
    // identity: always use the driver's real UID for the remote slot. Refuse
    // any other app's explicit nonzero UID instead of granting cross-app access.
    Ok(match (code, request) {
        (1 | 2 | 3 | 7, wire::Request::Uid(arg)) if arg == 0 || arg == uid => (
            match code {
                1 => TX_GENERATE_ASK,
                2 => TX_EXPORT_ASK,
                3 => TX_HAS_ASK,
                _ => TX_REMOVE_ALL_UID_KEY,
            },
            Request::Uid(uid),
        ),
        (4 | 5 | 6 | 8, wire::Request::Key(arg, Some(kname)))
            if (arg == 0 || arg == uid) && !kname.is_empty() =>
        {
            (
                match code {
                    4 => TX_GENERATE_AUTH,
                    5 => TX_REMOVE_AUTH,
                    6 => TX_EXPORT_AUTH,
                    _ => TX_HAS_AUTH,
                },
                Request::UidKey { uid, kname },
            )
        }
        (9, wire::Request::Init(arg, Some(kname), Some(challenge)))
            if (arg == 0 || arg == uid) && !kname.is_empty() && !challenge.is_empty() =>
        {
            (
                TX_INIT_SIGN,
                Request::InitSign {
                    uid,
                    kname,
                    challenge,
                },
            )
        }
        (10, wire::Request::Session(id)) if id > 0 => (TX_FINISH_SIGN, Request::Session(id as u64)),
        (11, wire::Request::None) => (TX_GET_DEVICE_ID, Request::None),
        _ => return Err(BAD_VALUE),
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::request_for;
    use super::*;

    #[test]
    fn maps_the_application_contract_without_confusing_hal_numbers() {
        for (sdk, hal) in [
            (1, 5),
            (2, 1),
            (3, 9),
            (4, 7),
            (5, 13),
            (6, 3),
            (7, 12),
            (8, 10),
            (9, 11),
            (10, 4),
            (11, 8),
        ] {
            let bytes = request_for(sdk, 10123, "key", "challenge", 91);
            let parsed = wire::parse_remote_request(sdk, &bytes).unwrap();
            assert_eq!(convert_request(10123, sdk, parsed).unwrap().0, hal);
        }
    }

    #[test]
    fn sdk_default_namespace_always_maps_to_the_authenticated_caller() {
        for code in 1..=9 {
            let bytes = request_for(code, 0, "key", "challenge", 0);
            let parsed = wire::parse_remote_request(code, &bytes).unwrap();
            let (_, request) = convert_request(1010123, code, parsed).unwrap();
            let uid = match request {
                Request::Uid(uid) | Request::UidKey { uid, .. } | Request::InitSign { uid, .. } => {
                    uid
                }
                _ => panic!("unexpected request for SDK code {code}"),
            };
            assert_eq!(uid, 1010123);
        }
    }

    #[test]
    fn refuses_a_spoofed_request_uid_and_extra_arguments_before_network() {
        for code in 1..=9 {
            let bytes = request_for(code, 10124, "key", "challenge", 1);
            let request = wire::parse_remote_request(code, &bytes).unwrap();
            assert!(convert_request(10123, code, request).is_err());
        }
        let mut bytes = request_for(3, 10123, "", "", 0);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(wire::parse_remote_request(3, &bytes).is_err());
    }

    #[test]
    fn session_is_owned_by_the_real_caller_and_configuration() {
        let config = remote::Config::default();
        let mut sessions = Sessions::default();
        let init = request_for(9, 10123, "key", "challenge", 0);
        let opened = sessions.answer_with(&config, 10123, 9, &init, |tx, _| {
            assert_eq!(tx, dispatch::TX_INIT_SIGN);
            Ok(Outcome::Init {
                code: 0,
                session: 999,
            })
        });
        assert_eq!(opened.code, 0);
        assert_ne!(opened.session, 999);
        let finish = request_for(10, 0, "", "", opened.session);
        let foreign = sessions.answer_with(&config, 10124, 10, &finish, |_, _| {
            panic!("foreign session reached network")
        });
        assert_eq!(foreign.code, NO_SESSION);
        let changed = remote::Config {
            device_id: "other-device".into(),
            ..config.clone()
        };
        assert_eq!(
            sessions
                .answer_with(&changed, 10123, 10, &finish, |_, _| panic!(
                    "changed configuration reached network"
                ))
                .code,
            NO_SESSION
        );
        let completed = sessions.answer_with(&config, 10123, 10, &finish, |tx, request| {
            assert_eq!(tx, dispatch::TX_FINISH_SIGN);
            assert_eq!(request, &Request::Session(999));
            Ok(Outcome::Buffer {
                code: 0,
                data: vec![7, 8],
                field: 0,
            })
        });
        assert_eq!(completed.data, [7, 8]);
        assert_eq!(
            sessions
                .answer_with(&config, 10123, 10, &finish, |_, _| panic!("session reused"))
                .code,
            NO_SESSION
        );
    }

    #[test]
    fn remote_failure_is_an_error_not_a_software_reply() {
        let mut sessions = Sessions::default();
        let request = request_for(2, 10123, "", "", 0);
        let reply = sessions.answer_with(&remote::Config::default(), 10123, 2, &request, |_, _| {
            Err("offline".into())
        });
        assert_eq!(reply, Reply::error(UNAVAILABLE));
        assert!(sessions.entries.is_empty());
    }

    #[test]
    fn private_channel_frames_are_bounded_and_preserve_raw_reply() {
        let original = Reply {
            code: -5,
            session: 51,
            data: vec![0, 1, 255],
        };
        assert_eq!(Reply::decode(&original.encode()).unwrap(), original);
        assert!(Reply::decode(&[0; 11]).is_err());
        assert!(
            read_frame(
                &mut (MAX_FRAME as u32 + 1).to_be_bytes().as_slice(),
                MAX_FRAME
            )
            .is_err()
        );
        assert!(parse_selection(br#"{"uids":[10123,10123]}"#).is_err());
        assert!(parse_selection(br#"{"uids":[1000]}"#).is_err());
        assert!(parse_selection(br#"{"uids":[10123,1010123]}"#).is_ok());
    }
}
