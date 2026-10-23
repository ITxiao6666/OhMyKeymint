//! Private, inherited channels between the native SoterServer hook and its root
//! broker. Tokens, package discovery and HTTPS remain outside the Android app.
//! There is no filesystem socket, Zygisk companion, local TA, or SDK emulation.

use crate::{
    dispatch::{self, Outcome, Request},
    remote,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

const MAX_FRAME: usize = 4 * 1024 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_secs(2);
const CALL_TIMEOUT: Duration = Duration::from_secs(25);
const UNAVAILABLE: i32 = -20;
const NO_SESSION: i32 = -1000;
const SESSION_TTL: Duration = Duration::from_secs(120);
// Process-local diagnostic state only: never retain credentials or write a file.
static LAST_GATE: Mutex<&'static str> = Mutex::new("");

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    uids: Vec<u32>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Call {
    uid: u32,
    tx: u32,
    request: Request,
}
struct Authorization {
    selection: Selection,
    fresh: bool,
}

/// Diagnostic metadata only. No free-form strings or request contents can cross
/// this logging channel, even if the injected host supplies a malformed event.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum NativeReason {
    NoSdkScope,
    UnsupportedCaller,
    NotSelected,
    UnsupportedShape,
    UnsupportedTx,
    DecodeFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Observation {
    Sdk {
        uid: i32,
        wire_tx: u32,
        oneway: bool,
        eligible: bool,
        selected: bool,
    },
    Native {
        uid: Option<u32>,
        wire_tx: u32,
        contract: crate::hal::Contract,
        reason: NativeReason,
    },
    HalReply {
        uid: u32,
        wire_tx: u32,
        tx: u32,
        contract: crate::hal::Contract,
        code: i32,
        elapsed_ms: u64,
    },
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observations {
    events: [Option<Observation>; 32],
    dropped: u64,
}

#[derive(Default)]
struct Diagnostics {
    pending: Mutex<Observations>,
    dropped: AtomicU64,
}

impl Diagnostics {
    fn observe(&self, event: Observation) {
        if let Ok(mut pending) = self.pending.try_lock() {
            if let Some(slot) = pending.events.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(event);
                return;
            }
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn take(&self) -> Observations {
        let mut events =
            std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
        events.dropped = self.dropped.swap(0, Ordering::Relaxed);
        events
    }
}

impl Observations {
    fn publish(&self) {
        for event in self.events.iter().flatten() {
            match event {
                Observation::Sdk {
                    uid,
                    wire_tx,
                    oneway,
                    eligible,
                    selected,
                } => {
                    log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=sdk uid={uid} wire_tx={wire_tx} oneway={oneway} eligible={eligible} selected={selected}");
                }
                Observation::Native {
                    uid,
                    wire_tx,
                    contract,
                    reason,
                } => {
                    let route = if matches!(reason, NativeReason::DecodeFailed) {
                        "error"
                    } else {
                        "native"
                    };
                    log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=route uid={uid:?} hal={contract:?} wire_tx={wire_tx} route={route} reason={reason:?}");
                }
                Observation::HalReply {
                    uid,
                    wire_tx,
                    tx,
                    contract,
                    code,
                    elapsed_ms,
                } => {
                    log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=hal_reply uid={uid} hal={contract:?} wire_tx={wire_tx} tx={tx} result={code} elapsed_ms={elapsed_ms}");
                }
            }
        }
        if self.dropped != 0 {
            log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=observe dropped={}", self.dropped);
        }
    }
}

pub struct Client {
    authorization: Arc<Mutex<Authorization>>,
    calls: Mutex<Option<UnixStream>>,
    diagnostics: Arc<Diagnostics>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut impl Read) -> io::Result<T> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size > MAX_FRAME {
        return Err(invalid("SOTER frame exceeds limit"));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid SOTER frame"))
}
fn write_frame<T: Serialize>(stream: &mut impl Write, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_FRAME {
        return Err(invalid("SOTER frame exceeds limit"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)
}
fn timeout(stream: &UnixStream, duration: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(duration))?;
    stream.set_write_timeout(Some(duration))
}

impl Client {
    pub fn new(mut auth: UnixStream, calls: UnixStream) -> io::Result<Self> {
        timeout(&auth, AUTH_TIMEOUT)?;
        timeout(&calls, CALL_TIMEOUT)?;
        let selection = query_selection(&mut auth, None).inspect_err(|error| {
            log::warn!(target: "omk_soter_remote",
                "event=soter path=native_remote stage=authorization state=unavailable reason={:?} action=initialization_failed",
                error.kind());
        })?;
        log::info!(target: "omk_soter_remote",
            "event=soter path=native_remote stage=authorization state=ready selected_uids={}",
            selection.uids.len());
        let authorization = Arc::new(Mutex::new(Authorization {
            selection,
            fresh: true,
        }));
        let snapshot = Arc::downgrade(&authorization);
        let diagnostics = Arc::new(Diagnostics::default());
        let pending = Arc::clone(&diagnostics);
        std::thread::Builder::new()
            .name("omk-soter-auth".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(750));
                let Some(snapshot) = snapshot.upgrade() else {
                    return;
                };
                let events = pending.take();
                match query_selection(&mut auth, Some(&events)) {
                    Ok(selection) => {
                        let mut current = snapshot.lock().unwrap_or_else(|e| e.into_inner());
                        if current.selection.uids != selection.uids {
                            log::info!(target: "omk_soter_remote",
                                "event=soter path=native_remote stage=authorization state=changed selected_uids={}",
                                selection.uids.len());
                        }
                        *current = Authorization {
                            selection,
                            fresh: true,
                        }
                    }
                    Err(error) => {
                        snapshot.lock().unwrap_or_else(|e| e.into_inner()).fresh = false;
                        log::warn!(target: "omk_soter_remote",
                            "event=soter path=native_remote stage=authorization state=unavailable reason={:?} action=fail_closed",
                            error.kind());
                        return;
                    }
                }
            })?;
        Ok(Self {
            authorization,
            calls: Mutex::new(Some(calls)),
            diagnostics,
        })
    }

    pub fn observe(&self, event: Observation) {
        self.diagnostics.observe(event);
    }

    pub fn selected(&self, uid: u32) -> bool {
        self.authorization
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .selection
            .uids
            .binary_search(&uid)
            .is_ok()
    }

    pub fn forward(&self, uid: u32, tx: u32, request: Request) -> Outcome {
        let authorization = self.authorization.lock().unwrap_or_else(|e| e.into_inner());
        if !authorization.fresh || authorization.selection.uids.binary_search(&uid).is_err() {
            let reason = if authorization.fresh {
                "uid_not_selected"
            } else {
                "stale_authorization"
            };
            log::warn!(target: "omk_soter_remote",
                "event=soter path=native_remote stage=broker_call uid={uid} tx={tx} reason={reason} result={UNAVAILABLE}");
            return Outcome::Code(UNAVAILABLE);
        }
        drop(authorization);
        // A slow remote TEE must not queue every Binder worker behind a mutex.
        let Ok(mut channels) = self.calls.try_lock() else {
            log::warn!(target: "omk_soter_remote",
                "event=soter path=native_remote stage=broker_call uid={uid} tx={tx} reason=busy result={UNAVAILABLE}");
            return Outcome::Code(UNAVAILABLE);
        };
        let Some(stream) = channels.as_mut() else {
            log::warn!(target: "omk_soter_remote",
                "event=soter path=native_remote stage=broker_call uid={uid} tx={tx} reason=channel_closed result={UNAVAILABLE}");
            return Outcome::Code(UNAVAILABLE);
        };
        match write_frame(stream, &Call { uid, tx, request })
            .and_then(|()| read_frame::<Outcome>(stream))
        {
            Ok(outcome) => outcome,
            Err(error) => {
                *channels = None;
                log::warn!(target: "omk_soter_remote",
                    "event=soter path=native_remote stage=broker_call uid={uid} tx={tx} reason={:?} result={UNAVAILABLE}",
                    error.kind());
                Outcome::Code(UNAVAILABLE)
            }
        }
    }
}

fn query_selection(
    stream: &mut UnixStream,
    observations: Option<&Observations>,
) -> io::Result<Selection> {
    if let Some(events) = observations
        .filter(|events| events.dropped != 0 || events.events.iter().any(Option::is_some))
    {
        stream.write_all(&[2])?;
        write_frame(stream, events)?;
    } else {
        stream.write_all(&[1])?;
    }
    let selection: Selection = read_frame(stream)?;
    if selection.uids.len() > pif_common::soter::MAX_APP_TARGETS
        || selection
            .uids
            .iter()
            .any(|uid| !(10000..20000).contains(&(uid % 100000)))
        || selection.uids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("invalid SOTER UID selection"));
    }
    Ok(selection)
}

fn log_gate(reason: &'static str) {
    let mut previous = LAST_GATE.lock().unwrap_or_else(|error| error.into_inner());
    if *previous != reason {
        log::info!(target: "omk_soter_remote",
            "event=soter path=native_remote stage=config reason={reason}");
        *previous = reason;
    }
}

pub fn active_config() -> Result<Option<remote::Config>, String> {
    let config = remote::Config::load().inspect_err(|_| log_gate("config_unreadable"))?;
    let beta_enabled = if config.app_enabled && config.enabled {
        pif_common::soter::read()
            .inspect_err(|_| log_gate("beta_config_unreadable"))
            .map_err(|e| e.to_string())?
    } else {
        false
    };
    let reason = active_config_reason(&config, beta_enabled);
    log_gate(reason);
    Ok((reason == "ready").then_some(config))
}

fn active_config_reason(config: &remote::Config, beta_enabled: bool) -> &'static str {
    if !config.app_enabled {
        "app_mode_disabled"
    } else if !config.enabled {
        "relay_disabled"
    } else if beta_enabled {
        "tencent_beta_enabled"
    } else {
        "ready"
    }
}

/// Both streams are socketpairs created by root and handed to the exact host
/// through ptrace. There is deliberately no public listener or caller UID field
/// accepted from arbitrary processes.
pub fn serve(mut auth: UnixStream, mut calls: UnixStream) -> io::Result<()> {
    auth.set_write_timeout(Some(AUTH_TIMEOUT))?;
    calls.set_write_timeout(Some(CALL_TIMEOUT))?;
    std::thread::Builder::new()
        .name("omk-soter-allow".into())
        .spawn(move || {
            let mut last_selection = None;
            let mut run = || -> io::Result<()> {
                loop {
                    let mut op = [0];
                    auth.read_exact(&mut op)?;
                    let observations = if op == [2] {
                        Some(read_frame::<Observations>(&mut auth)?)
                    } else if op != [1] {
                        return Err(invalid("invalid SOTER authorization query"));
                    } else { None };
                    // A read error closes the channel; an empty list means disabled,
                    // not a failed read that would silently switch calls to stock.
                    let config = active_config().map_err(io::Error::other)?;
                    let uids = match config {
                        Some(config) => remote::app_uids(&config)
                            .inspect_err(|_| {
                                log::warn!(target: "omk_soter_remote",
                                    "event=soter path=native_remote stage=authorization reason=package_resolution_failed");
                            })
                            .map_err(io::Error::other)?,
                        None => Vec::new(),
                    };
                    if last_selection.as_ref() != Some(&uids) {
                        log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=selection selected_uids={}", uids.len());
                        last_selection = Some(uids.clone());
                    }
                    write_frame(&mut auth, &Selection { uids })?;
                    // Reply first: file logging must not delay this authorization
                    // response. The Binder worker only enqueues metadata in memory.
                    if let Some(events) = observations { events.publish(); }
                }
            };
            if let Err(error) = run() {
                log::info!(target: "omk_soter_remote",
                    "event=soter path=native_remote stage=authorization_channel state=closed reason={:?}",
                    error.kind());
            }
        })?;
    std::thread::Builder::new()
        .name("omk-soter-relay".into())
        .spawn(move || {
            let mut sessions = Sessions::default();
            loop {
                let call = match read_frame::<Call>(&mut calls) {
                    Ok(call) => call,
                    Err(error) => {
                        log::info!(target: "omk_soter_remote",
                            "event=soter path=native_remote stage=call_channel state=closed reason={:?}",
                            error.kind());
                        break;
                    }
                };
                let uid = call.uid;
                let tx = call.tx;
                let started = Instant::now();
                log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=broker_start uid={uid} tx={tx}");
                let response = match active_config() {
                    Ok(Some(config)) => match remote::app_uids(&config) {
                        Ok(uids) if uids.binary_search(&uid).is_ok() => {
                            sessions.answer(&config, call, |uid, tx, request| {
                                remote::forward_app(&config, uid, tx, request)
                            })
                        }
                        selection => {
                            let reason = if selection.is_err() { "package_resolution_failed" } else { "uid_not_selected" };
                            log::warn!(target: "omk_soter_remote",
                                "event=soter path=native_remote stage=broker_authorize uid={uid} tx={tx} reason={reason} result={UNAVAILABLE}");
                            Outcome::Code(UNAVAILABLE)
                        }
                    },
                    _ => {
                        log::warn!(target: "omk_soter_remote",
                            "event=soter path=native_remote stage=broker_authorize uid={uid} tx={tx} reason=config_inactive result={UNAVAILABLE}");
                        Outcome::Code(UNAVAILABLE)
                    }
                };
                let code = match &response {
                    Outcome::Code(code) | Outcome::Buffer { code, .. } | Outcome::Init { code, .. } | Outcome::Exception { code, .. } => *code,
                };
                log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=broker_reply uid={uid} tx={tx} result={code} elapsed_ms={}", started.elapsed().as_millis());
                if let Err(error) = write_frame(&mut calls, &response) {
                    log::warn!(target: "omk_soter_remote",
                        "event=soter path=native_remote stage=broker_reply uid={uid} tx={tx} reason={:?}",
                        error.kind());
                    break;
                }
            }
        })?;
    Ok(())
}

struct Session {
    uid: u32,
    remote: u64,
    config: remote::Config,
    opened: Instant,
}
#[derive(Default)]
struct Sessions {
    next: u64,
    entries: BTreeMap<u64, Session>,
}

impl Sessions {
    fn answer(
        &mut self,
        config: &remote::Config,
        call: Call,
        send: impl FnOnce(u32, u32, &Request) -> Result<Outcome, String>,
    ) -> Outcome {
        self.entries
            .retain(|_, entry| entry.opened.elapsed() < SESSION_TTL);
        let Call {
            uid,
            tx,
            mut request,
        } = call;
        if !dispatch::handles(tx) || dispatch::ATTK_TRANSACTIONS.contains(&tx) {
            log::warn!(target: "omk_soter_remote",
                "event=soter path=native_remote stage=session uid={uid} tx={tx} reason=unsupported_transaction result=-22");
            return Outcome::Code(-22);
        }
        match &mut request {
            Request::Uid(arg)
            | Request::UidKey { uid: arg, .. }
            | Request::InitSign { uid: arg, .. } => {
                if *arg != 0 && *arg != uid {
                    log::warn!(target: "omk_soter_remote",
                        "event=soter path=native_remote stage=session uid={uid} tx={tx} reason=uid_argument_mismatch result=-22");
                    return Outcome::Code(-22);
                }
                *arg = uid;
            }
            Request::Session(id) if tx == dispatch::TX_FINISH_SIGN => {
                let Some(entry) = self.entries.get(id) else {
                    log::warn!(target: "omk_soter_remote",
                        "event=soter path=native_remote stage=session uid={uid} tx={tx} reason=missing_or_expired result={NO_SESSION}");
                    return Outcome::Code(NO_SESSION);
                };
                if entry.uid != uid || entry.config != *config {
                    log::warn!(target: "omk_soter_remote",
                        "event=soter path=native_remote stage=session uid={uid} tx={tx} reason=owner_or_config_mismatch result={NO_SESSION}");
                    return Outcome::Code(NO_SESSION);
                }
                *id = self.entries.remove(id).unwrap().remote;
            }
            Request::None if tx == dispatch::TX_GET_DEVICE_ID => {}
            _ => {
                log::warn!(target: "omk_soter_remote",
                    "event=soter path=native_remote stage=session uid={uid} tx={tx} reason=invalid_request_shape result=-22");
                return Outcome::Code(-22);
            }
        }
        if tx == dispatch::TX_INIT_SIGN && self.entries.len() >= 64 {
            log::warn!(target: "omk_soter_remote",
                "event=soter path=native_remote stage=session uid={uid} tx={tx} reason=capacity result={NO_SESSION}");
            return Outcome::Code(NO_SESSION);
        }
        let outcome = match send(uid, tx, &request) {
            Ok(outcome) => outcome,
            Err(_) => {
                log::warn!(target: "omk_soter_remote",
                    "event=soter path=native_remote stage=forward uid={uid} tx={tx} reason=remote_request_failed result={UNAVAILABLE}");
                return Outcome::Code(UNAVAILABLE);
            }
        };
        if let Outcome::Init { code: 0, session } = outcome {
            if tx != dispatch::TX_INIT_SIGN || session == 0 {
                log::warn!(target: "omk_soter_remote",
                    "event=soter path=native_remote stage=session uid={uid} tx={tx} reason=invalid_remote_session result={NO_SESSION}");
                return Outcome::Code(NO_SESSION);
            }
            self.next = match self.next.checked_add(1) {
                Some(id) if id <= i64::MAX as u64 => id,
                _ => {
                    log::warn!(target: "omk_soter_remote",
                        "event=soter path=native_remote stage=session uid={uid} tx={tx} reason=id_exhausted result={NO_SESSION}");
                    return Outcome::Code(NO_SESSION);
                }
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
            Outcome::Init {
                code: 0,
                session: self.next,
            }
        } else {
            outcome
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_relay_stays_active_with_global_takeover_and_remote_relay_enabled() {
        let config = remote::Config {
            enabled: true,
            app_enabled: true,
            ..remote::Config::default()
        };
        assert_eq!(active_config_reason(&config, false), "ready");
        assert_eq!(active_config_reason(&config, true), "tencent_beta_enabled");
    }

    #[test]
    fn observation_queue_is_bounded_nonblocking_and_drops_only_diagnostics() {
        let diagnostics = Diagnostics::default();
        let event = Observation::Sdk {
            uid: 10123,
            wire_tx: 5,
            oneway: false,
            eligible: true,
            selected: true,
        };
        for _ in 0..40 {
            diagnostics.observe(event);
        }
        let events = diagnostics.take();
        assert_eq!(events.events.iter().flatten().count(), 32);
        assert_eq!(events.dropped, 8);
        let held = diagnostics.pending.lock().unwrap();
        diagnostics.observe(event); // Must not wait on the background collector.
        drop(held);
        let events = diagnostics.take();
        assert_eq!(events.dropped, 1);
        assert!(events.events.iter().all(Option::is_none));
        assert_eq!(diagnostics.take().dropped, 0);
    }

    #[test]
    fn observations_reject_free_form_data_and_do_not_replace_selection() {
        assert!(serde_json::from_str::<Observation>(r#"{"Sdk":{"uid":10123,"wire_tx":5,"oneway":false,"eligible":true,"selected":true,"token":"secret"}}"#).is_err());
        let oversized =
            serde_json::json!({"events": vec![serde_json::Value::Null; 33], "dropped": 0});
        assert!(serde_json::from_value::<Observations>(oversized).is_err());
        let (mut client, mut server) = UnixStream::pair().unwrap();
        timeout(&client, AUTH_TIMEOUT).unwrap();
        timeout(&server, AUTH_TIMEOUT).unwrap();
        let server = std::thread::spawn(move || {
            let mut op = [0];
            server.read_exact(&mut op).unwrap();
            assert_eq!(op, [2]);
            let events: Observations = read_frame(&mut server).unwrap();
            assert!(matches!(
                events.events[0],
                Some(Observation::Native {
                    reason: NativeReason::NoSdkScope,
                    ..
                })
            ));
            write_frame(&mut server, &Selection { uids: vec![10123] }).unwrap();
            server.read_exact(&mut op).unwrap();
            assert_eq!(op, [1]);
            write_frame(&mut server, &Selection::default()).unwrap();
        });
        let mut events = Observations::default();
        events.events[0] = Some(Observation::Native {
            uid: None,
            wire_tx: 5,
            contract: crate::hal::Contract::Qti,
            reason: NativeReason::NoSdkScope,
        });
        assert_eq!(
            query_selection(&mut client, Some(&events)).unwrap().uids,
            vec![10123]
        );
        assert!(query_selection(&mut client, Some(&Observations::default()))
            .unwrap()
            .uids
            .is_empty());
        server.join().unwrap();
    }

    #[test]
    fn frames_are_bounded_and_no_secret_or_local_reply_is_created() {
        assert!(read_frame::<Call>(&mut (MAX_FRAME as u32 + 1).to_be_bytes().as_slice()).is_err());
        let call = Call {
            uid: 10123,
            tx: 5,
            request: Request::Uid(0),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &call).unwrap();
        let decoded: Call = read_frame(&mut bytes.as_slice()).unwrap();
        let answer =
            Sessions::default().answer(&remote::Config::default(), decoded, |uid, tx, request| {
                assert_eq!((uid, tx), (10123, 5));
                assert_eq!(request, &Request::Uid(10123));
                Err("offline".into())
            });
        assert_eq!(answer, Outcome::Code(UNAVAILABLE));
    }
    #[test]
    fn sessions_are_bound_to_caller_and_destination() {
        let mut sessions = Sessions::default();
        let config = remote::Config::default();
        let opened = sessions.answer(
            &config,
            Call {
                uid: 10123,
                tx: 11,
                request: Request::InitSign {
                    uid: 0,
                    kname: "key".into(),
                    challenge: "challenge".into(),
                },
            },
            |_, _, _| {
                Ok(Outcome::Init {
                    code: 0,
                    session: 999,
                })
            },
        );
        let Outcome::Init { session, .. } = opened else {
            panic!("init failed")
        };
        for uid in [10124, 1010123] {
            assert_eq!(
                sessions.answer(
                    &config,
                    Call {
                        uid,
                        tx: 4,
                        request: Request::Session(session)
                    },
                    |_, _, _| panic!("foreign call")
                ),
                Outcome::Code(NO_SESSION)
            );
        }
        let changed = remote::Config {
            device_id: "changed".into(),
            ..config.clone()
        };
        assert_eq!(
            sessions.answer(
                &changed,
                Call {
                    uid: 10123,
                    tx: 4,
                    request: Request::Session(session)
                },
                |_, _, _| panic!("wrong server")
            ),
            Outcome::Code(NO_SESSION)
        );
        let finish = sessions.answer(
            &config,
            Call {
                uid: 10123,
                tx: 4,
                request: Request::Session(session),
            },
            |_, _, request| {
                assert_eq!(*request, Request::Session(999));
                Ok(Outcome::Code(0))
            },
        );
        assert_eq!(finish, Outcome::Code(0));
        assert!(sessions.entries.is_empty());
    }
}
