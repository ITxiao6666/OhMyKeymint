//! Private, inherited channels between the native SoterServer hook and its root
//! local identity broker. Package discovery and private keys remain outside the
//! Android app. There is no filesystem socket, remote relay, or SDK emulation.

use crate::{
    dispatch::{Outcome, Request},
    identities,
};
use serde::{Deserialize, Serialize};
use std::{
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
// Process-local diagnostic state only: never retain credentials or write a file.

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
                Observation::Sdk { uid, wire_tx, oneway, eligible, selected } => {
                    log::info!(target: "omk_soter_local", "event=soter path=native_local stage=sdk uid={uid} wire_tx={wire_tx} oneway={oneway} eligible={eligible} selected={selected}");
                }
                Observation::Native { uid, wire_tx, contract, reason } => {
                    let route = if matches!(reason, NativeReason::DecodeFailed) {
                        "error"
                    } else {
                        "native"
                    };
                    log::info!(target: "omk_soter_local", "event=soter path=native_local stage=route uid={uid:?} hal={contract:?} wire_tx={wire_tx} route={route} reason={reason:?}");
                }
                Observation::HalReply { uid, wire_tx, tx, contract, code, elapsed_ms } => {
                    log::info!(target: "omk_soter_local", "event=soter path=native_local stage=hal_reply uid={uid} hal={contract:?} wire_tx={wire_tx} tx={tx} result={code} elapsed_ms={elapsed_ms}");
                }
            }
        }
        if self.dropped != 0 {
            log::info!(target: "omk_soter_local", "event=soter path=native_local stage=observe dropped={}", self.dropped);
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
            log::warn!(target: "omk_soter_local",
                "event=soter path=native_local stage=authorization state=unavailable reason={:?} action=initialization_failed",
                error.kind());
        })?;
        log::info!(target: "omk_soter_local",
            "event=soter path=native_local stage=authorization state=ready selected_uids={}",
            selection.uids.len());
        let authorization = Arc::new(Mutex::new(Authorization { selection, fresh: true }));
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
                            log::info!(target: "omk_soter_local",
                                "event=soter path=native_local stage=authorization state=changed selected_uids={}",
                                selection.uids.len());
                        }
                        *current = Authorization {
                            selection,
                            fresh: true,
                        }
                    }
                    Err(error) => {
                        snapshot.lock().unwrap_or_else(|e| e.into_inner()).fresh = false;
                        log::warn!(target: "omk_soter_local",
                            "event=soter path=native_local stage=authorization state=unavailable reason={:?} action=fail_closed",
                            error.kind());
                        return;
                    }
                }
            })?;
        Ok(Self { authorization, calls: Mutex::new(Some(calls)), diagnostics })
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
            let reason =
                if authorization.fresh { "uid_not_selected" } else { "stale_authorization" };
            log::warn!(target: "omk_soter_local",
                "event=soter path=native_local stage=broker_call uid={uid} tx={tx} reason={reason} result={UNAVAILABLE}");
            return Outcome::Code(UNAVAILABLE);
        }
        drop(authorization);
        // Local key generation must not queue every Binder worker behind a mutex.
        let Ok(mut channels) = self.calls.try_lock() else {
            log::warn!(target: "omk_soter_local",
                "event=soter path=native_local stage=broker_call uid={uid} tx={tx} reason=busy result={UNAVAILABLE}");
            return Outcome::Code(UNAVAILABLE);
        };
        let Some(stream) = channels.as_mut() else {
            log::warn!(target: "omk_soter_local",
                "event=soter path=native_local stage=broker_call uid={uid} tx={tx} reason=channel_closed result={UNAVAILABLE}");
            return Outcome::Code(UNAVAILABLE);
        };
        match write_frame(stream, &Call { uid, tx, request })
            .and_then(|()| read_frame::<Outcome>(stream))
        {
            Ok(outcome) => outcome,
            Err(error) => {
                *channels = None;
                log::warn!(target: "omk_soter_local",
                    "event=soter path=native_local stage=broker_call uid={uid} tx={tx} reason={:?} result={UNAVAILABLE}",
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
    if selection.uids.len() > 512
        || selection.uids.iter().any(|uid| !(10000..20000).contains(&(uid % 100000)))
        || selection.uids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("invalid SOTER UID selection"));
    }
    Ok(selection)
}

pub fn active_config() -> Result<Option<identities::Config>, String> {
    let config = identities::load()?;
    Ok((config.enabled && !config.apps.is_empty()).then_some(config))
}

/// Private root-created channels handed only to the exact SoterServer process.
pub fn serve(mut auth: UnixStream, mut calls: UnixStream) -> io::Result<()> {
    auth.set_write_timeout(Some(AUTH_TIMEOUT))?;
    calls.set_write_timeout(Some(CALL_TIMEOUT))?;
    std::thread::Builder::new().name("omk-soter-allow".into()).spawn(move || {
        let mut run = || -> io::Result<()> {
            loop {
                let mut op = [0];
                auth.read_exact(&mut op)?;
                let observations = if op == [2] {
                    Some(read_frame::<Observations>(&mut auth)?)
                } else if op == [1] {
                    None
                } else {
                    return Err(invalid("Invalid SOTER authorization request"));
                };
                let config = identities::load().map_err(io::Error::other)?;
                let uids = identities::app_uids(&config).map_err(io::Error::other)?;
                write_frame(&mut auth, &Selection { uids })?;
                if let Some(events) = observations {
                    events.publish();
                }
            }
        };
        if let Err(error) = run() {
            log::info!("SOTER authorization channel closed: {:?}", error.kind());
        }
    })?;
    std::thread::Builder::new().name("omk-soter-local".into()).spawn(move || {
        while let Ok(call) = read_frame::<Call>(&mut calls) {
            let uid = call.uid;
            let tx = call.tx;
            let started = Instant::now();
            let outcome = identities::answer(uid, tx, call.request).unwrap_or_else(|error| {
                log::warn!("Local SOTER uid={uid} tx={tx} refused: {error}");
                Outcome::Code(UNAVAILABLE)
            });
            let code = match &outcome {
                Outcome::Code(code)
                | Outcome::Buffer { code, .. }
                | Outcome::Init { code, .. }
                | Outcome::Exception { code, .. } => *code,
            };
            log::info!(
                "event=soter path=local uid={uid} tx={tx} result={code} elapsed_ms={}",
                started.elapsed().as_millis()
            );
            if write_frame(&mut calls, &outcome).is_err() {
                break;
            }
        }
    })?;
    Ok(())
}
