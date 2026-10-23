//! Optional SOTER relay behind the software TA's native HAL service.
//!
//! This configuration is deliberately separate from the KeyMint/Integrity
//! relay. A disabled relay never touches the network or the local SOTER ledger.
//! An enabled relay that fails must not fall back to the local ledger: that
//! would mix two different ASK/AuthKey identities in the same application slot.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Value};

use crate::dispatch::{self, Outcome, Request};

pub const CONFIG_PATH: &str = "/data/misc/keystore/omk/data/soterta/remote.conf";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_PACKAGE_TABLE_BYTES: u64 = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_RELAY_URL: &str = "http://110.40.170.96:10886";
const DEFAULT_RELAY_DEVICE_ID: &str = "device-b-c3f204aa";
const DEFAULT_RELAY_TOKEN: &str = "aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd";
static CLIENT: OnceLock<Mutex<Option<(bool, reqwest::blocking::Client)>>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_CONFIG_PATH: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(crate) fn config_path() -> std::borrow::Cow<'static, Path> {
    #[cfg(test)]
    if let Some(path) = TEST_CONFIG_PATH.with(|slot| slot.borrow().clone()) {
        return std::borrow::Cow::Owned(path);
    }
    std::borrow::Cow::Borrowed(Path::new(CONFIG_PATH))
}

#[cfg(test)]
pub(crate) struct TestConfigPath {
    previous: Option<PathBuf>,
    // A thread-local override must be restored on the thread that installed it.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
pub(crate) fn test_config_path(path: PathBuf) -> TestConfigPath {
    TestConfigPath {
        previous: TEST_CONFIG_PATH.with(|slot| slot.replace(Some(path))),
        _thread: std::marker::PhantomData,
    }
}

#[cfg(test)]
impl Drop for TestConfigPath {
    fn drop(&mut self) {
        TEST_CONFIG_PATH.with(|slot| slot.replace(self.previous.take()));
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub enabled: bool,
    pub url: String,
    pub token: String,
    pub device_id: String,
    pub tls_insecure: bool,
    pub uid_map: String,
    pub app_enabled: bool,
    pub app_targets: Vec<String>,
}

impl Config {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut config = Self::default();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err("invalid SOTER remote config line".to_string());
            };
            let value = value.trim();
            match key.trim() {
                // `enabled` is the legacy spelling used by older OMK
                // installations.  New WebUI saves use `remote_enabled` so
                // the local software-TA takeover switch can be independent.
                "enabled" | "remote_enabled" => config.enabled = parse_bool(value)?,
                "url" => config.url = value.to_string(),
                "token" => config.token = value.to_string(),
                "device_id" => config.device_id = value.to_string(),
                "tls_insecure" => config.tls_insecure = parse_bool(value)?,
                "uid_map" => config.uid_map = value.to_string(),
                "app_enabled" => config.app_enabled = parse_bool(value)?,
                "app_targets" => {
                    config.app_targets = serde_json::from_str(value)
                        .map_err(|_| "invalid Soter application targets")?;
                }
                _ => return Err("unknown SOTER remote config key".to_string()),
            }
        }
        pif_common::soter::validate_app_targets(&config.app_targets)?;
        if config.enabled {
            if config.url.is_empty() {
                config.url = DEFAULT_RELAY_URL.to_string();
            }
            if config.device_id.is_empty() {
                config.device_id = DEFAULT_RELAY_DEVICE_ID.to_string();
            }
            if config.token.is_empty() {
                config.token = DEFAULT_RELAY_TOKEN.to_string();
            }
            let url = reqwest::Url::parse(&config.url).map_err(|_| "invalid SOTER URL")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err("SOTER URL must be HTTP(S) without embedded credentials".to_string());
            }
            if config.token.is_empty() || config.device_id.is_empty() {
                return Err("SOTER token and device_id are required when enabled".to_string());
            }
            if [
                config.token.as_str(),
                config.device_id.as_str(),
                config.uid_map.as_str(),
            ]
            .iter()
            .any(|value| value.contains(['\r', '\n']))
            {
                return Err("SOTER remote config contains a newline".to_string());
            }
        }
        Ok(config)
    }

    pub fn load() -> Result<Self, String> {
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(config_path())
        {
            Ok(file) => {
                if !file
                    .metadata()
                    .map_err(|error| error.to_string())?
                    .is_file()
                {
                    return Err("Soter remote config is not a regular file".into());
                }
                let mut raw = String::new();
                file.take(32769)
                    .read_to_string(&mut raw)
                    .map_err(|error| error.to_string())?;
                if raw.len() > 32768 {
                    return Err("Soter remote config exceeds limit".into());
                }
                Self::parse(&raw)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("cannot read SOTER remote config: {error}")),
        }
    }
}

/// Resolve opt-ins in their exact Android user. Shared UIDs never grant access.
/// This is used only with a kernel-authenticated Binder sender, not a HAL UID argument.
pub fn app_uids(config: &Config) -> Result<Vec<u32>, String> {
    let mut table = String::new();
    std::fs::File::open("/data/system/packages.list")
        .and_then(|file| {
            file.take(MAX_PACKAGE_TABLE_BYTES + 1)
                .read_to_string(&mut table)
        })
        .map_err(|error| format!("cannot resolve Soter application selection: {error}"))?;
    if table.len() as u64 > MAX_PACKAGE_TABLE_BYTES {
        return Err("Android package table exceeds limit".into());
    }
    Ok(app_uids_in_table(config, &table))
}

fn app_uids_in_table(config: &Config, table: &str) -> Vec<u32> {
    let mut uids = Vec::new();
    for target in &config.app_targets {
        let Some((wanted, user)) = pif_common::soter::parse_app_target(target) else {
            continue;
        };
        let id = table.lines().find_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            (fields.next()? == wanted)
                .then(|| fields.next()?.parse::<u32>().ok())
                .flatten()
        });
        let Some(id) = id.filter(|id| (10000..20000).contains(id)) else {
            continue;
        };
        let Some(uid) = user
            .checked_mul(100000)
            .and_then(|base| base.checked_add(id))
        else {
            continue;
        };
        if package_in_table(table, uid) == Some(wanted) {
            uids.push(uid);
        }
    }
    uids.sort_unstable();
    uids.dedup();
    uids
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err("invalid SOTER remote boolean".to_string()),
    }
}

fn mapped_uid(uid: u32, mapping: &str) -> u32 {
    mapping
        .split([',', ';', ' '])
        .filter_map(|part| part.split_once('=').or_else(|| part.split_once(':')))
        .find_map(|(from, to)| {
            (from.trim().parse::<u32>().ok()? == uid)
                .then(|| to.trim().parse::<u32>().ok())
                .flatten()
        })
        .unwrap_or(uid)
}

// The HAL's Binder caller is SoterServer, not the application. Resolve only
// the argument UID as a best-effort hint, never as authenticated identity.
// Read the existing Android table without a cache or a persistent OMK copy so
// package installs/removals and UID reuse cannot leave a stale attribution.
fn package_for_uid(uid: u32) -> Option<String> {
    let mut table = String::new();
    std::fs::File::open("/data/system/packages.list")
        .ok()?
        .take(MAX_PACKAGE_TABLE_BYTES + 1)
        .read_to_string(&mut table)
        .ok()?;
    if table.len() as u64 > MAX_PACKAGE_TABLE_BYTES {
        return None;
    }
    package_in_table(&table, uid).map(str::to_owned)
}

fn package_in_table(table: &str, uid: u32) -> Option<&str> {
    // packages.list records app IDs shared by Android user profiles. System
    // and isolated UIDs cannot identify an installed application this way.
    let app_id = uid % 100_000;
    if !(10_000..20_000).contains(&app_id) {
        return None;
    }
    let mut found = None;
    for line in table.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(package), Some(id)) = (fields.next(), fields.next()) else {
            continue;
        };
        if id.parse::<u32>().ok() != Some(app_id) {
            continue;
        }
        if !package.contains('.')
            || !package
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
            || found.is_some_and(|previous| previous != package)
        {
            // A shared UID is ambiguous; do not guess a foreground app or
            // infer identity from a key alias supplied by the application.
            return None;
        }
        found = Some(package);
    }
    found
}

fn request_body(
    config: &Config,
    tx: u32,
    request: &Request,
    lookup_package: impl FnOnce(u32) -> Option<String>,
) -> Result<Value, String> {
    use dispatch::*;
    let op = match tx {
        TX_EXPORT_ASK => "export_ask_public_key",
        TX_EXPORT_AUTH => "export_auth_key_public_key",
        TX_FINISH_SIGN => "finish_sign",
        TX_GENERATE_ASK => "generate_ask_key_pair",
        TX_GENERATE_AUTH => "generate_auth_key_pair",
        TX_GET_DEVICE_ID => "get_device_id",
        TX_HAS_ASK => "has_ask_already",
        TX_HAS_AUTH => "has_auth_key",
        TX_INIT_SIGN => "init_sign",
        TX_REMOVE_ALL_UID_KEY => "remove_all_uid_key",
        TX_REMOVE_AUTH => "remove_auth_key",
        // The ATTK trio is this device's own factory key pair and has no relay
        // operation: the QTI B-side HAL exposes no verified ATTK, and `ffi`
        // answers these three codes from the local ledger before it ever
        // consults the relay. Reaching this point means the caller skipped that
        // split, so refuse instead of inventing a remote ATTK.
        TX_EXPORT_ATTK | TX_GENERATE_ATTK | TX_VERIFY_ATTK => {
            return Err("ATTK transactions are answered locally, not relayed".to_string())
        }
        _ => return Err("unknown SOTER transaction".to_string()),
    };
    let mut body = json!({"op": op, "device_id": config.device_id});
    match request {
        Request::None => {}
        Request::Uid(uid) => body["uid"] = json!(mapped_uid(*uid, &config.uid_map)),
        Request::UidKey { uid, kname } => {
            body["uid"] = json!(mapped_uid(*uid, &config.uid_map));
            body["alias"] = json!(kname);
        }
        Request::InitSign {
            uid,
            kname,
            challenge,
        } => {
            body["uid"] = json!(mapped_uid(*uid, &config.uid_map));
            body["alias"] = json!(kname);
            body["challenge"] = json!(challenge);
        }
        Request::Session(session) => {
            body["session"] = json!(*session as i64);
        }
        Request::Magic(_) => {
            return Err("ATTK transactions are answered locally, not relayed".to_string())
        }
    }
    let uid = match request {
        Request::Uid(uid) | Request::UidKey { uid, .. } | Request::InitSign { uid, .. } => {
            Some(*uid)
        }
        _ => None,
    };
    if let Some(package) = uid.and_then(lookup_package) {
        // Resolve the source UID, before the optional A-to-B UID mapping.
        // `arg` is required by the relay protocol: this is NOT a trusted
        // Binder caller and must not grant access to remote key material.
        body["caller_pkg"] = json!(package);
        body["caller_pkg_src"] = json!("arg");
    }
    Ok(body)
}

fn decode_reply(tx: u32, body: &Value) -> Result<Outcome, String> {
    if body.get("local_only").and_then(Value::as_bool) == Some(true) {
        return Err("SOTER relay declined remote handling; local fallback is disabled".to_string());
    }
    let code = body
        .get("error_code")
        .and_then(Value::as_i64)
        .and_then(|v| i32::try_from(v).ok())
        .ok_or("remote SOTER reply has no valid error_code")?;
    if tx == dispatch::TX_INIT_SIGN {
        let session = match body.get("session") {
            Some(value) => value
                .as_i64()
                .map(|value| value as u64)
                .ok_or("remote SOTER init_sign reply has no valid session")?,
            // Failed init_sign calls from the relay carry only the vendor
            // error code (for example -5 when the AuthKey is absent).  The
            // stock HAL uses session 0 in that case, so do not turn an
            // otherwise valid error reply into a transport failure merely
            // because there is no session field.
            None if code != 0 => 0,
            None => return Err("remote SOTER init_sign reply has no valid session".to_string()),
        };
        return Ok(Outcome::Init { code, session });
    }
    if tx == dispatch::TX_GET_DEVICE_ID {
        let payload = match body.get("data").and_then(Value::as_str) {
            Some(encoded) => base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "remote SOTER reply has invalid base64")?,
            None if code != 0 => Vec::new(),
            None => return Err("remote SOTER success reply is missing data".to_string()),
        };
        let data = device_id_bytes(&payload);
        return Ok(Outcome::Buffer {
            code,
            field: data.len() as i32,
            data,
        });
    }
    if matches!(
        tx,
        dispatch::TX_EXPORT_ASK | dispatch::TX_EXPORT_AUTH | dispatch::TX_FINISH_SIGN
    ) {
        let data = match body.get("data").and_then(Value::as_str) {
            Some(encoded) => base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "remote SOTER reply has invalid base64")?,
            None if code != 0 => Vec::new(),
            None => return Err("remote SOTER success reply is missing data".to_string()),
        };
        let field = body
            .get("length")
            .and_then(Value::as_i64)
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(data.len() as i32);
        return Ok(Outcome::Buffer { code, data, field });
    }
    Ok(Outcome::Code(code))
}

/// The relay answers `get_device_id` the way the Java face spells it: 32 ASCII
/// hex characters with a trailing NUL (captured from the public relay,
/// 2026-09-28: 33 bytes for `090000005171734c42866bea148b21f5`). This TA replaces
/// the HAL underneath that Java layer, and a live HAL answers the transaction
/// with the 16 raw bytes whose hex is that string - the same bytes
/// [`crate::state::TaState::device_id`] hands out locally, and the same hex
/// every blob carries as `cpu_id`. Handing the spelling up instead would let one
/// device report two different ids.
fn device_id_bytes(payload: &[u8]) -> Vec<u8> {
    let kept = payload
        .iter()
        .rev()
        .skip_while(|byte| **byte == 0 || byte.is_ascii_whitespace())
        .count();
    let trimmed = &payload[..kept];
    match std::str::from_utf8(trimmed) {
        Ok(text) if text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
            hex::decode(text).unwrap_or_else(|_| payload.to_vec())
        }
        _ => payload.to_vec(),
    }
}

fn http_client(tls_insecure: bool) -> Result<reqwest::blocking::Client, String> {
    let cache = CLIENT.get_or_init(|| Mutex::new(None));
    let mut slot = cache.lock().unwrap_or_else(|error| error.into_inner());
    if let Some((current, client)) = slot.as_ref() {
        if *current == tls_insecure {
            return Ok(client.clone());
        }
    }
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(REQUEST_TIMEOUT)
        // The relay token belongs only to the configured endpoint. In
        // particular, ASK confirmation probes must not follow redirects.
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(tls_insecure)
        .build()
        .map_err(|error| format!("SOTER client setup failed: {error}"))?;
    *slot = Some((tls_insecure, client.clone()));
    Ok(client)
}

pub fn forward(config: &Config, tx: u32, request: &Request) -> Result<Outcome, String> {
    let body = request_body(config, tx, request, package_for_uid).inspect_err(|_| {
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=request tx={tx} reason=unsupported_request");
    })?;
    forward_body(config, tx, &body)
}

/// The caller must be the privileged app-entry bridge carrying the Binder
/// driver's sender UID, never a UID parsed from a Soter method argument.
pub fn forward_app(
    config: &Config,
    caller_uid: u32,
    tx: u32,
    request: &Request,
) -> Result<Outcome, String> {
    let mut body = request_body(config, tx, request, package_for_uid).inspect_err(|_| {
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=request uid={caller_uid} tx={tx} reason=unsupported_request");
    })?;
    if let Some(package) = package_for_uid(caller_uid) {
        body["caller_uid"] = json!(caller_uid);
        body["caller_pkg"] = json!(package);
        body["caller_pkg_src"] = json!("binder");
    } else {
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=request uid={caller_uid} tx={tx} reason=caller_package_unresolved");
        return Err("Soter Binder caller no longer resolves to an application".into());
    }
    forward_body(config, tx, &body)
}

fn forward_body(config: &Config, tx: u32, body: &Value) -> Result<Outcome, String> {
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    forward_with_ask_confirmation(tx, body, |probe_tx, probe_body| {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or("SOTER relay deadline exceeded")
            .inspect_err(|_| {
                log::warn!(target: "omk_soter_remote",
                    "event=soter path=remote_transport stage=request tx={probe_tx} reason=deadline_exceeded");
            })?;
        send_request(config, probe_tx, probe_body, timeout)
    })
}

// A subset of real HALs returns -5 on repeated ASK creation. Treat it as an
// idempotent success only after two fresh, read-only confirmations from the
// same relay slot. A failed confirmation preserves the original vendor error;
// it never generates another key, deletes a key, or switches to local state.
fn forward_with_ask_confirmation(
    tx: u32,
    body: &Value,
    mut send: impl FnMut(u32, &Value) -> Result<Outcome, String>,
) -> Result<Outcome, String> {
    let outcome = send(tx, body)?;
    if tx != dispatch::TX_GENERATE_ASK || outcome != Outcome::Code(crate::error::SOTER_ERR_NO_KEY) {
        return Ok(outcome);
    }
    let Some(uid) = body
        .get("uid")
        .and_then(Value::as_u64)
        .and_then(|uid| u32::try_from(uid).ok())
    else {
        return Ok(outcome);
    };
    let mut probe = body.clone();
    log::info!(target: "omk_soter_remote",
        "event=soter path=remote_transport stage=ask_confirmation state=start tx={tx}");
    probe["op"] = json!("has_ask_already");
    if !matches!(send(dispatch::TX_HAS_ASK, &probe), Ok(Outcome::Code(0))) {
        log::info!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=ask_confirmation state=unconfirmed reason=has_ask_failed tx={tx}");
        return Ok(outcome);
    }
    probe["op"] = json!("export_ask_public_key");
    if let Ok(Outcome::Buffer {
        code: 0,
        data,
        field,
    }) = send(dispatch::TX_EXPORT_ASK, &probe)
    {
        if usable_ask_export(&data, field, uid) {
            log::info!(target: "omk_soter_remote",
                "event=soter path=remote_transport stage=ask_confirmation state=confirmed tx={tx}");
            return Ok(Outcome::Code(0));
        }
    }
    log::info!(target: "omk_soter_remote",
        "event=soter path=remote_transport stage=ask_confirmation state=unconfirmed reason=export_not_usable tx={tx}");
    Ok(outcome)
}

fn usable_ask_export(data: &[u8], field: i32, uid: u32) -> bool {
    // This checks the exported wire structure, not hardware provenance or
    // Tencent's trust in the signing ATTK (which this client cannot establish).
    if usize::try_from(field).ok() != Some(data.len()) || data.len() as u64 > MAX_RESPONSE_BYTES {
        return false;
    }
    let Some((json, signature)) = crate::blob::parse(data) else {
        return false;
    };
    if signature.len() != crate::blob::SIGNATURE_LEN {
        return false;
    }
    let Ok(document) = serde_json::from_slice::<Value>(json) else {
        return false;
    };
    if document.get("counter").and_then(Value::as_u64).is_none()
        || document.get("uid").and_then(Value::as_str) != Some(uid.to_string().as_str())
        || document
            .get("pub_key")
            .and_then(Value::as_str)
            .and_then(crate::blob::public_key_from_pem)
            .is_none()
    {
        return false;
    }
    document
        .get("cpu_id")
        .and_then(Value::as_str)
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

// reqwest error Display/Debug can contain the endpoint and query parameters.
// Only this closed set of category labels may be included in diagnostic logs.
fn transport_error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_builder() {
        "request_build"
    } else if error.is_redirect() {
        "redirect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_request() {
        "request"
    } else {
        "transport"
    }
}

fn send_request(
    config: &Config,
    tx: u32,
    body: &Value,
    timeout: Duration,
) -> Result<Outcome, String> {
    let started = Instant::now();
    log::info!(target: "omk_soter_remote",
        "event=soter path=remote_transport stage=http_start tx={tx}");
    let url = format!("{}/api/soter/", config.url.trim_end_matches('/'));
    let client = http_client(config.tls_insecure).inspect_err(|_| {
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=http_error tx={tx} reason=client_setup elapsed_ms={}",
            started.elapsed().as_millis());
    })?;
    let response = client
        .post(url)
        .header("X-Relay-Token", &config.token)
        .timeout(timeout)
        .json(body)
        .send()
        .map_err(|error| {
            log::warn!(target: "omk_soter_remote",
                "event=soter path=remote_transport stage=http_error tx={tx} reason={} elapsed_ms={}",
                transport_error_kind(&error), started.elapsed().as_millis());
            format!("SOTER relay transport failed: {error}")
        })?;
    let status = response.status().as_u16();
    if !response.status().is_success() {
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=http_error tx={tx} reason=http_status http_status={status} elapsed_ms={}",
            started.elapsed().as_millis());
        return Err(format!("SOTER relay returned HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            log::warn!(target: "omk_soter_remote",
                "event=soter path=remote_transport stage=http_error tx={tx} reason=response_read error_kind={:?} http_status={status} elapsed_ms={}",
                error.kind(), started.elapsed().as_millis());
            format!("SOTER relay read failed: {error}")
        })?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=http_error tx={tx} reason=response_too_large http_status={status} elapsed_ms={}",
            started.elapsed().as_millis());
        return Err("SOTER relay reply is too large".to_string());
    }
    let reply: Value = serde_json::from_slice(&bytes).map_err(|_| {
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=http_error tx={tx} reason=invalid_json http_status={status} elapsed_ms={}",
            started.elapsed().as_millis());
        "SOTER relay reply is not JSON".to_string()
    })?;
    if reply.get("error").is_some() {
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=http_error tx={tx} reason=relay_rejected http_status={status} elapsed_ms={}",
            started.elapsed().as_millis());
        return Err("SOTER relay could not serve this operation".to_string());
    }
    let outcome = decode_reply(tx, &reply).inspect_err(|_| {
        let reason = if reply.get("local_only").and_then(Value::as_bool) == Some(true) {
            "local_only_rejected"
        } else {
            "invalid_reply_contract"
        };
        log::warn!(target: "omk_soter_remote",
            "event=soter path=remote_transport stage=http_error tx={tx} reason={reason} http_status={status} elapsed_ms={}",
            started.elapsed().as_millis());
    })?;
    let code = match &outcome {
        Outcome::Code(code)
        | Outcome::Buffer { code, .. }
        | Outcome::Init { code, .. }
        | Outcome::Exception { code, .. } => *code,
    };
    log::info!(target: "omk_soter_remote",
        "event=soter path=remote_transport stage=http_reply tx={tx} http_status={status} result={code} bytes={} elapsed_ms={}",
        bytes.len(), started.elapsed().as_millis());
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn transport_diagnostic_category_does_not_expose_error_url() {
        let error = reqwest::blocking::Client::new()
            .get("http://[")
            .build()
            .unwrap_err()
            .with_url(
                reqwest::Url::parse("https://secret-endpoint.invalid/?token=secret-token").unwrap(),
            );
        assert_eq!(error.url().unwrap().query(), Some("token=secret-token"));
        assert_eq!(transport_error_kind(&error), "request_build");
    }
    fn ask_document(uid: u32) -> Value {
        // A public-only structural fixture; no private key or hardware trust
        // is involved in checking whether an exported ASK is well formed.
        let key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&[0xff; 256]),
            rsa::BigUint::from(65537u32),
        )
        .unwrap();
        json!({
            "pub_key": crate::blob::public_key_pem(&key).unwrap(),
            "cpu_id": "0123456789abcdef0123456789abcdef",
            "counter": 1,
            "uid": uid.to_string(),
        })
    }

    fn ask_export(document: &Value, signature_len: usize) -> Outcome {
        let data = crate::blob::encode(
            &serde_json::to_vec(document).unwrap(),
            &vec![1; signature_len],
        );
        Outcome::Buffer {
            code: 0,
            field: data.len() as i32,
            data,
        }
    }

    #[test]
    fn existing_ask_confirmation_is_read_only_and_keeps_the_same_slot() {
        let config = Config {
            device_id: "same-b".into(),
            uid_map: "10123=10456".into(),
            ..Config::default()
        };
        let body = request_body(
            &config,
            dispatch::TX_GENERATE_ASK,
            &Request::Uid(10123),
            |_| Some("com.example.wallet".into()),
        )
        .unwrap();
        let mut calls = Vec::new();
        let result =
            forward_with_ask_confirmation(dispatch::TX_GENERATE_ASK, &body, |tx, probe| {
                calls.push(tx);
                assert_eq!(probe["device_id"], "same-b");
                assert_eq!(probe["uid"], 10456);
                assert_eq!(probe["caller_pkg"], "com.example.wallet");
                assert_eq!(probe["caller_pkg_src"], "arg");
                match tx {
                    dispatch::TX_GENERATE_ASK => {
                        assert_eq!(probe["op"], "generate_ask_key_pair");
                        Ok(Outcome::Code(-5))
                    }
                    dispatch::TX_HAS_ASK => {
                        assert_eq!(probe["op"], "has_ask_already");
                        Ok(Outcome::Code(0))
                    }
                    dispatch::TX_EXPORT_ASK => {
                        assert_eq!(probe["op"], "export_ask_public_key");
                        Ok(ask_export(&ask_document(10456), crate::blob::SIGNATURE_LEN))
                    }
                    _ => panic!("confirmation must not mutate keys or sign"),
                }
            })
            .unwrap();
        assert_eq!(result, Outcome::Code(0));
        assert_eq!(
            calls,
            [
                dispatch::TX_GENERATE_ASK,
                dispatch::TX_HAS_ASK,
                dispatch::TX_EXPORT_ASK
            ]
        );
    }

    #[test]
    fn ask_confirmation_does_not_hide_vendor_or_transport_failures() {
        let body = json!({"op": "generate_ask_key_pair", "uid": 10123});
        for (tx, answer) in [
            (dispatch::TX_GENERATE_ASK, Ok(Outcome::Code(0))),
            (dispatch::TX_GENERATE_ASK, Ok(Outcome::Code(-20))),
            (dispatch::TX_GENERATE_ASK, Err("offline".to_string())),
            (dispatch::TX_GENERATE_AUTH, Ok(Outcome::Code(-5))),
            (dispatch::TX_HAS_ASK, Ok(Outcome::Code(-5))),
        ] {
            let mut count = 0;
            let result = forward_with_ask_confirmation(tx, &body, |_, _| {
                count += 1;
                answer.clone()
            });
            assert_eq!(result, answer);
            assert_eq!(count, 1);
        }
        for has_reply in [
            Ok(Outcome::Code(-5)),
            Ok(Outcome::Code(1)),
            Err("timeout".into()),
        ] {
            let mut calls = Vec::new();
            let result =
                forward_with_ask_confirmation(dispatch::TX_GENERATE_ASK, &body, |tx, _| {
                    calls.push(tx);
                    match tx {
                        dispatch::TX_GENERATE_ASK => Ok(Outcome::Code(-5)),
                        dispatch::TX_HAS_ASK => has_reply.clone(),
                        _ => panic!("absent ASK must not be exported"),
                    }
                })
                .unwrap();
            assert_eq!(result, Outcome::Code(-5));
            assert_eq!(calls, [dispatch::TX_GENERATE_ASK, dispatch::TX_HAS_ASK]);
        }
        for export_reply in [
            Err("offline".into()),
            Ok(Outcome::Buffer {
                code: -20,
                data: Vec::new(),
                field: 0,
            }),
            Ok(Outcome::Buffer {
                code: 0,
                data: vec![1, 2, 3],
                field: 3,
            }),
        ] {
            let result =
                forward_with_ask_confirmation(dispatch::TX_GENERATE_ASK, &body, |tx, _| match tx {
                    dispatch::TX_GENERATE_ASK => Ok(Outcome::Code(-5)),
                    dispatch::TX_HAS_ASK => Ok(Outcome::Code(0)),
                    dispatch::TX_EXPORT_ASK => export_reply.clone(),
                    _ => panic!("unexpected transaction"),
                })
                .unwrap();
            assert_eq!(result, Outcome::Code(-5));
        }
    }

    #[test]
    fn existing_ask_export_requires_a_complete_matching_key_document() {
        let valid = ask_document(10123);
        let validate = |document: &Value, tail: usize, length_delta: i32, uid: u32| {
            let Outcome::Buffer { data, field, .. } = ask_export(document, tail) else {
                unreachable!()
            };
            usable_ask_export(&data, field + length_delta, uid)
        };
        assert!(validate(&valid, 256, 0, 10123));
        assert!(!validate(&valid, 0, 0, 10123));
        assert!(!validate(&valid, 1, 0, 10123));
        assert!(!validate(&valid, 256, -1, 10123));
        assert!(!validate(&valid, 256, 0, 10456));
        assert!(!usable_ask_export(&[], 0, 10123));
        assert!(!usable_ask_export(&[0xff; 4], 4, 10123));
        let malformed_json = crate::blob::encode(b"not json", &[1; crate::blob::SIGNATURE_LEN]);
        assert!(!usable_ask_export(
            &malformed_json,
            malformed_json.len() as i32,
            10123
        ));
        for (field, value) in [
            ("pub_key", json!("not a public key")),
            ("cpu_id", json!("wrong-device-id")),
            ("counter", json!(-1)),
            ("uid", json!(10123)),
        ] {
            let mut malformed = valid.clone();
            malformed[field] = value;
            assert!(!validate(&malformed, 256, 0, 10123), "invalid {field}");
        }
        let oversized = ask_export(&valid, MAX_RESPONSE_BYTES as usize);
        let Outcome::Buffer { data, field, .. } = oversized else {
            unreachable!()
        };
        assert!(!usable_ask_export(&data, field, 10123));
    }

    #[test]
    fn relay_redirects_do_not_forward_the_token_to_another_endpoint() {
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let port = origin.local_addr().unwrap().port();
        let destination_port = destination.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = origin.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = [0u8; 4096];
            assert!(socket.read(&mut request).unwrap() > 0);
            socket.write_all(format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{destination_port}/other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ).as_bytes()).unwrap();
        });
        let config = Config {
            enabled: true,
            url: format!("http://127.0.0.1:{port}"),
            token: "fixture-only-token".into(),
            device_id: "fixture-b".into(),
            ..Config::default()
        };
        let error = forward(&config, dispatch::TX_HAS_ASK, &Request::Uid(10123)).unwrap_err();
        assert!(error.contains("HTTP 302"), "{error}");
        server.join().unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn package_hint_handles_profiles_missing_packages_and_shared_uids() {
        let table = "com.example.wallet 10123 0 /data/user/0/com.example.wallet default\n\
                     com.example.other 10456 0 /data/user/0/com.example.other default\n";
        assert_eq!(package_in_table(table, 10123), Some("com.example.wallet"));
        assert_eq!(package_in_table(table, 1010123), Some("com.example.wallet"));
        assert_eq!(package_in_table(table, 10999), None);
        assert_eq!(package_in_table("android 1000 0", 1000), None);
        assert_eq!(
            package_in_table("com.example.isolated 99001 0", 99001),
            None
        );
        assert_eq!(
            package_in_table("malformed\ncom.example.no_uid bad 0", 10123),
            None
        );
        assert_eq!(package_in_table("com.example/invalid 10123 0", 10123), None);
        let shared = format!("{table}com.example.shared 10123 0\n");
        assert_eq!(package_in_table(&shared, 10123), None);
        // A fresh table must not retain a previous package after UID reuse.
        assert_eq!(
            package_in_table("com.example.new 10123 0", 10123),
            Some("com.example.new")
        );
    }

    #[test]
    fn app_selection_is_empty_by_default_and_profile_specific() {
        let table = "com.example.wallet 10123 0\ncom.example.other 10124 0\n";
        assert!(app_uids_in_table(&Config::default(), table).is_empty());
        let config = Config {
            app_targets: vec!["com.example.wallet@10".into()],
            ..Config::default()
        };
        assert_eq!(app_uids_in_table(&config, table), [1010123]);
        assert!(app_uids_in_table(&config, "com.example.replacement 10123 0\n").is_empty());
        let shared = format!("{table}com.example.shared 10123 0\n");
        assert!(app_uids_in_table(&config, &shared).is_empty());
        let parsed =
            Config::parse("app_enabled=true\napp_targets=[\"com.example.wallet@10\"]").unwrap();
        assert!(parsed.app_enabled);
        assert!(!parsed.enabled);
        assert_eq!(parsed.app_targets, config.app_targets);
        assert!(Config::parse("app_targets=[\"com.example.wallet\"]").is_err());
    }

    #[test]
    fn package_hint_uses_unmapped_argument_uid_and_is_never_trusted() {
        let config = Config {
            uid_map: "10123=10456".into(),
            ..Config::default()
        };
        for (tx, request) in [
            (dispatch::TX_HAS_ASK, Request::Uid(10123)),
            (
                dispatch::TX_HAS_AUTH,
                Request::UidKey {
                    uid: 10123,
                    kname: "auth".into(),
                },
            ),
            (
                dispatch::TX_INIT_SIGN,
                Request::InitSign {
                    uid: 10123,
                    kname: "auth".into(),
                    challenge: "nonce".into(),
                },
            ),
        ] {
            let body = request_body(&config, tx, &request, |uid| {
                assert_eq!(uid, 10123);
                Some("com.example.wallet".into())
            })
            .unwrap();
            assert_eq!(body["uid"], 10456);
            assert_eq!(body["caller_pkg"], "com.example.wallet");
            assert_eq!(body["caller_pkg_src"], "arg");
            assert!(body.get("caller_uid").is_none());
        }
        let unknown = request_body(&config, dispatch::TX_HAS_ASK, &Request::Uid(10123), |_| {
            None
        })
        .unwrap();
        assert!(unknown.get("caller_pkg").is_none());
        assert!(unknown.get("caller_pkg_src").is_none());
        for (tx, request) in [
            (dispatch::TX_GET_DEVICE_ID, Request::None),
            (dispatch::TX_FINISH_SIGN, Request::Session(42)),
        ] {
            let body = request_body(&config, tx, &request, |_| {
                panic!("no application UID in this transaction")
            })
            .unwrap();
            assert!(body.get("caller_pkg").is_none());
        }
    }

    #[test]
    fn local_only_replies_never_become_remote_success() {
        for tx in [
            dispatch::TX_HAS_ASK,
            dispatch::TX_GENERATE_AUTH,
            dispatch::TX_INIT_SIGN,
            dispatch::TX_FINISH_SIGN,
        ] {
            assert!(decode_reply(
                tx,
                &json!({"local_only": true, "error_code": 0, "session": 42, "data": ""})
            )
            .is_err());
        }
        assert_eq!(
            decode_reply(
                dispatch::TX_HAS_ASK,
                &json!({"local_only": false, "error_code": -5})
            )
            .unwrap(),
            Outcome::Code(-5)
        );
    }

    #[test]
    fn config_fixture_is_thread_local_and_restores_the_previous_path() {
        let absent =
            std::env::temp_dir().join(format!("soterta-absent-config-{}", std::process::id()));
        let _outer = test_config_path(absent.clone());
        assert_eq!(Config::load().unwrap(), Config::default());
        let nested = absent.with_extension("nested");
        {
            let _inner = test_config_path(nested.clone());
            assert_eq!(config_path().as_ref(), nested.as_path());
            assert_eq!(
                std::thread::spawn(|| config_path().into_owned())
                    .join()
                    .unwrap(),
                PathBuf::from(CONFIG_PATH)
            );
        }
        assert_eq!(config_path().as_ref(), absent.as_path());
        assert_eq!(Config::load().unwrap(), Config::default());
    }

    #[test]
    fn separate_config_is_off_by_default_and_uid_map_is_explicit() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        let defaults = Config::parse("enabled=true").unwrap();
        assert_eq!(defaults.url, DEFAULT_RELAY_URL);
        assert_eq!(defaults.device_id, DEFAULT_RELAY_DEVICE_ID);
        assert_eq!(defaults.token, DEFAULT_RELAY_TOKEN);
        for fields in 0..=7 {
            let raw = format!(
                "enabled=true\nurl={}\ndevice_id={}\ntoken={}",
                if fields & 1 != 0 {
                    DEFAULT_RELAY_URL
                } else {
                    ""
                },
                if fields & 2 != 0 {
                    DEFAULT_RELAY_DEVICE_ID
                } else {
                    ""
                },
                if fields & 4 != 0 {
                    DEFAULT_RELAY_TOKEN
                } else {
                    ""
                },
            );
            assert!(Config::parse(&raw).unwrap() == defaults);
        }
        let custom_url = Config::parse("enabled=true\nurl=https://custom.example.test").unwrap();
        assert_eq!(custom_url.url, "https://custom.example.test");
        assert_eq!(custom_url.device_id, DEFAULT_RELAY_DEVICE_ID);
        assert_eq!(custom_url.token, DEFAULT_RELAY_TOKEN);
        let cfg = Config::parse(
            "enabled=true\nurl=https://example.test\ntoken=soter-only\ndevice_id=synthetic-b\nuid_map=10001=10002",
        )
        .unwrap();
        assert_eq!(cfg.device_id, "synthetic-b");
        assert_eq!(mapped_uid(10001, &cfg.uid_map), 10002);
        assert_eq!(mapped_uid(20001, &cfg.uid_map), 20001);
        let split = Config::parse("remote_enabled=true").unwrap();
        assert!(split.enabled);
        assert_eq!(split.url, DEFAULT_RELAY_URL);
        let body = request_body(
            &cfg,
            dispatch::TX_INIT_SIGN,
            &Request::InitSign {
                uid: 10001,
                kname: "AuthKey".into(),
                challenge: "nonce".into(),
            },
            |_| None,
        )
        .unwrap();
        assert_eq!(body["uid"], 10002);
        assert_eq!(body["device_id"], "synthetic-b");
        assert_eq!(body["challenge"], "nonce");
    }

    #[test]
    fn remote_reply_preserves_session_and_negative_vendor_status() {
        assert_eq!(
            decode_reply(
                dispatch::TX_INIT_SIGN,
                &json!({"error_code": 0, "session": 42}),
            )
            .unwrap(),
            Outcome::Init {
                code: 0,
                session: 42
            }
        );
        assert_eq!(
            decode_reply(
                dispatch::TX_FINISH_SIGN,
                &json!({"error_code": -26, "data": "", "length": 0}),
            )
            .unwrap(),
            Outcome::Buffer {
                code: -26,
                data: Vec::new(),
                field: 0,
            }
        );
        assert_eq!(
            decode_reply(dispatch::TX_INIT_SIGN, &json!({"error_code": -5}),).unwrap(),
            Outcome::Init {
                code: -5,
                session: 0,
            }
        );
        assert!(decode_reply(dispatch::TX_INIT_SIGN, &json!({"error_code": 0})).is_err());
        // The ATTK trio is answered from the local ledger (ffi never forwards
        // it), so the relay mapping must not invent a remote ATTK operation.
        assert!(request_body(
            &Config::default(),
            dispatch::TX_EXPORT_ATTK,
            &Request::None,
            |_| None
        )
        .is_err());
        assert!(request_body(
            &Config::default(),
            dispatch::TX_VERIFY_ATTK,
            &Request::None,
            |_| None
        )
        .is_err());
        let signed = decode_reply(
            dispatch::TX_INIT_SIGN,
            &json!({"error_code": 0, "session": -2}),
        )
        .unwrap();
        assert_eq!(
            signed,
            Outcome::Init {
                code: 0,
                session: (-2i64) as u64
            }
        );
    }

    #[test]
    fn the_relayed_device_id_is_handed_up_as_the_raw_hal_bytes() {
        // The relay spells the id the way the Java face does: 32 hex characters
        // plus a NUL, base64-wrapped (public relay capture, 2026-09-28).
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(b"090000005171734c42866bea148b21f5\0");
        assert_eq!(
            decode_reply(
                dispatch::TX_GET_DEVICE_ID,
                &json!({
                    "error_code": 0,
                    "data": encoded,
                    "length": 33,
                    "text": "090000005171734c42866bea148b21f5"
                }),
            )
            .unwrap(),
            Outcome::Buffer {
                code: 0,
                data: hex::decode("090000005171734c42866bea148b21f5").unwrap(),
                field: 16,
            }
        );
        // A reply that already carries raw bytes is passed through untouched.
        let raw = base64::engine::general_purpose::STANDARD.encode([0x0au8, 0xff, 0x00]);
        assert_eq!(
            decode_reply(
                dispatch::TX_GET_DEVICE_ID,
                &json!({"error_code": 0, "data": raw, "length": 3}),
            )
            .unwrap(),
            Outcome::Buffer {
                code: 0,
                data: vec![0x0a, 0xff, 0x00],
                field: 3,
            }
        );
    }

    #[test]
    fn forwards_to_the_soter_server_with_its_own_token_and_device() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let count = socket.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&request[..end]);
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|v| v.parse::<usize>().ok())
                        })
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let answer = br#"{"op":"init_sign","error_code":0,"session":42}"#;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        answer.len()
                    )
                    .as_bytes(),
                )
                .unwrap();
            socket.write_all(answer).unwrap();
            String::from_utf8(request).unwrap()
        });
        let config = Config {
            enabled: true,
            url: format!("http://127.0.0.1:{port}"),
            token: "soter-token".into(),
            device_id: "soter-b".into(),
            uid_map: "10001=10002".into(),
            ..Config::default()
        };
        let outcome = forward(
            &config,
            dispatch::TX_INIT_SIGN,
            &Request::InitSign {
                uid: 10001,
                kname: "AuthKey".into(),
                challenge: "nonce".into(),
            },
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome::Init {
                code: 0,
                session: 42
            }
        );
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /api/soter/ HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("x-relay-token: soter-token"));
        assert!(request.contains("\"device_id\":\"soter-b\""));
        assert!(request.contains("\"uid\":10002"));
    }
}
