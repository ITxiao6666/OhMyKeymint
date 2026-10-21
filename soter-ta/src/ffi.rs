//! Shared Soter runtime and its retained C ABI compatibility entry points.
//!
//! The Rust Binder daemon uses the safe `initialize`, `answer` and `save`
//! functions. The ABI wrappers share exactly the same routing and persistence.

use std::ffi::{c_char, CStr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::dispatch::{self, Outcome, Request};
use crate::platform::{self, Platform};
use crate::remote;
use crate::state::TaState;

/// Reply kinds, mirrored by `SOTERTA_KIND_*` in the daemon.
pub const SOTERTA_KIND_CODE: i32 = 0;
pub const SOTERTA_KIND_BUFFER: i32 = 1;
pub const SOTERTA_KIND_INIT: i32 = 2;

/// `soterta_handle` and `soterta_dead_reply` results.
pub const SOTERTA_HANDLED: i32 = 0;
pub const SOTERTA_UNHANDLED: i32 = 1;
pub const SOTERTA_ERROR: i32 = -1;

/// One reply, mirrored by `struct soterta_reply` in the daemon.
///
/// `buffer` is allocated here and released by [`soterta_free`].
#[repr(C)]
pub struct SotertaReply {
    pub kind: i32,
    pub code: i32,
    pub field: i32,
    pub session: i64,
    pub buffer: *mut u8,
    pub buffer_len: usize,
}

impl SotertaReply {
    fn empty() -> Self {
        Self {
            kind: SOTERTA_KIND_CODE,
            code: 0,
            field: 0,
            session: 0,
            buffer: std::ptr::null_mut(),
            buffer_len: 0,
        }
    }
}

/// The ledger plus where it is persisted.
struct Shared {
    path: PathBuf,
    state: TaState,
}

static SHARED: Mutex<Option<Shared>> = Mutex::new(None);
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
/// A missing config after remote mode was active must not silently switch the
/// native HAL to a different local key identity.
static REMOTE_WAS_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Lock a global, ignoring poisoning: a panic in one transaction must not turn
/// every later transaction into a failure while the daemon keeps serving.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn set_error(message: impl Into<String>) {
    *lock(&LAST_ERROR) = Some(message.into());
}

fn clear_error() {
    *lock(&LAST_ERROR) = None;
}

/// Read a C string argument; `None` for a null pointer or invalid UTF-8.
///
/// # Safety
///
/// `pointer` must be null or point to a NUL-terminated string.
unsafe fn c_string(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    CStr::from_ptr(pointer).to_str().ok().map(str::to_owned)
}

/// Hand a reply buffer to the caller, to be released by [`soterta_free`].
fn leak_buffer(data: Vec<u8>) -> (*mut u8, usize) {
    let mut boxed = data.into_boxed_slice();
    let pointer = boxed.as_mut_ptr();
    let len = boxed.len();
    std::mem::forget(boxed);
    (pointer, len)
}

fn reclaim_buffer(pointer: *mut u8, len: usize) {
    if pointer.is_null() {
        return;
    }
    // `into_boxed_slice` shrinks to fit, so the capacity equals the length.
    drop(unsafe { Vec::from_raw_parts(pointer, len, len) });
}

fn fill(reply: &mut SotertaReply, outcome: Outcome) {
    match outcome {
        Outcome::Code(code) => {
            reply.kind = SOTERTA_KIND_CODE;
            reply.code = code;
        }
        Outcome::Buffer { code, data, field } => {
            reply.kind = SOTERTA_KIND_BUFFER;
            reply.code = code;
            reply.field = field;
            if !data.is_empty() {
                let (pointer, len) = leak_buffer(data);
                reply.buffer = pointer;
                reply.buffer_len = len;
            }
        }
        Outcome::Init { code, session } => {
            reply.kind = SOTERTA_KIND_INIT;
            reply.code = code;
            reply.session = session as i64;
        }
        Outcome::Exception { code, message } => {
            // `handle_request` never answers with an exception: a malformed
            // request is answered by the daemon itself, which owns the parcel.
            reply.kind = SOTERTA_KIND_CODE;
            reply.code = code;
            set_error(format!("unexpected exception outcome: {message}"));
        }
    }
}

pub fn save() -> Result<(), String> {
    let mut slot = lock(&SHARED);
    let Some(shared) = slot.as_mut() else {
        return Err("state is not initialized".to_string());
    };
    shared
        .state
        .store(&shared.path)
        .map_err(|error| error.to_string())
}

fn create_state_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Map parsed arguments onto the request shape `tx` expects.
///
/// `Ok(None)` means the transaction is not this TA's; `Err` means an argument
/// that the transaction needs was absent from the request.
fn request_for(
    tx: u32,
    uid: u32,
    kname: Option<String>,
    challenge: Option<String>,
    session: i64,
) -> Result<Option<Request>, String> {
    let needs_key = matches!(
        tx,
        dispatch::TX_GENERATE_AUTH
            | dispatch::TX_HAS_AUTH
            | dispatch::TX_EXPORT_AUTH
            | dispatch::TX_REMOVE_AUTH
            | dispatch::TX_INIT_SIGN
    );
    if needs_key && kname.is_none() {
        return Err(format!("transaction {tx} carried no key name"));
    }
    if tx == dispatch::TX_INIT_SIGN && challenge.is_none() {
        return Err(format!("transaction {tx} carried no challenge"));
    }
    Ok(match tx {
        dispatch::TX_GET_DEVICE_ID => Some(Request::None),
        dispatch::TX_HAS_ASK
        | dispatch::TX_GENERATE_ASK
        | dispatch::TX_EXPORT_ASK
        | dispatch::TX_REMOVE_ALL_UID_KEY => Some(Request::Uid(uid)),
        dispatch::TX_GENERATE_AUTH
        | dispatch::TX_HAS_AUTH
        | dispatch::TX_EXPORT_AUTH
        | dispatch::TX_REMOVE_AUTH => Some(Request::UidKey {
            uid,
            kname: kname.unwrap_or_default(),
        }),
        dispatch::TX_INIT_SIGN => Some(Request::InitSign {
            uid,
            kname: kname.unwrap_or_default(),
            challenge: challenge.unwrap_or_default(),
        }),
        dispatch::TX_FINISH_SIGN => Some(Request::Session(session as u64)),
        // The daemon does not read the byte `generateAttkKeyPair` carries; the
        // answer does not depend on it.
        dispatch::TX_GENERATE_ATTK => Some(Request::Magic(0)),
        dispatch::TX_EXPORT_ATTK | dispatch::TX_VERIFY_ATTK => Some(Request::None),
        _ => None,
    })
}

/// Load the ledger, or create a fresh one, and remember where it lives.
///
/// Returns `0` when an existing state was loaded, `1` when a new one was
/// generated and persisted, and a negative value on failure (see
/// [`soterta_last_error`]). A state file that exists but cannot be read is a
/// failure, never a new identity: the previous revision is restored when it can
/// be, and the daemon refuses to start when it cannot.
///
/// # Safety
///
/// `state_path` must be null or a NUL-terminated path.
#[no_mangle]
pub unsafe extern "C" fn soterta_init(state_path: *const c_char) -> i32 {
    let Some(path) = c_string(state_path) else {
        set_error("state path is missing");
        return SOTERTA_ERROR;
    };
    match initialize(Path::new(&path)) {
        Ok(created) => i32::from(created),
        Err(error) => {
            set_error(error);
            SOTERTA_ERROR
        }
    }
}

/// Load the existing local ledger, or create it at the configured state path.
pub fn initialize(path: &Path) -> Result<bool, String> {
    let path = path.to_path_buf();
    if let Some(parent) = path.parent() {
        if let Err(error) = create_state_dir(parent) {
            return Err(format!("cannot create {}: {error}", parent.display()));
        }
    }
    let (state, created) = match TaState::load_or_error(&path) {
        Ok(Some(state)) => (state, false),
        Ok(None) => match TaState::generate_local() {
            Some(state) => (state, true),
            None => {
                return Err("cannot generate a local device key".into());
            }
        },
        Err(message) => {
            // An identity file that exists but cannot be read is not a fresh
            // device: minting a new one here would silently change the device id
            // (and with it every blob a client may still hold). Refuse instead.
            return Err(message);
        }
    };
    if created {
        if let Err(error) = state.store(&path) {
            return Err(format!("cannot write {}: {error}", path.display()));
        }
    }
    *lock(&SHARED) = Some(Shared { path, state });
    REMOTE_WAS_ACTIVE.store(false, Ordering::Release);
    clear_error();
    Ok(created)
}

/// Install the daemon's platform hooks.
///
/// `boot_ms` answers milliseconds on a boot-monotone clock and `bio_mark` the
/// fingerprint evidence mark. A missing bio hook explicitly disables the gate;
/// an installed bio hook whose evidence or clock cannot be read refuses local
/// signing with `-26`, including when a probe returns a negative value.
#[no_mangle]
pub extern "C" fn soterta_set_platform(
    boot_ms: Option<platform::Probe>,
    bio_mark: Option<platform::Probe>,
) {
    platform::install(boot_ms, bio_mark);
}

/// Answer one transaction from arguments the daemon has already parsed.
///
/// Returns [`SOTERTA_HANDLED`] with `reply` filled in, [`SOTERTA_UNHANDLED`] when
/// the transaction is not this TA's, or [`SOTERTA_ERROR`] when an argument is
/// missing or no state was loaded.
///
/// # Safety
///
/// `kname` and `challenge` must be null or NUL-terminated strings, and `reply`
/// must point to a writable [`SotertaReply`].
#[no_mangle]
pub unsafe extern "C" fn soterta_handle(
    tx: u32,
    uid: u32,
    kname: *const c_char,
    challenge: *const c_char,
    session: i64,
    reply: *mut SotertaReply,
) -> i32 {
    if reply.is_null() {
        set_error("reply slot is null");
        return SOTERTA_ERROR;
    }
    *reply = SotertaReply::empty();
    let request = match request_for(tx, uid, c_string(kname), c_string(challenge), session) {
        Ok(Some(request)) => request,
        Ok(None) => return SOTERTA_UNHANDLED,
        Err(message) => {
            set_error(message);
            return SOTERTA_ERROR;
        }
    };
    match answer(tx, request) {
        Ok(Some(outcome)) => {
            fill(&mut *reply, outcome);
            SOTERTA_HANDLED
        }
        Ok(None) => SOTERTA_UNHANDLED,
        Err(error) => {
            set_error(error);
            SOTERTA_ERROR
        }
    }
}

/// Dispatch parsed Rust arguments through the existing local/relay selection.
pub fn answer(tx: u32, request: Request) -> Result<Option<Outcome>, String> {
    if lock(&SHARED).is_none() {
        return Err("state is not initialized".into());
    }
    let remote_config = remote::Config::load();
    let relay_active = match &remote_config {
        Ok(config) if config.enabled => {
            REMOTE_WAS_ACTIVE.store(true, Ordering::Release);
            true
        }
        Ok(_) if remote::config_path().is_file() => {
            REMOTE_WAS_ACTIVE.store(false, Ordering::Release);
            false
        }
        Ok(_) => REMOTE_WAS_ACTIVE.load(Ordering::Acquire),
        Err(_) => true,
    };
    // The ATTK trio is this device's own factory key pair, not a relayed
    // operation: the relay protocol has no ATTK operation (the QTI B-side HAL
    // exposes no verified ATTK), while the vendor engineering-mode key check
    // reads `verifyAttkKeyPair` on *this* device through cryptoeng. Answer those
    // three codes from the local ledger even while the relay is active, so the
    // engineering mode sees a present device key instead of a relayed failure.
    let use_remote = relays(relay_active, tx);
    if use_remote {
        let answer = match remote_config {
            Ok(config) if config.enabled => remote::forward(&config, tx, &request),
            Ok(_) => Err("SOTER remote config disappeared while active".to_string()),
            Err(error) => Err(error),
        };
        let outcome = match answer {
            Ok(outcome) => {
                clear_error();
                outcome
            }
            Err(error) => {
                log::warn!("Soter relay request failed; local fallback is disabled");
                set_error(error);
                let Some(dead) = dispatch::dead_reply(tx) else {
                    return Ok(None);
                };
                dead
            }
        };
        return Ok(Some(outcome));
    }
    // The sign transactions read the platform before the ledger lock is taken:
    // the hooks spawn a platform dump, and that must not stall every other
    // transaction the daemon serves.
    let platform = if dispatch::consults_platform(tx) {
        let Some(snapshot) = platform::current() else {
            // An enabled but unreadable fingerprint gate is not permission to
            // sign. Refuse without creating/consuming a local sign session.
            let code = crate::error::SOTER_ERR_NO_FINGERPRINT;
            return Ok(match tx {
                dispatch::TX_INIT_SIGN => Some(Outcome::Init { code, session: 0 }),
                dispatch::TX_FINISH_SIGN => Some(Outcome::Buffer {
                    code,
                    data: Vec::new(),
                    field: 0,
                }),
                _ => None,
            });
        };
        snapshot
    } else {
        Platform::default()
    };
    let outcome = {
        let mut slot = lock(&SHARED);
        let Some(shared) = slot.as_mut() else {
            return Err("state is not initialized".into());
        };
        dispatch::handle_request(&mut shared.state, tx, request, platform)
    };
    let Some(outcome) = outcome else {
        return Ok(None);
    };
    if let Err(error) = save() {
        // Do not hand out material the ledger cannot keep: a device id or a
        // signature that does not survive a restart would be worse than none.
        return Err(format!("cannot persist state: {error}"));
    }
    clear_error();
    Ok(Some(outcome))
}

/// The answer the stock HAL gives for `tx` while its TA is dead.
///
/// Returns [`SOTERTA_HANDLED`] with `reply` filled in, or [`SOTERTA_UNHANDLED`]
/// for a code that is not part of this interface.
///
/// # Safety
///
/// `reply` must point to a writable [`SotertaReply`].
#[no_mangle]
pub unsafe extern "C" fn soterta_dead_reply(tx: u32, reply: *mut SotertaReply) -> i32 {
    if reply.is_null() {
        set_error("reply slot is null");
        return SOTERTA_ERROR;
    }
    *reply = SotertaReply::empty();
    match dispatch::dead_reply(tx) {
        Some(outcome) => {
            fill(&mut *reply, outcome);
            clear_error();
            SOTERTA_HANDLED
        }
        None => SOTERTA_UNHANDLED,
    }
}

/// Persist the ledger now; the daemon calls this before it exits.
#[no_mangle]
pub extern "C" fn soterta_save() -> i32 {
    match save() {
        Ok(()) => {
            clear_error();
            SOTERTA_HANDLED
        }
        Err(error) => {
            set_error(error);
            SOTERTA_ERROR
        }
    }
}

/// Release the buffer [`soterta_handle`] allocated and clear the reply.
///
/// # Safety
///
/// `reply` must be null or point to a reply this module filled in.
#[no_mangle]
pub unsafe extern "C" fn soterta_free(reply: *mut SotertaReply) {
    if reply.is_null() {
        return;
    }
    reclaim_buffer((*reply).buffer, (*reply).buffer_len);
    *reply = SotertaReply::empty();
}

/// Copy the last error message into `buffer` and return its length, or `-1`.
///
/// # Safety
///
/// `buffer` must be writable for `capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn soterta_last_error(buffer: *mut c_char, capacity: i32) -> i32 {
    if buffer.is_null() || capacity <= 0 {
        return -1;
    }
    let message = lock(&LAST_ERROR).clone().unwrap_or_default();
    let bytes = message.as_bytes();
    let limit = (capacity as usize).saturating_sub(1).min(bytes.len());
    std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), buffer, limit);
    *buffer.add(limit) = 0;
    limit as i32
}

/// Whether `tx` goes to the relay instead of the local ledger.
///
/// The ATTK trio stays local even while the relay is on: it is this device's own
/// factory key pair, the relay protocol has no ATTK operation (the QTI B-side
/// HAL exposes no verified ATTK), and the vendor engineering-mode key check
/// reads `verifyAttkKeyPair` on this device through cryptoeng. Routing those
/// three codes to a relay whose protocol cannot carry them is what left the
/// engineering-mode SOTER key red while the software TA was otherwise live.
fn relays(relay_active: bool, tx: u32) -> bool {
    relay_active && !dispatch::ATTK_TRANSACTIONS.contains(&tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_never_takes_the_attk_trio_off_device() {
        for tx in dispatch::ATTK_TRANSACTIONS {
            assert!(!relays(true, tx), "ATTK tx {tx} must stay local");
            assert!(!relays(false, tx));
        }
        for tx in [
            dispatch::TX_EXPORT_ASK,
            dispatch::TX_GET_DEVICE_ID,
            dispatch::TX_FINISH_SIGN,
        ] {
            assert!(relays(true, tx));
            assert!(!relays(false, tx));
        }
    }
}
