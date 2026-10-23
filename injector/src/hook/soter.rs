//! Native SoterServer -> vendor HAL forwarding. The Tencent SDK request and
//! response are never replaced. No KeyMint routing or Beta fixture is used.
use super::{
    binder::*,
    intercept::{
        copy_process_buffer, copy_process_value, copy_to_process, native_pending, native_read,
        native_submission, synchronize_binder_fd_generation, write_process_value, BinderIoctlGuard,
    },
    BinderStateKey, OLD_IOCTL,
};
use soter_ta::{
    bridge::{Client, NativeReason, Observation},
    dispatch::{Outcome, MAX_REQUEST_BYTES},
    hal::{self, Contract, OwnedReply},
};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    ffi::c_void,
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock, Mutex, RwLock,
    },
    time::Instant,
};

type Ioctl = unsafe extern "C" fn(i32, i32, *mut c_void) -> i32;
static ENABLED: AtomicBool = AtomicBool::new(false);
static CLIENT: RwLock<Option<Arc<Client>>> = RwLock::new(None);
static REPLIES: LazyLock<Mutex<HashMap<(BinderStateKey, usize), OwnedReply>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const MAX_IO: usize = 1024 * 1024;
const BR_REPLY: u32 = 0x8040_7203;

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn initialize(auth: UnixStream, calls: UnixStream) -> anyhow::Result<()> {
    let client = Client::new(auth, calls)?;
    *CLIENT.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(client));
    ENABLED.store(true, Ordering::Release);
    super::install::init_soter_hooks()?;
    log::info!(target: "omk_soter_remote", "event=soter path=native_remote stage=hook state=ready independent_of_beta=true");
    Ok(())
}

#[derive(Clone, Copy)]
struct Scope {
    connection: BinderStateKey,
    uid: Option<u32>,
    oneway: bool,
    id: u64,
}
struct Synthetic {
    scope: u64,
    events: VecDeque<Vec<u8>>,
}
#[derive(Default)]
struct Connection {
    synthetic: VecDeque<Synthetic>,
    pending: Option<Copyback>,
}
#[derive(Default)]
struct State {
    scopes: Vec<Scope>,
    next_scope: u64,
    connections: HashMap<BinderStateKey, Connection>,
}
struct Copyback {
    arg: usize,
    original: binder_write_read,
    output: binder_write_read,
    read: Vec<u8>,
    ret: i32,
    errno: i32,
    freed: Vec<usize>,
}
thread_local! { static STATE: RefCell<State> = RefCell::default(); }

pub fn reset_thread(connection: BinderStateKey) {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.connections.remove(&connection);
        state.scopes.retain(|s| s.connection != connection);
    });
}
pub fn retire_connection(connection: BinderStateKey) {
    REPLIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(key, _), _| *key != connection);
}
fn fail(errno: i32) -> i32 {
    unsafe {
        *libc::__errno() = errno;
    }
    -1
}
fn bytes_of<T>(value: &T) -> &[u8] {
    // Used only for repr(C) Binder UAPI structures initialized in full below.
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}
fn transaction(bytes: &[u8]) -> Option<binder_transaction_data> {
    if bytes.len() < size_of::<binder_transaction_data>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) })
}
fn command(bytes: &[u8]) -> Option<(u32, usize)> {
    let cmd = u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?);
    let len = 4 + _ioc_size(cmd);
    (len <= bytes.len()).then_some((cmd, len))
}
fn current_scope() -> Option<Scope> {
    STATE.with(|s| s.borrow().scopes.last().copied())
}

fn receive(fd: i32, connection: BinderStateKey, bytes: &[u8]) {
    let mut at = 0;
    while let Some((cmd, len)) = command(&bytes[at..]) {
        let payload = &bytes[at + 4..at + len];
        if (cmd >> 8) & 255 == b'r' as u32 {
            native_read(fd, cmd);
            if _ioc_nr(cmd) == BR_TRANSACTION_NR {
                if let Some(tr) = transaction(payload) {
                    let app = if tr.data_size <= MAX_REQUEST_BYTES {
                        copy_process_buffer(unsafe { tr.data.ptr.buffer } as usize, tr.data_size)
                            .ok()
                            .and_then(|data| hal::aidl_token(&data))
                            .is_some_and(|(token, _)| token == hal::APP)
                    } else {
                        false
                    };
                    let oneway = tr.flags & TF_ONE_WAY != 0;
                    let uid = u32::try_from(tr.sender_euid)
                        .ok()
                        .filter(|uid| app && !oneway && (10000..20000).contains(&(uid % 100000)));
                    if app {
                        if let Some(client) =
                            CLIENT.read().unwrap_or_else(|e| e.into_inner()).as_ref()
                        {
                            client.observe(Observation::Sdk {
                                uid: tr.sender_euid,
                                wire_tx: tr.code,
                                oneway,
                                eligible: uid.is_some(),
                                selected: uid.is_some_and(|uid| client.selected(uid)),
                            });
                        }
                    }
                    STATE.with(|s| {
                        let mut s = s.borrow_mut();
                        while s.scopes.last().is_some_and(|scope| scope.oneway) {
                            s.scopes.pop();
                        }
                        s.next_scope = s.next_scope.wrapping_add(1);
                        let id = s.next_scope;
                        s.scopes.push(Scope {
                            connection,
                            uid,
                            oneway,
                            id,
                        });
                    });
                }
            }
        }
        at += len;
        if at >= bytes.len() {
            break;
        }
    }
}

fn accepted_real(fd: i32, connection: BinderStateKey, cmd: u32, payload: &[u8]) {
    if (cmd >> 8) & 255 != b'c' as u32 {
        return;
    }
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        match _ioc_nr(cmd) {
            BC_TRANSACTION_NR | BC_TRANSACTION_SG_NR | BC_REPLY_NR | BC_REPLY_SG_NR => {
                let reply = matches!(_ioc_nr(cmd), BC_REPLY_NR | BC_REPLY_SG_NR);
                let expects =
                    !reply && transaction(payload).is_some_and(|tr| tr.flags & TF_ONE_WAY == 0);
                native_submission(fd, reply, expects);
                if matches!(_ioc_nr(cmd), BC_REPLY_NR | BC_REPLY_SG_NR)
                    && s.scopes
                        .last()
                        .is_some_and(|scope| scope.connection == connection)
                {
                    s.scopes.pop();
                }
            }
            _ => {}
        }
    });
}

// Observe only a bounded HAL header on bypassed calls. A failed diagnostic read
// must never change the original Binder routing or make a stock call fail.
fn observe_native(payload: &[u8], reason: NativeReason) {
    let Some(tr) = transaction(payload) else {
        return;
    };
    let Ok(header) = copy_process_buffer(
        unsafe { tr.data.ptr.buffer } as usize,
        tr.data_size.min(256),
    ) else {
        return;
    };
    let Some((contract, _)) = Contract::identify(&header) else {
        return;
    };
    if let Some(client) = CLIENT.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        client.observe(Observation::Native {
            uid: current_scope().and_then(|scope| scope.uid),
            wire_tx: tr.code,
            contract,
            reason,
        });
    }
}

fn synthetic(connection: BinderStateKey, cmd: u32, payload: &[u8]) -> Result<bool, i32> {
    if (cmd >> 8) & 255 != b'c' as u32
        || !matches!(_ioc_nr(cmd), BC_TRANSACTION_NR | BC_TRANSACTION_SG_NR)
    {
        return Ok(false);
    }
    let Some(scope) = current_scope() else {
        observe_native(payload, NativeReason::NoSdkScope);
        return Ok(false);
    };
    let Some(uid) = scope.uid else {
        observe_native(payload, NativeReason::UnsupportedCaller);
        return Ok(false);
    };
    let client = CLIENT.read().unwrap_or_else(|e| e.into_inner()).clone();
    let Some(client) = client.filter(|client| client.selected(uid)) else {
        observe_native(payload, NativeReason::NotSelected);
        return Ok(false);
    };
    let Some(tr) = transaction(payload) else {
        return Ok(false);
    };
    if tr.flags & TF_ONE_WAY != 0
        || tr.data_size > MAX_REQUEST_BYTES
        || tr.offsets_size > 32 * size_of::<usize>()
    {
        observe_native(payload, NativeReason::UnsupportedShape);
        return Ok(false);
    }
    let data = copy_process_buffer(unsafe { tr.data.ptr.buffer } as usize, tr.data_size)?;
    let Some((contract, start)) = Contract::identify(&data) else {
        return Ok(false);
    };
    if contract.candidate(tr.code).is_none() {
        client.observe(Observation::Native {
            uid: Some(uid),
            wire_tx: tr.code,
            contract,
            reason: NativeReason::UnsupportedTx,
        });
        return Ok(false);
    }
    let offsets = if tr.offsets_size.is_multiple_of(size_of::<usize>()) {
        copy_process_buffer(unsafe { tr.data.ptr.offsets } as usize, tr.offsets_size)?
            .as_chunks::<8>()
            .0
            .iter()
            .map(|v| u64::from_ne_bytes(*v) as usize)
            .collect::<Vec<_>>()
    } else {
        log::warn!(target: "omk_soter_remote", "event=soter path=native_remote stage=decode uid={uid} wire_tx={} reason=invalid_offsets", tr.code);
        return Err(libc::EINVAL);
    };
    let (tx, request) =
        match contract.resolve_request(tr.code, &data, start, &offsets, |address, size| {
            copy_process_buffer(address, size).ok()
        }) {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                client.observe(Observation::Native {
                    uid: Some(uid),
                    wire_tx: tr.code,
                    contract,
                    reason: NativeReason::UnsupportedTx,
                });
                return Ok(false);
            }
            Err(_) => {
                client.observe(Observation::Native {
                    uid: Some(uid),
                    wire_tx: tr.code,
                    contract,
                    reason: NativeReason::DecodeFailed,
                });
                // The wire number can name different reply shapes in the two
                // AIDL layouts. Reject the boundary instead of guessing a method
                // or issuing a successful request to the original HAL.
                return Err(libc::EINVAL);
            }
        };
    // Native-only operations never consume synthetic reply capacity.
    // Check ownership bounds before making a remote mutation.
    {
        let replies = REPLIES.lock().unwrap_or_else(|e| e.into_inner());
        if replies.len() >= 64
            || replies
                .values()
                .map(OwnedReply::allocation_size)
                .sum::<usize>()
                > 16 * MAX_IO
        {
            log::warn!(target: "omk_soter_remote", "event=soter path=native_remote stage=reply uid={uid} tx={tx} reason=reply_capacity");
            return Err(libc::EBUSY);
        }
    }
    let started = Instant::now();
    let outcome = client.forward(uid, tx, request);
    let code = match &outcome {
        Outcome::Code(c)
        | Outcome::Buffer { code: c, .. }
        | Outcome::Init { code: c, .. }
        | Outcome::Exception { code: c, .. } => *c,
    };
    // No token, endpoint, alias, key material or challenge is written to logs.
    client.observe(Observation::HalReply {
        uid,
        wire_tx: tr.code,
        tx,
        contract,
        code,
        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    });
    let reply = contract.reply(tx, outcome);
    let pointer = reply.bytes.as_ptr() as usize;
    let mut response: binder_transaction_data = unsafe { std::mem::zeroed() };
    response.data_size = reply.bytes.len();
    response.offsets_size = reply.offsets.len() * size_of::<usize>();
    response.data.ptr = binder_transaction_data_data_ptr {
        buffer: pointer as _,
        offsets: reply.offsets.as_ptr() as _,
    };
    let mut event = BR_REPLY.to_ne_bytes().to_vec();
    event.extend_from_slice(bytes_of(&response));
    REPLIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((connection, pointer), reply);
    STATE.with(|s| {
        s.borrow_mut()
            .connections
            .entry(connection)
            .or_default()
            .synthetic
            .push_back(Synthetic {
                scope: scope.id,
                events: VecDeque::from([BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes().to_vec(), event]),
            })
    });
    Ok(true)
}

fn drain(connection: BinderStateKey, capacity: usize) -> Result<Option<Vec<u8>>, i32> {
    let scope = current_scope().map(|s| s.id);
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let state = s.connections.entry(connection).or_default();
        if native_pending(connection) {
            return Ok(None);
        }
        let Some(pending) = state
            .synthetic
            .front_mut()
            .filter(|v| Some(v.scope) == scope)
        else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        while pending
            .events
            .front()
            .is_some_and(|event| bytes.len() + event.len() <= capacity)
        {
            bytes.extend(pending.events.pop_front().unwrap());
        }
        if bytes.is_empty() {
            return Err(libc::EINVAL);
        }
        if pending.events.is_empty() {
            state.synthetic.pop_front();
        }
        Ok(Some(bytes))
    })
}

fn copyback(connection: BinderStateKey, saved: Copyback) -> i32 {
    let read_start = saved.output.read_consumed - saved.read.len();
    if !copy_to_process(saved.output.read_buffer as usize + read_start, &saved.read)
        || !write_process_value(saved.arg as *mut binder_write_read, &saved.output)
    {
        STATE.with(|s| {
            s.borrow_mut()
                .connections
                .entry(connection)
                .or_default()
                .pending = Some(saved)
        });
        return fail(libc::EFAULT);
    }
    let mut replies = REPLIES.lock().unwrap_or_else(|e| e.into_inner());
    for pointer in saved.freed {
        replies.remove(&(connection, pointer));
    }
    unsafe {
        *libc::__errno() = saved.errno;
    }
    saved.ret
}

/// # Safety
/// Same ABI as the original libc ioctl. Every application pointer is accessed
/// through the existing checked process-memory helpers.
pub unsafe fn ioctl(fd: i32, request: i32, arg: *mut c_void) -> i32 {
    let original = OLD_IOCTL.load(Ordering::Acquire);
    if original.is_null() {
        return libc::syscall(libc::SYS_ioctl, fd, request, arg) as i32;
    }
    let original: Ioctl = std::mem::transmute(original);
    ioctl_with(fd, request, arg, original)
}

unsafe fn ioctl_with(fd: i32, request: i32, arg: *mut c_void, original: Ioctl) -> i32 {
    if request as u32 != BINDER_WRITE_READ {
        return original(fd, request, arg);
    }
    let token = match synchronize_binder_fd_generation(fd) {
        Ok(t) => t,
        Err(_) => return fail(libc::ESTALE),
    };
    let guard = match BinderIoctlGuard::begin(token) {
        Ok(g) => g,
        Err(e) => return fail(e),
    };
    let connection = token.connection;
    let Some(mut bwr) = copy_process_value(arg.cast()) else {
        return fail(libc::EFAULT);
    };
    let pending = STATE.with(|s| {
        s.borrow_mut()
            .connections
            .entry(connection)
            .or_default()
            .pending
            .take()
    });
    if let Some(pending) = pending {
        if pending.arg != arg as usize
            || pending.original.write_buffer != bwr.write_buffer
            || pending.original.read_buffer != bwr.read_buffer
            || pending.original.write_size != bwr.write_size
            || pending.original.read_size != bwr.read_size
        {
            STATE.with(|s| {
                s.borrow_mut()
                    .connections
                    .entry(connection)
                    .or_default()
                    .pending = Some(pending)
            });
            return fail(libc::EBUSY);
        }
        return copyback(connection, pending);
    }
    if bwr.write_size > MAX_IO
        || bwr.read_size > MAX_IO
        || bwr.write_consumed > bwr.write_size
        || bwr.read_consumed > bwr.read_size
    {
        return fail(libc::EINVAL);
    }
    let input = bwr;
    let write = match copy_process_buffer(bwr.write_buffer as usize, bwr.write_size) {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    let mut freed = Vec::new();
    let mut ret = 0;
    let mut errno = 0;
    while bwr.write_consumed < bwr.write_size {
        let rest = &write[bwr.write_consumed..];
        let Some((cmd, len)) = command(rest) else {
            ret = -1;
            errno = libc::EINVAL;
            break;
        };
        let payload = &rest[4..len];
        if (cmd >> 8) & 255 == b'c' as u32
            && _ioc_nr(cmd) == BC_FREE_BUFFER_NR
            && payload.len() == 8
        {
            let pointer = u64::from_ne_bytes(payload.try_into().unwrap()) as usize;
            if REPLIES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&(connection, pointer))
            {
                freed.push(pointer);
                bwr.write_consumed += len;
                continue;
            }
        }
        match synthetic(connection, cmd, payload) {
            Ok(true) => {
                bwr.write_consumed += len;
                continue;
            }
            Err(e) => {
                ret = -1;
                errno = e;
                break;
            }
            Ok(false) => {}
        }
        let mut part: binder_write_read = std::mem::zeroed();
        part.write_buffer = rest.as_ptr() as _;
        part.write_size = len;
        ret = original(
            guard.fd(),
            request,
            (&mut part as *mut binder_write_read).cast(),
        );
        errno = *libc::__errno();
        if part.write_consumed > len {
            ret = -1;
            errno = libc::EPROTO;
            break;
        }
        bwr.write_consumed += part.write_consumed;
        if part.write_consumed == len {
            accepted_real(fd, connection, cmd, payload);
        }
        if ret != 0 {
            break;
        }
        if part.write_consumed != len {
            ret = -1;
            errno = libc::EPROTO;
            break;
        }
    }
    let mut read = Vec::new();
    if ret == 0 && bwr.read_size > bwr.read_consumed {
        let capacity = bwr.read_size - bwr.read_consumed;
        match drain(connection, capacity) {
            Ok(Some(bytes)) => read = bytes,
            Err(e) => {
                ret = -1;
                errno = e;
            }
            Ok(None) => {
                read.resize(capacity, 0);
                let mut part: binder_write_read = std::mem::zeroed();
                part.read_buffer = read.as_mut_ptr() as _;
                part.read_size = capacity;
                ret = original(
                    guard.fd(),
                    request,
                    (&mut part as *mut binder_write_read).cast(),
                );
                errno = *libc::__errno();
                if part.read_consumed > capacity {
                    read.clear();
                    ret = -1;
                    errno = libc::EPROTO;
                } else {
                    read.truncate(part.read_consumed);
                    receive(fd, connection, &read);
                }
            }
        }
        bwr.read_consumed += read.len();
    }
    copyback(
        connection,
        Copyback {
            arg: arg as usize,
            original: input,
            output: bwr,
            read,
            ret,
            errno,
            freed,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static DRIVER_WRITES: AtomicUsize = AtomicUsize::new(0);
    #[test]
    fn native_observation_does_not_change_unscoped_routing_or_fault_on_bad_buffers() {
        const TRANSACTION: u32 = 0x4040_6300; // BC_TRANSACTION, arm64 Binder UAPI.
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.code = 5;
        tr.data_size = MAX_REQUEST_BYTES + 1;
        tr.data.ptr = binder_transaction_data_data_ptr {
            buffer: 1,
            offsets: 0,
        };
        assert!(current_scope().is_none());
        assert_eq!(synthetic(0, TRANSACTION, bytes_of(&tr)), Ok(false));
        let mut header = soter_ta::parcel::Reply::ok();
        header.string16("vendor.qti.hardware.soter.ISoter");
        tr.data_size = header.as_bytes().len();
        tr.data.ptr.buffer = header.as_bytes().as_ptr() as _;
        let before = bytes_of(&tr).to_vec();
        assert_eq!(synthetic(0, TRANSACTION, bytes_of(&tr)), Ok(false));
        assert_eq!(bytes_of(&tr), before);
        assert!(current_scope().is_none());
    }

    #[test]
    fn compact_calls_without_an_authorized_app_keep_the_original_transaction() {
        const TRANSACTION: u32 = 0x4040_6300;
        let connection = 125;
        for uid in [None, Some(10124), Some(1010124)] {
            reset_thread(connection);
            STATE.with(|state| {
                state.borrow_mut().scopes.push(Scope {
                    connection,
                    uid,
                    oneway: false,
                    id: 1,
                })
            });
            for wire in [2, 6, 9] {
                let mut parcel = soter_ta::parcel::Reply::ok();
                parcel.string16("vendor.qti.hardware.soter.ISoter");
                let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
                tr.code = wire;
                tr.target.ptr = 0x1234;
                tr.cookie = 0x5678;
                tr.data_size = parcel.as_bytes().len();
                tr.data.ptr = binder_transaction_data_data_ptr {
                    buffer: parcel.as_bytes().as_ptr() as _,
                    offsets: 0,
                };
                let before = bytes_of(&tr).to_vec();
                assert_eq!(synthetic(connection, TRANSACTION, bytes_of(&tr)), Ok(false));
                assert_eq!(bytes_of(&tr), before);
                assert!(!STATE.with(|state| state.borrow().connections.contains_key(&connection)));
            }
        }
        reset_thread(connection);
    }

    unsafe extern "C" fn driver(_fd: i32, _request: i32, arg: *mut c_void) -> i32 {
        let bwr = &mut *arg.cast::<binder_write_read>();
        assert_eq!(
            bwr.read_size, 0,
            "test must not issue a kernel read for synthetic replies"
        );
        let data = std::slice::from_raw_parts(bwr.write_buffer as *const u8, bwr.write_size);
        let (cmd, _) = command(data).unwrap();
        assert_ne!(
            _ioc_nr(cmd),
            BC_FREE_BUFFER_NR,
            "fake buffer reached driver"
        );
        DRIVER_WRITES.fetch_add(1, Ordering::Relaxed);
        bwr.write_consumed = bwr.write_size;
        0
    }

    #[test]
    fn synthetic_read_and_free_preserve_suffix_and_do_not_repeat() {
        let fd = 9191;
        let connection = synchronize_binder_fd_generation(fd).unwrap().connection;
        reset_thread(connection);
        let reply = Contract::Hidl.reply(
            8,
            Outcome::Buffer {
                code: 0,
                data: vec![5; 16],
                field: 16,
            },
        );
        let pointer = reply.bytes.as_ptr() as usize;
        REPLIES.lock().unwrap().insert((connection, pointer), reply);
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.scopes.push(Scope {
                connection,
                uid: Some(10123),
                oneway: false,
                id: 1,
            });
            s.connections
                .entry(connection)
                .or_default()
                .synthetic
                .push_back(Synthetic {
                    scope: 1,
                    events: VecDeque::from([vec![7; 4]]),
                });
        });
        let mut read = [0u8; 4];
        let mut bwr: binder_write_read = unsafe { std::mem::zeroed() };
        bwr.read_size = 4;
        bwr.read_buffer = read.as_mut_ptr() as _;
        assert_eq!(
            unsafe {
                ioctl_with(
                    fd,
                    BINDER_WRITE_READ as i32,
                    (&mut bwr as *mut binder_write_read).cast(),
                    driver,
                )
            },
            0
        );
        assert_eq!(read, [7; 4]);
        assert_eq!(bwr.read_consumed, 4);
        assert!(drain(connection, 100).unwrap().is_none());

        let mut write = BC_FREE_BUFFER_CMD.to_ne_bytes().to_vec();
        write.extend_from_slice(&(pointer as u64).to_ne_bytes());
        write.extend_from_slice(&0x630cu32.to_ne_bytes()); // BC_ENTER_LOOPER
        let mut bwr: binder_write_read = unsafe { std::mem::zeroed() };
        bwr.write_buffer = write.as_ptr() as _;
        bwr.write_size = write.len();
        let before = DRIVER_WRITES.load(Ordering::Relaxed);
        assert_eq!(
            unsafe {
                ioctl_with(
                    fd,
                    BINDER_WRITE_READ as i32,
                    (&mut bwr as *mut binder_write_read).cast(),
                    driver,
                )
            },
            0
        );
        assert_eq!(bwr.write_consumed, write.len());
        assert_eq!(DRIVER_WRITES.load(Ordering::Relaxed), before + 1);
        assert!(!REPLIES.lock().unwrap().contains_key(&(connection, pointer)));
        reset_thread(connection);
    }

    #[test]
    fn real_submission_uses_existing_terminal_failure_classifier() {
        let fd = 9292;
        let connection = synchronize_binder_fd_generation(fd).unwrap().connection;
        native_submission(fd, false, true);
        assert!(native_pending(connection));
        receive(fd, connection, &0x7205u32.to_ne_bytes()); // BR_DEAD_REPLY before completion
        assert!(!native_pending(connection));
        native_submission(fd, false, true);
        receive(fd, connection, &BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes());
        receive(fd, connection, &0x7211u32.to_ne_bytes()); // BR_FAILED_REPLY after completion
        assert!(!native_pending(connection));
        reset_thread(connection);
    }

    #[test]
    fn incoming_driver_uid_not_argument_or_neighbor_controls_scope() {
        let fd = 9393;
        let connection = synchronize_binder_fd_generation(fd).unwrap().connection;
        let mut parcel = soter_ta::parcel::Reply::ok();
        parcel.string16(hal::APP);
        parcel.i32(10199);
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.sender_euid = 10123;
        tr.data_size = parcel.as_bytes().len();
        tr.data.ptr = binder_transaction_data_data_ptr {
            buffer: parcel.as_bytes().as_ptr() as _,
            offsets: 0,
        };
        let mut event = BR_TRANSACTION_CMD.to_ne_bytes().to_vec();
        event.extend_from_slice(bytes_of(&tr));
        receive(fd, connection, &event);
        assert_eq!(current_scope().unwrap().uid, Some(10123));
        tr.data_size = 0;
        tr.sender_euid = 1000;
        let mut event = BR_TRANSACTION_CMD.to_ne_bytes().to_vec();
        event.extend_from_slice(bytes_of(&tr));
        receive(fd, connection, &event);
        assert_eq!(current_scope().unwrap().uid, None);
        accepted_real(fd, connection, BC_REPLY_CMD, bytes_of(&tr));
        receive(fd, connection, &BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes());
        assert_eq!(current_scope().unwrap().uid, Some(10123));
        accepted_real(fd, connection, BC_REPLY_CMD, bytes_of(&tr));
        receive(fd, connection, &BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes());
        assert!(current_scope().is_none());
        reset_thread(connection);
    }
    #[test]
    fn pending_reply_drains_once_in_complete_commands() {
        reset_thread(123);
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.scopes.push(Scope {
                connection: 123,
                uid: Some(10123),
                oneway: false,
                id: 7,
            });
            s.connections
                .entry(123)
                .or_default()
                .synthetic
                .push_back(Synthetic {
                    scope: 7,
                    events: VecDeque::from([vec![1; 4], vec![2; 68]]),
                });
        });
        assert_eq!(drain(123, 4).unwrap(), Some(vec![1; 4]));
        assert_eq!(drain(123, 4), Err(libc::EINVAL));
        assert_eq!(drain(123, 68).unwrap(), Some(vec![2; 68]));
        assert_eq!(drain(123, 100).unwrap(), None);
        reset_thread(123);
    }
    #[test]
    fn real_completion_and_nested_scope_precede_synthetic_reply() {
        reset_thread(124);
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.scopes.push(Scope {
                connection: 124,
                uid: None,
                oneway: false,
                id: 9,
            });
            let c = s.connections.entry(124).or_default();
            c.synthetic.push_back(Synthetic {
                scope: 9,
                events: VecDeque::from([vec![1; 4]]),
            });
        });
        STATE.with(|s| {
            s.borrow_mut().scopes.push(Scope {
                connection: 124,
                uid: None,
                oneway: false,
                id: 10,
            })
        });
        assert!(drain(124, 100).unwrap().is_none());
        STATE.with(|s| {
            s.borrow_mut().scopes.pop();
        });
        assert_eq!(drain(124, 100).unwrap(), Some(vec![1; 4]));
        reset_thread(124);
    }
}
