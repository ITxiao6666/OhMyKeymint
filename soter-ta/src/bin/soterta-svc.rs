//! Rust Binder entry point for the Qualcomm Soter compatibility service.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rsbinder::{Binder, Interface, Parcel, ProcessState, Remotable, Stability, StatusCode};
use soter_ta::{dispatch, ffi, parcel::SOTER_INTERFACE, platform};

const DEFAULT_NAME: &str = "vendor.qti.hardware.soter.ISoter/default";
const DEFAULT_STATE: &str = "/data/misc/keystore/omk/data/soterta/state.json";
const INTERFACE_VERSION: u32 = 0x00ff_ffff;
const INTERFACE_HASH: u32 = 0x00ff_fffe;
const HASH: &str = "81832c92aa802927e98f3bf426e95b03e5d7f5e6";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Dead,
    Log,
    Answer,
}

#[derive(Debug)]
struct Options {
    mode: Mode,
    state: PathBuf,
    name: String,
    bio_gate: bool,
    help: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Dead,
            state: PathBuf::from(DEFAULT_STATE),
            name: DEFAULT_NAME.into(),
            bio_gate: true,
            help: false,
        }
    }
}

fn options(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut result = Options::default();
    for arg in args {
        if let Some(mode) = arg.strip_prefix("--mode=") {
            result.mode = match mode {
                "dead" => Mode::Dead,
                "log" => Mode::Log,
                "answer" => Mode::Answer,
                _ => return Err("invalid mode".into()),
            };
        } else if let Some(path) = arg.strip_prefix("--state=") {
            if path.is_empty() || !Path::new(path).is_absolute() {
                return Err("state must be an absolute path".into());
            }
            result.state = path.into();
        } else if let Some(name) = arg.strip_prefix("--name=") {
            if name.is_empty() || name.len() > 256 || name.contains('\0') {
                return Err("invalid service name".into());
            }
            result.name = name.into();
        } else if let Some(gate) = arg.strip_prefix("--bio-gate=") {
            result.bio_gate = match gate {
                "on" => true,
                "off" => false,
                _ => return Err("invalid biometric gate".into()),
            };
        } else if arg == "--help" {
            result.help = true;
        } else {
            return Err("unknown argument; use --help".into());
        }
    }
    Ok(result)
}

fn read_words(parcel: &mut Parcel) -> rsbinder::Result<Vec<u8>> {
    let size = parcel.data_avail();
    if size > dispatch::MAX_REQUEST_BYTES || !size.is_multiple_of(4) {
        return Err(StatusCode::BadValue);
    }
    let mut bytes = Vec::with_capacity(size);
    for _ in 0..size / 4 {
        bytes.extend_from_slice(&parcel.read_i32()?.to_le_bytes());
    }
    Ok(bytes)
}

fn write_words(parcel: &mut Parcel, bytes: &[u8]) -> rsbinder::Result<()> {
    let (words, tail) = bytes.as_chunks::<4>();
    if !tail.is_empty() {
        return Err(StatusCode::BadValue);
    }
    for word in words {
        parcel.write_i32(i32::from_le_bytes(*word))?;
    }
    Ok(())
}

// Response formatting only, never authorization or a source of app identity.
// Unknown or unreadable clients retain the standard Parcelable contract.
fn native_client(cmdline: &[u8]) -> bool {
    let Some(program) = cmdline.split(|byte| *byte == 0).next() else {
        return false;
    };
    std::str::from_utf8(program)
        .ok()
        .and_then(|program| Path::new(program).file_name())
        .is_some_and(|name| name == "cryptoeng")
}

fn native_caller() -> bool {
    let pid = rsbinder::get_calling_pid();
    if pid <= 0 {
        return false;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(format!("/proc/{pid}/cmdline"))
        .and_then(|file| file.take(4097).read_to_end(&mut bytes))
        .is_ok()
        && bytes.len() <= 4096
        && native_client(&bytes)
}

#[derive(Clone, Copy)]
struct SoterService(Mode);

impl Remotable for SoterService {
    fn descriptor() -> &'static str {
        SOTER_INTERFACE
    }

    fn on_transact(
        &self,
        code: u32,
        reader: &mut Parcel,
        reply: &mut Parcel,
    ) -> rsbinder::Result<()> {
        if matches!(code, INTERFACE_VERSION | INTERFACE_HASH) {
            if reader.data_avail() != 0 {
                return Err(StatusCode::BadValue);
            }
            reply.write_i32(0)?;
            return if code == INTERFACE_VERSION {
                reply.write_i32(1)
            } else {
                reply.write(&HASH)
            };
        }
        if !dispatch::handles(code) {
            return Err(StatusCode::UnknownTransaction);
        }
        // rsbinder already consumed and validated the interface token. Parsing
        // the complete remaining payload happens before any side effect.
        let bytes = read_words(reader)?;
        let (tx, request) = dispatch::resolve_request(code, &bytes).ok_or(StatusCode::BadValue)?;
        let outcome = match self.0 {
            Mode::Answer => ffi::answer(tx, request).map_err(|_| {
                log::error!("Soter runtime request failed: tx={tx}");
                StatusCode::FailedTransaction
            })?,
            Mode::Dead => dispatch::dead_reply(tx),
            Mode::Log => {
                log::info!(
                    "Soter request: wire_tx={code} tx={tx} pid={}",
                    rsbinder::get_calling_pid()
                );
                if !dispatch::ATTK_TRANSACTIONS.contains(&tx) {
                    return Err(StatusCode::UnknownTransaction);
                }
                dispatch::dead_reply(tx)
            }
        }
        .ok_or(StatusCode::UnknownTransaction)?;
        let bytes = if native_caller() {
            outcome.to_native_reply_bytes()
        } else {
            outcome.to_reply_bytes()
        };
        write_words(reply, &bytes)
    }

    fn on_dump(&self, writer: &mut dyn std::io::Write, _args: &[String]) -> rsbinder::Result<()> {
        writeln!(writer, "Soter Rust service; mode={:?}", self.0)
            .map_err(|_| StatusCode::FailedTransaction)
    }
}

unsafe extern "C" fn boot_ms() -> i64 {
    let mut now = std::mem::zeroed::<libc::timespec>();
    if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) != 0 {
        return -1;
    }
    now.tv_sec
        .saturating_mul(1000)
        .saturating_add(now.tv_nsec / 1_000_000)
}

fn sum_counter(dump: &str, key: &str) -> Option<u64> {
    let mut total = None::<u64>;
    for (_, tail) in dump
        .match_indices(key)
        .map(|(index, _)| (index, &dump[index + key.len()..]))
    {
        let Some(tail) = tail.trim_start().strip_prefix(':') else {
            continue;
        };
        let value = tail.trim_start();
        let digits = value.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            continue;
        }
        let value = value[..digits].parse::<u64>().ok()?;
        total = Some(total.unwrap_or(0).checked_add(value)?);
    }
    total
}

fn bio_mark() -> Option<u64> {
    // A fixed executable and arguments, not a shell. Both time and output are
    // bounded. Biometric counter output is not persisted or logged.
    let mut child = Command::new("/system/bin/dumpsys")
        .args(["-t", "2", "fingerprint"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut output = child.stdout.take()?;
    use std::os::fd::AsRawFd;
    let fd = output.as_raw_fd();
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();
    let success = loop {
        let mut chunk = [0u8; 4096];
        match output.read(&mut chunk) {
            Ok(0) => match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Err(_) => break false,
                Ok(None) => {}
            },
            Ok(count) => {
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.len() > 64 * 1024 {
                    break false;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break false,
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if !success {
        let _ = child.kill();
    }
    let _ = child.wait();
    if !success {
        return None;
    }
    let dump = std::str::from_utf8(&bytes).ok()?;
    let plain = sum_counter(dump, "\"accept\"");
    let crypto = sum_counter(dump, "\"acceptCrypto\"");
    if plain.is_none() && crypto.is_none() {
        return None;
    }
    let accepted = plain.unwrap_or(0).checked_add(crypto.unwrap_or(0))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let tag = u32::from_str_radix(boot.get(..8)?, 16).ok()? & 0x7fff_ffff;
    Some((u64::from(tag) << platform::BOOT_TAG_SHIFT) | (accepted & 0xffff_ffff))
}

unsafe extern "C" fn fingerprint_mark() -> i64 {
    bio_mark().map(|mark| mark as i64).unwrap_or(-1)
}

fn serve(options: &Options) -> Result<(), String> {
    // Block before any threads start; the main thread handles orderly shutdown.
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut signals, signal);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0 {
            return Err("cannot block termination signals".into());
        }
    }
    // Dead/log modes do not create a ledger.
    if options.mode == Mode::Answer {
        ffi::initialize(&options.state)?;
    }
    platform::install(Some(boot_ms), options.bio_gate.then_some(fingerprint_mark));
    ProcessState::init_default().map_err(|error| error.to_string())?;
    ProcessState::start_thread_pool();
    let mut binder = Binder::new_with_stability(SoterService(options.mode), Stability::Vintf);
    if let Err(error) = rsbinder::hub::add_service(&options.name, binder.as_binder()) {
        log::warn!("VINTF registration failed ({error}); trying a fresh system-stable binder");
        binder = Binder::new(SoterService(options.mode));
        rsbinder::hub::add_service(&options.name, binder.as_binder())
            .map_err(|error| error.to_string())?;
    }
    log::info!("ready: mode={:?} service={}", options.mode, options.name);
    let mut signal = 0;
    if unsafe { libc::sigwait(&signals, &mut signal) } != 0 {
        return Err("cannot wait for termination".into());
    }
    if options.mode == Mode::Answer {
        ffi::save()?;
    }
    drop(binder);
    Ok(())
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("soterta-svc")
            .with_max_level(log::LevelFilter::Info),
    );
    let result = (|| {
        let options = options(std::env::args().skip(1))?;
        if options.help {
            println!("soterta-svc [--mode=dead|log|answer] [--state=PATH] [--name=SERVICE] [--bio-gate=on|off]");
        } else {
            serve(&options)?;
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        eprintln!("soterta-svc: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_rejects_invalid_options() {
        for args in [vec!["--state=relative"], vec!["--bio-gate=maybe"]] {
            assert!(options(args.into_iter().map(str::to_string)).is_err());
        }
    }

    #[test]
    fn native_reply_selection_requires_exact_process_name() {
        assert!(native_client(b"/vendor/bin/cryptoeng\0--arg\0"));
        assert!(native_client(b"cryptoeng\0"));
        for name in [
            b"com.tencent.soter.soterserver\0".as_slice(),
            b"cryptoeng_fake\0",
            b"notcryptoeng\0",
            b"/vendor/bin/cryptoeng/other\0",
            b"\0",
            b"\xff\0",
        ] {
            assert!(!native_client(name));
        }
    }

    #[test]
    fn biometric_counter_parser_preserves_missing_evidence() {
        assert_eq!(sum_counter("no data", "\"accept\""), None);
        assert_eq!(
            sum_counter(
                "{\"accept\": 3, \"acceptCrypto\": 6} {\"accept\": 7}",
                "\"accept\""
            ),
            Some(10)
        );
        assert_eq!(sum_counter("\"accept\": -1", "\"accept\""), None);
        assert_eq!(
            sum_counter("\"accept\": 18446744073709551616", "\"accept\""),
            None
        );
    }

    #[test]
    fn binder_boundary_checks_sizes_before_dispatch() {
        let service = SoterService(Mode::Dead);
        let mut input = Parcel::new();
        let mut reply = Parcel::new();
        assert_eq!(
            service.on_transact(5, &mut input, &mut reply),
            Err(StatusCode::BadValue)
        );
        assert_eq!(reply.data_size(), 0);
        assert_eq!(
            service.on_transact(99, &mut input, &mut reply),
            Err(StatusCode::UnknownTransaction)
        );
        assert!(write_words(&mut reply, &[1, 2, 3]).is_err());
    }

    #[test]
    #[ignore = "child entry point for isolated Android Binder integration test"]
    fn binder_child_service() {
        let name =
            std::env::var("OMK_SOTER_TEST_SERVICE").expect("test-only service name required");
        assert!(name.starts_with("omk.soter.test."));
        serve(&Options {
            name,
            ..Options::default()
        })
        .unwrap();
    }

    fn check_remote(native: bool) {
        let name = std::env::var("OMK_SOTER_TEST_SERVICE").unwrap();
        ProcessState::init_default().unwrap();
        let remote = rsbinder::hub::check_service(&name).expect("isolated test service registered");
        let proxy = remote.as_proxy().unwrap();
        for tx in [8, 6, 8, 6] {
            let data = proxy.prepare_transact(true).unwrap();
            let mut reply = proxy.submit_transact(tx, &data, 0).unwrap().unwrap();
            reply.set_data_position(0);
            let expected = dispatch::dead_reply(dispatch::TX_GET_DEVICE_ID).unwrap();
            let expected = if native {
                expected.to_native_reply_bytes()
            } else {
                expected.to_reply_bytes()
            };
            assert_eq!(read_words(&mut reply).unwrap(), expected);
        }
        let data = proxy.prepare_transact(true).unwrap();
        let mut reply = proxy
            .submit_transact(INTERFACE_VERSION, &data, 0)
            .unwrap()
            .unwrap();
        reply.set_data_position(0);
        assert_eq!(reply.read_i32().unwrap(), 0);
        assert_eq!(reply.read_i32().unwrap(), 1);
        let mut reply = proxy
            .submit_transact(INTERFACE_HASH, &data, 0)
            .unwrap()
            .unwrap();
        reply.set_data_position(0);
        assert_eq!(reply.read_i32().unwrap(), 0);
        assert_eq!(reply.read::<String>().unwrap(), HASH);
        assert!(proxy.submit_transact(5, &data, 0).is_err());
    }

    #[test]
    #[ignore = "native client child entry point for isolated Android Binder test"]
    fn binder_native_client() {
        check_remote(true);
    }

    #[test]
    #[ignore = "requires explicitly authorized Android root Binder test"]
    fn binder_roundtrip() {
        use std::os::unix::process::CommandExt;
        assert_eq!(
            unsafe { libc::getuid() },
            0,
            "run isolated Binder test as root"
        );
        let name = format!("omk.soter.test.{}", std::process::id());
        std::env::set_var("OMK_SOTER_TEST_SERVICE", &name);
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _server = Child(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::binder_child_service", "--ignored"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        ProcessState::init_default().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while rsbinder::hub::check_service(&name).is_none() {
            assert!(Instant::now() < deadline, "test service did not register");
            std::thread::sleep(Duration::from_millis(100));
        }
        check_remote(false);
        let status = Command::new(std::env::current_exe().unwrap())
            .arg0("/vendor/bin/cryptoeng")
            .args(["--exact", "tests::binder_native_client", "--ignored"])
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        std::env::remove_var("OMK_SOTER_TEST_SERVICE");
    }
}
