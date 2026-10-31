use super::*;
use kmr_common::consts::{is_isolated_uid, AID_USER_OFFSET};
use rsbinder::Parcel;

mod framework;

const ACTIVITY_SERVICE: &str = "activity";
const ACTIVITY_DESCRIPTOR: &str = "android.app.IActivityManager";
const MAX_PROCESSES: i32 = 16_384;
const MAX_PACKAGES: i32 = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessParcelLayout {
    Legacy,
    WithDependencies,
    Structured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActivityContract {
    transaction: rsbinder::TransactionCode,
    layout: ProcessParcelLayout,
}

fn activity_contract(sdk: u32) -> Option<ActivityContract> {
    // Generated IActivityManager.Stub constants from the corresponding AOSP
    // android12/12L/13/14/15/16/17-release AIDL, not a probe of unknown methods.
    let (transaction, layout) = match sdk {
        31 | 32 => (76, ProcessParcelLayout::Legacy),
        33 => (78, ProcessParcelLayout::Legacy),
        34 => (86, ProcessParcelLayout::WithDependencies),
        35 => (87, ProcessParcelLayout::WithDependencies),
        36 => (88, ProcessParcelLayout::WithDependencies),
        37 => (15, ProcessParcelLayout::Structured),
        _ => return None,
    };
    Some(ActivityContract { transaction, layout })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    uids: [u32; 4],
    start_time: u64,
}

/// Procfs may hide other UIDs from SYSTEM with ENOENT (hidepid=2). The
/// existing helper retains real/saved root, but Binder calls must remain SYSTEM.
/// Only this thread regains root while reading identity metadata.
struct ProcReadEuid {
    previous: libc::uid_t,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ProcReadEuid {
    fn enter() -> Result<Self> {
        let previous = unsafe { libc::geteuid() };
        if unsafe { libc::getuid() } != kmr_common::consts::AID_ROOT
            || !matches!(previous, kmr_common::consts::AID_ROOT | kmr_common::consts::AID_SYSTEM)
        {
            bail!("proc identity reads require the privileged helper");
        }
        if previous != kmr_common::consts::AID_ROOT {
            set_thread_euid(kmr_common::consts::AID_ROOT)
                .context("failed to enter root for proc identity read")?;
        }
        Ok(Self { previous, _thread_bound: std::marker::PhantomData })
    }
}

impl Drop for ProcReadEuid {
    fn drop(&mut self) {
        if unsafe { libc::geteuid() } != self.previous {
            if let Err(error) = set_thread_euid(self.previous) {
                // Never dispatch another Binder request under an unintended UID.
                // This guard only exists in the separate privileged helper.
                eprintln!("privileged helper cannot restore proc-read EUID: {error}");
                unsafe { libc::_exit(1) };
            }
        }
    }
}

fn set_thread_euid(uid: libc::uid_t) -> std::io::Result<()> {
    // Linux credentials are per-thread. Bypass libc's process-wide setresuid
    // wrapper so monitor and Binder worker threads keep their own credentials.
    // Real and saved IDs stay unchanged, including the helper's saved root UID.
    let result =
        unsafe { libc::syscall(libc::SYS_setresuid, libc::uid_t::MAX, uid, libc::uid_t::MAX) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn read_process_identity(pid: u32) -> Result<ProcessIdentity> {
    let _identity = ProcReadEuid::enter()?;
    let directory = format!("/proc/{pid}");
    let before = std::fs::read_to_string(format!("{directory}/stat"))
        .with_context(|| format!("failed initial proc identity read for pid={pid}"))?;
    let status = std::fs::read_to_string(format!("{directory}/status"))
        .with_context(|| format!("failed proc UID read for pid={pid}"))?;
    let after = std::fs::read_to_string(format!("{directory}/stat"))
        .with_context(|| format!("failed final proc identity read for pid={pid}"))?;
    let start_time = parse_start_time(&before, pid)?;
    if parse_start_time(&after, pid)? != start_time {
        bail!("process identity changed while reading proc metadata");
    }
    let uid_line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .context("process status has no UID tuple")?;
    let uids = uid_line
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let uids: [u32; 4] = uids.try_into().map_err(|_| anyhow!("invalid process UID tuple"))?;
    Ok(ProcessIdentity { uids, start_time })
}

fn parse_start_time(stat: &str, pid: u32) -> Result<u64> {
    let (pid_text, _) = stat.split_once(' ').context("process stat has no PID")?;
    if pid_text.parse::<u32>()? != pid {
        bail!("process stat PID mismatch");
    }
    // comm is parenthesized and may itself contain spaces and parentheses.
    let end_name = stat.rfind(')').context("process stat has no comm terminator")?;
    let start_time = stat[end_name + 1..]
        .split_whitespace()
        .nth(19)
        .context("process stat has no starttime")?
        .parse::<u64>()?;
    if start_time == 0 {
        bail!("process stat has an invalid starttime");
    }
    Ok(start_time)
}

fn resolve_packages_with_identity(
    uid: u32,
    pid: u32,
    mut identity: impl FnMut(u32) -> Result<ProcessIdentity>,
    query: impl FnOnce(u32, u32) -> Result<Vec<String>>,
) -> Result<Vec<String>> {
    if !is_isolated_uid(uid) || pid == 0 || pid > i32::MAX as u32 {
        return Ok(Vec::new());
    }
    let before = identity(pid).context("isolated caller identity check before package lookup")?;
    if before.uids != [uid; 4] {
        bail!("isolated caller PID does not have the forwarded kernel UID");
    }
    let packages = query(uid, pid).context("isolated caller ActivityManager package lookup")?;
    if identity(pid).context("isolated caller identity check after package lookup")? != before {
        bail!("isolated caller identity changed during ActivityManager lookup");
    }
    Ok(packages)
}

fn query_activity_packages(uid: u32, pid: u32) -> Result<Vec<String>> {
    let sdk = rsproperties::get::<u32>("ro.build.version.sdk")
        .context("Android SDK is unavailable for process attribution")?;
    let mut contract =
        activity_contract(sdk).context("unsupported ActivityManager wire version")?;
    // OEMs insert methods into this non-stable AIDL. Read the actual Stub constant
    // from the trusted system framework instead of calling an SDK-based guess.
    contract.transaction = framework::running_processes_transaction()
        .context("cannot resolve installed ActivityManager transaction")?;
    rsbinder::ProcessState::init_default()
        .map_err(|error| anyhow!("failed to initialize Binder in privileged helper: {error}"))?;
    let binder = require_binder_service(ACTIVITY_SERVICE, hub::try_get_service(ACTIVITY_SERVICE))?;
    if binder.descriptor() != ACTIVITY_DESCRIPTOR {
        bail!("ActivityManager descriptor mismatch");
    }
    let proxy = binder.as_proxy().context("ActivityManager Binder was unexpectedly local")?;
    let data = proxy.prepare_transact(true)?;
    let mut reply = proxy
        .submit_transact(contract.transaction, &data, rsbinder::FLAG_CLEAR_BUF)?
        .context("ActivityManager returned no process list")?;
    reply.set_data_position(0);
    let status: Status = reply.read()?;
    if !status.is_ok() {
        return Err(anyhow::Error::new(status));
    }
    read_matching_packages(&mut reply, contract.layout, uid, pid)
}

struct RunningProcess {
    pid: i32,
    owner_uid: i32,
    packages: Vec<String>,
}

fn read_package_array(parcel: &mut Parcel) -> Result<Vec<String>> {
    let count: i32 = parcel.read()?;
    if count == -1 {
        return Ok(Vec::new());
    }
    if !(0..=MAX_PACKAGES).contains(&count) {
        bail!("invalid process package count");
    }
    let mut packages = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let package: Option<String> = parcel.read()?;
        if let Some(package) = package {
            packages.push(package);
        }
    }
    Ok(packages)
}

fn read_process(parcel: &mut Parcel, layout: ProcessParcelLayout) -> Result<RunningProcess> {
    let end = if layout == ProcessParcelLayout::Structured {
        let start = parcel.data_position();
        let size: i32 = parcel.read()?;
        if size < 4 {
            bail!("invalid structured process record size");
        }
        let end = start.checked_add(size as usize).context("process record size overflow")?;
        if end > parcel.data_size() {
            bail!("truncated structured process record");
        }
        Some(end)
    } else {
        None
    };
    let _name: Option<String> = parcel.read()?;
    let pid = parcel.read()?;
    let owner_uid = parcel.read()?;
    let packages = read_package_array(parcel)?;
    if let Some(end) = end {
        if parcel.data_position() > end {
            bail!("structured process identity exceeds record size");
        }
        parcel.set_data_position(end);
    } else {
        if layout == ProcessParcelLayout::WithDependencies {
            // pkgDeps is not ownership information and must never affect scope.
            let _dependencies = read_package_array(parcel)?;
        }
        for _ in 0..6 {
            let _: i32 = parcel.read()?;
        }
        let component_package: Option<String> = parcel.read()?;
        if component_package.is_some() {
            let _: String = parcel.read()?;
        }
        for _ in 0..3 {
            let _: i32 = parcel.read()?;
        }
        let _: i64 = parcel.read()?;
    }
    Ok(RunningProcess { pid, owner_uid, packages })
}

fn valid_package_name(package: &str) -> bool {
    !package.is_empty()
        && package.len() <= 255
        && package.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn read_matching_packages(
    parcel: &mut Parcel,
    layout: ProcessParcelLayout,
    uid: u32,
    pid: u32,
) -> Result<Vec<String>> {
    let count: i32 = parcel.read()?;
    if count == -1 {
        return Ok(Vec::new());
    }
    if !(0..=MAX_PROCESSES).contains(&count) {
        bail!("invalid running process count");
    }
    let mut matching = None;
    for _ in 0..count {
        match parcel.read::<i32>()? {
            0 => continue,
            1 => {}
            _ => bail!("invalid running process presence marker"),
        }
        let process = read_process(parcel, layout)?;
        if process.pid != pid as i32 {
            continue;
        }
        if matching.is_some() {
            bail!("ActivityManager returned duplicate caller PIDs");
        }
        let owner_uid = u32::try_from(process.owner_uid).context("invalid process owner UID")?;
        if owner_uid / AID_USER_OFFSET != uid / AID_USER_OFFSET || is_isolated_uid(owner_uid) {
            bail!("isolated process owner identity mismatch");
        }
        if process.packages.iter().any(|package| !valid_package_name(package)) {
            bail!("ActivityManager returned an invalid process package");
        }
        matching = Some(process.packages);
    }
    if parcel.data_position() != parcel.data_size() {
        bail!("unexpected trailing running process data");
    }
    let mut packages = matching.unwrap_or_default();
    packages.sort();
    packages.dedup();
    Ok(packages)
}

pub(super) fn execute_helper_request(request: &str) -> Result<String> {
    let (uid, pid) = request.split_once('\t').context("missing isolated caller identity")?;
    let uid = uid.parse::<u32>()?;
    let pid = pid.parse::<u32>()?;
    let packages =
        resolve_packages_with_identity(uid, pid, read_process_identity, query_activity_packages)?;
    if packages.is_empty() {
        Ok("NONE\n".to_owned())
    } else {
        Ok(format!("OK\t{}\n", packages.join("\t")))
    }
}

pub(super) fn parse_helper_response(response: &str) -> Result<Vec<String>> {
    if response == "NONE" {
        return Ok(Vec::new());
    }
    let packages =
        response.strip_prefix("OK\t").context("invalid process identity helper response")?;
    let packages: Vec<String> = packages.split('\t').map(str::to_owned).collect();
    if packages.len() > MAX_PACKAGES as usize
        || packages.iter().any(|package| !valid_package_name(package))
    {
        bail!("invalid process packages from privileged helper");
    }
    Ok(packages)
}

#[cfg(test)]
mod tests;
