use std::{
    fs::{self, File, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use pif_common::{
    parse_catalog, validate_product, DeviceEntry, PifProfile, MAX_CATALOG_BYTES, MAX_PROFILE_BYTES,
    MAX_PROP_BYTES,
};
use serde::Serialize;
use ureq::http::Uri;

use crate::{root_path, security_patch, webui_http};

const PROFILE_PATH: &str = root_path!("data/pif_fingerprint.json");
// GitHub Raw has a short cache window for the bot branch. Keep jsDelivr as a
// fallback for devices that cannot reach GitHub directly, rather than making
// a week-old CDN response the normal source for a daily feed.
const PRIMARY_BASE: &str = "https://raw.githubusercontent.com/KOWX712/PlayIntegrityFix/bot";
const FALLBACK_BASE: &str = "https://fastly.jsdelivr.net/gh/KOWX712/PlayIntegrityFix@bot";
const JSDELIVR_HOSTS: [&str; 2] = ["fastly.jsdelivr.net", "cdn.jsdelivr.net"];
const RAW_HOST: &str = "raw.githubusercontent.com";
const MAX_REDIRECTS: usize = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_NAMES: [&[u8]; 2] = [b"com.google.android.gms.unstable", b"com.android.vending"];

#[derive(Debug, Clone)]
enum FeedResource {
    Catalog,
    Profile(String),
}

impl FeedResource {
    fn relative_path(&self) -> String {
        match self {
            Self::Catalog => "device_list.json".to_string(),
            Self::Profile(product) => format!("device_prop/{product}.prop"),
        }
    }

    fn max_bytes(&self) -> usize {
        match self {
            Self::Catalog => MAX_CATALOG_BYTES,
            Self::Profile(_) => MAX_PROP_BYTES,
        }
    }

    fn size_label(&self) -> &'static str {
        match self {
            Self::Catalog => "64 KiB",
            Self::Profile(_) => "4 KiB",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Catalog => "PIF device catalog",
            Self::Profile(_) => "PIF device profile",
        }
    }
}

#[derive(Debug, Serialize)]
struct DisabledState {
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct EnabledState<'a> {
    enabled: bool,
    model: &'a str,
    product: &'a str,
    fingerprint: &'a str,
    security_patch: &'a str,
}

pub fn list_devices() -> Result<String> {
    let entries = download_catalog()?;
    serde_json::to_string(&entries).context("failed to serialize PIF device catalog")
}

pub fn fingerprint_state() -> Result<String> {
    state_json(load_profile(Path::new(PROFILE_PATH))?.as_ref())
}

pub fn apply_fingerprint(product: &str) -> Result<String> {
    validate_product(product).map_err(anyhow::Error::msg)?;
    let catalog = download_catalog()?;
    let selected = catalog
        .iter()
        .find(|entry| entry.product == product)
        .ok_or_else(|| anyhow!("selected product is not present in the current PIF catalog"))?;
    let resource = FeedResource::Profile(product.to_string());
    let contents = download_feed(&resource)?;
    let profile = PifProfile::from_source(selected, contents.as_bytes())
        .map_err(anyhow::Error::msg)
        .context("downloaded PIF profile failed validation")?;

    let path = Path::new(PROFILE_PATH);
    let _lock = security_patch::acquire_data_operation_lock(path)?;
    persist_profile(path, &profile, KEYSTORE_UID, KEYSTORE_GID)?;
    refresh_target_processes()?;
    state_json(Some(&profile))
}

pub fn disable_fingerprint() -> Result<String> {
    let path = Path::new(PROFILE_PATH);
    let _lock = security_patch::acquire_data_operation_lock(path)?;
    remove_profile(path)?;
    refresh_target_processes()?;
    state_json(None)
}

fn download_catalog() -> Result<Vec<DeviceEntry>> {
    let contents = download_feed(&FeedResource::Catalog)?;
    parse_catalog(contents.as_bytes()).map_err(anyhow::Error::msg)
}

fn download_feed(resource: &FeedResource) -> Result<String> {
    let relative = resource.relative_path();
    let primary = format!("{PRIMARY_BASE}/{relative}");
    let fallback = format!("{FALLBACK_BASE}/{relative}");
    let policy = webui_http::DownloadPolicy {
        resource: resource.label(),
        redirect_allowlist: "the fixed PlayIntegrityFix feed paths",
        max_bytes: resource.max_bytes(),
        max_size_label: resource.size_label(),
        max_redirects: MAX_REDIRECTS,
        timeout: REQUEST_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
    };

    let fetch = |url: &str| -> Result<String> {
        let uri: Uri = url
            .parse()
            .with_context(|| format!("{} URL is invalid", resource.label()))?;
        if !is_allowed_feed_uri(&uri, resource) {
            bail!("{} URL is outside the fixed feed paths", resource.label());
        }
        webui_http::download_https_utf8(uri, &policy, |uri| is_allowed_feed_uri(uri, resource))
    };

    match fetch(&primary) {
        Ok(contents) => Ok(contents),
        Err(primary_error) => fetch(&fallback).with_context(|| {
            format!("both PIF feed sources failed; primary source error: {primary_error:#}")
        }),
    }
}

fn is_allowed_feed_uri(uri: &Uri, resource: &FeedResource) -> bool {
    if uri.scheme_str() != Some("https") || uri.query().is_some() {
        return false;
    }
    let Some(authority) = uri.authority() else {
        return false;
    };
    let authority = authority.as_str();
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_suffix(":443") {
        Some(host) if !host.contains(':') => host,
        Some(_) => return false,
        None if authority.contains(':') => return false,
        None => authority,
    };
    let relative = resource.relative_path();
    let jsdelivr_path = format!("/gh/KOWX712/PlayIntegrityFix@bot/{relative}");
    let raw_path = format!("/KOWX712/PlayIntegrityFix/bot/{relative}");
    (JSDELIVR_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
        && uri.path() == jsdelivr_path)
        || (host.eq_ignore_ascii_case(RAW_HOST) && uri.path() == raw_path)
}

fn state_json(profile: Option<&PifProfile>) -> Result<String> {
    match profile {
        Some(profile) => {
            profile.validate().map_err(anyhow::Error::msg)?;
            serde_json::to_string(&EnabledState {
                enabled: true,
                model: &profile.model,
                product: &profile.product,
                fingerprint: &profile.fingerprint,
                security_patch: &profile.security_patch,
            })
        }
        None => serde_json::to_string(&DisabledState { enabled: false }),
    }
    .context("failed to serialize PIF fingerprint state")
}

fn load_profile(path: &Path) -> Result<Option<PifProfile>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect PIF profile {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("PIF profile path is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_PROFILE_BYTES as u64 {
        bail!("PIF profile exceeds the 4 KiB limit");
    }
    let contents =
        fs::read(path).with_context(|| format!("failed to read PIF profile {}", path.display()))?;
    let profile = PifProfile::from_json(&contents).map_err(anyhow::Error::msg)?;
    let canonical = profile.to_canonical_json().map_err(anyhow::Error::msg)?;
    if contents != canonical.as_bytes() {
        bail!("PIF profile is not canonical JSON");
    }
    Ok(Some(profile))
}

fn persist_profile(path: &Path, profile: &PifProfile, uid: u32, gid: u32) -> Result<()> {
    let contents = profile.to_canonical_json().map_err(anyhow::Error::msg)?;
    validate_profile_target(path)?;
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o600, uid, gid).with_context(
        || {
            format!(
                "failed to atomically replace PIF profile {}",
                path.display()
            )
        },
    )?;
    validate_profile_target(path)?;
    enforce_profile_metadata(path, uid, gid)?;
    let saved = load_profile(path)?.ok_or_else(|| anyhow!("PIF profile vanished after write"))?;
    if &saved != profile {
        bail!("PIF profile read-back does not match the requested profile");
    }
    Ok(())
}

fn validate_profile_target(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("PIF profile path has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect PIF state directory {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        bail!(
            "PIF state parent is not a real directory: {}",
            parent.display()
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!("PIF profile path is not a regular file: {}", path.display());
        }
    }
    Ok(())
}

fn enforce_profile_metadata(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to reopen PIF profile {}", path.display()))?;
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PIF profile owner");
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PIF profile mode");
    }
    file.sync_all()
        .context("failed to sync PIF profile metadata")?;
    Ok(())
}

fn remove_profile(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            bail!("PIF profile path is not a regular file: {}", path.display())
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect PIF profile before removal"),
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("PIF profile path has no parent"))?;
    fs::remove_file(path)
        .with_context(|| format!("failed to remove PIF profile {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("failed to sync PIF state directory after removal")
}

fn refresh_target_processes() -> Result<()> {
    let entries = fs::read_dir("/proc").context("failed to scan processes after PIF update")?;
    let mut failures = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let name = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
        if !PROCESS_NAMES.contains(&name) {
            continue;
        }
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            // A matching process can exit between the /proc scan and kill.
            // Treat that expected race as an already-refreshed process.
            if error.raw_os_error() != Some(libc::ESRCH) {
                failures.push(format!(
                    "{} (pid {pid}): {error}",
                    String::from_utf8_lossy(name)
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to stop PIF target process(es): {}",
            failures.join("; ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn sample_profile() -> PifProfile {
        PifProfile::from_source(
            &DeviceEntry {
                model: "Pixel 6".to_string(),
                product: "oriole_beta".to_string(),
            },
            b"FINGERPRINT=google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel 6\nSECURITY_PATCH=2026-08-05\n",
        )
        .unwrap()
    }

    #[test]
    fn feed_allowlist_accepts_only_exact_resource_paths() {
        let catalog = FeedResource::Catalog;
        for url in [
            "https://fastly.jsdelivr.net/gh/KOWX712/PlayIntegrityFix@bot/device_list.json",
            "https://cdn.jsdelivr.net:443/gh/KOWX712/PlayIntegrityFix@bot/device_list.json",
            "https://raw.githubusercontent.com/KOWX712/PlayIntegrityFix/bot/device_list.json",
        ] {
            assert!(
                is_allowed_feed_uri(&url.parse().unwrap(), &catalog),
                "{url}"
            );
        }
        for url in [
            "http://fastly.jsdelivr.net/gh/KOWX712/PlayIntegrityFix@bot/device_list.json",
            "https://fastly.jsdelivr.net:444/gh/KOWX712/PlayIntegrityFix@bot/device_list.json",
            "https://fastly.jsdelivr.net:bad/gh/KOWX712/PlayIntegrityFix@bot/device_list.json",
            "https://fastly.jsdelivr.net/gh/KOWX712/PlayIntegrityFix@master/device_list.json",
            "https://fastly.jsdelivr.net/gh/KOWX712/PlayIntegrityFix@bot/device_list.json?x=1",
            "https://fastly.jsdelivr.net.evil.example/gh/KOWX712/PlayIntegrityFix@bot/device_list.json",
        ] {
            assert!(!is_allowed_feed_uri(&url.parse().unwrap(), &catalog), "{url}");
        }
    }

    #[test]
    fn profile_allowlist_binds_the_validated_product_to_the_path() {
        let profile = FeedResource::Profile("oriole_beta".to_string());
        assert!(is_allowed_feed_uri(
            &"https://fastly.jsdelivr.net/gh/KOWX712/PlayIntegrityFix@bot/device_prop/oriole_beta.prop"
                .parse()
                .unwrap(),
            &profile
        ));
        assert!(!is_allowed_feed_uri(
            &"https://fastly.jsdelivr.net/gh/KOWX712/PlayIntegrityFix@bot/device_prop/raven_beta.prop"
                .parse()
                .unwrap(),
            &profile
        ));
    }

    #[test]
    fn state_json_matches_the_webui_canonical_contract() {
        let profile = sample_profile();
        assert_eq!(state_json(None).unwrap(), r#"{"enabled":false}"#);
        assert_eq!(
            state_json(Some(&profile)).unwrap(),
            r#"{"enabled":true,"model":"Pixel 6","product":"oriole_beta","fingerprint":"google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys","security_patch":"2026-08-05"}"#
        );
    }

    #[test]
    fn profile_persistence_is_atomic_and_verified() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pif_fingerprint.json");
        let profile = sample_profile();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        fs::write(&path, b"stale").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        persist_profile(&path, &profile, uid, gid).unwrap();
        assert_eq!(load_profile(&path).unwrap(), Some(profile));
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.gid(), gid);
    }

    #[test]
    fn loader_rejects_symlinks_and_noncanonical_json() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::write(&real, sample_profile().to_canonical_json().unwrap()).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(load_profile(&link).is_err());

        let noncanonical = temp.path().join("noncanonical");
        fs::write(
            &noncanonical,
            format!("{}\n", sample_profile().to_canonical_json().unwrap()),
        )
        .unwrap();
        assert!(load_profile(&noncanonical).is_err());
    }
}
