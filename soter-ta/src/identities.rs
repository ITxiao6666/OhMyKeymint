//! Local random SOTER material and explicit package/user CPU-ID overrides.
//! Policy follows Ommega 4721358e/55e7dec9; CPU-ID parsing follows
//! tricky-soter-service's local_support and per-UID mapping.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    dispatch::{self, Outcome, Request},
    platform::Platform,
    state::TaState,
};

pub const ROOT: &str = "/data/misc/keystore/omk/data/soter";
const MAX_FILE: usize = 4 * 1024 * 1024;
const MAX_APPS: usize = 512;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub cpu_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct App {
    pub identity: String,
    #[serde(default)]
    pub cpu_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub enabled: bool,
    pub identities: Vec<Identity>,
    pub apps: BTreeMap<String, App>,
}

impl Default for Config {
    fn default() -> Self {
        Self { version: 1, enabled: false, identities: Vec::new(), apps: BTreeMap::new() }
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub enum Change {
    #[serde(rename = "enabled")]
    Enabled { enabled: bool },
    #[serde(rename = "add")]
    Add { name: String },
    #[serde(rename = "remove")]
    Remove { id: String },
    #[serde(rename = "app")]
    App { target: String, identity: Option<String>, cpu_id: String },
    #[serde(rename = "apps")]
    Apps { targets: Vec<String>, identity: String },
}

pub fn valid_cpu_id(value: &str) -> bool {
    matches!(value.len(), 32 | 36) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn target(value: &str) -> Option<(&str, u32)> {
    let (package, user) = value.split_once('@')?;
    let user_id = user.parse::<u32>().ok()?;
    if user != user_id.to_string()
        || user_id > (u32::MAX - 19999) / 100000
        || !package.contains('.')
        || package.len() > 255
        || !package.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    {
        return None;
    }
    Some((package, user_id))
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.identities.len() > 32 || self.apps.len() > MAX_APPS {
            return Err("Unsupported or oversized SOTER identity configuration".into());
        }
        let mut ids = BTreeSet::new();
        for item in &self.identities {
            if !valid_id(&item.id)
                || !ids.insert(item.id.as_str())
                || item.name.trim().is_empty()
                || item.name.chars().count() > 64
                || item.name.chars().any(char::is_control)
                || !valid_cpu_id(&item.cpu_id)
            {
                return Err("Invalid local SOTER identity".into());
            }
        }
        for (key, app) in &self.apps {
            if target(key).is_none()
                || !ids.contains(app.identity.as_str())
                || (!app.cpu_id.is_empty() && !valid_cpu_id(&app.cpu_id))
            {
                return Err("Invalid application identity or CPU-ID".into());
            }
        }
        Ok(())
    }

    pub fn selected<'a>(&'a self, uid: u32, packages: &str) -> Result<Option<&'a App>, String> {
        if !self.enabled || !(10000..20000).contains(&(uid % 100000)) {
            return Ok(None);
        }
        let mut found: Option<Option<&App>> = None;
        for line in packages.lines() {
            let mut fields = line.split_whitespace();
            let (Some(package), Some(number)) = (fields.next(), fields.next()) else { continue };
            if number.parse::<u32>().ok() != Some(uid % 100000) {
                continue;
            }
            let next = self.apps.get(&format!("{package}@{}", uid / 100000));
            if let Some(previous) = found {
                if previous != next {
                    return Err("Conflicting shared-UID SOTER identities".into());
                }
            }
            found = Some(next);
        }
        Ok(found.flatten())
    }

    pub fn selected_uids(&self, packages: &str) -> Vec<u32> {
        let mut candidates = BTreeSet::new();
        for key in self.apps.keys() {
            let Some((package, user)) = target(key) else { continue };
            for line in packages.lines() {
                let mut fields = line.split_whitespace();
                if fields.next() != Some(package) {
                    continue;
                }
                if let Some(app) = fields
                    .next()
                    .and_then(|n| n.parse::<u32>().ok())
                    .filter(|id| (10000..20000).contains(id))
                {
                    candidates.insert(user * 100000 + app);
                }
            }
        }
        candidates
            .into_iter()
            .filter(|uid| self.selected(*uid, packages).ok().flatten().is_some())
            .collect()
    }
}

fn private_directory(path: &Path) -> Result<File, String> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.to_string()),
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err("SOTER directory must be owner-only".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(file)
}

fn read(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_FILE as u64
    {
        return Err("Invalid private SOTER file".into());
    }
    let mut raw = Vec::new();
    file.take(MAX_FILE as u64 + 1).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    if raw.len() > MAX_FILE {
        return Err("SOTER file exceeds size limit".into());
    }
    Ok(Some(raw))
}

fn write(path: &Path, raw: &[u8]) -> Result<(), String> {
    if raw.len() > MAX_FILE {
        return Err("SOTER file exceeds size limit".into());
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(raw)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(path.parent().unwrap())?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|e| e.to_string())
}

fn config_at(root: &Path) -> Result<Config, String> {
    let Some(raw) = read(&root.join("identities.json"))? else { return Ok(Config::default()) };
    let config: Config = serde_json::from_slice(&raw).map_err(|_| "Invalid SOTER configuration")?;
    config.validate()?;
    Ok(config)
}

pub fn load() -> Result<Config, String> {
    config_at(Path::new(ROOT))
}

pub fn public_json() -> Result<String, String> {
    serde_json::to_string(&load()?).map_err(|e| e.to_string())
}

pub fn change(change: Change) -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("SOTER configuration requires root".into());
    }
    change_at(Path::new(ROOT), change)
        .and_then(|value| serde_json::to_string(&value).map_err(|e| e.to_string()))
}

fn change_at(root: &Path, change: Change) -> Result<Config, String> {
    let _guard = private_directory(root)?;
    let mut config = config_at(root)?;
    let mut removed = None;
    match change {
        Change::Enabled { enabled } => config.enabled = enabled,
        Change::Add { name } => {
            if config.identities.len() >= 32
                || name.trim().is_empty()
                || name.chars().count() > 64
                || name.chars().any(char::is_control)
            {
                return Err("Invalid identity name or limit reached".into());
            }
            let state = TaState::generate_local().ok_or("Cannot generate local SOTER material")?;
            let mut bytes = [0; 16];
            OsRng.fill_bytes(&mut bytes);
            let id = hex::encode(bytes);
            write(&root.join(format!("{id}.json")), &state.to_json())?;
            config.identities.push(Identity { id, name: name.trim().into(), cpu_id: state.cpu_id });
        }
        Change::Remove { id } => {
            if !valid_id(&id) {
                return Err("Invalid local SOTER identity ID".into());
            }
            config.identities.retain(|item| item.id != id);
            config.apps.retain(|_, app| app.identity != id);
            removed = Some(root.join(format!("{id}.json")));
        }
        Change::App { target: key, identity, cpu_id } => {
            if target(&key).is_none() {
                return Err("Invalid package/user target".into());
            }
            if let Some(identity) = identity {
                config
                    .apps
                    .insert(key, App { identity, cpu_id: cpu_id.trim().to_ascii_lowercase() });
            } else {
                config.apps.remove(&key);
            }
        }
        Change::Apps { targets, identity } => {
            if targets.is_empty()
                || targets.len() > MAX_APPS
                || targets.iter().any(|key| target(key).is_none())
                || !config.identities.iter().any(|item| item.id == identity)
            {
                return Err("Invalid bulk SOTER identity selection".into());
            }
            for key in targets {
                config
                    .apps
                    .entry(key)
                    .or_insert_with(|| App { identity: identity.clone(), cpu_id: String::new() });
            }
        }
    }
    config.validate()?;
    write(&root.join("identities.json"), &serde_json::to_vec(&config).map_err(|e| e.to_string())?)?;
    // Revoke routing before removing private material. A failed unlink is
    // retryable by ID, but cannot leave an app routed to a missing identity.
    if let Some(path) = removed {
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => {
                return Err(format!("Identity disabled, private material deletion failed: {error}"))
            }
        }
        File::open(root).and_then(|directory| directory.sync_all()).map_err(|e| e.to_string())?;
    }
    Ok(config)
}

pub fn app_uids(config: &Config) -> Result<Vec<u32>, String> {
    if !config.enabled || config.apps.is_empty() {
        return Ok(Vec::new());
    }
    let packages = fs::read_to_string("/data/system/packages.list").map_err(|e| e.to_string())?;
    Ok(config.selected_uids(&packages))
}

pub fn answer(uid: u32, tx: u32, request: Request) -> Result<Outcome, String> {
    answer_at(
        Path::new(ROOT),
        uid,
        tx,
        request,
        &fs::read_to_string("/data/system/packages.list").map_err(|e| e.to_string())?,
    )
}

fn answer_at(
    root: &Path,
    uid: u32,
    tx: u32,
    request: Request,
    packages: &str,
) -> Result<Outcome, String> {
    let _guard = private_directory(root)?;
    let config = config_at(root)?;
    let app = config.selected(uid, packages)?.ok_or("SOTER caller is not selected")?;
    if dispatch::ATTK_TRANSACTIONS.contains(&tx) {
        return Err("Factory ATTK operations remain native".into());
    }
    match &request {
        Request::Uid(value)
        | Request::UidKey { uid: value, .. }
        | Request::InitSign { uid: value, .. }
            if *value != uid =>
        {
            return Err("SOTER argument UID differs from Binder caller".into())
        }
        _ => (),
    }
    let identity = config
        .identities
        .iter()
        .find(|item| item.id == app.identity)
        .ok_or("Missing SOTER identity")?;
    let path: PathBuf = root.join(format!("{}.json", identity.id));
    let raw = read(&path)?.ok_or("Missing local identity material")?;
    let mut state = TaState::from_json(&raw).ok_or("Invalid local identity material")?;
    if state.cpu_id != identity.cpu_id || state.attk.private().is_none() {
        return Err("Local SOTER identity material does not match its policy".into());
    }
    let effective_cpu = if app.cpu_id.is_empty() { &identity.cpu_id } else { &app.cpu_id };
    if state.cpu_overrides.get(&uid).is_some_and(|previous| previous != effective_cpu) {
        if let Some(entry) = state.uids.get_mut(&uid) {
            entry.ask = None;
            entry.auth.clear();
        }
        state.sessions.retain(|_, session| session.uid != uid);
    }
    state.cpu_overrides.insert(uid, effective_cpu.clone());
    if state.uids.len() >= MAX_APPS && !state.uids.contains_key(&uid) {
        return Err("Local SOTER caller limit reached".into());
    }
    if matches!(tx, dispatch::TX_GENERATE_AUTH)
        && state.uids.get(&uid).is_some_and(|entry| entry.auth.len() >= 64)
    {
        return Err("Local SOTER key limit reached".into());
    }
    if let Request::Session(session) = &request {
        if state.sessions.get(session).is_none_or(|entry| entry.uid != uid) {
            return Ok(Outcome::Buffer { code: -1000, data: Vec::new(), field: 0 });
        }
    }
    // CPU-ID overrides affect all public identity views for this transaction.
    // Keep the underlying ledger's random identity stable between calls.
    let cpu = state.cpu_id.clone();
    if !app.cpu_id.is_empty() {
        state.cpu_id.clone_from(&app.cpu_id);
    }
    let response = dispatch::handle_request(&mut state, tx, request, Platform::default())
        .ok_or("Unsupported local SOTER request")?;
    state.cpu_id = cpu;
    write(&path, &state.to_json())?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_install_has_no_default_identity_or_files() {
        let root = tempfile::tempdir().unwrap();
        let config = config_at(root.path()).unwrap();
        assert!(!config.enabled);
        assert!(config.identities.is_empty());
        assert!(config.apps.is_empty());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn cpu_id_accepts_qti_and_mtk_lengths_only() {
        for length in [32, 36] {
            assert!(valid_cpu_id(&"a".repeat(length)));
        }
        for value in ["a".repeat(31), "a".repeat(33), "z".repeat(32)] {
            assert!(!valid_cpu_id(&value));
        }
    }

    #[test]
    fn identity_persists_and_cpu_id_views_are_consistent() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = change_at(root.path(), Change::Add { name: "Local".into() }).unwrap();
        let item = config.identities[0].clone();
        let override_id = "ab".repeat(18);
        change_at(
            root.path(),
            Change::App {
                target: "com.example.app@0".into(),
                identity: Some(item.id.clone()),
                cpu_id: override_id.clone(),
            },
        )
        .unwrap();
        change_at(root.path(), Change::Enabled { enabled: true }).unwrap();
        let packages = "com.example.app 10123";
        assert_eq!(
            answer_at(root.path(), 10123, dispatch::TX_GENERATE_ASK, Request::Uid(10123), packages)
                .unwrap(),
            Outcome::Code(0)
        );
        let answer =
            answer_at(root.path(), 10123, dispatch::TX_GET_DEVICE_ID, Request::None, packages)
                .unwrap();
        assert!(
            matches!(answer, Outcome::Buffer { data, .. } if hex::encode(&data) == override_id)
        );
        let exported =
            answer_at(root.path(), 10123, dispatch::TX_EXPORT_ASK, Request::Uid(10123), packages)
                .unwrap();
        let Outcome::Buffer { data, .. } = exported else { panic!("ASK export") };
        let length = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        let json: serde_json::Value = serde_json::from_slice(&data[4..4 + length]).unwrap();
        assert_eq!(json["cpu_id"], override_id);
        assert_eq!(config_at(root.path()).unwrap().identities[0], item);
        assert!(answer_at(
            root.path(),
            10123,
            dispatch::TX_GENERATE_ASK,
            Request::Uid(10124),
            packages
        )
        .is_err());
    }

    #[test]
    fn removal_revokes_only_matching_apps_and_erases_material() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let first = change_at(root.path(), Change::Add { name: "First".into() }).unwrap();
        let removed = first.identities[0].id.clone();
        let config = change_at(root.path(), Change::Add { name: "Other".into() }).unwrap();
        let kept = config.identities[1].id.clone();
        for (target, identity) in [
            ("com.example.one@0", &removed),
            ("com.example.one@10", &removed),
            ("com.example.other@0", &kept),
        ] {
            change_at(
                root.path(),
                Change::App {
                    target: target.into(),
                    identity: Some(identity.clone()),
                    cpu_id: String::new(),
                },
            )
            .unwrap();
        }
        let config = change_at(root.path(), Change::Remove { id: removed.clone() }).unwrap();
        assert_eq!(config.identities.len(), 1);
        assert_eq!(config.identities[0].id, kept);
        assert_eq!(config.apps.len(), 1);
        assert!(config.apps.contains_key("com.example.other@0"));
        assert!(!root.path().join(format!("{removed}.json")).exists());
        assert!(root.path().join(format!("{kept}.json")).exists());
        assert_eq!(config_at(root.path()).unwrap().apps, config.apps);
        assert!(change_at(root.path(), Change::Remove { id: removed }).is_ok());
        assert!(change_at(root.path(), Change::Remove { id: "../identities".into() }).is_err());
    }

    #[test]
    fn bulk_assignment_is_atomic_and_preserves_existing_assignments_and_switch() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = change_at(root.path(), Change::Add { name: "First".into() }).unwrap();
        let first = config.identities[0].id.clone();
        let config = change_at(root.path(), Change::Add { name: "Second".into() }).unwrap();
        let second = config.identities[1].id.clone();
        let override_id = "ab".repeat(16);
        change_at(
            root.path(),
            Change::App {
                target: "com.example.existing@0".into(),
                identity: Some(first.clone()),
                cpu_id: override_id.clone(),
            },
        )
        .unwrap();
        let targets = vec![
            "com.example.existing@0".into(),
            "com.example.new@0".into(),
            "com.example.new@10".into(),
            "com.example.new@0".into(),
        ];
        let config = change_at(
            root.path(),
            Change::Apps { targets: targets.clone(), identity: second.clone() },
        )
        .unwrap();
        assert!(!config.enabled);
        assert_eq!(config.apps.len(), 3);
        assert_eq!(
            config.apps["com.example.existing@0"],
            App { identity: first, cpu_id: override_id }
        );
        assert_eq!(config.apps["com.example.new@0"].identity, second);
        assert_eq!(config.apps["com.example.new@10"].identity, second);
        let before = fs::read(root.path().join("identities.json")).unwrap();
        for change in [
            Change::Apps {
                targets: vec!["com.example.other@0".into(), "invalid".into()],
                identity: second.clone(),
            },
            Change::Apps { targets: targets.clone(), identity: "00".repeat(16) },
            Change::Apps { targets: Vec::new(), identity: second.clone() },
        ] {
            assert!(change_at(root.path(), change).is_err());
            assert_eq!(fs::read(root.path().join("identities.json")).unwrap(), before);
        }
        change_at(root.path(), Change::Apps { targets, identity: second }).unwrap();
        assert_eq!(config_at(root.path()).unwrap().apps, config.apps);
    }

    #[test]
    fn bulk_assignment_over_capacity_leaves_all_policy_unchanged() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = change_at(root.path(), Change::Add { name: "Local".into() }).unwrap();
        let id = config.identities[0].id.clone();
        let targets = (0..MAX_APPS).map(|i| format!("com.example.app{i}@0")).collect();
        change_at(root.path(), Change::Apps { targets, identity: id.clone() }).unwrap();
        let before = fs::read(root.path().join("identities.json")).unwrap();
        assert!(change_at(
            root.path(),
            Change::Apps { targets: vec!["com.example.overflow@0".into()], identity: id }
        )
        .is_err());
        assert_eq!(fs::read(root.path().join("identities.json")).unwrap(), before);
    }

    #[test]
    fn master_and_shared_uid_policies_fail_closed() {
        let mut config = Config::default();
        let id = "ab".repeat(16);
        config.identities.push(Identity {
            id: id.clone(),
            name: "Local".into(),
            cpu_id: "00".repeat(16),
        });
        config.apps.insert("com.example.one@0".into(), App { identity: id, cpu_id: String::new() });
        assert!(config.selected(10123, "com.example.one 10123").unwrap().is_none());
        config.enabled = true;
        assert!(config.selected(10123, "com.example.one 10123").unwrap().is_some());
        assert!(config.selected(10123, "com.example.one 10123\ncom.example.two 10123").is_err());
        assert!(config.selected(110123, "com.example.one 10123").unwrap().is_none());
        config.apps.get_mut("com.example.one@0").unwrap().identity = "missing".into();
        assert!(config.validate().is_err());
    }
}
