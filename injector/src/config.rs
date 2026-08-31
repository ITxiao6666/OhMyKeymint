use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::runtime::{
    file_watch::{self, WatchTrigger},
    fs::atomic_replace_preserving_metadata,
    retry::{retry_read_race, ReadRaceErrorKind, RetryOutcome},
};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

pub const DEFAULT_CONFIG_PATH: &str = "/data/misc/keystore/omk/injector.toml";
const CURRENT_CONFIG_VERSION: u32 = 1;
const REPLACE_SAVE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const REPLACE_SAVE_RETRY_LIMIT: usize = 10;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InjectorConfig {
    pub version: u32,
    pub scoop: Vec<String>,
    pub scoop_details: BTreeMap<String, toml::Table>,
    pub main: MainConfig,
    pub filter: FilterConfig,
    pub intercept: InterceptConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct MainConfig {
    pub enabled: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    pub enabled: bool,
    pub deny_packages: Vec<String>,
    pub block_android_package: bool,
    pub allow_unknown_package: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct InterceptConfig {
    pub get_security_level: bool,
    pub get_key_entry: bool,
    pub update_subcomponent: bool,
    pub list_entries: bool,
    pub delete_key: bool,
    pub grant: bool,
    pub ungrant: bool,
    pub get_number_of_entries: bool,
    pub list_entries_batched: bool,
    pub get_supplementary_attestation_info: bool,
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            scoop: default_scoop(),
            scoop_details: BTreeMap::new(),
            main: MainConfig::default(),
            filter: FilterConfig::default(),
            intercept: InterceptConfig::default(),
        }
    }
}

fn default_scoop() -> Vec<String> {
    [
        "io.github.vvb2060.keyattestation",
        "com.google.android.gsf",
        "com.google.android.gms",
        "com.android.vending",
        "com.eltavine.duckdetector",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: "debug".to_string(),
        }
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_packages: Vec::new(),
            block_android_package: true,
            allow_unknown_package: false,
        }
    }
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            get_security_level: true,
            get_key_entry: true,
            update_subcomponent: true,
            list_entries: true,
            delete_key: true,
            grant: true,
            ungrant: true,
            get_number_of_entries: true,
            list_entries_batched: true,
            get_supplementary_attestation_info: true,
        }
    }
}

#[derive(Debug)]
enum LoadError {
    Missing(io::Error),
    Io(io::Error),
    Parse(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(error) | Self::Io(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LoadContext {
    Startup,
    Reload(WatchTrigger),
}

#[derive(Deserialize)]
struct ScoopHeaderValue {
    package: String,
}

#[derive(Deserialize)]
struct ConfigVersion {
    version: Option<toml::Spanned<i64>>,
}

#[derive(Serialize)]
struct WritableConfig<'a> {
    main: &'a MainConfig,
    filter: &'a FilterConfig,
    intercept: &'a InterceptConfig,
}

static CONFIG: OnceLock<RwLock<Arc<InjectorConfig>>> = OnceLock::new();
static WATCHER_STARTED: OnceLock<()> = OnceLock::new();
static CONFIG_FILE_WRITE_LOCK: Mutex<()> = Mutex::new(());

impl LoadContext {
    fn label(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Reload(trigger) => trigger.label(),
        }
    }
}

pub fn get() -> Arc<InjectorConfig> {
    if CONFIG.get().is_none() || WATCHER_STARTED.get().is_none() {
        ensure_initialized();
    }
    Arc::clone(
        &CONFIG
            .get()
            .expect("injector config should be initialized")
            .read()
            .expect("injector config lock poisoned"),
    )
}

fn ensure_initialized() {
    let path = config_path();
    CONFIG.get_or_init(|| {
        RwLock::new(Arc::new(
            load_or_seed(&path, LoadContext::Startup)
                .expect("startup config loading always returns a fallback"),
        ))
    });
    WATCHER_STARTED.get_or_init(|| start_watcher(path));
}

fn config_path() -> PathBuf {
    std::env::var_os("OMK_INJECTOR_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn load_from_path(path: &Path, allow_migration: bool) -> Result<InjectorConfig, LoadError> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| LoadError::Io(io::Error::other("config file write lock poisoned")))?;
    let contents = fs::read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            LoadError::Missing(error)
        } else {
            LoadError::Io(error)
        }
    })?;
    let (config, migrated_contents) =
        parse_versioned_config(&contents, allow_migration).map_err(LoadError::Parse)?;
    if let Some(migrated_contents) = migrated_contents {
        let (default_uid, default_gid) = default_owner(path);
        atomic_replace_preserving_metadata(
            path,
            migrated_contents.as_bytes(),
            0o600,
            default_uid,
            default_gid,
        )
        .map_err(LoadError::Io)?;
        log::info!("migrated injector.toml to version {CURRENT_CONFIG_VERSION}");
    }
    Ok(config)
}

fn load_with_context(
    path: &Path,
    context: LoadContext,
) -> Result<RetryOutcome<InjectorConfig>, LoadError> {
    match context {
        LoadContext::Reload(trigger) if trigger.should_retry_reads() => load_with_read_race_retry(
            path,
            context,
            |path| load_from_path(path, false),
            std::thread::sleep,
        ),
        LoadContext::Startup => {
            load_from_path(path, true).map(|value| RetryOutcome { value, retries: 0 })
        }
        LoadContext::Reload(_) => {
            load_from_path(path, false).map(|value| RetryOutcome { value, retries: 0 })
        }
    }
}

fn load_or_seed(path: &Path, context: LoadContext) -> Option<InjectorConfig> {
    match load_with_context(path, context) {
        Ok(loaded) => {
            if loaded.retries > 0 {
                log::info!(
                    "{} config load from {} succeeded after {} retr{}",
                    context.label(),
                    path.display(),
                    loaded.retries,
                    if loaded.retries == 1 { "y" } else { "ies" }
                );
            }
            if matches!(context, LoadContext::Startup) {
                log::info!(
                    "loaded config from {} via {}",
                    path.display(),
                    context.label()
                );
            }
            Some(loaded.value)
        }
        Err(LoadError::Missing(error)) if matches!(context, LoadContext::Startup) => {
            log::warn!(
                "config missing at {} during startup: {}; seeding defaults",
                path.display(),
                error
            );
            let mut config = InjectorConfig::default();
            if let Err(write_error) = write_config(path, &config) {
                log::error!(
                    "failed to seed config at {}: {}; disabling injector",
                    path.display(),
                    write_error
                );
                config.main.enabled = false;
            }
            Some(config)
        }
        Err(error) => {
            log::warn!(
                "load from {} via {} failed: {}; keeping current config",
                path.display(),
                context.label(),
                error
            );
            if matches!(context, LoadContext::Startup) {
                let mut config = current_config_snapshot();
                config.main.enabled = false;
                Some(config)
            } else {
                None
            }
        }
    }
}

fn current_config_snapshot() -> InjectorConfig {
    match CONFIG.get() {
        Some(lock) => match lock.read() {
            Ok(config) => config.as_ref().clone(),
            Err(error) => {
                log::error!("current config lock poisoned while snapshotting: {}", error);
                InjectorConfig::default()
            }
        },
        None => InjectorConfig::default(),
    }
}

fn write_config(path: &Path, config: &InjectorConfig) -> io::Result<()> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| io::Error::other("config file write lock poisoned"))?;
    let contents = render_config(config)?;
    write_config_contents(path, &contents)
}

fn write_config_contents(path: &Path, contents: &str) -> io::Result<()> {
    let (default_uid, default_gid) = default_owner(path);
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o600, default_uid, default_gid)?;
    log::info!("wrote config to {}", path.display());
    Ok(())
}

pub fn read_scoop_for_webui() -> Result<Vec<String>, String> {
    read_scoop_from_path(&config_path())
}

pub fn replace_scoop_for_webui(packages: Vec<String>) -> Result<(), String> {
    replace_scoop_at_path(&config_path(), packages)
}

fn read_scoop_from_path(path: &Path) -> Result<Vec<String>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let (config, _) = parse_versioned_config(&contents, false)?;
    Ok(config.scoop)
}

fn replace_scoop_at_path(path: &Path, packages: Vec<String>) -> Result<(), String> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| "config file write lock poisoned".to_string())?;
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let (mut config, _) = parse_versioned_config(&contents, false)?;
    let packages = normalize_packages(packages);
    if let Some(package) = packages
        .iter()
        .find(|package| !is_valid_exact_package_name(package))
    {
        return Err(format!("invalid exact package name in scoop: {package}"));
    }
    config.scoop = packages;
    let rendered = render_config(&config)
        .map_err(|error| format!("failed to render {}: {error}", path.display()))?;
    parse_versioned_config(&rendered, false)
        .map_err(|error| format!("refusing to write invalid {}: {error}", path.display()))?;
    write_config_contents(path, &rendered)
        .map_err(|error| format!("failed to update {}: {error}", path.display()))
}

fn is_valid_exact_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn default_owner(path: &Path) -> (u32, u32) {
    if path == Path::new(DEFAULT_CONFIG_PATH) {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
}

fn render_config(config: &InjectorConfig) -> io::Result<String> {
    let mut contents = String::from(
        "# With `[filter].enabled = true`, a UID is intercepted when any package\n\
         # sharing that UID is listed in `scoop`.\n\
         # Filter deny settings still apply to every package resolved for the UID.\n\n",
    );
    contents.push_str(&format!("version = {}\n\n", config.version));
    contents.push_str(
        "# Add one exact package name per line. Blank lines and lines whose first non-space character is # are ignored.\n",
    );
    // Keep the package list easy to edit: bare one-package-per-line entries
    // are accepted by preprocess_config and intentionally omit TOML punctuation.
    contents.push_str("scoop = [\n");
    for package in &config.scoop {
        let package = package.trim();
        contents.push_str("  ");
        if is_bare_scoop_package(package) {
            contents.push_str(package);
        } else {
            contents.push('"');
            contents.push_str(&escape_toml_basic_string(package));
            contents.push_str("\",");
        }
        contents.push('\n');
    }
    contents.push_str("]\n\n");

    let base = toml::to_string_pretty(&WritableConfig {
        main: &config.main,
        filter: &config.filter,
        intercept: &config.intercept,
    })
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    contents.push_str(&base);

    for (package, table) in &config.scoop_details {
        contents.push('\n');
        contents.push_str("[scoop.");
        contents.push_str(package);
        contents.push_str("]\n");
        if !table.is_empty() {
            let table_body = toml::to_string_pretty(table)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            contents.push_str(&table_body);
        }
    }

    Ok(contents)
}

#[cfg(test)]
fn parse_config(contents: &str) -> Result<InjectorConfig, String> {
    parse_versioned_config(contents, true).map(|(config, _)| config)
}

fn parse_versioned_config(
    contents: &str,
    allow_migration: bool,
) -> Result<(InjectorConfig, Option<String>), String> {
    let without_bom = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let bom_len = contents.len() - without_bom.len();
    let preprocessed = preprocess_config(without_bom)?;
    let version: ConfigVersion =
        toml::from_str(&preprocessed).map_err(|error| error.to_string())?;
    let migrated = match version.version {
        None => {
            if !allow_migration {
                return Err(
                    "injector config version 0 requires an injector restart to migrate".into(),
                );
            }
            Some(insert_config_version(contents, bom_len))
        }
        Some(version) => match *version.get_ref() {
            0 if allow_migration => Some(replace_config_version(contents, bom_len)?),
            0 => {
                return Err(
                    "injector config version 0 requires an injector restart to migrate".into(),
                )
            }
            version if version == i64::from(CURRENT_CONFIG_VERSION) => None,
            version if version < 0 => {
                return Err(format!("config version must not be negative: {version}"))
            }
            version => {
                return Err(format!(
                "config version {version} is newer than supported version {CURRENT_CONFIG_VERSION}"
            ))
            }
        },
    };
    let candidate = migrated.as_deref().unwrap_or(contents);
    let candidate = candidate.strip_prefix('\u{feff}').unwrap_or(candidate);
    let preprocessed = preprocess_config(candidate)?;
    let parsed: InjectorConfig =
        toml::from_str(&preprocessed).map_err(|error| error.to_string())?;
    Ok((parsed.normalized(), migrated))
}

fn insert_config_version(contents: &str, bom_len: usize) -> String {
    let newline = if contents.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut migrated = String::with_capacity(contents.len() + 12);
    migrated.push_str(&contents[..bom_len]);
    migrated.push_str("version = 1");
    migrated.push_str(newline);
    migrated.push_str(&contents[bom_len..]);
    migrated
}

fn replace_config_version(contents: &str, bom_len: usize) -> Result<String, String> {
    // Bare scoop entries are expanded before TOML parsing, so a span from the
    // preprocessed text cannot safely be applied to the original file.
    let without_bom = &contents[bom_len..];
    let mut line_offset = 0;

    for line in without_bom.split_inclusive('\n') {
        let line_body = line.strip_suffix('\n').unwrap_or(line);
        let line_body = line_body.strip_suffix('\r').unwrap_or(line_body);
        let trimmed = line_body.trim_start();
        let Some(after_name) = version_key_suffix(trimmed) else {
            line_offset += line.len();
            continue;
        };
        let Some(after_equals) = after_name.trim_start().strip_prefix('=') else {
            line_offset += line.len();
            continue;
        };
        let value = after_equals.trim_start();
        let token_end = value
            .find(|character: char| character.is_whitespace() || character == '#')
            .unwrap_or(value.len());
        if token_end == 0 {
            line_offset += line.len();
            continue;
        }

        let value_offset = line_body.len() - value.len();
        let start = bom_len + line_offset + value_offset;
        let end = start + token_end;
        let mut migrated = contents.to_string();
        migrated.replace_range(start..end, "1");
        return Ok(migrated);
    }

    Err("config version 0 was parsed but its source value could not be located".to_string())
}

fn version_key_suffix(line: &str) -> Option<&str> {
    if let Some(after_name) = line.strip_prefix("version") {
        if after_name.chars().next().is_some_and(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
        }) {
            return None;
        }
        return Some(after_name);
    }

    let quote = line
        .chars()
        .next()
        .filter(|character| *character == '"' || *character == '\'')?;
    let close = if quote == '"' {
        let mut escaped = false;
        line.char_indices().skip(1).find_map(|(index, character)| {
            if escaped {
                escaped = false;
                None
            } else if character == '\\' {
                escaped = true;
                None
            } else if character == quote {
                Some(index)
            } else {
                None
            }
        })?
    } else {
        line.char_indices()
            .skip(1)
            .find_map(|(index, character)| (character == quote).then_some(index))?
    };
    let key_fragment = &line[..=close];
    let parsed = toml::from_str::<toml::Value>(&format!("key = {key_fragment}")).ok()?;
    let key = parsed.get("key").and_then(toml::Value::as_str)?;
    (key == "version").then(|| &line[close + quote.len_utf8()..])
}

fn preprocess_config(contents: &str) -> Result<String, String> {
    let mut rewritten = String::with_capacity(contents.len());
    let mut scoop_array_depth = 0i32;

    for (line_no, line) in contents.split_inclusive('\n').enumerate() {
        let (line_body, ending) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        let (line_body, has_carriage_return) = match line_body.strip_suffix('\r') {
            Some(body) => (body, true),
            None => (line_body, false),
        };
        let mut body = line_body.to_string();

        if scoop_array_depth > 0 {
            body = rewrite_scoop_array_entry(&body);
            scoop_array_depth = (scoop_array_depth + scoop_bracket_delta(&body)).max(0);
        } else if let Some(open_index) = scoop_array_open_index(&body) {
            scoop_array_depth = scoop_bracket_delta(&body[open_index..]).max(0);
        }

        let body = rewrite_scoop_header(&body, line_no + 1)?;
        rewritten.push_str(&body);
        if has_carriage_return {
            rewritten.push('\r');
        }
        rewritten.push_str(ending);
    }
    Ok(rewritten)
}

fn scoop_array_open_index(line: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    let after_name = trimmed.strip_prefix("scoop")?;
    if after_name
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return None;
    }
    let after_equals = after_name.trim_start().strip_prefix('=')?.trim_start();
    after_equals
        .starts_with('[')
        .then(|| line.len() - after_equals.len())
}

fn scoop_bracket_delta(text: &str) -> i32 {
    let mut delta = 0;
    let mut quote = None;
    let mut escaped = false;

    for character in text.chars() {
        if let Some(active_quote) = quote {
            match active_quote {
                '"' => {
                    if escaped {
                        escaped = false;
                    } else if character == '\\' {
                        escaped = true;
                    } else if character == '"' {
                        quote = None;
                    }
                }
                '\'' if character == '\'' => quote = None,
                _ => {}
            }
            continue;
        }

        match character {
            '"' | '\'' => quote = Some(character),
            '#' => break,
            '[' => delta += 1,
            ']' => delta -= 1,
            _ => {}
        }
    }

    delta
}

fn rewrite_scoop_array_entry(line: &str) -> String {
    let trimmed = line.trim_start();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || matches!(trimmed.as_bytes().first(), Some(b'"' | b'\'' | b']'))
    {
        return line.to_string();
    }

    let (value, comment) = match trimmed.find('#') {
        Some(index) => (&trimmed[..index], Some(&trimmed[index..])),
        None => (trimmed, None),
    };
    let mut value = value.trim_end();
    if let Some(without_comma) = value.strip_suffix(',') {
        value = without_comma.trim_end();
    }
    if !is_bare_scoop_package(value) {
        return line.to_string();
    }

    let leading = &line[..line.len() - trimmed.len()];
    let mut rewritten = String::with_capacity(line.len() + 4);
    rewritten.push_str(leading);
    rewritten.push('"');
    rewritten.push_str(&escape_toml_basic_string(value));
    rewritten.push_str("\",");
    if let Some(comment) = comment {
        rewritten.push(' ');
        rewritten.push_str(comment.trim_start());
    }
    rewritten
}

fn is_bare_scoop_package(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            !character.is_whitespace()
                && !matches!(
                    character,
                    '"' | '\'' | '[' | ']' | '{' | '}' | '=' | ',' | '#'
                )
        })
}

fn escape_toml_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character => escaped.push(character),
        }
    }
    escaped
}

fn rewrite_scoop_header(line: &str, line_no: usize) -> Result<String, String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("[[") || !trimmed.starts_with("[scoop.") {
        return Ok(line.to_string());
    }

    let leading = &line[..line.len() - trimmed.len()];
    let Some(close_idx) = trimmed.find(']') else {
        return Err(format!(
            "line {line_no}: unterminated [scoop.<package>] header"
        ));
    };
    let header = &trimmed[..=close_idx];
    let trailer = &trimmed[close_idx + 1..];
    let header_body = &header[1..header.len() - 1];
    let package_fragment = header_body
        .strip_prefix("scoop.")
        .ok_or_else(|| format!("line {line_no}: invalid scoop header"))?;
    let package = decode_scoop_package_header(package_fragment.trim(), line_no)?;

    Ok(format!("{leading}[scoop_details.{package:?}]{trailer}"))
}

fn decode_scoop_package_header(fragment: &str, line_no: usize) -> Result<String, String> {
    if fragment.is_empty() {
        return Err(format!("line {line_no}: empty scoop package name"));
    }

    if (fragment.starts_with('"') && fragment.ends_with('"'))
        || (fragment.starts_with('\'') && fragment.ends_with('\''))
    {
        let wrapped = format!("package = {fragment}");
        let decoded: ScoopHeaderValue =
            toml::from_str(&wrapped).map_err(|error| format!("line {line_no}: {error}"))?;
        let package = decoded.package.trim();
        if package.is_empty() {
            return Err(format!("line {line_no}: empty scoop package name"));
        }
        return Ok(package.to_string());
    }

    Ok(fragment.to_string())
}

fn normalize_packages(packages: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for package in packages {
        let package = package.trim();
        if !package.is_empty() && seen.insert(package.to_string()) {
            normalized.push(package.to_string());
        }
    }
    normalized
}

fn normalize_scoop_details(
    details: BTreeMap<String, toml::Table>,
) -> BTreeMap<String, toml::Table> {
    let mut normalized = BTreeMap::new();
    for (package, table) in details {
        let package = package.trim();
        if !package.is_empty() {
            normalized.insert(package.to_string(), table);
        }
    }
    normalized
}

fn start_watcher(path: PathBuf) {
    let reload_path = path.clone();
    if let Err(error) =
        file_watch::spawn_path_watcher("injector-config-watch", path, move |trigger| {
            reload_runtime_config(&reload_path, trigger);
        })
    {
        log::error!("failed to start config watcher thread: {}", error);
    }
}

fn reload_runtime_config(path: &Path, trigger: WatchTrigger) {
    let Some(config) = load_or_seed(path, LoadContext::Reload(trigger)) else {
        return;
    };
    if let Some(lock) = CONFIG.get() {
        match lock.write() {
            Ok(mut guard) => {
                let level = config.main.log_level_filter();
                *guard = Arc::new(config);
                log::set_max_level(level);
                log::info!(
                    "reloaded config from {} via {}",
                    path.display(),
                    trigger.label()
                );
            }
            Err(error) => {
                log::error!(
                    "failed to apply config reload from {}: {}",
                    path.display(),
                    error
                );
            }
        }
    }
}

fn load_with_read_race_retry<F, S>(
    path: &Path,
    context: LoadContext,
    mut loader: F,
    sleeper: S,
) -> Result<RetryOutcome<InjectorConfig>, LoadError>
where
    F: FnMut(&Path) -> Result<InjectorConfig, LoadError>,
    S: FnMut(Duration),
{
    retry_read_race(
        || loader(path),
        |error| match error {
            LoadError::Missing(_) | LoadError::Io(_) => ReadRaceErrorKind::Retryable,
            LoadError::Parse(_) => ReadRaceErrorKind::Fatal,
        },
        REPLACE_SAVE_RETRY_LIMIT,
        REPLACE_SAVE_RETRY_INTERVAL,
        sleeper,
        |retries, error, interval| {
            log::warn!(
                "{} config load from {} hit read-side race on retry {}/{}: {}; waiting {} ms",
                context.label(),
                path.display(),
                retries,
                REPLACE_SAVE_RETRY_LIMIT,
                error,
                interval.as_millis()
            );
        },
    )
}

pub fn parse_level_filter(value: &str) -> Option<LevelFilter> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

impl MainConfig {
    pub fn log_level_filter(&self) -> LevelFilter {
        parse_level_filter(&self.log_level).unwrap_or(LevelFilter::Debug)
    }
}

impl InjectorConfig {
    fn normalized(mut self) -> Self {
        self.scoop = normalize_packages(self.scoop);
        self.scoop_details = normalize_scoop_details(self.scoop_details);
        self
    }
}

#[cfg(test)]
mod tests;
