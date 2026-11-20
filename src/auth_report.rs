// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Summarizes authentication-token and SOTER evidence from the rotating logs.
//!
//! A failing biometric or passkey operation is already distinguishable in the
//! log by its structured event and stage. This report counts those events over a
//! bounded tail so a user can report one short JSON blob instead of the log.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
};

use anyhow::{Context, Result};
use serde::Serialize;

/// Bytes read from the end of one log file.
const WINDOW_BYTES: u64 = 1024 * 1024;
/// Counted `event=<name>` values written by the keymint and injector paths.
const EVENTS: [&str; 8] = [
    "auth_token_received",
    "auth_token_verification",
    "auth_token_cached",
    "auth_token_rejected",
    "auth_token_dropped",
    "auth_token_sid_mismatch",
    "auth_token_type_mismatch",
    "soter",
];

#[derive(Debug, Default, Serialize)]
pub struct AuthReport {
    /// Log files that existed, newest last.
    files: Vec<String>,
    /// Complete lines counted after discarding a partial first line.
    lines: usize,
    /// `event=auth_token_*` / `event=soter` counts.
    events: BTreeMap<String, usize>,
    /// Rejection and drop stages, for example `rejected:shape`.
    stages: BTreeMap<String, usize>,
    /// Verification modes, for example `mode:system_mac`.
    modes: BTreeMap<String, usize>,
    /// Token sources, for example `source:direct`.
    sources: BTreeMap<String, usize>,
    /// SOTER HAL replies that refused to sign without a fresh fingerprint.
    soter_no_fingerprint: usize,
    /// Effective compatibility switch at report time.
    force_skip_system_biometric_hat_verification: Option<bool>,
}

/// Read the current and rotated logs and summarize them.
pub fn auth_report() -> Result<String> {
    let mut report = AuthReport::default();
    for path in [
        crate::root_path!("logs/keymint.log.1"),
        crate::root_path!("logs/keymint.log"),
        crate::root_path!("logs/injector.log.1"),
        crate::root_path!("logs/injector.log"),
    ] {
        let Ok(mut file) = File::open(path) else { continue };
        let length = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        if length > WINDOW_BYTES {
            file.seek(SeekFrom::Start(length - WINDOW_BYTES))
                .map_err(|error| anyhow::anyhow!("seek {path}: {error}"))
                .ok();
        }
        let mut window = Vec::new();
        file.read_to_end(&mut window).with_context(|| format!("read {path}"))?;
        let text = String::from_utf8_lossy(&window);
        // A tail read usually starts mid-record; skip that partial line.
        let text = match text.find('\n') {
            Some(position) if length > WINDOW_BYTES => &text[position + 1..],
            _ => &text[..],
        };
        summarize(text, &mut report);
        report.files.push(path.to_string());
    }
    // A WebUI helper is a short-lived process, so the global config may not be
    // bootstrapped; read the file in that case instead of reporting nothing.
    report.force_skip_system_biometric_hat_verification = crate::config::CONFIG
        .get()
        .and_then(|config| config.read().ok())
        .map(|config| config.main.force_skip_system_biometric_hat_verification)
        .or_else(|| {
            crate::config::load_config_file()
                .ok()
                .map(|file| file.main.force_skip_system_biometric_hat_verification)
        });
    serde_json::to_string(&report).context("encode authentication report")
}

/// Count one window of log lines. Separated from file handling so it is testable.
fn summarize(text: &str, report: &mut AuthReport) {
    for line in text.lines() {
        report.lines += 1;
        if let Some(name) = event_name(line) {
            if EVENTS.contains(&name) {
                *report.events.entry(name.to_string()).or_default() += 1;
            }
        }
        if let Some(stage) = field(line, "stage=") {
            // Only keep stages that belong to token handling; a SOTER HAL stage is
            // already represented by `events.soter`.
            if line.contains("event=auth_token_") {
                *report.stages.entry(stage.to_string()).or_default() += 1;
            }
        }
        if let Some(mode) = field(line, "mode=") {
            *report.modes.entry(mode.to_string()).or_default() += 1;
        }
        if let Some(source) = field(line, "source=") {
            *report.sources.entry(source.to_string()).or_default() += 1;
        }
        if line.contains("event=soter") && line.contains("result=-26") {
            report.soter_no_fingerprint += 1;
        }
    }
}

fn event_name(line: &str) -> Option<&str> {
    let start = line.find("event=")? + "event=".len();
    let rest = &line[start..];
    let end = rest.find(|character: char| !character.is_ascii_alphanumeric() && character != '_');
    Some(match end {
        Some(position) => &rest[..position],
        None => rest,
    })
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest
        .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .unwrap_or(rest.len());
    let value = &rest[..end];
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        "2026-11-18 10:00:00 UTC [INFO] omk - event=auth_token_received source=direct authType=0x2\n",
        "2026-11-18 10:00:00 UTC [DEBUG] omk - event=auth_token_verification mode=biometric_compatibility authType=0x2\n",
        "2026-11-18 10:00:01 UTC [DEBUG] omk - event=auth_token_cached stage=localized\n",
        "2026-11-18 10:00:02 UTC [WARN] omk - event=auth_token_rejected stage=localization: stale token\n",
        "2026-11-18 10:00:03 UTC [WARN] omk - event=auth_token_sid_mismatch key=abcd\n",
        "2026-11-18 10:00:04 UTC [INFO] omk_soter_local - event=soter path=native_local stage=hal_reply uid=1 result=-26\n",
        "2026-11-18 10:00:05 UTC [INFO] omk_soter_local - event=soter path=native_local stage=hal_reply uid=1 result=0\n",
        "unrelated line without events\n",
    );

    #[test]
    fn counts_events_stages_modes_and_sources() {
        let mut report = AuthReport::default();
        summarize(SAMPLE, &mut report);
        assert_eq!(report.lines, 8);
        assert_eq!(report.events["auth_token_received"], 1);
        assert_eq!(report.events["auth_token_verification"], 1);
        assert_eq!(report.events["auth_token_cached"], 1);
        assert_eq!(report.events["auth_token_rejected"], 1);
        assert_eq!(report.events["auth_token_sid_mismatch"], 1);
        assert_eq!(report.events["soter"], 2);
        assert_eq!(report.soter_no_fingerprint, 1);
        assert_eq!(report.stages["localization"], 1);
        assert_eq!(report.modes["biometric_compatibility"], 1);
        assert_eq!(report.sources["direct"], 1);
    }

    #[test]
    fn soter_stages_do_not_pollute_token_stages() {
        let mut report = AuthReport::default();
        summarize(SAMPLE, &mut report);
        assert!(!report.stages.contains_key("hal_reply"));
    }

    #[test]
    fn event_name_stops_at_punctuation() {
        assert_eq!(event_name("x event=auth_token_rejected: y"), Some("auth_token_rejected"));
        assert_eq!(event_name("x event=auth_token_cached"), Some("auth_token_cached"));
        assert_eq!(event_name("no event here"), None);
    }
}
