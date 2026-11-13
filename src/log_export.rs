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

//! Collects the OMK runtime logs into one support archive on shared storage.
//!
//! The archive never includes `config.toml` or `keybox.xml`: both carry device
//! identifiers and key material. It does carry a manifest describing the device
//! it came from so a report can be triaged without asking for those files.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// Directory the loggers append to.
const LOG_DIR: &str = "/data/misc/keystore/omk/logs";
/// Shared storage the WebUI host can read without root.
const EXPORT_DIR: &str = "/sdcard/Download";
/// Newest-first rotated log pair per process.
const LOG_FILES: [&str; 4] = ["keymint.log", "keymint.log.1", "injector.log", "injector.log.1"];
/// Larger files keep only their tail, which is where the failure is.
const MAX_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
/// Total payload budget for one archive.
const MAX_ARCHIVE_BYTES: u64 = 24 * 1024 * 1024;
const BLOCK: usize = 512;

struct ArchiveEntry {
    name: String,
    data: Vec<u8>,
    dropped_bytes: Option<u64>,
}

/// Writes the current logs to `/sdcard/Download` and returns the archive path.
pub(crate) fn export_logs() -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let archive = Path::new(EXPORT_DIR).join(format!("omk-logs-{}.tar", stamp(now)));
    let parent = archive.parent().unwrap_or_else(|| Path::new(EXPORT_DIR));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0_u64;
    for name in LOG_FILES {
        let path = Path::new(LOG_DIR).join(name);
        let Ok(metadata) = fs::metadata(&path) else { continue };
        if !metadata.is_file() {
            continue;
        }
        let budget = MAX_ARCHIVE_BYTES.saturating_sub(total);
        if budget == 0 {
            skipped.push(name);
            continue;
        }
        let limit = MAX_ENTRY_BYTES.min(budget);
        let (data, dropped_bytes) = read_tail(&path, metadata.len(), limit)
            .with_context(|| format!("read {}", path.display()))?;
        total = total.saturating_add(data.len() as u64);
        entries.push(ArchiveEntry { name: format!("logs/{name}"), data, dropped_bytes });
    }

    let manifest = manifest(now, &entries, &skipped);
    let mut file =
        File::create(&archive).with_context(|| format!("create {}", archive.display()))?;
    write_archive(&mut file, &manifest, &entries, now)
        .with_context(|| format!("write {}", archive.display()))?;
    file.flush().with_context(|| format!("flush {}", archive.display()))?;
    file.sync_all().ok();
    Ok(archive)
}

/// Reads the tail of a log file, dropping a partial first line when truncated.
fn read_tail(path: &Path, size: u64, limit: u64) -> Result<(Vec<u8>, Option<u64>)> {
    let mut file = File::open(path)?;
    if size <= limit {
        let mut data = Vec::with_capacity(size as usize);
        file.read_to_end(&mut data)?;
        return Ok((data, None));
    }

    let dropped = size - limit;
    file.seek(SeekFrom::Start(dropped))?;
    let mut data = Vec::with_capacity(limit as usize);
    file.take(limit).read_to_end(&mut data)?;
    // The first line of a tail read is usually cut mid-record; drop it so every
    // line in the archive is complete.
    if let Some(newline) = data.iter().position(|byte| *byte == b'\n') {
        data.drain(..=newline);
    }
    Ok((data, Some(dropped)))
}

fn manifest(now: u64, entries: &[ArchiveEntry], skipped: &[&str]) -> Vec<u8> {
    let mut text = String::new();
    text.push_str("OhMyKeymint log export\n");
    text.push_str(&format!("generated: {}\n", iso8601(now)));
    text.push_str(&format!("package-version: {}\n", env!("CARGO_PKG_VERSION")));
    for (label, property) in [
        ("device-brand", "ro.product.brand"),
        ("device-model", "ro.product.model"),
        ("android-release", "ro.build.version.release"),
        ("android-sdk", "ro.build.version.sdk"),
        ("build-fingerprint", "ro.build.fingerprint"),
    ] {
        let value = rsproperties::get::<String>(property).unwrap_or_else(|_| "unknown".to_string());
        text.push_str(&format!("{label}: {value}\n"));
    }
    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        text.push_str(&format!("kernel-release: {}\n", release.trim()));
    }
    text.push_str("\nfiles:\n");
    for entry in entries {
        match entry.dropped_bytes {
            Some(dropped) => text.push_str(&format!(
                "  {}: {} bytes (older {} bytes omitted)\n",
                entry.name,
                entry.data.len(),
                dropped
            )),
            None => {
                text.push_str(&format!("  {}: {} bytes\n", entry.name, entry.data.len()));
            }
        }
    }
    if !skipped.is_empty() {
        text.push_str("\nskipped (archive byte budget reached):\n");
        for name in skipped {
            text.push_str(&format!("  logs/{name}\n"));
        }
    }
    text.push_str(
        "\nexcluded: config.toml and keybox.xml are never exported because they contain \
         device identifiers and key material.\n",
    );
    text.into_bytes()
}

fn write_archive<W: Write>(
    writer: &mut W,
    manifest: &[u8],
    entries: &[ArchiveEntry],
    modified: u64,
) -> io::Result<()> {
    write_entry(writer, "manifest.txt", manifest, modified)?;
    for entry in entries {
        write_entry(writer, &entry.name, &entry.data, modified)?;
    }
    // Two zero blocks terminate a tar stream.
    writer.write_all(&[0_u8; BLOCK * 2])
}

fn write_entry<W: Write>(writer: &mut W, name: &str, data: &[u8], modified: u64) -> io::Result<()> {
    let header = tar_header(name, data.len() as u64, modified)?;
    writer.write_all(&header)?;
    writer.write_all(data)?;
    let padding = (BLOCK - data.len() % BLOCK) % BLOCK;
    if padding > 0 {
        writer.write_all(&vec![0_u8; padding])?;
    }
    Ok(())
}

/// Builds a ustar header for a regular file. Only short names are used here.
fn tar_header(name: &str, size: u64, modified: u64) -> io::Result<[u8; BLOCK]> {
    let mut header = [0_u8; BLOCK];
    if name.len() > 100 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "tar entry name is too long"));
    }
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(format!("{modified:011o}\0").as_bytes());
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..269].copy_from_slice(b"omk\0");
    header[297..301].copy_from_slice(b"omk\0");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    Ok(header)
}

/// `YYYYmmdd-HHMMSS` in UTC, used for the archive name.
fn stamp(seconds: u64) -> String {
    let (year, month, day, hour, minute, second) = parts(seconds);
    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}")
}

/// `YYYY-MM-DD HH:MM:SS UTC`, used inside the manifest.
fn iso8601(seconds: u64) -> String {
    let (year, month, day, hour, minute, second) = parts(seconds);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn parts(seconds: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = (rest / 3_600) as u32;
    let minute = ((rest % 3_600) / 60) as u32;
    let second = (rest % 60) as u32;
    (year, month, day, hour, minute, second)
}

/// Days since the Unix epoch to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_match_known_instants() {
        assert_eq!(stamp(0), "19700101-000000");
        assert_eq!(iso8601(0), "1970-01-01 00:00:00 UTC");
        // 2026-11-14T00:00:00Z and 2026-11-14T05:20:00Z
        assert_eq!(stamp(1_794_614_400), "20261114-000000");
        assert_eq!(iso8601(1_794_633_600), "2026-11-14 05:20:00 UTC");
    }

    #[test]
    fn tar_header_records_name_size_and_checksum() {
        let header = tar_header("manifest.txt", 42, 1_794_614_400).unwrap();
        assert_eq!(&header[..12], b"manifest.txt");
        assert_eq!(&header[124..136], b"00000000052\0"); // 42 decimal as octal
        assert_eq!(&header[156..157], b"0");
        assert_eq!(&header[257..263], b"ustar\0");
        let recorded = std::str::from_utf8(&header[148..156]).unwrap();
        let checksum = u32::from_str_radix(recorded[..6].trim(), 8).unwrap();
        let mut zeroed = header;
        zeroed[148..156].copy_from_slice(b"        ");
        assert_eq!(checksum, zeroed.iter().map(|byte| u32::from(*byte)).sum::<u32>());
    }

    #[test]
    fn manifest_names_skipped_files_and_exclusions() {
        let text = String::from_utf8(manifest(0, &[], &["injector.log"])).unwrap();
        assert!(text.contains("skipped (archive byte budget reached):"));
        assert!(text.contains("  logs/injector.log"));
        assert!(text.contains("config.toml and keybox.xml are never exported"));
    }

    #[test]
    fn long_entry_names_are_rejected() {
        assert!(tar_header(&"a".repeat(101), 0, 0).is_err());
    }
}
