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

use std::boxed::Box;
use std::collections::HashMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{eprintln, format, vec::Vec};

use anyhow::{anyhow, Context as _};
use log::{Level, LevelFilter, Log, Metadata as LogMetadata, Record};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::{writer::simple::SimpleWriter, Encode};

pub const DEFAULT_MAX_LOG_SIZE_BYTES: u64 = 4 * 1024 * 1024;

const MAX_RATE_LIMIT_SITES: usize = 512;
const WARNING_WINDOW: Duration = Duration::from_secs(30);
const WARNING_BURST: u32 = 4;
const VERBOSE_WINDOW: Duration = Duration::from_secs(1);
const VERBOSE_BURST: u32 = 32;

/// Apply the same bounded burst policy before logs reach Android and files.
///
/// Warn, Debug, Trace and high-volume SOTER diagnostic Info are limited. Errors
/// always reach the underlying logger; other Info stays available for state changes. Buckets
/// contain source metadata and counts, never a formatted message or payload.
pub struct RateLimitedLogger<L> {
    inner: L,
    limiter: Mutex<LogRateLimiter>,
}

impl<L: Log> RateLimitedLogger<L> {
    pub fn new(inner: L) -> Self {
        Self {
            inner,
            limiter: Mutex::new(LogRateLimiter::default()),
        }
    }

    fn log_at(&self, record: &Record, now: Instant) {
        if !self.inner.enabled(record.metadata()) {
            return;
        }
        let decision = self
            .limiter
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .admit(record, now);
        if let Some(summary) = decision.summary {
            self.publish_summary(summary);
        }
        if decision.publish {
            self.inner.log(record);
        }
    }

    fn publish_summary(&self, summary: SuppressedLogs) {
        let site = summary.site;
        self.inner.log(
            &Record::builder()
                .level(site.level)
                .target(&site.target)
                .module_path(site.module.as_deref())
                .file(site.file.as_deref())
                .line(site.line)
                .args(format_args!(
                    "event=log_rate_limit suppressed={} window_ms={} source_line={}",
                    summary.count,
                    summary.window.as_millis(),
                    site.line.unwrap_or(0),
                ))
                .build(),
        );
    }
}

impl<L: Log> Log for RateLimitedLogger<L> {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        self.log_at(record, Instant::now());
    }

    fn flush(&self) {
        let summaries = self
            .limiter
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take_summaries();
        for summary in summaries {
            self.publish_summary(summary);
        }
        self.inner.flush();
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct LogSite {
    level: Level,
    target: String,
    module: Option<String>,
    file: Option<String>,
    line: Option<u32>,
}

impl From<&Record<'_>> for LogSite {
    fn from(record: &Record<'_>) -> Self {
        Self {
            level: record.level(),
            target: record.target().to_owned(),
            module: record.module_path().map(str::to_owned),
            file: record.file().map(str::to_owned),
            line: record.line(),
        }
    }
}

struct LogWindow {
    started: Instant,
    last_seen: Instant,
    published: u32,
    suppressed: u64,
}

struct SuppressedLogs {
    site: LogSite,
    count: u64,
    window: Duration,
}

struct LogDecision {
    publish: bool,
    summary: Option<SuppressedLogs>,
}

#[derive(Default)]
struct LogRateLimiter {
    sites: HashMap<LogSite, LogWindow>,
}

fn log_rate_policy(level: Level, target: &str) -> Option<(Duration, u32)> {
    match level {
        Level::Warn => Some((WARNING_WINDOW, WARNING_BURST)),
        Level::Debug | Level::Trace => Some((VERBOSE_WINDOW, VERBOSE_BURST)),
        Level::Info if target == "omk_soter_remote" => Some((VERBOSE_WINDOW, VERBOSE_BURST)),
        Level::Error | Level::Info => None,
    }
}

impl LogRateLimiter {
    fn admit(&mut self, record: &Record, now: Instant) -> LogDecision {
        let Some((window, burst)) = log_rate_policy(record.level(), record.target()) else {
            return LogDecision {
                publish: true,
                summary: None,
            };
        };
        let site = LogSite::from(record);
        let mut summary = None;
        if !self.sites.contains_key(&site) && self.sites.len() >= MAX_RATE_LIMIT_SITES {
            if let Some(oldest) = self
                .sites
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_seen)
                .map(|(site, _)| site.clone())
            {
                if let Some(bucket) = self.sites.remove(&oldest) {
                    if bucket.suppressed != 0 {
                        summary = Some(SuppressedLogs {
                            window: log_rate_policy(oldest.level, &oldest.target).unwrap().0,
                            site: oldest,
                            count: bucket.suppressed,
                        });
                    }
                }
            }
        }
        let bucket = self.sites.entry(site.clone()).or_insert(LogWindow {
            started: now,
            last_seen: now,
            published: 0,
            suppressed: 0,
        });
        bucket.last_seen = now;
        if now.saturating_duration_since(bucket.started) >= window {
            if bucket.suppressed != 0 {
                summary = Some(SuppressedLogs {
                    site,
                    count: bucket.suppressed,
                    window,
                });
            }
            bucket.started = now;
            bucket.published = 0;
            bucket.suppressed = 0;
        }
        if bucket.published < burst {
            bucket.published += 1;
            LogDecision {
                publish: true,
                summary,
            }
        } else {
            bucket.suppressed = bucket.suppressed.saturating_add(1);
            LogDecision {
                publish: false,
                summary,
            }
        }
    }

    fn take_summaries(&mut self) -> Vec<SuppressedLogs> {
        self.sites
            .iter_mut()
            .filter_map(|(site, bucket)| {
                let count = std::mem::take(&mut bucket.suppressed);
                (count != 0).then(|| SuppressedLogs {
                    site: site.clone(),
                    count,
                    window: log_rate_policy(site.level, &site.target).unwrap().0,
                })
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct LockedRotatingFileAppender {
    path: PathBuf,
    file: Mutex<Option<File>>,
    encoder: Box<dyn Encode>,
    max_size_bytes: u64,
}

impl LockedRotatingFileAppender {
    pub fn new<P: AsRef<Path>>(path: P, encoder: Box<dyn Encode>) -> io::Result<Self> {
        Self::with_max_size(path, encoder, DEFAULT_MAX_LOG_SIZE_BYTES)
    }

    pub fn with_max_size<P: AsRef<Path>>(
        path: P,
        encoder: Box<dyn Encode>,
        max_size_bytes: u64,
    ) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let _ = fs::remove_file(suffixed_path(&path, ".lock"));
        Ok(Self {
            path,
            file: Mutex::new(None),
            encoder,
            max_size_bytes,
        })
    }

    fn open_log_file(path: &Path) -> io::Result<File> {
        fs::create_dir_all(Self::parent_dir(path))?;
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let fd = file.as_raw_fd();
        if let Ok(parent_metadata) = fs::metadata(Self::parent_dir(path)) {
            let _ = unsafe { libc::fchown(fd, parent_metadata.uid(), parent_metadata.gid()) };
        }
        let _ = unsafe { libc::fchmod(fd, 0o660) };
        Ok(file)
    }

    fn parent_dir(path: &Path) -> &Path {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    fn rotate_if_needed(&self, next_write_len: usize) -> io::Result<Option<Metadata>> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };

        if metadata.len() == 0
            || metadata.len().saturating_add(next_write_len as u64) <= self.max_size_bytes
        {
            return Ok(Some(metadata));
        }

        rotate_existing_log_file(&self.path)?;
        Ok(None)
    }
}

fn rotate_existing_log_file(path: &Path) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }

    let rotated_path = suffixed_path(path, ".1");
    let ignore_not_found = |result: io::Result<()>| match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    };

    ignore_not_found(fs::remove_file(&rotated_path))?;
    ignore_not_found(fs::rename(path, &rotated_path))
}

impl Append for LockedRotatingFileAppender {
    fn append(&self, record: &Record) -> anyhow::Result<()> {
        let mut encoded = SimpleWriter(Vec::new());
        self.encoder
            .encode(&mut encoded, record)
            .with_context(|| format!("failed to encode {}", self.path.display()))?;
        let data = encoded.0;

        let mut file = self
            .file
            .lock()
            .map_err(|error| anyhow!("failed to lock log writer: {}", error))?;
        let _file_guard = FileLockGuard::lock_path(&self.path)
            .with_context(|| format!("failed to lock {}", self.path.display()))?;
        let metadata = self
            .rotate_if_needed(data.len())
            .with_context(|| format!("failed to rotate {}", self.path.display()))?;

        let cached_file_matches = match (file.as_ref(), metadata.as_ref()) {
            (Some(file), Some(metadata)) => file.metadata().is_ok_and(|cached| {
                cached.dev() == metadata.dev() && cached.ino() == metadata.ino()
            }),
            (Some(_), None) => false,
            (None, _) => true,
        };
        if !cached_file_matches {
            *file = None;
        }
        if file.is_none() {
            *file = Some(
                Self::open_log_file(&self.path)
                    .with_context(|| format!("failed to open {}", self.path.display()))?,
            );
        }

        if let Err(error) = file.as_mut().unwrap().write_all(&data) {
            *file = None;
            return Err(error).with_context(|| format!("failed to write {}", self.path.display()));
        }
        if let Err(error) = file.as_mut().unwrap().flush() {
            *file = None;
            return Err(error).with_context(|| format!("failed to flush {}", self.path.display()));
        }
        Ok(())
    }

    fn flush(&self) {}
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

struct FileLockGuard {
    #[cfg(unix)]
    file: File,
}

impl FileLockGuard {
    #[cfg(unix)]
    fn lock_path(path: &Path) -> io::Result<Self> {
        let parent = LockedRotatingFileAppender::parent_dir(path);
        let file = match File::open(parent) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(parent)?;
                File::open(parent)?
            }
            Err(error) => return Err(error),
        };
        let fd = file.as_raw_fd();
        let result = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if result == 0 {
            Ok(Self { file })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(unix))]
    fn lock_path(_path: &Path) -> io::Result<Self> {
        Ok(Self {})
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub fn build_console_file_config<P: AsRef<Path>>(
    file_path: P,
    pattern: &str,
    level: LevelFilter,
    error_prefix: &str,
) -> anyhow::Result<(Config, bool)> {
    let mut builder = Config::builder();
    let mut root = Root::builder();
    if fs::read_link("/proc/self/fd/1")
        .map(|target| target != Path::new("/dev/null"))
        .unwrap_or(true)
    {
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new(pattern)))
            .build();
        builder = builder.appender(Appender::builder().build("stdout", Box::new(stdout)));
        root = root.appender("stdout");
    }
    let path = file_path.as_ref();

    match FileLockGuard::lock_path(path).and_then(|_guard| rotate_existing_log_file(path)) {
        Ok(()) => {}
        Err(error) => eprintln!(
            "{} startup log refresh skipped for {}: {}",
            error_prefix,
            path.display(),
            error
        ),
    }

    let file_logging_ready =
        match LockedRotatingFileAppender::new(path, Box::new(PatternEncoder::new(pattern))) {
            Ok(file) => {
                builder = builder.appender(Appender::builder().build("file", Box::new(file)));
                root = root.appender("file");
                true
            }
            Err(error) => {
                eprintln!(
                    "{} file logging disabled for {}: {}",
                    error_prefix,
                    path.display(),
                    error
                );
                false
            }
        };

    Ok((builder.build(root.build(level))?, file_logging_ready))
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone, Default)]
    struct CapturedLogger {
        records: Arc<Mutex<Vec<(Level, String)>>>,
    }

    impl Log for CapturedLogger {
        fn enabled(&self, _metadata: &LogMetadata) -> bool {
            true
        }

        fn log(&self, record: &Record) {
            self.records
                .lock()
                .unwrap()
                .push((record.level(), record.args().to_string()));
        }

        fn flush(&self) {}
    }

    fn limited_message(
        logger: &RateLimitedLogger<CapturedLogger>,
        now: Instant,
        level: Level,
        source_line: u32,
    ) {
        logger.log_at(
            &Record::builder()
                .args(format_args!("event=test_runtime caller={source_line}"))
                .level(level)
                .target("runtime-test")
                .module_path(Some("logging::tests"))
                .file(Some("logging-test.rs"))
                .line(Some(source_line))
                .build(),
            now,
        );
    }

    #[test]
    fn repeated_warnings_preserve_the_burst_and_report_suppressed_count() {
        let sink = CapturedLogger::default();
        let logger = RateLimitedLogger::new(sink.clone());
        let now = Instant::now();
        for _ in 0..12 {
            limited_message(&logger, now, Level::Warn, 1);
        }
        assert_eq!(sink.records.lock().unwrap().len(), WARNING_BURST as usize);

        limited_message(&logger, now + WARNING_WINDOW, Level::Warn, 1);
        let records = sink.records.lock().unwrap();
        assert_eq!(records.len(), WARNING_BURST as usize + 2);
        assert_eq!(records[4].0, Level::Warn);
        assert_eq!(
            records[4].1,
            "event=log_rate_limit suppressed=8 window_ms=30000 source_line=1"
        );
        assert!(records[5].1.starts_with("event=test_runtime"));
    }

    #[test]
    fn warning_buckets_are_per_source_and_verbose_buckets_reset_independently() {
        let sink = CapturedLogger::default();
        let logger = RateLimitedLogger::new(sink.clone());
        let now = Instant::now();
        for _ in 0..40 {
            limited_message(&logger, now, Level::Debug, 1);
            limited_message(&logger, now, Level::Warn, 1);
        }
        limited_message(&logger, now, Level::Warn, 2);
        assert_eq!(
            sink.records.lock().unwrap().len(),
            (VERBOSE_BURST + WARNING_BURST + 1) as usize
        );
        limited_message(&logger, now + VERBOSE_WINDOW, Level::Debug, 1);
        limited_message(&logger, now + VERBOSE_WINDOW, Level::Warn, 1);
        let records = sink.records.lock().unwrap();
        assert_eq!(records.len(), (VERBOSE_BURST + WARNING_BURST + 3) as usize);
        assert!(records[37].1.contains("suppressed=8 window_ms=1000"));
    }

    #[test]
    fn soter_info_diagnostics_are_bounded_without_limiting_other_info() {
        let sink = CapturedLogger::default();
        let logger = RateLimitedLogger::new(sink.clone());
        let now = Instant::now();
        let record = Record::builder()
            .args(format_args!("event=soter path=native_remote stage=observe"))
            .level(Level::Info)
            .target("omk_soter_remote")
            .line(Some(1))
            .build();
        for _ in 0..40 {
            logger.log_at(&record, now);
        }
        assert_eq!(sink.records.lock().unwrap().len(), VERBOSE_BURST as usize);
        logger.log_at(&record, now + VERBOSE_WINDOW);
        let records = sink.records.lock().unwrap();
        assert!(records[VERBOSE_BURST as usize]
            .1
            .contains("suppressed=8 window_ms=1000"));
        assert_eq!(records.len(), VERBOSE_BURST as usize + 2);
        assert_eq!(log_rate_policy(Level::Info, "runtime-test"), None);
        assert_eq!(log_rate_policy(Level::Error, "omk_soter_remote"), None);
    }

    #[test]
    fn errors_and_state_changes_are_never_rate_limited() {
        let sink = CapturedLogger::default();
        let logger = RateLimitedLogger::new(sink.clone());
        let now = Instant::now();
        for _ in 0..100 {
            limited_message(&logger, now, Level::Error, 1);
            limited_message(&logger, now, Level::Info, 1);
        }
        assert_eq!(sink.records.lock().unwrap().len(), 200);
        assert!(logger.limiter.lock().unwrap().sites.is_empty());
    }

    #[test]
    fn flush_reports_counts_once_without_resetting_the_warning_budget() {
        let sink = CapturedLogger::default();
        let logger = RateLimitedLogger::new(sink.clone());
        let now = Instant::now();
        for _ in 0..5 {
            limited_message(&logger, now, Level::Warn, 1);
        }
        logger.flush();
        logger.flush();
        limited_message(&logger, now, Level::Warn, 1);
        assert_eq!(sink.records.lock().unwrap().len(), 5);
        logger.flush();
        assert_eq!(sink.records.lock().unwrap().len(), 6);
    }

    #[test]
    fn the_rate_limiter_retains_only_bounded_source_metadata() {
        let sink = CapturedLogger::default();
        let logger = RateLimitedLogger::new(sink);
        let now = Instant::now();
        for line in 0..MAX_RATE_LIMIT_SITES as u32 + 16 {
            limited_message(&logger, now, Level::Warn, line);
        }
        assert_eq!(
            logger.limiter.lock().unwrap().sites.len(),
            MAX_RATE_LIMIT_SITES
        );
    }

    #[test]
    fn concurrent_warnings_share_one_budget() {
        let sink = CapturedLogger::default();
        let logger = Arc::new(RateLimitedLogger::new(sink.clone()));
        let now = Instant::now();
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let logger = logger.clone();
                std::thread::spawn(move || {
                    for _ in 0..16 {
                        limited_message(&logger, now, Level::Warn, 1);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        logger.flush();
        let records = sink.records.lock().unwrap();
        assert_eq!(records.len(), WARNING_BURST as usize + 1);
        assert!(records[4].1.contains("suppressed=124"));
    }

    fn temp_log_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("omk-log-test-{}-{nanos}", std::process::id()))
            .join(name)
    }

    fn append_message(appender: &LockedRotatingFileAppender, message: &'static str) {
        let args = format_args!("{message}");
        let record = Record::builder()
            .args(args)
            .level(Level::Info)
            .target("logging-test")
            .build();
        log4rs::append::Append::append(appender, &record).unwrap();
    }

    fn log_lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn appender_does_not_create_sidecar_lock_file() {
        let path = temp_log_path("runtime.log");
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let lock_path = suffixed_path(&path, ".lock");
        fs::write(&lock_path, b"legacy").unwrap();

        let appender =
            LockedRotatingFileAppender::new(&path, Box::new(PatternEncoder::new("{m}{n}")))
                .unwrap();
        append_message(&appender, "hello");

        assert_eq!(log_lines(&path), ["hello"]);
        assert!(!lock_path.exists());
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn appender_rotates_without_sidecar_lock_file() {
        let path = temp_log_path("runtime.log");
        let parent = path.parent().unwrap();
        let appender = LockedRotatingFileAppender::with_max_size(
            &path,
            Box::new(PatternEncoder::new("{m}{n}")),
            8,
        )
        .unwrap();

        append_message(&appender, "abc");
        append_message(&appender, "defghijkl");

        assert_eq!(log_lines(&suffixed_path(&path, ".1")), ["abc"]);
        assert_eq!(log_lines(&path), ["defghijkl"]);
        assert!(!suffixed_path(&path, ".lock").exists());
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn appender_reopens_after_another_appender_rotates() {
        let path = temp_log_path("runtime.log");
        let parent = path.parent().unwrap();
        let first = LockedRotatingFileAppender::with_max_size(
            &path,
            Box::new(PatternEncoder::new("{m}{n}")),
            8,
        )
        .unwrap();
        let second = LockedRotatingFileAppender::with_max_size(
            &path,
            Box::new(PatternEncoder::new("{m}{n}")),
            8,
        )
        .unwrap();

        append_message(&first, "abc");
        append_message(&second, "defgh");
        append_message(&first, "i");

        assert_eq!(log_lines(&suffixed_path(&path, ".1")), ["abc"]);
        assert_eq!(log_lines(&path), ["defgh", "i"]);
        let _ = fs::remove_dir_all(parent);
    }
}
