//! Platform facts the pure core cannot know.
//!
//! A stock Soter TA signs only inside a fresh biometric match, and it reads that
//! match where it lives: in the secure world, from the fingerprint TA. The
//! software TA is an ordinary user-space process, so the closest it can get is
//! the framework's accepted-capture counter, which the daemon reads through the
//! hooks registered here (`soterta_set_platform`).
//!
//! A mark packs the daemon's per-boot tag in the high [`BOOT_TAG_SHIFT`] bits and
//! the counter in the low 32, so two marks are only comparable inside one boot:
//! a counter that restarted with the device must never look like evidence. The
//! daemon keeps the packed value non-negative on purpose — a negative answer is
//! this module's "cannot tell" — so the tag has to fit in 31 bits.

use std::sync::Mutex;

/// Bits of a mark that carry the per-boot tag.
pub const BOOT_TAG_SHIFT: u32 = 32;

/// What the platform can tell the software TA about one transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Platform {
    /// Milliseconds on the daemon's boot clock.
    pub boot_ms: Option<u64>,
    /// Fingerprint mark: accepted captures since boot, tagged with the boot.
    pub bio_mark: Option<u64>,
}

/// A daemon hook. A negative answer means "cannot tell".
pub type Probe = unsafe extern "C" fn() -> i64;

#[derive(Clone, Copy)]
struct Hooks {
    boot_ms: Option<Probe>,
    bio_mark: Option<Probe>,
}

impl Hooks {
    fn current(self) -> Option<Platform> {
        let snapshot = Platform {
            boot_ms: ask(self.boot_ms),
            bio_mark: ask(self.bio_mark),
        };
        // An installed biometric probe means the gate is enabled. Failure to
        // obtain its evidence must not look like an intentionally absent gate.
        if self.bio_mark.is_some() && (snapshot.boot_ms.is_none() || snapshot.bio_mark.is_none()) {
            None
        } else {
            Some(snapshot)
        }
    }
}

static HOOKS: Mutex<Hooks> = Mutex::new(Hooks {
    boot_ms: None,
    bio_mark: None,
});

/// Install the daemon's hooks; `None` leaves that fact unverifiable.
pub fn install(boot_ms: Option<Probe>, bio_mark: Option<Probe>) {
    let mut hooks = HOOKS.lock().unwrap_or_else(|error| error.into_inner());
    *hooks = Hooks { boot_ms, bio_mark };
}

/// Ask the hooks for the current values. `None` refuses a local sign operation
/// when the enabled biometric gate cannot obtain all required evidence.
pub fn current() -> Option<Platform> {
    let hooks = *HOOKS.lock().unwrap_or_else(|error| error.into_inner());
    hooks.current()
}

fn ask(hook: Option<Probe>) -> Option<u64> {
    let hook = hook?;
    let value = unsafe { hook() };
    if value < 0 {
        None
    } else {
        Some(value as u64)
    }
}

/// Whether two marks were taken inside the same boot.
pub fn same_boot(left: u64, right: u64) -> bool {
    left >> BOOT_TAG_SHIFT == right >> BOOT_TAG_SHIFT
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn available() -> i64 {
        1
    }
    unsafe extern "C" fn unavailable() -> i64 {
        -1
    }

    #[test]
    fn enabled_gate_refuses_missing_evidence_but_explicit_off_is_preserved() {
        assert!(Hooks {
            boot_ms: None,
            bio_mark: None
        }
        .current()
        .is_some());
        assert!(Hooks {
            boot_ms: Some(available),
            bio_mark: Some(available)
        }
        .current()
        .is_some());
        for hooks in [
            Hooks {
                boot_ms: Some(available),
                bio_mark: Some(unavailable),
            },
            Hooks {
                boot_ms: Some(unavailable),
                bio_mark: Some(available),
            },
            Hooks {
                boot_ms: None,
                bio_mark: Some(available),
            },
        ] {
            assert!(hooks.current().is_none());
        }
    }
}
