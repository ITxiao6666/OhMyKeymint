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

//! Read-only device prerequisites for local RKP issuance.
//!
//! Adapted from Duck-ToolBox `rkp-device status` (MIT). Passing these checks only
//! means the resources exist: firmware acceptance and server behaviour stay
//! unconfirmed until an issuance run completes.

use anyhow::{Context, Result};
use serde::Serialize;

use super::native;

/// Reported by every run; the WebUI states both before a request is sent.
pub(crate) const LIMITATIONS: [&str; 2] = ["partial_device_support", "rkp_only"];

#[derive(Debug, Serialize)]
pub(crate) struct PrereqReport {
    prerequisites_met: bool,
    android_arm64: bool,
    root: bool,
    library_present: bool,
    device_present: bool,
    v1_available: bool,
    v1_native_available: bool,
    v2_available: bool,
    aidl_apk: Option<String>,
    qualcomm_soc: bool,
    mediatek_soc: bool,
    library_path: &'static str,
    device_path: &'static str,
    fingerprint: String,
    limitations: [&'static str; 2],
    blockers: Vec<&'static str>,
}

/// Observed device facts, separated from discovery so the rules stay testable.
pub(crate) struct Facts {
    pub(crate) android_arm64: bool,
    pub(crate) root: bool,
    pub(crate) library_present: bool,
    pub(crate) device_present: bool,
    pub(crate) v1_available: bool,
    pub(crate) aidl_apk: Option<String>,
    pub(crate) qualcomm: bool,
    pub(crate) mediatek: bool,
    pub(crate) fingerprint: String,
}

pub(crate) fn status() -> Result<String> {
    let fingerprint = rsproperties::get::<String>("ro.build.fingerprint").unwrap_or_default();
    let facts = Facts {
        android_arm64: cfg!(all(target_os = "android", target_arch = "aarch64")),
        root: unsafe { libc::geteuid() } == 0,
        library_present: native::library_present(),
        device_present: native::device_present(),
        v1_available: crate::rkp_v1_bridge::available(),
        aidl_apk: crate::rkp_v1_bridge::aidl_apk(),
        qualcomm: native::qualcomm(),
        mediatek: native::mediatek_soc(),
        fingerprint,
    };
    serde_json::to_string(&report(facts)).context("encode RKP status")
}

pub(crate) fn report(facts: Facts) -> PrereqReport {
    // Only the AIDL bridge is vendor independent; the native adapters use
    // Qualcomm's `libkeymasterdeviceutils` ABI.
    let v2_available = facts.qualcomm && facts.library_present && facts.device_present;
    let mut blockers = Vec::new();
    for (passed, name) in [
        (facts.android_arm64, "android_arm64_required"),
        (facts.root, "root_required"),
        (!facts.fingerprint.trim().is_empty(), "fingerprint_missing"),
    ] {
        if !passed {
            blockers.push(name);
        }
    }
    if !facts.v1_available && !v2_available {
        if !facts.mediatek && !facts.library_present {
            blockers.push("keymint_library_missing");
        }
        if !facts.mediatek && !facts.device_present {
            blockers.push("smcinvoke_missing");
        }
        blockers.push("v1_unavailable");
    }
    match (facts.qualcomm, facts.mediatek) {
        (false, false) => blockers.push("soc_vendor_unknown"),
        (true, true) => blockers.push("soc_vendor_conflict"),
        _ => {}
    }
    PrereqReport {
        prerequisites_met: blockers.is_empty(),
        android_arm64: facts.android_arm64,
        root: facts.root,
        library_present: facts.library_present,
        device_present: facts.device_present,
        v1_available: facts.v1_available,
        v1_native_available: v2_available,
        v2_available,
        aidl_apk: facts.aidl_apk,
        qualcomm_soc: facts.qualcomm,
        mediatek_soc: facts.mediatek,
        library_path: native::LIBRARY_PATH,
        device_path: native::DEVICE_PATH,
        fingerprint: facts.fingerprint,
        limitations: LIMITATIONS,
        blockers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qualcomm_facts() -> Facts {
        Facts {
            android_arm64: true,
            root: true,
            library_present: true,
            device_present: true,
            v1_available: true,
            aidl_apk: Some("/apex/com.android.rkpd/priv-app/rkpdapp/rkpdapp.apk".into()),
            qualcomm: true,
            mediatek: false,
            fingerprint: "brand/device:16/build/id:user/release-keys".into(),
        }
    }

    #[test]
    fn complete_qualcomm_device_reports_no_blockers() {
        let report = report(qualcomm_facts());
        assert!(report.prerequisites_met);
        assert!(report.v1_available && report.v2_available && report.v1_native_available);
        assert!(report.blockers.is_empty());
        assert_eq!(report.limitations, LIMITATIONS);
    }

    #[test]
    fn aidl_only_device_skips_qualcomm_blockers() {
        let report = report(Facts {
            library_present: false,
            device_present: false,
            qualcomm: false,
            mediatek: true,
            ..qualcomm_facts()
        });
        assert!(report.prerequisites_met);
        assert!(report.v1_available);
        assert!(!report.v2_available && !report.v1_native_available);
        assert!(!report.qualcomm_soc && report.mediatek_soc);
    }

    #[test]
    fn missing_every_path_reports_each_blocker() {
        let report = report(Facts {
            v1_available: false,
            aidl_apk: None,
            library_present: false,
            device_present: false,
            ..qualcomm_facts()
        });
        assert!(!report.prerequisites_met);
        for blocker in ["keymint_library_missing", "smcinvoke_missing", "v1_unavailable"] {
            assert!(report.blockers.contains(&blocker), "missing {blocker}");
        }
    }

    #[test]
    fn unprivileged_or_rootless_runs_are_blocked() {
        let report = report(Facts { root: false, fingerprint: "  ".into(), ..qualcomm_facts() });
        assert!(!report.prerequisites_met);
        assert!(report.blockers.contains(&"root_required"));
        assert!(report.blockers.contains(&"fingerprint_missing"));
    }

    #[test]
    fn unknown_or_conflicting_vendor_is_blocked() {
        assert!(report(Facts { qualcomm: false, ..qualcomm_facts() })
            .blockers
            .contains(&"soc_vendor_unknown"));
        assert!(report(Facts { mediatek: true, ..qualcomm_facts() })
            .blockers
            .contains(&"soc_vendor_conflict"));
    }
}
