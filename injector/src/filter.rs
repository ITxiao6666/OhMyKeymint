use crate::config::{parse_scoop_target, FilterConfig, ScoopTarget};
use kmr_common::consts::{AID_APP_START, AID_USER_OFFSET};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub enum PackageResolution {
    Known(Vec<String>),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterReason {
    Disabled,
    Allowed,
    RejectedAndroidPackage,
    RejectedByDenylist,
    RejectedNotInScope,
    RejectedUnknownPackage,
}

#[derive(Debug, Clone)]
pub struct FilterDecision {
    pub allowed: bool,
    pub reason: FilterReason,
    pub packages: Vec<String>,
}

pub fn evaluate(
    scoop: &[String],
    config: &FilterConfig,
    uid: u32,
    resolution: PackageResolution,
) -> FilterDecision {
    if !config.enabled {
        return FilterDecision {
            allowed: true,
            reason: FilterReason::Disabled,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }

    if config.block_android_package && uid % AID_USER_OFFSET < AID_APP_START {
        return FilterDecision {
            allowed: false,
            reason: FilterReason::RejectedAndroidPackage,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }

    let packages = match resolution {
        PackageResolution::Known(packages) => packages,
        PackageResolution::Unknown => {
            let allowed = config.allow_unknown_package;
            return FilterDecision {
                allowed,
                reason: if allowed {
                    FilterReason::Allowed
                } else {
                    FilterReason::RejectedUnknownPackage
                },
                packages: Vec::new(),
            };
        }
    };

    let reason = if config.block_android_package
        && packages.iter().any(|pkg| pkg == "android" || pkg.starts_with("android."))
    {
        FilterReason::RejectedAndroidPackage
    } else if packages.iter().any(|pkg| config.deny_packages.contains(pkg)) {
        FilterReason::RejectedByDenylist
    } else if !scoop.iter().any(|target| match parse_scoop_target(target) {
        Some(ScoopTarget::Package(package)) => packages.iter().any(|pkg| pkg == package),
        Some(ScoopTarget::PackageUser(package, user)) => {
            user == uid / AID_USER_OFFSET && packages.iter().any(|pkg| pkg == package)
        }
        Some(ScoopTarget::Uid(target_uid)) => target_uid == uid,
        None => false,
    }) {
        FilterReason::RejectedNotInScope
    } else {
        FilterReason::Allowed
    };

    FilterDecision { allowed: reason == FilterReason::Allowed, reason, packages }
}
