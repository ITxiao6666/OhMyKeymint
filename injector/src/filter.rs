use crate::config::{parse_scoop_target, FilterConfig, ScoopTarget};
use kmr_common::consts::{AID_APP_START, AID_SYSTEM, AID_USER_OFFSET};

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

/// Allow one explicitly configured shared-system-UID application without
/// allowing every UID-1000 process. Both the exact argv[0] package and Binder
/// SID must match, and list/deny rules remain authoritative.
pub fn evaluate_system_app(
    scoop: &[String],
    config: &FilterConfig,
    uid: u32,
    sid: &str,
    process: &str,
) -> Option<FilterDecision> {
    if uid % AID_USER_OFFSET != AID_SYSTEM {
        return None;
    }
    let domain = sid.strip_prefix("u:r:")?.split_once(':')?.0;
    if !domain.ends_with("_app")
        || !valid_package_process(process)
        || config.system_app_contexts.get(process).map(String::as_str) != Some(sid)
    {
        return None;
    }
    let mut app_filter = config.clone();
    app_filter.block_android_package = false;
    Some(evaluate(scoop, &app_filter, uid, PackageResolution::Known(vec![process.to_owned()])))
}

fn valid_package_process(process: &str) -> bool {
    process.contains('.')
        && process.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}
