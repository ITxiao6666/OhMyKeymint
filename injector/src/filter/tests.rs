use super::*;

fn base_config() -> FilterConfig {
    FilterConfig::default()
}

fn base_scope() -> Vec<String> {
    vec!["com.allowed".to_string()]
}

#[test]
fn disabled_filter_reports_disabled_and_allows() {
    let mut config = base_config();
    config.enabled = false;

    let decision = evaluate(&base_scope(), &config, 10_000, PackageResolution::Unknown);
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::Disabled);
}

#[test]
fn android_package_is_rejected_when_blocking_is_enabled() {
    let config = base_config();
    let scope = vec!["android".to_string()];

    let decision =
        evaluate(&scope, &config, 10_000, PackageResolution::Known(vec!["android".to_string()]));
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
}

#[test]
fn denylist_rejection_takes_precedence_over_scope() {
    let mut config = base_config();
    config.block_android_package = false;
    config.deny_packages = vec!["com.example.app".to_string()];
    let scope = vec!["com.example.app".to_string()];

    let decision = evaluate(
        &scope,
        &config,
        10_000,
        PackageResolution::Known(vec!["com.example.app".to_string()]),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedByDenylist);
}

#[test]
fn known_package_outside_scope_is_rejected() {
    let mut config = base_config();
    config.block_android_package = false;

    let decision = evaluate(
        &base_scope(),
        &config,
        10_000,
        PackageResolution::Known(vec!["com.other".to_string()]),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedNotInScope);
}

#[test]
fn unknown_package_policy_only_allows_app_uids() {
    let mut config = base_config();
    config.allow_unknown_package = true;

    for uid in [10_000, 110_000] {
        let decision = evaluate(&base_scope(), &config, uid, PackageResolution::Unknown);
        assert!(decision.allowed);
        assert_eq!(decision.reason, FilterReason::Allowed);
    }
    for uid in [9_999, 109_999] {
        let decision = evaluate(&base_scope(), &config, uid, PackageResolution::Unknown);
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
    }
}

#[test]
fn root_follows_android_package_policy() {
    let mut config = base_config();
    config.allow_unknown_package = true;

    let decision = evaluate(&base_scope(), &config, 0, PackageResolution::Unknown);
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);

    config.block_android_package = false;
    let decision = evaluate(&base_scope(), &config, 0, PackageResolution::Unknown);
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::Allowed);
}

#[test]
fn android_prefixed_package_in_scope_is_allowed() {
    let config = base_config();
    let scope = vec!["com.android.vending".to_string()];
    let decision = evaluate(&scope, &config, 10_000, PackageResolution::Known(scope.clone()));
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::Allowed);
}

#[test]
fn empty_scope_keeps_android_and_denylist_precedence() {
    let mut config = base_config();
    config.block_android_package = false;
    let decision =
        evaluate(&[], &config, 10_000, PackageResolution::Known(vec!["com.anything".to_string()]));
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedNotInScope);

    let config = base_config();
    let decision =
        evaluate(&[], &config, 10_000, PackageResolution::Known(vec!["android".to_string()]));
    assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);

    let mut config = base_config();
    config.block_android_package = false;
    config.deny_packages = vec!["com.blocked".to_string()];
    let decision =
        evaluate(&[], &config, 10_000, PackageResolution::Known(vec!["com.blocked".to_string()]));
    assert_eq!(decision.reason, FilterReason::RejectedByDenylist);
}

#[test]
fn package_user_target_matches_only_the_current_caller_user() {
    let scope = vec!["com.allowed@10".to_string()];
    for (uid, allowed) in [(10_123, false), (1_010_123, true), (1_110_123, false)] {
        let decision = evaluate(
            &scope,
            &base_config(),
            uid,
            PackageResolution::Known(vec!["com.allowed".to_string()]),
        );
        assert_eq!(decision.allowed, allowed, "caller uid={uid}");
    }
    for uid in [10_123, 1_010_123] {
        assert!(
            evaluate(
                &base_scope(),
                &base_config(),
                uid,
                PackageResolution::Known(vec!["com.allowed".to_string()]),
            )
            .allowed
        );
    }
}

#[test]
fn uid_target_matches_the_full_uid_and_still_obeys_package_safety() {
    let scope = vec!["uid:1010123".to_string()];
    let mut config = base_config();
    for (uid, allowed) in [(10_123, false), (1_010_123, true)] {
        assert_eq!(
            evaluate(
                &scope,
                &config,
                uid,
                PackageResolution::Known(vec!["com.unlisted".to_string()]),
            )
            .allowed,
            allowed
        );
    }
    assert_eq!(
        evaluate(&scope, &config, 1_010_123, PackageResolution::Unknown).reason,
        FilterReason::RejectedUnknownPackage
    );
    config.deny_packages = vec!["com.blocked".to_string()];
    assert_eq!(
        evaluate(
            &scope,
            &config,
            1_010_123,
            PackageResolution::Known(vec!["com.unlisted".to_string(), "com.blocked".to_string()]),
        )
        .reason,
        FilterReason::RejectedByDenylist
    );
    assert_eq!(
        evaluate(
            &scope,
            &config,
            1_010_123,
            PackageResolution::Known(vec!["android".to_string()]),
        )
        .reason,
        FilterReason::RejectedAndroidPackage
    );
    assert_eq!(
        evaluate(&["uid:1000".to_string()], &config, 1000, PackageResolution::Unknown).reason,
        FilterReason::RejectedAndroidPackage
    );
}

#[test]
fn package_user_target_applies_to_shared_uid_with_deny_priority() {
    let scope = vec!["com.allowed@10".to_string()];
    let packages = vec!["com.other".to_string(), "com.allowed".to_string()];
    let mut config = base_config();
    assert!(
        evaluate(&scope, &config, 1_010_123, PackageResolution::Known(packages.clone()),).allowed
    );
    config.deny_packages = vec!["com.other".to_string()];
    assert_eq!(
        evaluate(&scope, &config, 1_010_123, PackageResolution::Known(packages)).reason,
        FilterReason::RejectedByDenylist
    );
}
