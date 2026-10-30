use super::*;
use std::sync::Arc;

unsafe extern "C" fn release_test_binder(binder: *mut c_void) {
    drop(Arc::from_raw(binder as *const ()));
}

fn registered(counter: &Arc<()>) -> RegisteredServiceTarget {
    RegisteredServiceTarget {
        _binder: RawBinder {
            binder: Arc::into_raw(counter.clone()) as usize,
            dec_strong: release_test_binder,
        },
        target: LocalBinderTarget { ptr: 0x4100, cookie: 0x4200 },
    }
}

#[test]
fn missing_and_failed_service_identity_queries_remain_retryable() {
    let cache = OnceLock::new();
    assert_eq!(resolve_registered_service_target(&cache, || Ok(None)).unwrap(), None);
    assert!(resolve_registered_service_target(&cache, || Err(anyhow!("unavailable"))).is_err());
    assert!(cache.get().is_none());
    let counter = Arc::new(());
    let candidate = registered(&counter);
    let target = candidate.target;
    assert_eq!(
        resolve_registered_service_target(&cache, || Ok(Some(candidate))).unwrap(),
        Some(target)
    );
    assert_eq!(
        resolve_registered_service_target(&cache, || panic!(
            "confirmed identities must not be refreshed from requests"
        ))
        .unwrap(),
        Some(target)
    );
    assert_eq!(Arc::strong_count(&counter), 2);
    drop(cache);
    assert_eq!(Arc::strong_count(&counter), 1);
}

#[test]
fn registered_service_identities_become_ready_independently() {
    let service_cache = OnceLock::new();
    let maintenance_cache = OnceLock::new();
    let counter = Arc::new(());
    let service = registered(&counter);
    let target = service.target;
    assert_eq!(
        resolve_registered_service_target(&service_cache, || Ok(Some(service))).unwrap(),
        Some(target)
    );
    assert_eq!(resolve_registered_service_target(&maintenance_cache, || Ok(None)).unwrap(), None);
    assert_eq!(
        resolve_registered_service_target(&service_cache, || panic!(
            "another unregistered interface must not invalidate service identity"
        ))
        .unwrap(),
        Some(target)
    );
}
