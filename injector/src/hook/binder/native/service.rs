use super::*;
use crate::forward::BypassGuard;
use crate::identify::{
    KEYSTORE_AUTHORIZATION_INTERFACE, KEYSTORE_MAINTENANCE_INTERFACE, KEYSTORE_SERVICE_INTERFACE,
};

struct RegisteredServiceTarget {
    // Keep the registered object alive while its address is used as an identity.
    _binder: RawBinder,
    target: LocalBinderTarget,
}

static SERVICE_TARGET: OnceLock<RegisteredServiceTarget> = OnceLock::new();
static MAINTENANCE_TARGET: OnceLock<RegisteredServiceTarget> = OnceLock::new();
static AUTHORIZATION_TARGET: OnceLock<RegisteredServiceTarget> = OnceLock::new();
static WORKER_STARTED: OnceLock<std::result::Result<(), String>> = OnceLock::new();

const REGISTERED_SERVICES: [(&str, &CStr, &OnceLock<RegisteredServiceTarget>); 3] = [
    (
        KEYSTORE_SERVICE_INTERFACE,
        c"android.system.keystore2.IKeystoreService/default",
        &SERVICE_TARGET,
    ),
    (KEYSTORE_MAINTENANCE_INTERFACE, c"android.security.maintenance", &MAINTENANCE_TARGET),
    (KEYSTORE_AUTHORIZATION_INTERFACE, c"android.security.authorization", &AUTHORIZATION_TARGET),
];

pub(crate) fn registered_service_target(interface: &str) -> Option<LocalBinderTarget> {
    REGISTERED_SERVICES
        .iter()
        .find(|(descriptor, _, _)| *descriptor == interface)
        .and_then(|(_, _, cache)| cache.get())
        .map(|registered| registered.target)
}

pub(crate) fn start_registered_service_target_worker() -> Result<()> {
    let result = WORKER_STARTED.get_or_init(|| {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("omk-binder-identity".into())
            .spawn(move || {
                let mut ready_tx = Some(ready_tx);
                loop {
                    for (_, name, cache) in REGISTERED_SERVICES {
                        if let Err(error) = load_registered_service_target(name, cache) {
                            log::debug!(
                                "event=interface service identity {name:?} not ready: {error:#}"
                            );
                        }
                    }
                    if let Some(ready_tx) = ready_tx.take() {
                        let _ = ready_tx.send(());
                    }
                    if REGISTERED_SERVICES.iter().all(|(_, _, cache)| cache.get().is_some()) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            })
            .map_err(|error| error.to_string())?;
        ready_rx.recv().map_err(|error| error.to_string())
    });
    result.as_ref().map_err(|error| anyhow!(error.clone())).copied()
}

fn load_registered_service_target(
    name: &CStr,
    cache: &OnceLock<RegisteredServiceTarget>,
) -> Result<Option<LocalBinderTarget>> {
    resolve_registered_service_target(cache, || {
        // ServiceManager supplies the identity. Never learn it from a caller's
        // interface token or dereference the incoming transaction's cookie.
        let _guard = BypassGuard::enter();
        let api = native_binder_api()?;
        let binder = unsafe { (api.service_manager_check_service)(name.as_ptr()) };
        if binder.is_null() {
            return Ok(None);
        }
        let binder = RawBinder { binder: binder as usize, dec_strong: api.binder_dec_strong };
        let carrier = native_binder_carrier(api, &binder)?;
        let object =
            unsafe { std::ptr::read_unaligned(carrier.as_ptr() as *const flat_binder_object) };
        if object.hdr.type_ != BINDER_TYPE_BINDER {
            bail!("registered service {name:?} is not a strong local Binder");
        }
        let target = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier) }
            .ok_or_else(|| anyhow!("registered service {name:?} is not a local Binder"))?;
        Ok(Some(RegisteredServiceTarget { _binder: binder, target }))
    })
}

fn resolve_registered_service_target(
    cache: &OnceLock<RegisteredServiceTarget>,
    resolve: impl FnOnce() -> Result<Option<RegisteredServiceTarget>>,
) -> Result<Option<LocalBinderTarget>> {
    if let Some(registered) = cache.get() {
        return Ok(Some(registered.target));
    }
    // A temporarily missing service or lookup failure must remain retryable.
    // Do not hold a cache initialization lock across the Binder transaction.
    let Some(registered) = resolve()? else {
        return Ok(None);
    };
    Ok(Some(cache.get_or_init(|| registered).target))
}

#[cfg(test)]
mod tests;
