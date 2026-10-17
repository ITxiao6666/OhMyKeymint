// Copyright 2021, The Android Open Source Project
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

//! Provide the [`KeyMintDevice`] wrapper for operating directly on a KeyMint device.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock, RwLock,
};

use crate::android::hardware::security::keymint::IKeyMintOperation::BnKeyMintOperation;
use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, IKeyMintDevice::IKeyMintDevice,
    IKeyMintOperation::IKeyMintOperation, KeyCharacteristics::KeyCharacteristics,
    KeyCreationResult::KeyCreationResult, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use crate::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use crate::config::{config, Config, CryptoConfig, MainConfig};
use crate::global::DB;
use crate::keymaster::db::Uuid;
use crate::keymaster::error::{map_km_error, map_ks_error};
use crate::keymaster::utils::{
    key_characteristics_to_internal, key_creation_result_to_aidl,
    key_parameter_conversion_error_code, key_parameters_to_km, key_params_to_aidl, AppUid,
};
use crate::keymint::{clock, sdd, soft};
use crate::{
    android::hardware::security::keymint::ErrorCode::ErrorCode,
    err,
    keymaster::{
        db::{
            BlobInfo, BlobMetaData, BlobMetaEntry, CertificateInfo, DateTime, KeyEntry,
            KeyEntryLoadBits, KeyIdGuard, KeyMetaData, KeyMetaEntry, KeyType,
            KeymasterDb as KeystoreDB, SubComponentType,
        },
        error::KsError as Error,
        super_key::KeyBlob,
    },
    watchdog as wd,
};
use anyhow::{anyhow, Context, Result};
use kmr_common::consts::AID_KEYSTORE;
use kmr_crypto_boring::ec::BoringEc;
use kmr_crypto_boring::hmac::BoringHmac;
use kmr_crypto_boring::rng::BoringRng;
use kmr_crypto_boring::rsa::BoringRsa;
use kmr_ta::device::CsrSigningAlgorithm;
use kmr_ta::{HardwareInfo, KeyMintHalVersion, KeyMintTa, RpcInfo, RpcInfoV3};
use kmr_wire::keymint::{AttestationKey, KeyParam};
use kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR;
use kmr_wire::*;
use log::{error, info, warn};
use rand::RngExt;
use regex::Regex;
use rsbinder::{ExceptionCode, Interface, Status, Strong};

// The OS version property is of form "12" or "12.1" or "12.1.3".
const OS_VERSION_REGEX: &str = r"^(?P<major>\d{1,2})(\.(?P<minor>\d{1,2}))?(\.(?P<sub>\d{1,2}))?$";

// The patchlevel properties are of form "YYYY-MM-DD".
const PATCHLEVEL_REGEX: &str = r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})$";

// Just use [`String`] for errors here.
type HalInfoError = String;

/// Retrieve a numeric value from a possible match.
fn extract_u32(value: Option<regex::Match>) -> std::result::Result<u32, HalInfoError> {
    match value {
        Some(m) => {
            let s = m.as_str();
            match s.parse::<u32>() {
                Ok(v) => Ok(v),
                Err(e) => Err(format!("failed to parse integer: {e:?}")),
            }
        }
        None => Err("failed to find match".to_string()),
    }
}

/// Extract a patchlevel in form YYYYMM from a "YYYY-MM-DD" property value.
pub(crate) fn extract_truncated_patchlevel(
    prop_value: &str,
) -> std::result::Result<u32, HalInfoError> {
    let patchlevel_regex = Regex::new(PATCHLEVEL_REGEX)
        .map_err(|e| format!("failed to compile patchlevel regexp: {e:?}"))?;

    let captures = patchlevel_regex
        .captures(prop_value)
        .ok_or_else(|| "failed to match patchlevel regex".to_string())?;
    let year = extract_u32(captures.name("year"))?;
    let month = extract_u32(captures.name("month"))?;
    if !(1..=12).contains(&month) {
        return Err(format!("month out of range: {month}"));
    }
    // no day
    Ok(year * 100 + month)
}

/// Extract a patchlevel in form YYYYMMDD from a "YYYY-MM-DD" property value.
pub(crate) fn extract_patchlevel(prop_value: &str) -> std::result::Result<u32, HalInfoError> {
    let patchlevel_regex = Regex::new(PATCHLEVEL_REGEX)
        .map_err(|e| format!("failed to compile patchlevel regexp: {e:?}"))?;

    let captures = patchlevel_regex
        .captures(prop_value)
        .ok_or_else(|| "failed to match patchlevel regex".to_string())?;
    let year = extract_u32(captures.name("year"))?;
    let month = extract_u32(captures.name("month"))?;
    if !(1..=12).contains(&month) {
        return Err(format!("month out of range: {month}"));
    }
    let day = extract_u32(captures.name("day"))?;
    if !(1..=31).contains(&day) {
        return Err(format!("day out of range: {day}"));
    }
    Ok(year * 10000 + month * 100 + day)
}

/// Extract the boot patchlevel as either its raw wire value or YYYYMMDD.
pub(crate) fn extract_boot_patchlevel(prop_value: &str) -> std::result::Result<u32, HalInfoError> {
    prop_value
        .parse::<u32>()
        .or_else(|_| extract_patchlevel(prop_value))
}

/// Generate HAL information from property values.
fn populate_hal_info_from(
    os_version_prop: &str,
    os_patchlevel_prop: &str,
    vendor_patchlevel_prop: &str,
) -> std::result::Result<SetHalInfoRequest, HalInfoError> {
    let os_version_regex = Regex::new(OS_VERSION_REGEX)
        .map_err(|e| format!("failed to compile version regexp: {e:?}"))?;
    let captures = os_version_regex
        .captures(os_version_prop)
        .ok_or_else(|| "failed to match OS version regex".to_string())?;
    let major = extract_u32(captures.name("major"))?;
    let minor = extract_u32(captures.name("minor")).unwrap_or(0u32);
    let sub = extract_u32(captures.name("sub")).unwrap_or(0u32);
    let os_version = (major * 10000) + (minor * 100) + sub;

    Ok(SetHalInfoRequest {
        os_version,
        os_patchlevel: extract_truncated_patchlevel(os_patchlevel_prop)?,
        vendor_patchlevel: extract_patchlevel(vendor_patchlevel_prop)?,
    })
}

/// Wrapper for operating directly on a KeyMint device.
/// These methods often mirror methods in [`crate::security_level`]. However
/// the functions in [`crate::security_level`] make assumptions that hold, and has side effects
/// that make sense, only if called by an external client through binder.
/// In addition we are trying to maintain a separation between interface services
/// so that the architecture is compatible with a future move to multiple thread pools.
/// So the simplest approach today is to write new implementations of them for internal use.
/// Because these methods run very early, we don't even try to cooperate with
/// the operation slot database; we assume there will be plenty of slots.
pub struct KeyMintDevice {
    km_dev: KeyMintWrapper,
    version: i32,
    km_uuid: RwLock<Uuid>,
    security_level: SecurityLevel,
}

impl KeyMintDevice {
    /// Version number of KeyMasterDevice@V4_0
    pub const KEY_MASTER_V4_0: i32 = 40;
    /// Version number of KeyMasterDevice@V4_1
    pub const KEY_MASTER_V4_1: i32 = 41;
    /// Version number of KeyMintDevice@V1
    pub const KEY_MINT_V1: i32 = 100;
    /// Version number of KeyMintDevice@V2
    pub const KEY_MINT_V2: i32 = 200;
    /// Version number of KeyMintDevice@V3
    pub const KEY_MINT_V3: i32 = 300;
    /// Version number of KeyMintDevice@V4
    pub const KEY_MINT_V4: i32 = 400;
    /// Version number of KeyMintDevice@V5
    pub const KEY_MINT_V5: i32 = 500;

    /// Get a [`KeyMintDevice`] for the given [`SecurityLevel`]
    pub fn get(security_level: SecurityLevel) -> Result<KeyMintDevice> {
        let km_uuid = RwLock::new(Uuid::from(security_level));
        let wrapper: KeyMintWrapper = KeyMintWrapper::new(security_level)?;
        let version = wrapper
            .get_hardware_info()
            .context(err!("Failed to get hardware info"))?
            .version_number;
        Ok(KeyMintDevice {
            km_dev: wrapper,
            version,
            km_uuid,
            security_level,
        })
    }

    /// Get a [`KeyMintDevice`] for the given [`SecurityLevel`], return
    /// [`None`] if the error `HARDWARE_TYPE_UNAVAILABLE` is returned
    pub fn get_or_none(security_level: SecurityLevel) -> Result<Option<KeyMintDevice>> {
        KeyMintDevice::get(security_level).map(Some).or_else(|e| {
            match e.root_cause().downcast_ref::<Error>() {
                Some(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)) => Ok(None),
                _ => Err(e),
            }
        })
    }

    pub fn uuid(&self) -> Uuid {
        *self.km_uuid.read().unwrap()
    }

    pub fn terminate_uuid(&mut self) -> Result<()> {
        DB.with(|db| {
            let mut db = db.borrow_mut();
            db.terminate_uuid(&self.km_uuid.read().unwrap())
                .context(err!("terminate_uuid failed"))
        })?;

        self.km_uuid = RwLock::new(Uuid::from(self.security_level));
        Ok(())
    }

    /// Returns the version of the underlying KeyMint/KeyMaster device.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns the self advertised security level of the KeyMint device.
    /// This may differ from the requested security level if the best security level
    /// on the device is Software.
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Create a KM key and store in the database.
    pub fn create_and_store_key<F>(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
        creator: F,
    ) -> Result<()>
    where
        F: FnOnce(&dyn IKeyMintDevice) -> Result<KeyCreationResult, rsbinder::Status>,
    {
        let creation_result =
            map_km_error(creator(&self.km_dev)).context(err!("creator failed"))?;
        let result = (|| {
            let key_parameters =
                key_characteristics_to_internal(creation_result.keyCharacteristics);
            let creation_date = DateTime::now().context(err!("DateTime::now() failed"))?;
            let mut key_metadata = KeyMetaData::new();
            key_metadata.add(KeyMetaEntry::CreationDate(creation_date));
            let mut blob_metadata = BlobMetaData::new();
            let km_uuid = *self.km_uuid.read().unwrap();
            blob_metadata.add(BlobMetaEntry::KmUuid(km_uuid));
            db.store_new_key(
                key_desc,
                key_type,
                &key_parameters,
                &BlobInfo::new(&creation_result.keyBlob, &blob_metadata),
                &CertificateInfo::new(None, None),
                &key_metadata,
                &km_uuid,
                None,
            )
            .context(err!("store_new_key failed"))?;
            Ok(())
        })();
        if result.is_err() {
            // The new blob has not become a durable entry. Delete only this
            // fresh blob and preserve the original publication error.
            if let Err(error) = map_km_error(self.km_dev.deleteKey(&creation_result.keyBlob)) {
                warn!("event=unpublished_internal_key_cleanup_failed error={error:?}");
            }
        }
        result
    }

    /// Generate a KeyDescriptor for internal-use keys.
    pub fn internal_descriptor(alias: String) -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: AID_KEYSTORE as i64,
            alias: Some(alias),
            blob: None,
        }
    }

    /// Look up an internal-use key in the database given a key descriptor.
    fn lookup_from_desc(
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        db.load_key_entry(
            key_desc,
            key_type,
            KeyEntryLoadBits::KM,
            AppUid(AID_KEYSTORE as i64),
            |_, _| Ok(()),
        )
        .context(err!("load_key_entry failed."))
    }

    /// Look up the key in the database, and return None if it is absent.
    fn not_found_is_none(
        lookup: Result<(KeyIdGuard, KeyEntry)>,
    ) -> Result<Option<(KeyIdGuard, KeyEntry)>> {
        match lookup {
            Ok(result) => Ok(Some(result)),
            Err(e) => match e.root_cause().downcast_ref::<Error>() {
                Some(&Error::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(None),
                _ => Err(e),
            },
        }
    }

    /// This does the lookup and store in separate transactions; caller must
    /// hold a lock before calling.
    pub fn lookup_or_generate_key<F>(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
        params: &[KeyParameter],
        allow_invalid_key_blob_upgrade: bool,
        validate_characteristics: F,
    ) -> Result<(KeyIdGuard, KeyBlob<'_>)>
    where
        F: FnOnce(&[KeyCharacteristics]) -> bool,
    {
        // We use a separate transaction for the lookup than for the store
        // - to keep the code simple
        // - because the caller needs to hold a lock in any case
        // - because it avoids holding database locks during slow
        //   KeyMint operations
        let lookup = Self::not_found_is_none(Self::lookup_from_desc(db, key_desc, key_type))
            .context(err!("first lookup failed"))?;

        if let Some((key_id_guard, mut key_entry)) = lookup {
            // If the key is associated with a different km instance
            // or if there is no blob metadata for some reason the key entry
            // is considered corrupted and needs to be replaced with a new one.
            let key_blob = key_entry
                .take_key_blob_info()
                .and_then(|(key_blob, blob_metadata)| {
                    if Some(*self.km_uuid.read().unwrap()) == blob_metadata.km_uuid().copied() {
                        Some(key_blob)
                    } else {
                        None
                    }
                });

            if let Some(key_blob_vec) = key_blob {
                // Keep a copy because the normal upgrade helper takes ownership of its
                // `KeyBlob`; the boot-level recovery path may need to retry the original bytes.
                let original_key_blob = key_blob_vec.clone();
                let get_characteristics = |key_blob: &[u8]| {
                    map_km_error({
                        let _wp = wd::watch(concat!(
                            "KeyMintDevice::lookup_or_generate_key: ",
                            "calling IKeyMintDevice::getKeyCharacteristics."
                        ));
                        self.km_dev.getKeyCharacteristics(key_blob, &[], &[])
                    })
                };
                let existing_key = self.upgrade_keyblob_if_required_with(
                    db,
                    &key_id_guard,
                    KeyBlob::NonSensitive(key_blob_vec),
                    get_characteristics,
                );

                let (key_characteristics, key_blob, recovered_invalid_blob) = match existing_key {
                    Ok((key_characteristics, key_blob)) => (key_characteristics, key_blob, false),
                    Err(error)
                        if allow_invalid_key_blob_upgrade
                            && matches!(
                                error.root_cause().downcast_ref::<Error>(),
                                Some(Error::Km(ErrorCode::INVALID_KEY_BLOB))
                            ) =>
                    {
                        // The boot-level key is module-owned and may have been created while a
                        // synchronized security patch was active.  Ask the same KeyMint TA to
                        // rewrite its patch-level authorizations so the key material and derived
                        // boot-level encryption keys remain unchanged after restoring defaults.
                        let upgraded_blob = {
                            let _wp = wd::watch(
                                "KeyMintDevice::lookup_or_generate_key: calling IKeyMintDevice::upgradeKey for boot-level key",
                            );
                            map_km_error(self.km_dev.upgradeKey(&original_key_blob, &[]))
                        }
                        .context(err!("upgrading invalid boot-level keyblob"))?;
                        if upgraded_blob.is_empty() {
                            return Err(Error::Km(ErrorCode::INVALID_KEY_BLOB)).context(err!(
                                "upgradeKey returned an empty blob for invalid boot-level key"
                            ));
                        }

                        let mut new_blob_metadata = BlobMetaData::new();
                        new_blob_metadata.add(BlobMetaEntry::KmUuid(*self.km_uuid.read().unwrap()));
                        db.set_blob(
                            &key_id_guard,
                            SubComponentType::KEY_BLOB,
                            Some(&upgraded_blob),
                            Some(&new_blob_metadata),
                        )
                        .context(err!("failed to persist upgraded boot-level keyblob"))?;

                        let key_characteristics = get_characteristics(&upgraded_blob).context(
                            err!("calling getKeyCharacteristics after boot-level keyblob upgrade"),
                        )?;
                        (
                            key_characteristics,
                            KeyBlob::NonSensitive(upgraded_blob),
                            true,
                        )
                    }
                    Err(error) => {
                        return Err(error).context(err!("calling getKeyCharacteristics"));
                    }
                };

                if validate_characteristics(&key_characteristics) {
                    return Ok((key_id_guard, key_blob));
                }

                if recovered_invalid_blob {
                    return Err(Error::Km(ErrorCode::INVALID_KEY_BLOB)).context(err!(
                        "upgraded boot-level keyblob failed characteristic validation"
                    ));
                }

                // If this point is reached the existing key is considered outdated or corrupted
                // in some way. It will be replaced with a new one below.
            }
        }

        self.create_and_store_key(db, key_desc, key_type, |km_dev| {
            km_dev.generateKey(params, None)
        })
        .context(err!("generate_and_store_key failed"))?;
        Self::lookup_from_desc(db, key_desc, key_type)
            .and_then(|(key_id_guard, mut key_entry)| {
                Ok((
                    key_id_guard,
                    key_entry
                        .take_key_blob_info()
                        .ok_or(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                        .map(|(key_blob, _)| KeyBlob::NonSensitive(key_blob))
                        .context(err!("Missing key blob info."))?,
                ))
            })
            .context(err!("second lookup failed"))
    }

    /// Call the passed closure; if it returns `KEY_REQUIRES_UPGRADE`, call upgradeKey, and
    /// write the upgraded key to the database.
    fn upgrade_keyblob_if_required_with<'a, T, F>(
        &self,
        db: &mut KeystoreDB,
        key_id_guard: &KeyIdGuard,
        key_blob: KeyBlob<'a>,
        f: F,
    ) -> Result<(T, KeyBlob<'a>)>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        let (f_result, upgraded_blob) = crate::keymaster::utils::upgrade_keyblob_if_required_with(
            &self.km_dev,
            self.version(),
            &key_blob,
            &[],
            f,
            |upgraded_blob| {
                let mut new_blob_metadata = BlobMetaData::new();
                new_blob_metadata.add(BlobMetaEntry::KmUuid(*self.km_uuid.read().unwrap()));

                db.set_blob(
                    key_id_guard,
                    SubComponentType::KEY_BLOB,
                    Some(upgraded_blob),
                    Some(&new_blob_metadata),
                )
                .context(err!("Failed to insert upgraded blob into the database"))?;
                Ok(())
            },
        )?;
        let returned_blob = match upgraded_blob {
            None => key_blob,
            Some(upgraded_blob) => KeyBlob::NonSensitive(upgraded_blob),
        };
        Ok((f_result, returned_blob))
    }

    /// Use the created key in an operation that can be done with
    /// a call to begin followed by a call to finish.
    pub fn use_key_in_one_step(
        &self,
        db: &mut KeystoreDB,
        key_id_guard: &KeyIdGuard,
        one_step: OneStepKeyOperation<'_>,
    ) -> Result<Vec<u8>> {
        let key_blob = KeyBlob::Ref(one_step.key_blob);

        let (begin_result, _) = self
            .upgrade_keyblob_if_required_with(db, key_id_guard, key_blob, |blob| {
                let _wp =
                    wd::watch("KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::begin");
                let result: std::result::Result<
                    crate::android::hardware::security::keymint::BeginResult::BeginResult,
                    Status,
                > = self.km_dev.begin(
                    one_step.purpose,
                    blob,
                    one_step.parameters,
                    one_step.auth_token,
                );
                map_km_error(result)
            })
            .context(err!("Failed to begin operation."))?;
        let operation: Strong<dyn IKeyMintOperation> = begin_result
            .operation
            .ok_or_else(Error::sys)
            .context(err!("Operation missing"))?;
        let _wp = wd::watch("KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::finish");
        map_km_error(operation.finish(Some(one_step.input), None, None, None, None))
            .context(err!("Failed to finish operation."))
    }
}

pub struct OneStepKeyOperation<'a> {
    pub key_blob: &'a [u8],
    pub purpose: KeyPurpose,
    pub parameters: &'a [KeyParameter],
    pub auth_token: Option<&'a HardwareAuthToken>,
    pub input: &'a [u8],
}
static KM_WRAPPER_STRONGBOX: OnceLock<Arc<KeyMintWrapperInner>> = OnceLock::new();

static KM_WRAPPER_TEE: OnceLock<Arc<KeyMintWrapperInner>> = OnceLock::new();

static KM_WRAPPER_LIFECYCLE: Mutex<()> = Mutex::new(());
static EARLY_BOOT_ENDED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct KeyMintWrapper {
    security_level: SecurityLevel,
    inner: Arc<KeyMintWrapperInner>,
    request_patchlevels: Option<kmr_ta::RequestPatchLevels>,
}

struct KeyMintWrapperInner {
    keymint: Mutex<KeyMintTa>,
}

impl Interface for KeyMintWrapper {}

fn key_parameter_conversion_status(error: ValueNotRecognized) -> Status {
    map_ks_error(Error::Km(key_parameter_conversion_error_code(error)))
}

fn begin_key_parameters_to_km(
    params: &[KeyParameter],
    version_number: i32,
) -> std::result::Result<Vec<KeyParam>, ValueNotRecognized> {
    let mut filtered = Vec::with_capacity(params.len());
    for param in params {
        match param.r#tag {
            Tag::ASSOCIATED_DATA | Tag::CONFIRMATION_TOKEN | Tag::UNIQUE_ID => match &param.r#value
            {
                KeyParameterValue::Blob(_) => continue,
                _ => return Err(ValueNotRecognized::Blob),
            },
            Tag::MIN_SECONDS_BETWEEN_OPS => match &param.r#value {
                KeyParameterValue::Integer(_) => continue,
                _ => return Err(ValueNotRecognized::Integer),
            },
            Tag::HARDWARE_TYPE => match &param.r#value {
                KeyParameterValue::SecurityLevel(_) => continue,
                _ => return Err(ValueNotRecognized::SecurityLevel),
            },
            Tag::IDENTITY_CREDENTIAL_KEY => match &param.r#value {
                KeyParameterValue::BoolValue(true) => continue,
                _ => return Err(ValueNotRecognized::Bool),
            },
            _ => filtered.push(param.clone()),
        }
    }
    key_parameters_to_km(&filtered, version_number)
}

fn ta_delay_range(code: KeyMintOperation, main: &MainConfig) -> [u16; 2] {
    use KeyMintOperation::*;
    match code {
        DeviceBegin
        | OperationUpdateAad
        | OperationUpdate
        | OperationFinish
        | OperationAbort
        | DeviceGetKeyCharacteristics => main.ta_operation_delay_ms,
        DeviceGenerateKey
        | DeviceImportKey
        | DeviceImportWrappedKey
        | DeviceUpgradeKey
        | DeviceConvertStorageKeyToEphemeral
        | RpcGenerateEcdsaP256KeyPair
        | RpcGenerateCertificateRequest
        | RpcGenerateCertificateV2Request => main.ta_generation_delay_ms,
        DeviceGetHardwareInfo
        | DeviceAddRngEntropy
        | DeviceDeleteKey
        | DeviceDeleteAllKeys
        | DeviceDestroyAttestationIds
        | DeviceEarlyBootEnded
        | GetRootOfTrustChallenge
        | GetRootOfTrust
        | SendRootOfTrust
        | SetAdditionalAttestationInfo
        | RpcGetHardwareInfo
        | SecureClockGenerateTimeStamp => main.ta_control_delay_ms,
        SetHalInfo
        | SetBootInfo
        | SetAttestationIds
        | SetHalVersion
        | SharedSecretGetSharedSecretParameters
        | SharedSecretComputeSharedSecret => [0, 0],
    }
}

fn sample_ta_delay(range: [u16; 2], rng: &mut impl rand::Rng) -> std::time::Duration {
    // Config validation guarantees ordered endpoints in 0..=250 ms.
    let min_us = u64::from(range[0]) * 1000;
    let max_us = u64::from(range[1]) * 1000;
    let micros = if min_us == max_us {
        min_us
    } else {
        rng.random_range(min_us..=max_us)
    };
    std::time::Duration::from_micros(micros)
}

fn delay_ta_call(code: KeyMintOperation) {
    let range = {
        let current = config().read().unwrap();
        ta_delay_range(code, &current.main)
    };
    if range == [0, 0] {
        return;
    }
    let delay = sample_ta_delay(range, &mut rand::rng());
    log::trace!("TA request {code:?}: extra delay {} us", delay.as_micros());
    // No config or TA mutex is held here. Higher-level operation/RPC guards
    // still serialize their callers, and existing operations remain live.
    std::thread::sleep(delay);
}

#[allow(non_snake_case)]
impl IKeyMintDevice for KeyMintWrapper {
    fn begin(
        &self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: &[KeyParameter],
        auth_token: Option<&HardwareAuthToken>,
    ) -> Result<crate::android::hardware::security::keymint::BeginResult::BeginResult, Status> {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let km_params = begin_key_parameters_to_km(params, version_number)
            .map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::DeviceBegin(BeginRequest {
            purpose: kmr_wire::keymint::KeyPurpose::try_from(purpose.0)
                .map_err(key_parameter_conversion_status)?,
            key_blob: key_blob.to_vec(),
            params: km_params.clone(),
            auth_token: auth_token.map(|at| at.to_km()).transpose().map_err(|_| {
                Status::new_service_specific_error(ErrorCode::INVALID_ARGUMENT.0, None)
            })?,
        });

        let result = self.process_ta_request(req);
        let result: InternalBeginResult = match result.rsp {
            Some(PerformOpRsp::DeviceBegin(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        let operation = crate::keymaster::keymint_operation::KeyMintOperation::new(
            self.clone(),
            result.challenge,
            km_params,
            result.op_handle,
        );
        let operation = BnKeyMintOperation::new_binder(operation);

        let out_params = key_params_to_aidl(&result.params, version_number);
        let out_params = out_params.map_err(|error| {
            log::error!("failed to convert begin out params to AIDL: {error:#}");
            Status::new_service_specific_error(ErrorCode::UNKNOWN_ERROR.0, None)
        })?;

        Ok(
            crate::android::hardware::security::keymint::BeginResult::BeginResult {
                operation: Some(operation),
                challenge: result.challenge,
                params: out_params,
            },
        )
    }

    fn getHardwareInfo(
        &self,
    ) -> Result<
        crate::android::hardware::security::keymint::KeyMintHardwareInfo::KeyMintHardwareInfo,
        Status,
    > {
        delay_ta_call(KeyMintOperation::DeviceGetHardwareInfo);
        let hardware_info: keymint::KeyMintHardwareInfo = self
            .inner
            .keymint
            .lock()
            .unwrap()
            .get_hardware_info()
            .unwrap();

        Ok(
            crate::android::hardware::security::keymint::KeyMintHardwareInfo::KeyMintHardwareInfo {
                securityLevel: SecurityLevel(hardware_info.security_level as i32),
                versionNumber: hardware_info.version_number,
                keyMintName: hardware_info.key_mint_name,
                keyMintAuthorName: hardware_info.key_mint_author_name,
                timestampTokenRequired: hardware_info.timestamp_token_required,
            },
        )
    }

    fn addRngEntropy(&self, data: &[u8]) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceAddRngEntropy(AddRngEntropyRequest {
            data: data.to_vec(),
        });
        self.process_status_only(req).map_err(map_ks_error)
    }

    fn generateKey(
        &self,
        keyParams: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        attestation_key: Option<
            &crate::android::hardware::security::keymint::AttestationKey::AttestationKey,
        >,
    ) -> rsbinder::status::Result<
        crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult,
    > {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let key_parameters = key_parameters_to_km(keyParams, version_number)
            .map_err(key_parameter_conversion_status)?;
        let attestation_key = if let Some(ak) = attestation_key {
            let key_parameters = key_parameters_to_km(&ak.attestKeyParams, version_number)
                .map_err(key_parameter_conversion_status)?;
            Some(AttestationKey {
                key_blob: ak.keyBlob.clone(),
                attest_key_params: key_parameters,
                issuer_subject_name: ak.issuerSubjectName.clone(),
            })
        } else {
            None
        };

        let req = PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
            key_params: key_parameters,
            attestation_key,
        });
        let result = self.process_ta_request(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceGenerateKey(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        key_creation_result_to_aidl(result, version_number)
    }

    fn importKey(
        &self,
        key_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        key_format: crate::android::hardware::security::keymint::KeyFormat::KeyFormat,
        key_data: &[u8],
        attestation_key: Option<
            &crate::android::hardware::security::keymint::AttestationKey::AttestationKey,
        >,
    ) -> rsbinder::status::Result<
        crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult,
    > {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let key_parameters = key_parameters_to_km(key_params, version_number)
            .map_err(key_parameter_conversion_status)?;
        let attestation_key = if let Some(ak) = attestation_key {
            let key_parameters = key_parameters_to_km(&ak.attestKeyParams, version_number)
                .map_err(key_parameter_conversion_status)?;
            Some(AttestationKey {
                key_blob: ak.keyBlob.clone(),
                attest_key_params: key_parameters,
                issuer_subject_name: ak.issuerSubjectName.clone(),
            })
        } else {
            None
        };

        let key_format = kmr_wire::keymint::KeyFormat::try_from(key_format.0)
            .map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::DeviceImportKey(ImportKeyRequest {
            key_params: key_parameters,
            key_format,
            key_data: key_data.to_vec(),
            attestation_key,
        });
        let result = self.process_ta_request(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceImportKey(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        key_creation_result_to_aidl(result, version_number)
    }

    fn importWrappedKey(
        &self,
        wrapped_key_data: &[u8],
        wrapping_key_blob: &[u8],
        masking_key: &[u8],
        unwrapping_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        password_sid: i64,
        biometric_sid: i64,
    ) -> rsbinder::status::Result<
        crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult,
    > {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let unwrapping_params = key_parameters_to_km(unwrapping_params, version_number)
            .map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::DeviceImportWrappedKey(ImportWrappedKeyRequest {
            wrapped_key_data: wrapped_key_data.to_vec(),
            wrapping_key_blob: wrapping_key_blob.to_vec(),
            masking_key: masking_key.to_vec(),
            unwrapping_params,
            password_sid,
            biometric_sid,
        });

        let result = self.process_ta_request(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceImportWrappedKey(rsp)) => rsp.ret,
            Some(_) => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        key_creation_result_to_aidl(result, version_number)
    }

    fn upgradeKey(
        &self,
        key_blob_to_upgrade: &[u8],
        upgrade_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
    ) -> rsbinder::status::Result<Vec<u8>> {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let upgrade_params = key_parameters_to_km(upgrade_params, version_number)
            .map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::DeviceUpgradeKey(UpgradeKeyRequest {
            key_blob_to_upgrade: key_blob_to_upgrade.to_vec(),
            upgrade_params,
        });

        let result = self.process_ta_request(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceUpgradeKey(rsp)) => rsp.ret,
            Some(_) => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        Ok(result)
    }

    fn deleteKey(&self, key_blob: &[u8]) -> rsbinder::status::Result<()> {
        self.delete_Key(key_blob).map_err(map_ks_error)
    }

    fn deleteAllKeys(&self) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceDeleteAllKeys(DeleteAllKeysRequest {});
        self.process_status_only(req).map_err(map_ks_error)
    }

    fn destroyAttestationIds(&self) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceDestroyAttestationIds(DestroyAttestationIdsRequest {});
        self.process_status_only(req).map_err(map_ks_error)
    }

    fn deviceLocked(
        &self,
        _password_only: bool,
        _timestamp_token: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> rsbinder::status::Result<()> {
        Result::Err(Status::from(ExceptionCode::UnsupportedOperation))
    }

    fn earlyBootEnded(&self) -> rsbinder::status::Result<()> {
        EARLY_BOOT_ENDED.store(true, Ordering::Release);
        let req = PerformOpReq::DeviceEarlyBootEnded(EarlyBootEndedRequest {});
        self.process_status_only(req).map_err(map_ks_error)
    }

    fn convertStorageKeyToEphemeral(
        &self,
        storage_key_blob: &[u8],
    ) -> rsbinder::status::Result<Vec<u8>> {
        let req =
            PerformOpReq::DeviceConvertStorageKeyToEphemeral(ConvertStorageKeyToEphemeralRequest {
                storage_key_blob: storage_key_blob.to_vec(),
            });

        let result = self.process_ta_request(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceConvertStorageKeyToEphemeral(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        Ok(result)
    }

    fn getKeyCharacteristics(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        app_data: &[u8],
    ) -> rsbinder::status::Result<
        Vec<crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics>,
    > {
        let req = PerformOpReq::DeviceGetKeyCharacteristics(GetKeyCharacteristicsRequest {
            key_blob: key_blob.to_vec(),
            app_id: app_id.to_vec(),
            app_data: app_data.to_vec(),
        });

        let result = self.process_ta_request(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceGetKeyCharacteristics(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        let version_number = resolve_hardware_profile(self.security_level).version_number;
        result.iter().map(|kc| {
            let params = key_params_to_aidl(&kc.authorizations, version_number)
                .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
                .map_err(map_ks_error)?;

            Ok(crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics {
                authorizations: params,
                securityLevel: SecurityLevel(kc.security_level as i32),
            })
        }).collect()
    }

    fn getRootOfTrustChallenge(&self) -> rsbinder::status::Result<[u8; 16]> {
        let req = PerformOpReq::GetRootOfTrustChallenge(GetRootOfTrustChallengeRequest {});

        let result = self.process_ta_request(req);
        let result = match result.rsp {
            Some(PerformOpRsp::GetRootOfTrustChallenge(rsp)) => rsp.ret,
            Some(_) => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        Ok(result)
    }

    fn getRootOfTrust(&self, challenge: &[u8; 16]) -> rsbinder::status::Result<Vec<u8>> {
        let req = PerformOpReq::GetRootOfTrust(GetRootOfTrustRequest {
            challenge: *challenge,
        });

        let result = self.process_ta_request(req);
        let result = match result.rsp {
            Some(PerformOpRsp::GetRootOfTrust(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        Ok(result)
    }

    fn sendRootOfTrust(&self, root_of_trust: &[u8]) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::SendRootOfTrust(SendRootOfTrustRequest {
            root_of_trust: root_of_trust.to_vec(),
        });
        self.process_status_only(req).map_err(map_ks_error)
    }

    fn setAdditionalAttestationInfo(
        &self,
        info: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
    ) -> rsbinder::status::Result<()> {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let additional_info =
            key_parameters_to_km(info, version_number).map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::SetAdditionalAttestationInfo(SetAdditionalAttestationInfoRequest {
            info: additional_info,
        });
        self.process_status_only(req).map_err(map_ks_error)
    }
}

impl KeyMintWrapper {
    pub fn new(security_level: SecurityLevel) -> Result<Self> {
        if security_level == SecurityLevel::STRONGBOX
            && !crate::plat::keymint_profile::strongbox_keymint_present()
        {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("StrongBox KeyMint HAL is not present"));
        }

        Ok(KeyMintWrapper {
            security_level,
            inner: shared_keymint_wrapper_inner(security_level)?,
            request_patchlevels: None,
        })
    }

    pub fn with_patchlevels(&self, patchlevels: Option<kmr_ta::RequestPatchLevels>) -> Self {
        Self {
            security_level: self.security_level,
            inner: self.inner.clone(),
            request_patchlevels: patchlevels,
        }
    }

    pub fn clear_attestation_cache(&self) {
        self.inner.keymint.lock().unwrap().clear_attestation_cache();
    }

    pub fn localize_auth_token(&self, auth_token: &HardwareAuthToken) -> Result<HardwareAuthToken> {
        let km_token = auth_token
            .to_km()
            .context(err!("invalid auth token fields"))?;
        let mac_input = kmr_ta::hardware_auth_token_mac_input(&km_token)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context(err!("failed to build auth token MAC input"))?;
        let hmac_key = self
            .inner
            .keymint
            .lock()
            .unwrap()
            .get_hmac_key()
            .ok_or(Error::Km(ErrorCode::HARDWARE_NOT_YET_AVAILABLE))
            .context(err!("auth-token HMAC key is not initialized"))?;
        let mac = kmr_common::crypto::hmac_sha256(&BoringHmac, &hmac_key.0, &mac_input)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context(err!("failed to localize auth token MAC"))?;

        let mut localized = auth_token.clone();
        localized.mac = mac;
        Ok(localized)
    }

    pub fn get_hardware_info(&self) -> Result<keymint::KeyMintHardwareInfo, Error> {
        delay_ta_call(KeyMintOperation::DeviceGetHardwareInfo);
        self.inner
            .keymint
            .lock()
            .unwrap()
            .get_hardware_info()
            .map_err(|_| Error::Km(ErrorCode::UNKNOWN_ERROR))
    }

    fn process_ta_request(&self, req: PerformOpReq) -> PerformOpResponse {
        delay_ta_call(req.code());
        let mut ta = self.inner.keymint.lock().unwrap();
        ta.process_req_with_patchlevels(req, self.request_patchlevels)
    }

    fn process_status_only(&self, req: PerformOpReq) -> Result<(), Error> {
        let error_code = self.process_ta_request(req).error_code;
        match error_code {
            0 => Ok(()),
            _ => Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        }
    }

    pub fn op_update_aad(
        &self,
        op_handle: i64,
        input: &[u8],
        auth_token: Option<
            &crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken,
        >,
        timestamp_token: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> Result<(), Error> {
        let hardware_auth_token = auth_token.map(|at| at.to_km()).transpose()?;
        let timestamp_token = timestamp_token.map(timestamp_token_to_wire);

        let req = PerformOpReq::OperationUpdateAad(UpdateAadRequest {
            op_handle,
            input: input.to_vec(),
            auth_token: hardware_auth_token,
            timestamp_token,
        });
        let result = self.process_ta_request(req);
        let error_code = result.error_code;
        let _result: UpdateAadResponse = match result.rsp {
            Some(PerformOpRsp::OperationUpdateAad(rsp)) => rsp,
            Some(_) => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
            None => return Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        };

        Ok(())
    }

    pub fn op_update(
        &self,
        op_handle: i64,
        input: &[u8],
        auth_token: Option<
            &crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken,
        >,
        timestamp_token: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> Result<Vec<u8>, Error> {
        let hardware_auth_token = auth_token.map(|at| at.to_km()).transpose()?;
        let timestamp_token = timestamp_token.map(timestamp_token_to_wire);

        let req = PerformOpReq::OperationUpdate(UpdateRequest {
            op_handle,
            input: input.to_vec(),
            auth_token: hardware_auth_token,
            timestamp_token,
        });
        let result = self.process_ta_request(req);
        let error_code = result.error_code;
        let result: UpdateResponse = match result.rsp {
            Some(PerformOpRsp::OperationUpdate(rsp)) => rsp,
            Some(_) => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
            None => return Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        };

        Ok(result.ret)
    }

    pub fn op_finish(
        &self,
        op_handle: i64,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
        auth_token: Option<
            &crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken,
        >,
        timestamp_token: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
        confirmation_token: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let hardware_auth_token = auth_token.map(|at| at.to_km()).transpose()?;
        let timestamp_token = timestamp_token.map(timestamp_token_to_wire);
        let input = input.map(|i| i.to_vec());
        let signature = signature.map(|s| s.to_vec());
        let confirmation_token = confirmation_token.map(|c| c.to_vec());

        let req = PerformOpReq::OperationFinish(FinishRequest {
            op_handle,
            input,
            signature,
            auth_token: hardware_auth_token,
            timestamp_token,
            confirmation_token,
        });
        let result = self.process_ta_request(req);
        let error_code = result.error_code;
        let result: FinishResponse = match result.rsp {
            Some(PerformOpRsp::OperationFinish(rsp)) => rsp,
            Some(_) => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
            None => return Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        };

        Ok(result.ret)
    }

    pub fn op_abort(&self, op_handle: i64) -> Result<(), Error> {
        let req = PerformOpReq::OperationAbort(AbortRequest { op_handle });
        let result = self.process_ta_request(req);
        let error_code = result.error_code;
        let _result: AbortResponse = match result.rsp {
            Some(PerformOpRsp::OperationAbort(rsp)) => rsp,
            Some(_) => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
            None => return Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        };

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn delete_Key(&self, key_blob: &[u8]) -> Result<(), Error> {
        self.process_status_only(PerformOpReq::DeviceDeleteKey(DeleteKeyRequest {
            key_blob: key_blob.to_vec(),
        }))
    }
}

fn timestamp_token_to_wire(
    token: &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
) -> kmr_wire::secureclock::TimeStampToken {
    kmr_wire::secureclock::TimeStampToken {
        challenge: token.challenge,
        timestamp: kmr_wire::secureclock::Timestamp {
            milliseconds: token.timestamp.milliSeconds,
        },
        mac: token.mac.clone(),
    }
}

pub fn get_keymint_security_level(
    security_level: SecurityLevel,
) -> Result<kmr_wire::keymint::SecurityLevel> {
    match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            Ok(kmr_wire::keymint::SecurityLevel::TrustedEnvironment)
        }
        SecurityLevel::STRONGBOX => Ok(kmr_wire::keymint::SecurityLevel::Strongbox),
        _ => Err(anyhow::anyhow!(err!("Unknown security level"))),
    }
}

pub fn get_keymaster_security_level(
    security_level: kmr_wire::keymint::SecurityLevel,
) -> Result<SecurityLevel> {
    match security_level {
        kmr_wire::keymint::SecurityLevel::TrustedEnvironment => {
            Ok(SecurityLevel::TRUSTED_ENVIRONMENT)
        }
        kmr_wire::keymint::SecurityLevel::Strongbox => Ok(SecurityLevel::STRONGBOX),
        _ => Err(anyhow::anyhow!(err!("Unknown security level"))),
    }
}

#[derive(Clone, Copy)]
struct ResolvedHardwareProfile {
    version_number: i32,
    impl_name: &'static str,
    author_name: &'static str,
    unique_id: &'static str,
}

fn resolve_hardware_profile(security_level: SecurityLevel) -> ResolvedHardwareProfile {
    static TEE_PROFILE: OnceLock<ResolvedHardwareProfile> = OnceLock::new();
    static STRONGBOX_PROFILE: OnceLock<ResolvedHardwareProfile> = OnceLock::new();
    let build = || {
        let profile = crate::plat::keymint_profile::resolve_hardware_profile(security_level);
        ResolvedHardwareProfile {
            version_number: profile.version_number,
            impl_name: Box::leak(profile.impl_name.into_boxed_str()),
            author_name: Box::leak(profile.author_name.into_boxed_str()),
            unique_id: Box::leak(profile.unique_id.into_boxed_str()),
        }
    };

    match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => *TEE_PROFILE.get_or_init(build),
        SecurityLevel::STRONGBOX => *STRONGBOX_PROFILE.get_or_init(build),
        _ => build(),
    }
}

fn bootstrap_auth_token_hmac(ta: &mut KeyMintTa, crypto: &CryptoConfig) -> Result<()> {
    if let Some(key) = crypto.auth_token_hmac_key {
        ta.set_device_hmac_key(&key)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context(err!("Failed to configure auth-token HMAC key"))?;
        info!("initialized auth-token HMAC key from configured key material");
        return Ok(());
    }

    let params = kmr_wire::sharedsecret::SharedSecretParameters {
        seed: crypto.shared_secret_seed.to_vec(),
        nonce: crypto.shared_secret_nonce.to_vec(),
    };

    ta.set_shared_secret_params(params.clone())
        .map_err(|error| anyhow::anyhow!("{error:?}"))
        .context(err!("Failed to configure shared secret parameters"))?;

    let req = PerformOpReq::SharedSecretComputeSharedSecret(ComputeSharedSecretRequest {
        params: vec![params],
    });
    let resp = ta.process_req(req);
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
            .context(err!("Failed to bootstrap auth-token HMAC key"));
    }
    match resp.rsp {
        Some(PerformOpRsp::SharedSecretComputeSharedSecret(rsp)) if rsp.ret.len() == 32 => {
            info!("initialized auth-token HMAC key from configured shared-secret parameters");
            Ok(())
        }
        _ => Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
            .context(err!("Unexpected shared-secret bootstrap response")),
    }
}

fn init_keymint_ta(security_level: SecurityLevel, config: &Config) -> Result<KeyMintTa> {
    let security_level = get_keymint_security_level(security_level)?;
    let profile = resolve_hardware_profile(get_keymaster_security_level(security_level)?);

    let hw_info = HardwareInfo {
        version_number: profile.version_number,
        security_level,
        impl_name: profile.impl_name,
        author_name: profile.author_name,
        unique_id: profile.unique_id,
    };

    let rpc_info_v3 = RpcInfoV3 {
        author_name: profile.author_name,
        unique_id: profile.unique_id,
        fused: false,
        supported_num_of_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
    };

    let mut rng = BoringRng;

    let sdd_mgr: Option<Box<dyn kmr_common::keyblob::SecureDeletionSecretManager>> =
        match sdd::HostSddManager::new(&mut rng) {
            Result::Ok(v) => Some(Box::new(v)),
            Err(e) => {
                error!("failed to initialize secure deletion data manager: {:?}", e);
                None
            }
        };

    let clock = clock::StdClock;
    let rsa = BoringRsa::default();
    let ec = BoringEc::default();
    let hkdf: Box<dyn kmr_common::crypto::Hkdf> = Box::new(BoringHmac);
    let imp = kmr_common::crypto::Implementation {
        rng: Box::new(rng),
        clock: Some(Box::new(clock)),
        compare: Box::new(kmr_crypto_boring::eq::BoringEq),
        aes: Box::new(kmr_crypto_boring::aes::BoringAes),
        des: Box::new(kmr_crypto_boring::des::BoringDes),
        hmac: Box::new(BoringHmac),
        rsa: Box::new(rsa),
        ec: Box::new(ec),
        ckdf: Box::new(kmr_crypto_boring::aes_cmac::BoringAesCmac),
        hkdf,
        sha256: Box::new(kmr_crypto_boring::sha256::BoringSha256),
        mldsa: Box::new(kmr_crypto_boring::mldsa::BoringMlDsa),
    };

    let keys: Box<dyn kmr_ta::device::RetrieveKeyMaterial> = Box::new(soft::Keys::new(
        config.crypto.root_kek_seed,
        config.crypto.kak_seed,
    ));
    let rpc: Box<dyn kmr_ta::device::RetrieveRpcArtifacts> = Box::new(soft::RpcArtifacts::new(
        soft::Derive::default(),
        CsrSigningAlgorithm::EdDSA,
    ));

    let dev = kmr_ta::device::Implementation {
        keys,
        sign_info: Some(Box::new(crate::keybox::KeyboxManager {})),
        // HAL populates attestation IDs from properties.
        attest_ids: Some(Box::new(crate::att_mgr::AttestationIdMgr {})),
        sdd_mgr,
        // `BOOTLOADER_ONLY` keys not supported.
        bootloader: Box::new(kmr_ta::device::BootloaderDone),
        // `STORAGE_KEY` keys not supported.
        sk_wrapper: None,
        // `TRUSTED_USER_PRESENCE_REQUIRED` keys not supported
        tup: Box::new(kmr_ta::device::TrustedPresenceUnsupported),
        // No support for converting previous implementation's keyblobs.
        legacy_key: None,
        rpc,
    };

    let allowed_aidl_versions = match profile.version_number {
        100 => vec![KeyMintHalVersion::V1],
        200 => vec![KeyMintHalVersion::V2],
        300 => vec![KeyMintHalVersion::V3],
        400 => vec![KeyMintHalVersion::V4],
        500 => vec![KeyMintHalVersion::V5],
        _ => Vec::new(),
    };

    let mut ta = KeyMintTa::new_allowing_versions(
        hw_info,
        RpcInfo::V3(rpc_info_v3),
        imp,
        dev,
        allowed_aidl_versions,
    );
    bootstrap_auth_token_hmac(&mut ta, &config.crypto)?;

    let hal_info = populate_hal_info_from(
        &config.trust.os_version.to_string(),
        &config.trust.os_patchlevel,
        &config.trust.vendor_patchlevel,
    )
    .map_err(anyhow::Error::msg)
    .context(err!("Failed to populate HAL patch levels"))?;
    let boot_patchlevel = extract_boot_patchlevel(&config.trust.boot_patchlevel)
        .map_err(anyhow::Error::msg)
        .context(err!("Failed to parse boot patch level"))?;

    let resp = ta.process_req(PerformOpReq::SetBootInfo(kmr_wire::SetBootInfoRequest {
        verified_boot_state: if config.trust.verified_boot_state {
            0
        } else {
            2
        },
        verified_boot_hash: config.trust.vb_hash.clone().to_vec(),
        verified_boot_key: config.trust.vb_key.clone().to_vec(),
        device_boot_locked: config.trust.device_locked,
        boot_patchlevel,
    }));
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)).context(err!("Failed to set boot info"));
    }

    let resp = ta.process_req(PerformOpReq::SetHalInfo(hal_info));
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)).context(err!("Failed to set HAL info"));
    }

    let resp = ta.process_req(PerformOpReq::SetHalVersion(
        kmr_wire::SetHalVersionRequest {
            aidl_version: profile.version_number as u32,
        },
    ));
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)).context(err!("Failed to set HAL version"));
    }

    if profile.version_number >= KeyMintDevice::KEY_MINT_V4 {
        if let Some(bundle) = crate::global::module_info_bundle() {
            let resp = ta.process_req(PerformOpReq::SetAdditionalAttestationInfo(
                kmr_wire::SetAdditionalAttestationInfoRequest {
                    info: vec![KeyParam::ModuleHash(bundle.sha256.clone())],
                },
            ));
            if resp.error_code != 0 {
                return Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
                    .context(err!("Failed to set additional attestation info"));
            }
        } else {
            warn!("moduleHash attestation bootstrap skipped because APEX module info bundle is unavailable");
        }
    } else {
        info!(
            "Skipping moduleHash attestation bootstrap for KeyMint version {}",
            profile.version_number
        );
    }

    if EARLY_BOOT_ENDED.load(Ordering::Acquire) {
        let resp = ta.process_req(PerformOpReq::DeviceEarlyBootEnded(EarlyBootEndedRequest {}));
        if resp.error_code != 0 {
            return Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
                .context(err!("Failed to restore early-boot-ended state"));
        }
    }

    Ok(ta)
}

pub fn get_keymint_wrapper(security_level: SecurityLevel) -> Result<KeyMintWrapper> {
    KeyMintWrapper::new(security_level)
}

pub fn localize_auth_token_for_omk(auth_token: &HardwareAuthToken) -> Result<HardwareAuthToken> {
    get_keymint_wrapper(SecurityLevel::TRUSTED_ENVIRONMENT)?.localize_auth_token(auth_token)
}

pub fn apply_runtime_config_update(
    candidate: Config,
    update_patchlevels: bool,
    security_patch_update: Option<(String, Option<String>)>,
) -> Result<()> {
    let patchlevels = if update_patchlevels {
        let hal_info = populate_hal_info_from(
            &candidate.trust.os_version.to_string(),
            &candidate.trust.os_patchlevel,
            &candidate.trust.vendor_patchlevel,
        )
        .map_err(anyhow::Error::msg)
        .context(err!("Failed to populate HAL patch levels"))?;
        let boot_patchlevel = extract_boot_patchlevel(&candidate.trust.boot_patchlevel)
            .map_err(anyhow::Error::msg)
            .context(err!("Failed to parse boot patch level"))?;
        Some((
            hal_info.os_patchlevel,
            hal_info.vendor_patchlevel,
            boot_patchlevel,
        ))
    } else {
        None
    };
    let _lifecycle = KM_WRAPPER_LIFECYCLE
        .lock()
        .map_err(|_| anyhow!("keymint wrapper lifecycle lock poisoned"))?;
    let mut tee = if patchlevels.is_some() {
        KM_WRAPPER_TEE
            .get()
            .map(|wrapper| wrapper.keymint.lock().unwrap())
    } else {
        None
    };
    let mut strongbox = if patchlevels.is_some() {
        KM_WRAPPER_STRONGBOX
            .get()
            .map(|wrapper| wrapper.keymint.lock().unwrap())
    } else {
        None
    };
    if tee.as_ref().is_some_and(|live| !live.patchlevels_are_set()) {
        return Err(anyhow!("TEE patch levels are not initialized"));
    }
    if strongbox
        .as_ref()
        .is_some_and(|live| !live.patchlevels_are_set())
    {
        return Err(anyhow!("StrongBox patch levels are not initialized"));
    }
    let mut runtime = config()
        .write()
        .map_err(|_| anyhow!("config lock poisoned while applying config change"))?;
    if let Some((desired, previous)) = security_patch_update {
        crate::plat::vbmeta::write_runtime_security_patch(&desired, previous.as_deref())?;
    }
    if let Some((os_patchlevel, vendor_patchlevel, boot_patchlevel)) = patchlevels {
        if let Some(live) = tee.as_mut() {
            live.update_patchlevels(os_patchlevel, vendor_patchlevel, boot_patchlevel)
                .map_err(|error| anyhow!("{error:?}"))
                .context(err!("Failed to update TEE patch levels"))?;
        }
        if let Some(live) = strongbox.as_mut() {
            live.update_patchlevels(os_patchlevel, vendor_patchlevel, boot_patchlevel)
                .map_err(|error| anyhow!("{error:?}"))
                .context(err!("Failed to update StrongBox patch levels"))?;
        }
    }
    *runtime = candidate;
    Ok(())
}

pub fn clear_initialized_attestation_caches() {
    if let Some(wrapper) = KM_WRAPPER_TEE.get() {
        let keymint = KeyMintWrapper {
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            inner: wrapper.clone(),
            request_patchlevels: None,
        };
        keymint.clear_attestation_cache();
    }

    if let Some(wrapper) = KM_WRAPPER_STRONGBOX.get() {
        let keymint = KeyMintWrapper {
            security_level: SecurityLevel::STRONGBOX,
            inner: wrapper.clone(),
            request_patchlevels: None,
        };
        keymint.clear_attestation_cache();
    }
}

fn shared_keymint_wrapper_inner(security_level: SecurityLevel) -> Result<Arc<KeyMintWrapperInner>> {
    let wrapper = match security_level {
        SecurityLevel::STRONGBOX => &KM_WRAPPER_STRONGBOX,
        SecurityLevel::TRUSTED_ENVIRONMENT => &KM_WRAPPER_TEE,
        SecurityLevel::SOFTWARE => {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("Software KeyMint not supported"))
        }
        _ => {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("Unknown security level"))
        }
    };
    if let Some(wrapper) = wrapper.get() {
        return Ok(wrapper.clone());
    }
    let _lifecycle = KM_WRAPPER_LIFECYCLE
        .lock()
        .map_err(|_| anyhow!("keymint wrapper lifecycle lock poisoned"))?;
    let snapshot = config()
        .read()
        .map_err(|_| anyhow!("config lock poisoned while initializing keymint wrapper"))?
        .clone();
    wrapper
        .get_or_try_init(|| {
            Ok(Arc::new(KeyMintWrapperInner {
                keymint: Mutex::new(init_keymint_ta(security_level, &snapshot)?),
            }))
        })
        .map(Arc::clone)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn ta_delay_categories_cover_operations_and_key_lifecycle() {
        use KeyMintOperation::*;
        let main = MainConfig {
            ta_operation_delay_ms: [17, 23],
            ta_generation_delay_ms: [5, 7],
            ta_control_delay_ms: [1, 2],
            ..MainConfig::default()
        };
        for code in [
            DeviceBegin,
            OperationUpdateAad,
            OperationUpdate,
            OperationFinish,
            OperationAbort,
            DeviceGetKeyCharacteristics,
        ] {
            assert_eq!(ta_delay_range(code, &main), [17, 23], "{code:?}");
        }
        for code in [
            DeviceGenerateKey,
            DeviceImportKey,
            DeviceImportWrappedKey,
            DeviceUpgradeKey,
            DeviceConvertStorageKeyToEphemeral,
            RpcGenerateEcdsaP256KeyPair,
            RpcGenerateCertificateRequest,
            RpcGenerateCertificateV2Request,
        ] {
            assert_eq!(ta_delay_range(code, &main), [5, 7], "{code:?}");
        }
        for code in [
            DeviceGetHardwareInfo,
            DeviceAddRngEntropy,
            DeviceDeleteKey,
            DeviceDeleteAllKeys,
            DeviceDestroyAttestationIds,
            DeviceEarlyBootEnded,
            GetRootOfTrustChallenge,
            GetRootOfTrust,
            SendRootOfTrust,
            SetAdditionalAttestationInfo,
            RpcGetHardwareInfo,
            SecureClockGenerateTimeStamp,
        ] {
            assert_eq!(ta_delay_range(code, &main), [1, 2], "{code:?}");
        }
        for code in [
            SetHalInfo,
            SetBootInfo,
            SetAttestationIds,
            SetHalVersion,
            SharedSecretGetSharedSecretParameters,
            SharedSecretComputeSharedSecret,
        ] {
            assert_eq!(ta_delay_range(code, &main), [0, 0], "{code:?}");
        }
    }

    #[test]
    fn ta_delay_sampling_is_per_call_and_bounded_in_microseconds() {
        use rand::SeedableRng;
        use std::time::Duration;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for range in [[0, 0], [1, 1], [250, 250]] {
            assert_eq!(
                sample_ta_delay(range, &mut rng),
                Duration::from_millis(range[0].into())
            );
        }
        for range in [[9, 21], [6, 16], [1, 4], [0, 250]] {
            let samples: Vec<_> = (0..64).map(|_| sample_ta_delay(range, &mut rng)).collect();
            assert!(samples
                .iter()
                .all(|value| *value >= Duration::from_millis(range[0].into())
                    && *value <= Duration::from_millis(range[1].into())));
            assert!(samples.windows(2).any(|pair| pair[0] != pair[1]));
            assert!(samples.iter().any(|value| value.as_micros() % 1000 != 0));
        }
    }

    fn param(tag: Tag, value: KeyParameterValue) -> KeyParameter {
        KeyParameter { tag, value }
    }

    #[test]
    fn hal_info_matches_aosp_encoding() {
        let tests = vec![
            (
                "12",
                "2021-02-02",
                "2022-03-04",
                SetHalInfoRequest {
                    os_version: 120000,
                    os_patchlevel: 202102,
                    vendor_patchlevel: 20220304,
                },
            ),
            (
                "12.5",
                "2021-02-02",
                "2022-03-04",
                SetHalInfoRequest {
                    os_version: 120500,
                    os_patchlevel: 202102,
                    vendor_patchlevel: 20220304,
                },
            ),
            (
                "12.5.7",
                "2021-02-02",
                "2022-03-04",
                SetHalInfoRequest {
                    os_version: 120507,
                    os_patchlevel: 202102,
                    vendor_patchlevel: 20220304,
                },
            ),
        ];
        for (os_version, os_patch, vendor_patch, want) in tests {
            let got = populate_hal_info_from(os_version, os_patch, vendor_patch).unwrap();
            assert_eq!(
                got, want,
                "Mismatch for input ({os_version}, {os_patch}, {vendor_patch})"
            );
        }
    }

    #[test]
    fn boot_patchlevel_accepts_wire_value_or_date() {
        assert_eq!(extract_boot_patchlevel("2025-06-05").unwrap(), 20250605);
        assert_eq!(extract_boot_patchlevel("20000000").unwrap(), 20000000);
        assert!(extract_boot_patchlevel("unavailable").is_err());
    }

    #[test]
    fn invalid_hal_info_matches_aosp_rejections() {
        let tests = vec![
            (
                "xx",
                "2021-02-02",
                "2022-03-04",
                "failed to match OS version",
            ),
            (
                "12.xx",
                "2021-02-02",
                "2022-03-04",
                "failed to match OS version",
            ),
            (
                "12.5.xx",
                "2021-02-02",
                "2022-03-04",
                "failed to match OS version",
            ),
            (
                "12",
                "20212-02-02",
                "2022-03-04",
                "failed to match patchlevel regex",
            ),
            (
                "12",
                "2021-xx-02",
                "2022-03-04",
                "failed to match patchlevel",
            ),
            ("12", "2021-13-02", "2022-03-04", "month out of range"),
            (
                "12",
                "2022-03-04",
                "2021-xx-02",
                "failed to match patchlevel",
            ),
            ("12", "2022-03-04", "2021-13-02", "month out of range"),
            ("12", "2022-03-04", "2021-03-32", "day out of range"),
        ];
        for (os_version, os_patch, vendor_patch, want_err) in tests {
            let result = populate_hal_info_from(os_version, os_patch, vendor_patch);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.contains(want_err),
                "Mismatch for input ({os_version}, {os_patch}, {vendor_patch}), got error '{err}', want '{want_err}'"
            );
        }
    }

    #[test]
    fn begin_conversion_skips_plain_accepted_metadata_tags() {
        let params = vec![
            param(
                Tag::PURPOSE,
                KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
            ),
            param(Tag::ASSOCIATED_DATA, KeyParameterValue::Blob(vec![1])),
            param(Tag::CONFIRMATION_TOKEN, KeyParameterValue::Blob(vec![2])),
            param(Tag::MIN_SECONDS_BETWEEN_OPS, KeyParameterValue::Integer(30)),
            param(
                Tag::HARDWARE_TYPE,
                KeyParameterValue::SecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT),
            ),
            param(Tag::UNIQUE_ID, KeyParameterValue::Blob(vec![3])),
            param(
                Tag::IDENTITY_CREDENTIAL_KEY,
                KeyParameterValue::BoolValue(true),
            ),
        ];

        assert_eq!(
            begin_key_parameters_to_km(&params, KeyMintDevice::KEY_MINT_V5).unwrap(),
            vec![KeyParam::Purpose(kmr_wire::keymint::KeyPurpose::Sign)]
        );
    }

    #[test]
    fn begin_conversion_keeps_malformed_begin_params_rejected() {
        assert!(matches!(
            begin_key_parameters_to_km(
                &[param(Tag::USER_AUTH_TYPE, KeyParameterValue::Integer(2))],
                KeyMintDevice::KEY_MINT_V5
            ),
            Err(ValueNotRecognized::HardwareAuthenticatorType)
        ));
        assert!(matches!(
            begin_key_parameters_to_km(
                &[param(
                    Tag::IDENTITY_CREDENTIAL_KEY,
                    KeyParameterValue::BoolValue(false),
                )],
                KeyMintDevice::KEY_MINT_V5
            ),
            Err(ValueNotRecognized::Bool)
        ));
    }

    fn test_crypto() -> kmr_common::crypto::Implementation {
        kmr_common::crypto::Implementation {
            rng: Box::new(BoringRng),
            clock: Some(Box::new(clock::StdClock)),
            compare: Box::new(kmr_crypto_boring::eq::BoringEq),
            aes: Box::new(kmr_crypto_boring::aes::BoringAes),
            des: Box::new(kmr_crypto_boring::des::BoringDes),
            hmac: Box::new(BoringHmac),
            rsa: Box::new(BoringRsa::default()),
            ec: Box::new(BoringEc::default()),
            ckdf: Box::new(kmr_crypto_boring::aes_cmac::BoringAesCmac),
            hkdf: Box::new(BoringHmac),
            sha256: Box::new(kmr_crypto_boring::sha256::BoringSha256),
            mldsa: Box::new(kmr_crypto_boring::mldsa::BoringMlDsa),
        }
    }

    pub(crate) fn test_ta() -> KeyMintTa {
        test_ta_with_profile(
            KeyMintDevice::KEY_MINT_V5,
            kmr_wire::keymint::SecurityLevel::TrustedEnvironment,
            None,
        )
    }

    fn test_ta_with_profile(
        version_number: i32,
        security_level: kmr_wire::keymint::SecurityLevel,
        sdd_mgr: Option<Box<dyn kmr_common::keyblob::SecureDeletionSecretManager>>,
    ) -> KeyMintTa {
        let hw_info = HardwareInfo {
            version_number,
            security_level,
            impl_name: "test",
            author_name: "test",
            unique_id: "test",
        };
        let rpc_info = RpcInfoV3 {
            author_name: "test",
            unique_id: "test",
            fused: false,
            supported_num_of_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
        };
        let dev = kmr_ta::device::Implementation {
            keys: Box::new(soft::Keys::new([0; 32], [1; 32])),
            sign_info: None,
            attest_ids: None,
            sdd_mgr,
            bootloader: Box::new(kmr_ta::device::BootloaderDone),
            sk_wrapper: None,
            tup: Box::new(kmr_ta::device::TrustedPresenceUnsupported),
            legacy_key: None,
            rpc: Box::new(kmr_ta::device::NoOpRetrieveRpcArtifacts),
        };

        KeyMintTa::new_allowing_versions(
            hw_info,
            RpcInfo::V3(rpc_info),
            test_crypto(),
            dev,
            vec![KeyMintHalVersion::V5],
        )
    }

    pub(crate) fn set_boot_info(ta: &mut KeyMintTa) -> i32 {
        ta.process_req(PerformOpReq::SetBootInfo(kmr_wire::SetBootInfoRequest {
            verified_boot_state: 0,
            verified_boot_hash: vec![0; 32],
            verified_boot_key: vec![0; 32],
            device_boot_locked: true,
            boot_patchlevel: 20250605,
        }))
        .error_code
    }

    #[test]
    fn wrapped_import_consumes_single_use_wrapping_key_only_after_success() {
        use der::{asn1::AnyRef, Decode, Encode, Sequence};
        use kmr_common::{
            crypto::Rng,
            keyblob::{
                sdd_mem::InMemorySlotManager, EncryptedKeyBlob, SecureDeletionData,
                SecureDeletionSecretManager, SecureDeletionSlot, SlotPurpose,
            },
            Error as KmError,
        };
        use kmr_wire::keymint::{
            Algorithm, BlockMode, DateTime, Digest, KeyFormat, KeyOrigin, KeyPurpose, PaddingMode,
            SecurityLevel,
        };
        use openssl::{
            encrypt::Encrypter,
            hash::MessageDigest,
            pkey::PKey,
            rsa::{Padding, Rsa},
            symm::{encrypt, encrypt_aead, Cipher},
        };

        #[derive(Default)]
        struct TestSddState {
            manager: InMemorySlotManager<4>,
            faulting_source: Option<SecureDeletionSlot>,
            delete_attempts: Vec<SecureDeletionSlot>,
        }

        struct SharedSdd(Arc<Mutex<TestSddState>>);

        impl SecureDeletionSecretManager for SharedSdd {
            fn get_or_create_factory_reset_secret(
                &mut self,
                rng: &mut dyn Rng,
            ) -> Result<SecureDeletionData, KmError> {
                self.0
                    .lock()
                    .unwrap()
                    .manager
                    .get_or_create_factory_reset_secret(rng)
            }

            fn get_factory_reset_secret(&self) -> Result<SecureDeletionData, KmError> {
                self.0.lock().unwrap().manager.get_factory_reset_secret()
            }

            fn new_secret(
                &mut self,
                rng: &mut dyn Rng,
                purpose: SlotPurpose,
            ) -> Result<(SecureDeletionSlot, SecureDeletionData), KmError> {
                self.0.lock().unwrap().manager.new_secret(rng, purpose)
            }

            fn get_secret(&self, slot: SecureDeletionSlot) -> Result<SecureDeletionData, KmError> {
                self.0.lock().unwrap().manager.get_secret(slot)
            }

            fn delete_secret(&mut self, slot: SecureDeletionSlot) -> Result<(), KmError> {
                let mut state = self.0.lock().unwrap();
                state.delete_attempts.push(slot);
                if let Some(source) = state.faulting_source {
                    return Err(if slot == source {
                        kmr_common::km_err!(
                            SecureHwCommunicationFailed,
                            "injected source consumption failure"
                        )
                    } else {
                        kmr_common::km_err!(UnknownError, "injected destination cleanup failure")
                    });
                }
                state.manager.delete_secret(slot)
            }

            fn delete_all(&mut self) {
                self.0.lock().unwrap().manager.delete_all();
            }
        }

        #[derive(Sequence)]
        struct TestSecureKeyWrapper<'a> {
            version: i32,
            #[asn1(type = "OCTET STRING")]
            encrypted_transport_key: &'a [u8],
            #[asn1(type = "OCTET STRING")]
            initialization_vector: &'a [u8],
            key_description: AnyRef<'a>,
            #[asn1(type = "OCTET STRING")]
            encrypted_key: &'a [u8],
            #[asn1(type = "OCTET STRING")]
            tag: &'a [u8],
        }

        let slots = Arc::new(Mutex::new(TestSddState::default()));
        let mut ta = test_ta_with_profile(
            KeyMintDevice::KEY_MINT_V5,
            SecurityLevel::TrustedEnvironment,
            Some(Box::new(SharedSdd(slots.clone()))),
        );
        assert_eq!(set_boot_info(&mut ta), 0);
        assert_eq!(
            ta.process_req(PerformOpReq::SetHalInfo(SetHalInfoRequest {
                os_version: 150000,
                os_patchlevel: 202506,
                vendor_patchlevel: 20250605,
            }))
            .error_code,
            0
        );
        let wrapping_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let wrapping = ta.process_req(PerformOpReq::DeviceImportKey(ImportKeyRequest {
            key_params: vec![
                KeyParam::Algorithm(Algorithm::Rsa),
                KeyParam::Purpose(KeyPurpose::WrapKey),
                KeyParam::KeySize(KeySizeInBits(2048)),
                KeyParam::RsaPublicExponent(RsaExponent(65537)),
                KeyParam::Padding(PaddingMode::RsaOaep),
                KeyParam::Digest(Digest::Sha256),
                KeyParam::RsaOaepMgfDigest(Digest::Sha1),
                KeyParam::UsageCountLimit(1),
                KeyParam::NoAuthRequired,
                KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: 0 }),
                KeyParam::CertificateNotAfter(DateTime {
                    ms_since_epoch: 2_000_000_000_000,
                }),
            ],
            key_format: KeyFormat::Pkcs8,
            key_data: wrapping_key.private_key_to_pkcs8().unwrap(),
            attestation_key: None,
        }));
        assert_eq!(wrapping.error_code, 0, "{wrapping:?}");
        let wrapping = match wrapping.rsp {
            Some(PerformOpRsp::DeviceImportKey(response)) => response.ret,
            response => panic!("unexpected wrapping key import response: {response:?}"),
        };
        assert!(wrapping.key_characteristics.iter().any(|chars| {
            chars.security_level == SecurityLevel::TrustedEnvironment
                && chars.authorizations.contains(&KeyParam::UsageCountLimit(1))
        }));
        let wrapping_slot = EncryptedKeyBlob::new(&wrapping.key_blob)
            .unwrap()
            .secure_deletion_slot()
            .expect("single-use hardware wrapping key requires a secure deletion slot");
        assert!(slots
            .lock()
            .unwrap()
            .manager
            .get_secret(wrapping_slot)
            .is_ok());

        let transport_key = [0x42; 32];
        let masking_key = [0x73; 32];
        let masked_transport_key: [u8; 32] =
            std::array::from_fn(|index| transport_key[index] ^ masking_key[index]);
        let mut encrypter = Encrypter::new(&wrapping_key).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        encrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        encrypter.set_rsa_mgf1_md(MessageDigest::sha1()).unwrap();
        let mut encrypted_transport_key =
            vec![0; encrypter.encrypt_len(&masked_transport_key).unwrap()];
        let encrypted_len = encrypter
            .encrypt(&masked_transport_key, &mut encrypted_transport_key)
            .unwrap();
        encrypted_transport_key.truncate(encrypted_len);

        // Existing TA vector extended with UsageCountLimit(1) so the destination
        // also owns a secure deletion slot: RAW AES-256, ECB, PKCS7, no auth.
        let key_description = hex::decode(concat!(
            "30350201033030a1083106020100020101a203020120a30402020100",
            "a4053103020101a6053103020140bf831503020101bf8377020500"
        ))
        .unwrap();
        let iv = [0x19; 12];
        let mut tag = [0; 16];
        let encrypted_key = encrypt_aead(
            Cipher::aes_256_gcm(),
            &transport_key,
            Some(&iv),
            &key_description,
            &[0x64; 32],
            &mut tag,
        )
        .unwrap();
        let encode_wrapper = |tag: &[u8]| {
            TestSecureKeyWrapper {
                version: 0,
                encrypted_transport_key: &encrypted_transport_key,
                initialization_vector: &iv,
                key_description: AnyRef::from_der(&key_description).unwrap(),
                encrypted_key: &encrypted_key,
                tag,
            }
            .to_der()
            .unwrap()
        };
        let import_request = |wrapped_key_data| {
            PerformOpReq::DeviceImportWrappedKey(ImportWrappedKeyRequest {
                wrapped_key_data,
                wrapping_key_blob: wrapping.key_blob.clone(),
                masking_key: masking_key.to_vec(),
                unwrapping_params: vec![
                    KeyParam::Padding(PaddingMode::RsaOaep),
                    KeyParam::Digest(Digest::Sha256),
                    KeyParam::RsaOaepMgfDigest(Digest::Sha1),
                ],
                password_sid: 0,
                biometric_sid: 0,
            })
        };
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let failed = ta.process_req(import_request(encode_wrapper(&bad_tag)));
        assert_eq!(failed.error_code, ErrorCode::VERIFICATION_FAILED.0);
        {
            let state = slots.lock().unwrap();
            assert!(state.manager.get_secret(wrapping_slot).is_ok());
            assert!(state.delete_attempts.is_empty());
        }

        let valid_wrapper = encode_wrapper(&tag);
        slots.lock().unwrap().faulting_source = Some(wrapping_slot);
        let failed_consumption = ta.process_req(import_request(valid_wrapper.clone()));
        assert_eq!(
            failed_consumption.error_code,
            ErrorCode::SECURE_HW_COMMUNICATION_FAILED.0
        );
        assert!(failed_consumption.rsp.is_none());
        {
            let mut state = slots.lock().unwrap();
            // Source consumption and destination cleanup both reached the manager.
            // The cleanup failure must not replace the source error or publish a key.
            assert_eq!(state.delete_attempts.len(), 2);
            assert_eq!(state.delete_attempts[0], wrapping_slot);
            assert_ne!(state.delete_attempts[1], wrapping_slot);
            assert!(state.manager.get_secret(wrapping_slot).is_ok());
            assert!(state.manager.get_secret(state.delete_attempts[1]).is_ok());
            state.faulting_source = None;
        }
        let imported = ta.process_req(import_request(valid_wrapper.clone()));
        assert_eq!(imported.error_code, 0, "{imported:?}");
        let imported = match imported.rsp {
            Some(PerformOpRsp::DeviceImportWrappedKey(response)) => response.ret,
            response => panic!("unexpected wrapped import response: {response:?}"),
        };
        let destination_slot = EncryptedKeyBlob::new(&imported.key_blob)
            .unwrap()
            .secure_deletion_slot()
            .expect("single-use destination requires a secure deletion slot");
        {
            let state = slots.lock().unwrap();
            assert!(state.manager.get_secret(wrapping_slot).is_err());
            assert!(state.manager.get_secret(destination_slot).is_ok());
            assert_eq!(state.delete_attempts[2], wrapping_slot);
        }
        assert_eq!(
            ta.process_req(import_request(valid_wrapper)).error_code,
            ErrorCode::INVALID_KEY_BLOB.0
        );

        let characteristics = ta.process_req(PerformOpReq::DeviceGetKeyCharacteristics(
            GetKeyCharacteristicsRequest {
                key_blob: imported.key_blob.clone(),
                app_id: vec![],
                app_data: vec![],
            },
        ));
        assert_eq!(characteristics.error_code, 0, "{characteristics:?}");
        let characteristics = match characteristics.rsp {
            Some(PerformOpRsp::DeviceGetKeyCharacteristics(response)) => response.ret,
            response => panic!("unexpected imported key characteristics: {response:?}"),
        };
        assert_eq!(characteristics, imported.key_characteristics);
        assert!(characteristics.iter().any(|chars| {
            chars.security_level == SecurityLevel::TrustedEnvironment
                && chars
                    .authorizations
                    .contains(&KeyParam::Algorithm(Algorithm::Aes))
                && chars
                    .authorizations
                    .contains(&KeyParam::Origin(KeyOrigin::SecurelyImported))
        }));

        let begin = ta.process_req(PerformOpReq::DeviceBegin(BeginRequest {
            purpose: KeyPurpose::Encrypt,
            key_blob: imported.key_blob,
            params: vec![
                KeyParam::BlockMode(BlockMode::Ecb),
                KeyParam::Padding(PaddingMode::Pkcs7),
            ],
            auth_token: None,
        }));
        assert_eq!(begin.error_code, 0, "{begin:?}");
        let op_handle = match begin.rsp {
            Some(PerformOpRsp::DeviceBegin(response)) => response.ret.op_handle,
            response => panic!("unexpected imported key begin response: {response:?}"),
        };
        let plaintext = b"wrapped key regression";
        let finish = ta.process_req(PerformOpReq::OperationFinish(FinishRequest {
            op_handle,
            input: Some(plaintext.to_vec()),
            signature: None,
            auth_token: None,
            timestamp_token: None,
            confirmation_token: None,
        }));
        assert_eq!(finish.error_code, 0, "{finish:?}");
        let ciphertext = match finish.rsp {
            Some(PerformOpRsp::OperationFinish(response)) => response.ret,
            response => panic!("unexpected imported key finish response: {response:?}"),
        };
        assert_eq!(
            ciphertext,
            encrypt(Cipher::aes_256_ecb(), &[0x64; 32], None, plaintext).unwrap()
        );
        assert!(slots
            .lock()
            .unwrap()
            .manager
            .get_secret(destination_slot)
            .is_err());
    }

    #[test]
    fn keymint_ta_early_boot_ended_rejects_late_boot_info() {
        let mut ta = test_ta();
        assert_eq!(set_boot_info(&mut ta), 0);

        let resp = ta.process_req(PerformOpReq::DeviceEarlyBootEnded(EarlyBootEndedRequest {}));
        assert_eq!(resp.error_code, 0);

        assert_eq!(set_boot_info(&mut ta), ErrorCode::EARLY_BOOT_ENDED.0);
    }

    #[test]
    fn operation_capacity_matches_hal_profile_and_reuses_released_slots() {
        use kmr_wire::keymint::{Algorithm, Digest, KeyPurpose, SecurityLevel};

        for (version, tee_capacity) in [
            (30, 16),
            (40, 16),
            (41, 16),
            (KeyMintDevice::KEY_MINT_V1, 32),
            (KeyMintDevice::KEY_MINT_V2, 32),
            (KeyMintDevice::KEY_MINT_V3, 32),
            (KeyMintDevice::KEY_MINT_V4, 32),
            (KeyMintDevice::KEY_MINT_V5, 32),
        ] {
            for (level, capacity) in [
                (SecurityLevel::TrustedEnvironment, tee_capacity),
                (SecurityLevel::Strongbox, 4),
            ] {
                let mut ta = test_ta_with_profile(version, level, None);
                assert_eq!(set_boot_info(&mut ta), 0);
                assert_eq!(
                    ta.process_req(PerformOpReq::SetHalInfo(SetHalInfoRequest {
                        os_version: 150000,
                        os_patchlevel: 202506,
                        vendor_patchlevel: 20250605,
                    }))
                    .error_code,
                    0
                );
                let generated =
                    ta.process_req(PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
                        key_params: vec![
                            KeyParam::Purpose(KeyPurpose::Sign),
                            KeyParam::Algorithm(Algorithm::Hmac),
                            KeyParam::KeySize(KeySizeInBits(256)),
                            KeyParam::Digest(Digest::Sha256),
                            KeyParam::MinMacLength(128),
                            KeyParam::NoAuthRequired,
                        ],
                        attestation_key: None,
                    }));
                assert_eq!(generated.error_code, 0, "{level:?} v{version}");
                let key_blob = match generated.rsp {
                    Some(PerformOpRsp::DeviceGenerateKey(response)) => response.ret.key_blob,
                    response => panic!("unexpected generate response: {response:?}"),
                };
                let begin = |ta: &mut KeyMintTa| {
                    ta.process_req(PerformOpReq::DeviceBegin(BeginRequest {
                        purpose: KeyPurpose::Sign,
                        key_blob: key_blob.clone(),
                        params: vec![KeyParam::Digest(Digest::Sha256), KeyParam::MacLength(128)],
                        auth_token: None,
                    }))
                };
                let mut handles = Vec::new();
                for slot in 0..capacity {
                    let response = begin(&mut ta);
                    assert_eq!(response.error_code, 0, "{level:?} v{version} slot {slot}");
                    match response.rsp {
                        Some(PerformOpRsp::DeviceBegin(response)) => {
                            handles.push(response.ret.op_handle);
                        }
                        response => panic!("unexpected begin response: {response:?}"),
                    }
                }
                assert_eq!(
                    begin(&mut ta).error_code,
                    ErrorCode::TOO_MANY_OPERATIONS.0,
                    "{level:?} v{version} must reject operations beyond {capacity}"
                );
                // Abort and finish both release slots without disturbing other operations.
                let aborted = handles.remove(0);
                assert_eq!(
                    ta.process_req(PerformOpReq::OperationAbort(AbortRequest {
                        op_handle: aborted,
                    }))
                    .error_code,
                    0
                );
                let replacement = begin(&mut ta);
                assert_eq!(replacement.error_code, 0);
                match replacement.rsp {
                    Some(PerformOpRsp::DeviceBegin(response)) => {
                        handles.push(response.ret.op_handle);
                    }
                    response => panic!("unexpected begin response: {response:?}"),
                }
                assert_eq!(begin(&mut ta).error_code, ErrorCode::TOO_MANY_OPERATIONS.0);
                for op_handle in handles {
                    assert_eq!(
                        ta.process_req(PerformOpReq::OperationFinish(FinishRequest {
                            op_handle,
                            input: Some(b"capacity regression".to_vec()),
                            signature: None,
                            auth_token: None,
                            timestamp_token: None,
                            confirmation_token: None,
                        }))
                        .error_code,
                        0,
                        "{level:?} v{version} existing operations must remain usable"
                    );
                }
                let mut reused_handles = Vec::new();
                for slot in 0..capacity {
                    let after_finish = begin(&mut ta);
                    assert_eq!(
                        after_finish.error_code, 0,
                        "{level:?} v{version} finished slot {slot} must be reusable"
                    );
                    match after_finish.rsp {
                        Some(PerformOpRsp::DeviceBegin(response)) => {
                            reused_handles.push(response.ret.op_handle);
                        }
                        response => panic!("unexpected begin response: {response:?}"),
                    }
                }
                assert_eq!(begin(&mut ta).error_code, ErrorCode::TOO_MANY_OPERATIONS.0);
                for op_handle in reused_handles {
                    assert_eq!(
                        ta.process_req(PerformOpReq::OperationAbort(AbortRequest { op_handle }))
                            .error_code,
                        0
                    );
                }
            }
        }
    }

    #[test]
    fn restarted_ta_binds_keyblobs_to_boot_key_and_state_but_not_boot_hash() {
        use kmr_wire::keymint::{Algorithm, Digest, KeyPurpose, SecurityLevel};

        let start = |level, key, hash, locked, state| {
            let mut ta = test_ta_with_profile(KeyMintDevice::KEY_MINT_V5, level, None);
            assert_eq!(
                ta.process_req(PerformOpReq::SetBootInfo(kmr_wire::SetBootInfoRequest {
                    verified_boot_state: state,
                    verified_boot_hash: vec![hash; 32],
                    verified_boot_key: vec![key; 32],
                    device_boot_locked: locked,
                    boot_patchlevel: 20250605,
                }))
                .error_code,
                0
            );
            assert_eq!(
                ta.process_req(PerformOpReq::SetHalInfo(SetHalInfoRequest {
                    os_version: 160000,
                    os_patchlevel: 202506,
                    vendor_patchlevel: 20250605,
                }))
                .error_code,
                0
            );
            ta
        };

        for level in [SecurityLevel::TrustedEnvironment, SecurityLevel::Strongbox] {
            let mut original = start(level, 0x12, 0x34, true, 0);
            let generated =
                original.process_req(PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
                    key_params: vec![
                        KeyParam::Purpose(KeyPurpose::Sign),
                        KeyParam::Algorithm(Algorithm::Hmac),
                        KeyParam::KeySize(KeySizeInBits(256)),
                        KeyParam::Digest(Digest::Sha256),
                        KeyParam::MinMacLength(128),
                        KeyParam::NoAuthRequired,
                    ],
                    attestation_key: None,
                }));
            assert_eq!(generated.error_code, 0, "{generated:?}");
            let blob = match generated.rsp {
                Some(PerformOpRsp::DeviceGenerateKey(response)) => response.ret.key_blob,
                response => panic!("unexpected generate response: {response:?}"),
            };
            drop(original);

            for (key, hash, locked, state, expected) in [
                (0x12, 0x34, true, 0, 0),
                (0x12, 0x56, true, 0, 0),
                (0x99, 0x34, true, 0, ErrorCode::INVALID_KEY_BLOB.0),
                (0x12, 0x34, false, 0, ErrorCode::INVALID_KEY_BLOB.0),
                (0x12, 0x34, true, 2, ErrorCode::INVALID_KEY_BLOB.0),
                (0x12, 0x34, true, 0, 0),
            ] {
                let mut restarted = start(level, key, hash, locked, state);
                let recovered = restarted.process_req(PerformOpReq::DeviceGetKeyCharacteristics(
                    GetKeyCharacteristicsRequest {
                        key_blob: blob.clone(),
                        app_id: vec![],
                        app_data: vec![],
                    },
                ));
                assert_eq!(recovered.error_code, expected, "{level:?}: {recovered:?}");
            }
        }
    }

    #[test]
    fn patchlevel_update_preserves_operations_and_use_counts() {
        let mut ta = test_ta();
        assert_eq!(set_boot_info(&mut ta), 0);
        assert_eq!(
            ta.process_req(PerformOpReq::SetHalInfo(SetHalInfoRequest {
                os_version: 160000,
                os_patchlevel: 202506,
                vendor_patchlevel: 20250605,
            }))
            .error_code,
            0
        );

        let generated = ta.process_req(PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
            key_params: vec![
                KeyParam::Purpose(kmr_wire::keymint::KeyPurpose::Sign),
                KeyParam::Algorithm(kmr_wire::keymint::Algorithm::Hmac),
                KeyParam::KeySize(KeySizeInBits(256)),
                KeyParam::Digest(kmr_wire::keymint::Digest::Sha256),
                KeyParam::MinMacLength(128),
                KeyParam::NoAuthRequired,
                KeyParam::MaxUsesPerBoot(1),
            ],
            attestation_key: None,
        }));
        assert_eq!(generated.error_code, 0);
        let key_blob = match generated.rsp {
            Some(PerformOpRsp::DeviceGenerateKey(response)) => response.ret.key_blob,
            response => panic!("unexpected generate response: {response:?}"),
        };

        let begin = ta.process_req(PerformOpReq::DeviceBegin(BeginRequest {
            purpose: kmr_wire::keymint::KeyPurpose::Sign,
            key_blob: key_blob.clone(),
            params: vec![
                KeyParam::Digest(kmr_wire::keymint::Digest::Sha256),
                KeyParam::MacLength(128),
            ],
            auth_token: None,
        }));
        assert_eq!(begin.error_code, 0);
        let op_handle = match begin.rsp {
            Some(PerformOpRsp::DeviceBegin(response)) => response.ret.op_handle,
            response => panic!("unexpected begin response: {response:?}"),
        };

        ta.update_patchlevels(202507, 20250705, 20250705).unwrap();
        assert_eq!(
            ta.process_req(PerformOpReq::OperationFinish(FinishRequest {
                op_handle,
                input: Some(b"message".to_vec()),
                signature: None,
                auth_token: None,
                timestamp_token: None,
                confirmation_token: None,
            }))
            .error_code,
            0
        );
        ta.update_patchlevels(202506, 20250605, 20250605).unwrap();

        let second_begin = ta.process_req(PerformOpReq::DeviceBegin(BeginRequest {
            purpose: kmr_wire::keymint::KeyPurpose::Sign,
            key_blob,
            params: vec![
                KeyParam::Digest(kmr_wire::keymint::Digest::Sha256),
                KeyParam::MacLength(128),
            ],
            auth_token: None,
        }));
        assert_eq!(second_begin.error_code, ErrorCode::KEY_MAX_OPS_EXCEEDED.0);
    }

    #[test]
    fn upgrade_key_rewraps_a_future_patchlevel_blob_after_restore() {
        let mut ta = test_ta();
        let boot_info = ta.process_req(PerformOpReq::SetBootInfo(kmr_wire::SetBootInfoRequest {
            verified_boot_state: 0,
            verified_boot_hash: vec![0; 32],
            verified_boot_key: vec![0; 32],
            device_boot_locked: true,
            boot_patchlevel: 20260805,
        }));
        assert_eq!(boot_info.error_code, 0);
        let hal_info = ta.process_req(PerformOpReq::SetHalInfo(SetHalInfoRequest {
            os_version: 160000,
            os_patchlevel: 202608,
            vendor_patchlevel: 20260805,
        }));
        assert_eq!(hal_info.error_code, 0);

        let generated = ta.process_req(PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
            key_params: vec![
                KeyParam::Purpose(kmr_wire::keymint::KeyPurpose::Sign),
                KeyParam::Algorithm(kmr_wire::keymint::Algorithm::Hmac),
                KeyParam::KeySize(KeySizeInBits(256)),
                KeyParam::Digest(kmr_wire::keymint::Digest::Sha256),
                KeyParam::MinMacLength(256),
                KeyParam::NoAuthRequired,
                KeyParam::EarlyBootOnly,
            ],
            attestation_key: None,
        }));
        assert_eq!(generated.error_code, 0);
        let key_blob = match generated.rsp {
            Some(PerformOpRsp::DeviceGenerateKey(response)) => response.ret.key_blob,
            response => panic!("unexpected generate response: {response:?}"),
        };

        ta.update_patchlevels(202606, 20260605, 20260605)
            .expect("patchlevel restore should succeed");
        let invalid = ta.process_req(PerformOpReq::DeviceGetKeyCharacteristics(
            GetKeyCharacteristicsRequest {
                key_blob: key_blob.clone(),
                app_id: vec![],
                app_data: vec![],
            },
        ));
        assert_eq!(invalid.error_code, ErrorCode::INVALID_KEY_BLOB.0);

        let upgraded = ta.process_req(PerformOpReq::DeviceUpgradeKey(UpgradeKeyRequest {
            key_blob_to_upgrade: key_blob,
            upgrade_params: vec![],
        }));
        assert_eq!(upgraded.error_code, 0);
        let upgraded_blob = match upgraded.rsp {
            Some(PerformOpRsp::DeviceUpgradeKey(response)) => response.ret,
            response => panic!("unexpected upgrade response: {response:?}"),
        };
        assert!(!upgraded_blob.is_empty());

        let characteristics = ta.process_req(PerformOpReq::DeviceGetKeyCharacteristics(
            GetKeyCharacteristicsRequest {
                key_blob: upgraded_blob,
                app_id: vec![],
                app_data: vec![],
            },
        ));
        assert_eq!(characteristics.error_code, 0);
    }

    #[test]
    fn request_patch_profiles_bind_keys_without_mutating_global_or_live_operations() {
        use kmr_wire::keymint::{Algorithm, Digest, KeyFormat, KeyPurpose};
        let mut ta = test_ta();
        assert_eq!(set_boot_info(&mut ta), 0);
        assert_eq!(
            ta.process_req(PerformOpReq::SetHalInfo(SetHalInfoRequest {
                os_version: 160000,
                os_patchlevel: 202506,
                vendor_patchlevel: 20250605,
            }))
            .error_code,
            0
        );
        let a = kmr_ta::RequestPatchLevels {
            os_patchlevel: 202604,
            vendor_patchlevel: 20260405,
            boot_patchlevel: 20260405,
        };
        let b = kmr_ta::RequestPatchLevels {
            os_patchlevel: 202605,
            vendor_patchlevel: 20260505,
            boot_patchlevel: 20260505,
        };
        let params = || {
            vec![
                KeyParam::Purpose(KeyPurpose::Sign),
                KeyParam::Algorithm(Algorithm::Hmac),
                KeyParam::KeySize(KeySizeInBits(256)),
                KeyParam::Digest(Digest::Sha256),
                KeyParam::MinMacLength(128),
                KeyParam::NoAuthRequired,
            ]
        };
        let generated = ta.process_req_with_patchlevels(
            PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
                key_params: params(),
                attestation_key: None,
            }),
            Some(a),
        );
        assert_eq!(generated.error_code, 0);
        let key = match generated.rsp {
            Some(PerformOpRsp::DeviceGenerateKey(rsp)) => rsp.ret,
            response => panic!("{response:?}"),
        };
        let auths = &key.key_characteristics[0].authorizations;
        assert!(auths.contains(&KeyParam::OsPatchlevel(a.os_patchlevel)));
        assert!(auths.contains(&KeyParam::VendorPatchlevel(a.vendor_patchlevel)));
        assert!(auths.contains(&KeyParam::BootPatchlevel(a.boot_patchlevel)));
        let characteristics = |blob: Vec<u8>| {
            PerformOpReq::DeviceGetKeyCharacteristics(GetKeyCharacteristicsRequest {
                key_blob: blob,
                app_id: vec![],
                app_data: vec![],
            })
        };
        assert_eq!(
            ta.process_req_with_patchlevels(characteristics(key.key_blob.clone()), Some(a))
                .error_code,
            0
        );
        assert_eq!(
            ta.process_req(characteristics(key.key_blob.clone()))
                .error_code,
            // The global value is June 2025, while profile A is April 2026.
            ErrorCode::INVALID_KEY_BLOB.0
        );
        assert_eq!(
            ta.process_req_with_patchlevels(characteristics(key.key_blob.clone()), Some(b))
                .error_code,
            ErrorCode::KEY_REQUIRES_UPGRADE.0
        );
        let begin = ta.process_req_with_patchlevels(
            PerformOpReq::DeviceBegin(BeginRequest {
                purpose: KeyPurpose::Sign,
                key_blob: key.key_blob.clone(),
                params: vec![KeyParam::Digest(Digest::Sha256), KeyParam::MacLength(128)],
                auth_token: None,
            }),
            Some(a),
        );
        assert_eq!(begin.error_code, 0);
        let handle = match begin.rsp {
            Some(PerformOpRsp::DeviceBegin(rsp)) => rsp.ret.op_handle,
            response => panic!("{response:?}"),
        };
        let imported = ta.process_req_with_patchlevels(
            PerformOpReq::DeviceImportKey(ImportKeyRequest {
                key_params: params(),
                key_format: KeyFormat::Raw,
                key_data: vec![7; 32],
                attestation_key: None,
            }),
            Some(b),
        );
        assert_eq!(imported.error_code, 0);
        let imported = match imported.rsp {
            Some(PerformOpRsp::DeviceImportKey(rsp)) => rsp.ret,
            response => panic!("{response:?}"),
        };
        assert!(imported.key_characteristics[0]
            .authorizations
            .contains(&KeyParam::OsPatchlevel(b.os_patchlevel)));
        assert_eq!(
            ta.process_req(PerformOpReq::OperationFinish(FinishRequest {
                op_handle: handle,
                input: Some(b"message".to_vec()),
                signature: None,
                auth_token: None,
                timestamp_token: None,
                confirmation_token: None,
            }))
            .error_code,
            0
        );
        let upgraded = ta.process_req_with_patchlevels(
            PerformOpReq::DeviceUpgradeKey(UpgradeKeyRequest {
                key_blob_to_upgrade: key.key_blob,
                upgrade_params: vec![],
            }),
            Some(b),
        );
        assert_eq!(upgraded.error_code, 0);
        let upgraded = match upgraded.rsp {
            Some(PerformOpRsp::DeviceUpgradeKey(rsp)) => rsp.ret,
            response => panic!("{response:?}"),
        };
        assert_eq!(
            ta.process_req_with_patchlevels(characteristics(upgraded.clone()), Some(b))
                .error_code,
            0
        );
        assert_eq!(
            ta.process_req_with_patchlevels(characteristics(upgraded.clone()), Some(a))
                .error_code,
            ErrorCode::INVALID_KEY_BLOB.0
        );
        // OMK's explicit upgrade path also permits restoring a lower patch
        // profile. Ordinary begin/characteristics still reject future blobs.
        let restored = ta.process_req_with_patchlevels(
            PerformOpReq::DeviceUpgradeKey(UpgradeKeyRequest {
                key_blob_to_upgrade: upgraded,
                upgrade_params: vec![],
            }),
            Some(a),
        );
        assert_eq!(restored.error_code, 0);
        let restored = match restored.rsp {
            Some(PerformOpRsp::DeviceUpgradeKey(rsp)) => rsp.ret,
            response => panic!("{response:?}"),
        };
        assert_eq!(
            ta.process_req_with_patchlevels(characteristics(restored), Some(a))
                .error_code,
            0
        );
        let global = ta.process_req(PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
            key_params: params(),
            attestation_key: None,
        }));
        assert_eq!(global.error_code, 0);
        let global = match global.rsp {
            Some(PerformOpRsp::DeviceGenerateKey(rsp)) => rsp.ret,
            response => panic!("{response:?}"),
        };
        assert!(global.key_characteristics[0]
            .authorizations
            .contains(&KeyParam::OsPatchlevel(202506)));
        assert!(global.key_characteristics[0]
            .authorizations
            .contains(&KeyParam::VendorPatchlevel(20250605)));
        assert!(global.key_characteristics[0]
            .authorizations
            .contains(&KeyParam::BootPatchlevel(20250605)));
    }
}
