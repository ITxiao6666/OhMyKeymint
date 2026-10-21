//! Software TA state: key ledger, anti-rollback counters and sign sessions.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::blob;
use crate::error::{
    SOTER_ERR_BAD_VALUE, SOTER_ERR_NO_AUTH_KEY, SOTER_ERR_NO_FINGERPRINT, SOTER_ERR_NO_KEY,
    SOTER_ERR_NO_SESSION, SOTER_ERR_TA_UNAVAILABLE, SOTER_OK,
};
use crate::platform::{same_boot, Platform};

/// Key size the stock TA uses for ASK and AuthKey.
const RSA_BITS: usize = 2048;
const RSA_EXPONENT: u32 = 65537;

/// How long a sign session may stay open before its biometric evidence stops
/// counting.
///
/// The stock TA keeps its own freshness window inside the secure world and this
/// work never captured it; two minutes is generous with a slow caller and still
/// refuses a session that sat open long enough for an unrelated fingerprint
/// match to fall inside it.
pub const BIO_WINDOW_MS: u64 = 120_000;

/// Suffix of the temporary file the atomic write goes through.
const SIDECAR_TEMP: &str = ".tmp";
/// Suffix of the previous revision kept beside the ledger.
const SIDECAR_BACKUP: &str = ".bak";

/// `state.json` + `.bak` / `.tmp`, without touching the extension.
fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().map(OsString::from).unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

/// Owner-only permissions for anything that holds key material.
fn set_owner_only(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// A key pair in PEM form, so the whole ledger fits in one JSON file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_pem: String,
    pub public_pem: String,
}

impl KeyPair {
    fn generate() -> Option<Self> {
        let mut rng = OsRng;
        let private =
            RsaPrivateKey::new_with_exp(&mut rng, RSA_BITS, &BigUint::from(RSA_EXPONENT)).ok()?;
        let public = RsaPublicKey::from(&private);
        Some(Self {
            private_pem: private.to_pkcs8_pem(LineEnding::LF).ok()?.to_string(),
            public_pem: public.to_public_key_pem(LineEnding::LF).ok()?,
        })
    }

    pub fn private(&self) -> Option<RsaPrivateKey> {
        RsaPrivateKey::from_pkcs8_pem(&self.private_pem).ok()
    }

    pub fn public(&self) -> Option<RsaPublicKey> {
        RsaPublicKey::from_public_key_pem(&self.public_pem).ok()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UidState {
    /// Anti-rollback counter, strictly increasing per uid on the wire.
    pub counter: u64,
    #[serde(default)]
    pub ask: Option<KeyPair>,
    #[serde(default)]
    pub auth: BTreeMap<String, KeyPair>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub uid: u32,
    pub kname: String,
    pub challenge: String,
    /// Boot-clock milliseconds when `initSign` opened the session. A session
    /// from an earlier boot can never carry fresh evidence: the boot clock
    /// restarted, and so did the counter the marks are read from.
    #[serde(default)]
    pub opened_ms: Option<u64>,
    /// Fingerprint mark when the session opened; the evidence is a mark that
    /// moved past this one inside the same boot.
    #[serde(default)]
    pub bio_mark: Option<u64>,
}

/// Everything the software TA knows. Serialized as a single JSON document so the
/// injector can keep it under `/data/misc/keystore/omk/data/soterta/state.json`
/// (mode 0600).
#[derive(Debug, Serialize, Deserialize)]
pub struct TaState {
    /// Synthetic device id: 32 hex characters, generated locally and never
    /// copied from another device.
    pub cpu_id: String,
    /// Device key that signs ASK blobs. A real device signs those with the
    /// ATTK inside the secure world, which cannot be reproduced here.
    pub attk: KeyPair,
    #[serde(default)]
    pub uids: BTreeMap<u32, UidState>,
    #[serde(default)]
    pub sessions: BTreeMap<u64, Session>,
    #[serde(default)]
    pub next_session: u64,
    /// Fingerprint template id reported in sign results, one per uid and stable
    /// across signatures (a finger id does not change between payments).
    #[serde(default)]
    pub fingerprints: BTreeMap<u32, String>,
    /// Highest fingerprint mark a signature has already spent. One accepted
    /// capture authorises one signature, like the biometric result a stock TA
    /// consumes with the sign it releases.
    #[serde(default)]
    pub bio_watermark: u64,
}

impl TaState {
    /// Fresh local state: new device id and a new device signing key.
    pub fn generate_local() -> Option<Self> {
        let mut rng = OsRng;
        let mut id = [0u8; 12];
        rng.fill_bytes(&mut id);
        Some(Self {
            cpu_id: format!("00000000{}", hex::encode(id)),
            attk: KeyPair::generate()?,
            uids: BTreeMap::new(),
            sessions: BTreeMap::new(),
            next_session: 0,
            fingerprints: BTreeMap::new(),
            bio_watermark: 0,
        })
    }

    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }

    pub fn load(path: &Path) -> Option<Self> {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| Self::from_json(&bytes))
    }

    /// Load the ledger, falling back to the previous revision.
    ///
    /// `Ok(None)` means no identity exists yet, so the caller may mint one.
    /// `Err` means an identity file is present but unreadable: the caller must
    /// stop instead of generating a second identity, because a new device id
    /// would look like a different device to every client that remembers this
    /// one (including the relay-era material they were registered against).
    pub fn load_or_error(path: &Path) -> Result<Option<Self>, String> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if let Some(state) = Self::from_json(&bytes) {
            return Ok(Some(state));
        }
        let backup = sibling_path(path, SIDECAR_BACKUP);
        match std::fs::read(&backup).map(|bytes| Self::from_json(&bytes)) {
            Ok(Some(state)) => {
                // Restore the last good revision so the next start is clean.
                state
                    .store(path)
                    .map_err(|error| format!("cannot restore {}: {error}", path.display()))?;
                Ok(Some(state))
            }
            _ => Err(format!(
                "{} is unreadable and {} cannot be used either",
                path.display(),
                backup.display()
            )),
        }
    }

    /// Persist the ledger atomically and keep the previous revision beside it.
    ///
    /// The write goes to a temporary file that is renamed over the target, and
    /// the file being replaced is copied to `<path>.bak` first, so a crash or a
    /// full disk can never leave a truncated file that the next start would
    /// read as "no identity yet".
    pub fn store(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let tmp = sibling_path(path, SIDECAR_TEMP);
        std::fs::write(&tmp, &bytes)?;
        set_owner_only(&tmp)?;
        if path.exists() {
            std::fs::copy(path, sibling_path(path, SIDECAR_BACKUP))?;
        }
        std::fs::rename(&tmp, path)?;
        set_owner_only(path)?;
        Ok(())
    }

    fn next_counter(&mut self, uid: u32) -> u64 {
        let entry = self.uids.entry(uid).or_default();
        entry.counter = entry.counter.wrapping_add(1);
        entry.counter
    }

    fn fingerprint_id(&mut self, uid: u32) -> String {
        if let Some(id) = self.fingerprints.get(&uid) {
            return id.clone();
        }
        let value = OsRng.next_u32() % 100_000_000;
        let id = format!("7{value:08}");
        self.fingerprints.insert(uid, id.clone());
        id
    }

    fn ask_of(&self, uid: u32) -> Option<KeyPair> {
        self.uids.get(&uid).and_then(|entry| entry.ask.clone())
    }

    fn auth_of(&self, uid: u32, kname: &str) -> Option<KeyPair> {
        self.uids
            .get(&uid)
            .and_then(|entry| entry.auth.get(kname))
            .cloned()
    }

    /// `generateAskKeyPair`: create the uid's ASK, keep an existing one.
    pub fn generate_ask(&mut self, uid: u32) -> i32 {
        let entry = self.uids.entry(uid).or_default();
        if entry.ask.is_none() {
            let Some(pair) = KeyPair::generate() else {
                return SOTER_ERR_TA_UNAVAILABLE;
            };
            entry.ask = Some(pair);
        }
        SOTER_OK
    }

    /// `hasAskAlready`: `SOTER_OK` means "yes", anything else means "no".
    pub fn has_ask(&self, uid: u32) -> i32 {
        if self.ask_of(uid).is_some() {
            SOTER_OK
        } else {
            SOTER_ERR_NO_KEY
        }
    }

    /// `exportAskPublicKey`: ASK blob signed with the device key.
    pub fn export_ask(&mut self, uid: u32) -> (i32, Vec<u8>) {
        let Some(pair) = self.ask_of(uid) else {
            return (SOTER_ERR_NO_KEY, Vec::new());
        };
        let Some(device_key) = self.attk.private() else {
            return (SOTER_ERR_TA_UNAVAILABLE, Vec::new());
        };
        let counter = self.next_counter(uid);
        let json = blob::key_json(&pair.public_pem, &self.cpu_id, counter, uid);
        let Some(signature) = blob::sign(&device_key, &json) else {
            return (SOTER_ERR_TA_UNAVAILABLE, Vec::new());
        };
        (SOTER_OK, blob::encode(&json, &signature))
    }

    /// `exportAttkPublicKey`: the device key that signs every ASK blob.
    ///
    /// On a real device this is the factory ATTK burned into the secure world.
    /// No live capture of this transaction exists (the A-side TA has been dead
    /// for the whole investigation, 调查-Soter中继可行性.md 18.2), so the reply
    /// reuses the ASK export shape: the key JSON signed by that same key.
    pub fn export_attk(&mut self) -> (i32, Vec<u8>) {
        let Some(device_key) = self.attk.private() else {
            return (SOTER_ERR_NO_KEY, Vec::new());
        };
        let counter = self.next_counter(0);
        let json = blob::key_json(&self.attk.public_pem, &self.cpu_id, counter, 0);
        let Some(signature) = blob::sign(&device_key, &json) else {
            return (SOTER_ERR_TA_UNAVAILABLE, Vec::new());
        };
        (SOTER_OK, blob::encode(&json, &signature))
    }

    /// `verifyAttkKeyPair`: the real TA compares the factory ATTK against a copy
    /// in the secure world. The vendor engineering-mode key check reaches this
    /// transaction through cryptoeng, so a present device key is valid.
    pub fn verify_attk(&self) -> i32 {
        if self.attk.private().is_some() {
            SOTER_OK
        } else {
            SOTER_ERR_NO_KEY
        }
    }

    /// `generateAttkKeyPair`: idempotent on purpose.
    ///
    /// Rotating here would invalidate every ASK blob already signed by this
    /// device key, and the vendor UI treats an existing key as already
    /// generated anyway. The byte argument is a magic the answer ignores.
    pub fn generate_attk(&mut self, _magic: i8) -> i32 {
        if self.attk.private().is_some() {
            SOTER_OK
        } else {
            SOTER_ERR_NO_KEY
        }
    }

    /// `generateAuthKeyPair`: needs the uid's ASK to exist, since the ASK is
    /// what signs the AuthKey blob.
    pub fn generate_auth(&mut self, uid: u32, kname: &str) -> i32 {
        if kname.is_empty() {
            return SOTER_ERR_BAD_VALUE;
        }
        if self.ask_of(uid).is_none() {
            return SOTER_ERR_NO_KEY;
        }
        let entry = self.uids.entry(uid).or_default();
        if !entry.auth.contains_key(kname) {
            let Some(pair) = KeyPair::generate() else {
                return SOTER_ERR_TA_UNAVAILABLE;
            };
            entry.auth.insert(kname.to_string(), pair);
        }
        SOTER_OK
    }

    pub fn has_auth(&self, uid: u32, kname: &str) -> i32 {
        if kname.is_empty() || self.auth_of(uid, kname).is_none() {
            SOTER_ERR_NO_AUTH_KEY
        } else {
            SOTER_OK
        }
    }

    /// `exportAuthKeyPublicKey`: AuthKey blob signed with the uid's ASK.
    pub fn export_auth(&mut self, uid: u32, kname: &str) -> (i32, Vec<u8>) {
        let Some(ask) = self.ask_of(uid) else {
            return (SOTER_ERR_NO_KEY, Vec::new());
        };
        let Some(auth) = self.auth_of(uid, kname) else {
            return (SOTER_ERR_NO_AUTH_KEY, Vec::new());
        };
        let Some(ask_key) = ask.private() else {
            return (SOTER_ERR_TA_UNAVAILABLE, Vec::new());
        };
        let counter = self.next_counter(uid);
        let json = blob::key_json(&auth.public_pem, &self.cpu_id, counter, uid);
        let Some(signature) = blob::sign(&ask_key, &json) else {
            return (SOTER_ERR_TA_UNAVAILABLE, Vec::new());
        };
        (SOTER_OK, blob::encode(&json, &signature))
    }

    pub fn remove_auth(&mut self, uid: u32, kname: &str) -> i32 {
        let Some(entry) = self.uids.get_mut(&uid) else {
            return SOTER_ERR_NO_AUTH_KEY;
        };
        if entry.auth.remove(kname).is_some() {
            SOTER_OK
        } else {
            SOTER_ERR_NO_AUTH_KEY
        }
    }

    /// `removeAllUidKey`: drop the ASK, every AuthKey and any open session.
    pub fn remove_all_uid(&mut self, uid: u32) -> i32 {
        let existed = self.uids.remove(&uid).is_some();
        self.sessions.retain(|_, session| session.uid != uid);
        if existed {
            SOTER_OK
        } else {
            SOTER_ERR_NO_KEY
        }
    }

    /// `initSign`: open a session for an existing AuthKey.
    ///
    /// The platform values become the baseline `finishSign` compares against:
    /// the moment the session opened and the fingerprint mark that was current
    /// then. A stock TA refuses to sign without a fresh match, and so does this
    /// one; see [`TaState::biometric_ok`].
    pub fn init_sign(
        &mut self,
        uid: u32,
        kname: &str,
        challenge: &str,
        platform: Platform,
    ) -> (i32, u64) {
        if kname.is_empty() {
            return (SOTER_ERR_BAD_VALUE, 0);
        }
        if self.auth_of(uid, kname).is_none() {
            return (SOTER_ERR_NO_AUTH_KEY, 0);
        }
        self.next_session = self.next_session.wrapping_add(1).max(1);
        let session = self.next_session;
        self.sessions.insert(
            session,
            Session {
                uid,
                kname: kname.to_string(),
                challenge: challenge.to_string(),
                opened_ms: platform.boot_ms,
                bio_mark: platform.bio_mark,
            },
        );
        (SOTER_OK, session)
    }

    /// `finishSign`: sign the challenge once with the AuthKey.
    ///
    /// Without a fingerprint match this answers `-26` and leaves the session
    /// open, so a client that only gets its press after a first refusal can
    /// still finish. Every other answer closes the session, whether or not
    /// signing worked.
    pub fn finish_sign(&mut self, session: u64, platform: Platform) -> (i32, Vec<u8>) {
        let Some(entry) = self.sessions.get(&session).cloned() else {
            return (SOTER_ERR_NO_SESSION, Vec::new());
        };
        if !self.biometric_ok(&entry, platform) {
            return (SOTER_ERR_NO_FINGERPRINT, Vec::new());
        }
        self.sessions.remove(&session);
        let Some(key) = self.auth_of(entry.uid, &entry.kname) else {
            return (SOTER_ERR_NO_AUTH_KEY, Vec::new());
        };
        let Some(private) = key.private() else {
            return (SOTER_ERR_TA_UNAVAILABLE, Vec::new());
        };
        let counter = self.next_counter(entry.uid);
        let fid = self.fingerprint_id(entry.uid);
        let json = blob::result_json(&entry.challenge, &fid, counter, &self.cpu_id, entry.uid);
        let Some(signature) = blob::sign(&private, &json) else {
            return (SOTER_ERR_TA_UNAVAILABLE, Vec::new());
        };
        (SOTER_OK, blob::encode(&json, &signature))
    }

    /// Whether the platform shows a fingerprint match this session may spend.
    ///
    /// Evidence has to be *verifiable* to count: both hooks installed, both
    /// marks taken in this boot, the session still inside [`BIO_WINDOW_MS`], the
    /// mark moved past the one the session opened with, and no earlier
    /// signature having spent it. Missing evidence here represents an explicit
    /// disabled gate. The shared runtime refuses unreadable evidence from an
    /// enabled gate before dispatch; a counter without a fresh match answers
    /// `false`, the `-26` a stock TA gives without a match.
    fn biometric_ok(&mut self, entry: &Session, platform: Platform) -> bool {
        let (Some(opened), Some(before), Some(now), Some(after)) = (
            entry.opened_ms,
            entry.bio_mark,
            platform.boot_ms,
            platform.bio_mark,
        ) else {
            return true;
        };
        if !same_boot(before, after) || now < opened || now - opened > BIO_WINDOW_MS {
            return false;
        }
        if after <= before {
            return false;
        }
        let watermark = if same_boot(self.bio_watermark, after) {
            self.bio_watermark
        } else {
            0
        };
        if after <= watermark {
            return false;
        }
        self.bio_watermark = after;
        true
    }

    /// `getDeviceId`: ASCII bytes of the same 32-hex-character string that is
    /// embedded as `cpu_id` in every blob. The stock HAL reports the id as a
    /// byte buffer and the Java layer passes it through, so keeping both
    /// spellings identical keeps a checker from seeing two ids on one device.
    pub fn device_id(&self) -> (i32, Vec<u8>) {
        // Raw bytes, not the hex spelling: a device with a working TA reports
        // the id whose hex is the `cpu_id` every blob carries (B-side capture,
        // 2026-09-24: 16 bytes `AAAAACAcoOGHTCs+rGtnwg==` against `cpu_id`
        // `00000000201ca0e1874c2b3eac6b67c2`), and the Java layer hands those
        // bytes to the application unchanged.
        match hex::decode(&self.cpu_id) {
            Ok(bytes) => (SOTER_OK, bytes),
            Err(_) => (SOTER_ERR_TA_UNAVAILABLE, Vec::new()),
        }
    }
}
