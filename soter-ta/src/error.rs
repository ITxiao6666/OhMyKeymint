//! `SoterErrorCode` values as they appear on the wire.
//!
//! `SoterErrorCode` is a plain `int32` in the HAL AIDL; the stock HAL forwards
//! whatever the TA/QSEE layer reported. The values below were read off the live
//! HAL of a OnePlus 13 whose TA is dead.

/// Success. The Java layer treats `rc == 0` as "yes/ok".
pub const SOTER_OK: i32 = 0;

/// No such key.
///
/// The stock HAL answers `-5` (`0xfffffffb`) to `hasAskAlready` for a uid that
/// has no ASK, and that is what an empty local ledger should answer too.
pub const SOTER_ERR_NO_KEY: i32 = -5;

/// No such AuthKey.
///
/// Captured on the live vendor TA of the PHB110 (2026-09-26, uid 10346 with an
/// ASK present): `getAuthKey`, `initSign` and `removeAuthKey` all answer `-6`
/// for a kname that does not exist. `-5` is what the same codes answer when the
/// whole TA is dead, so the AuthKey-scoped lookups must not reuse it.
pub const SOTER_ERR_NO_AUTH_KEY: i32 = -6;

/// No fresh biometric match for this sign session.
///
/// A live vendor TA signs only inside a fresh fingerprint match and answers `-26`
/// to `finishSign` without one: captured on the PHB110 and the MIX 4 on
/// 2026-09-26, where `finishSign` right after `initSign` (no prompt, no press)
/// answered `-26` while the same call after a real press answered `0`.
pub const SOTER_ERR_NO_FINGERPRINT: i32 = -26;

/// Raw `rsp->status` of a TEE command that could not be delivered.
///
/// This is the value every Soter call fails with while the TA is unavailable,
/// and it is also the honest answer when local key generation or signing fails.
pub const SOTER_ERR_TA_UNAVAILABLE: i32 = -20;

/// No such sign session.
///
/// The stock HAL answers `-1000` (`0xfffffc18`) to `finishSign` for a session it
/// does not know, captured on the OnePlus 13 on 2026-09-24 while its TA was dead.
pub const SOTER_ERR_NO_SESSION: i32 = -1000;

/// Malformed request, unknown alias/session and similar argument errors.
pub const SOTER_ERR_BAD_VALUE: i32 = -22;
