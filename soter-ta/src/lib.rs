//! Software Soter TA for the A-side device.
//!
//! The vendor AIDL HAL `vendor.qti.hardware.soter.ISoter` is a thin proxy over a
//! Qualcomm TA that lives in the secure world. On a device whose secure world is
//! unusable (unlocked bootloader with a dead TrustZone applet) every Soter call
//! fails with `-20`, which applications that use Soter as a local device-integrity
//! probe read as "this device is up to something".
//!
//! This crate implements the HAL state machine with purely local material: its own
//! RSA keys, its own device id, its own anti-rollback counters and sign sessions.
//! Applications that go through the Java `SoterService` then see a healthy,
//! self-consistent Soter.
//!
//! With remote.conf absent or disabled, the local ASK/AuthKey ledger remains
//! self-consistent across calls and restarts. An optional, separately configured
//! SOTER relay forwards through the same native HAL service to a remote B-side
//! TEE. Remote failures do not switch an active slot to this local ledger.
pub mod blob;
pub mod bridge;
pub mod dispatch;
pub mod error;
pub mod ffi;
pub mod hal;
pub mod parcel;
pub mod platform;
pub mod remote;
pub mod state;

pub use error::{
    SOTER_ERR_BAD_VALUE, SOTER_ERR_NO_KEY, SOTER_ERR_NO_SESSION, SOTER_ERR_TA_UNAVAILABLE, SOTER_OK,
};
pub use state::TaState;

#[cfg(test)]
mod tests;
