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

//! Accounting for keys that carry `Tag::USAGE_COUNT_LIMIT`.
//!
//! A KeyMint implementation consumes a use when an operation *produces its result*, not when the
//! operation is opened: a client may hold several operations for the same key, and only completed
//! operations count. Keystore polices the limit for stored keys, but self-managed (`Domain::BLOB`)
//! key blobs reach the TA directly and have no Keystore row, so the TA keeps its own accounting,
//! keyed by the key identifier derived from the blob the client presents.

use std::collections::HashMap;

use kmr_common::{km_err, Error};
use log::{info, trace, warn};

use crate::{operation::OpHandle, KeyId};

/// Bounds the operation accounting when completions are abandoned (for example because a finish
/// failed early). The operation table is far smaller than this, so the bound is not reachable
/// through normal use.
const MAX_IN_FLIGHT: usize = 256;

/// Per-process usage accounting for limited-use keys.
#[derive(Default)]
pub(crate) struct UsageLimits {
    /// Number of uses already consumed, per key.
    used: HashMap<KeyId, u32>,
    /// Operations that still owe a use, with the limit they were opened under.
    in_flight: HashMap<OpHandle, (KeyId, u32)>,
}

impl UsageLimits {
    /// Rejects a request for a key whose limit is already exhausted.
    pub(crate) fn ensure_available(&self, key: &KeyId, limit: u32) -> Result<(), Error> {
        let used = self.used.get(key).copied().unwrap_or(0);
        if used >= limit {
            return Err(km_err!(
                KeyMaxOpsExceeded,
                "key usage limit exhausted: {used} of {limit} uses consumed"
            ));
        }
        Ok(())
    }

    /// Remembers an opened operation so that its completion consumes exactly one use.
    pub(crate) fn track(&mut self, handle: OpHandle, key: KeyId, limit: u32) {
        if self.in_flight.len() >= MAX_IN_FLIGHT {
            warn!("dropping stale limited-use operation accounting");
            self.in_flight.clear();
        }
        self.in_flight.insert(handle, (key, limit));
    }

    /// Reports whether the operation may still produce a result.
    ///
    /// A sibling operation that already consumed the last allowed use is rejected here, before the
    /// crypto operation runs or touches its secure-deletion slot, so the limit stays observable at
    /// finish time even when several operations were opened up front.
    pub(crate) fn check_completion(&self, handle: OpHandle) -> Result<(), Error> {
        match self.in_flight.get(&handle) {
            Some((key, limit)) => self.ensure_available(key, *limit),
            None => Ok(()),
        }
    }

    /// Consumes one use for an operation that produced its result.
    pub(crate) fn complete(&mut self, handle: OpHandle) -> Result<(), Error> {
        let Some((key, limit)) = self.in_flight.remove(&handle) else {
            trace!("no limited-use accounting for completed operation op={}", handle.0);
            return Ok(());
        };
        self.ensure_available(&key, limit)?;
        let used = self.used.entry(key.clone()).or_insert(0);
        *used += 1;
        info!(
            "limited-use key use consumed: key={:02x?} used={}/{} op={}",
            key.short(),
            *used,
            limit,
            handle.0
        );
        Ok(())
    }

    /// Forgets an operation that produced no result.
    pub(crate) fn abandon(&mut self, handle: OpHandle) {
        self.in_flight.remove(&handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> KeyId {
        KeyId([byte; 32])
    }

    #[test]
    fn a_sibling_operation_cannot_use_the_last_allowance_twice() {
        let mut limits = UsageLimits::default();
        let key = key(0x11);
        assert!(limits.ensure_available(&key, 1).is_ok());
        limits.track(OpHandle(1), key.clone(), 1);
        limits.track(OpHandle(2), key.clone(), 1);

        assert!(limits.check_completion(OpHandle(1)).is_ok());
        assert!(limits.complete(OpHandle(1)).is_ok());
        // The second operation was opened before the first one completed, so it is only rejected
        // once its result would be produced.
        assert!(limits.check_completion(OpHandle(2)).is_err());
        assert!(limits.complete(OpHandle(2)).is_err());
        // The key stays exhausted for any later operation.
        assert!(limits.ensure_available(&key, 1).is_err());
    }

    #[test]
    fn a_higher_limit_allows_that_many_completions() {
        let mut limits = UsageLimits::default();
        let key = key(0x22);
        for handle in [OpHandle(1), OpHandle(2)] {
            limits.track(handle, key.clone(), 2);
        }
        assert!(limits.complete(OpHandle(1)).is_ok());
        assert!(limits.complete(OpHandle(2)).is_ok());

        limits.track(OpHandle(3), key.clone(), 2);
        assert!(limits.check_completion(OpHandle(3)).is_err());
    }

    #[test]
    fn abandoning_an_operation_does_not_consume_a_use() {
        let mut limits = UsageLimits::default();
        let key = key(0x33);
        limits.track(OpHandle(1), key.clone(), 1);
        limits.abandon(OpHandle(1));

        assert!(limits.ensure_available(&key, 1).is_ok());
        limits.track(OpHandle(2), key.clone(), 1);
        assert!(limits.complete(OpHandle(2)).is_ok());
        assert!(limits.ensure_available(&key, 1).is_err());
    }

    #[test]
    fn unrelated_keys_keep_independent_limits() {
        let mut limits = UsageLimits::default();
        let first = key(0x44);
        let second = key(0x55);
        limits.track(OpHandle(1), first.clone(), 1);
        limits.track(OpHandle(2), second.clone(), 1);

        assert!(limits.complete(OpHandle(1)).is_ok());
        assert!(limits.ensure_available(&first, 1).is_err());
        assert!(limits.ensure_available(&second, 1).is_ok());
        assert!(limits.complete(OpHandle(2)).is_ok());
    }
}
