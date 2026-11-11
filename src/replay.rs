//! Single-use enforcement for `CANONICAL_V1` request signatures.
//!
//! The timestamp window in [`crate::middleware`] bounds *how long* a captured request stays useful;
//! it does nothing about that request being used more than once inside the window. Those are
//! different properties, and only the second one is replay protection in the sense an attacker
//! cares about: anyone who observes one authentic signed request can resend those exact bytes
//! for the rest of the window. Every field the signature covers is unchanged, so the HMAC verifies
//! and the freshness check passes.
//!
//! [`ReplayGuard`] closes that by remembering which signatures have already been accepted and
//! refusing a second use. A signature is only ever recorded **after** it has been verified, which is
//! what keeps this from becoming a memory-exhaustion target: filling the map requires producing
//! valid HMACs, which requires the signing secret.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use uuid::Uuid;

/// How often expired entries are swept out, as a fraction of the replay window.
const PRUNE_INTERVAL_DIVISOR: u32 = 4;

/// Minimum spacing between two *capacity-triggered* sweeps, as a fraction of the replay window.
const CAPACITY_BACKOFF_DIVISOR: u32 = 16;

/// Hard ceiling on tracked signatures, past which the guard sweeps early and complains.
const MAX_TRACKED_SIGNATURES: usize = 100_000;

/// Identifies one accepted signature.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct SignatureId {
    /// The key that signed the request.
    key_id: Uuid,
    /// The raw HMAC-SHA256 digest.
    digest: Vec<u8>,
}

/// When the next routine and capacity-triggered sweeps become due.
#[derive(Debug)]
struct PruneSchedule {
    /// Next routine sweep.
    next: Instant,
    /// Earliest instant at which a capacity-triggered sweep may run again.
    next_capacity: Instant,
}

/// Rejects a validly-signed request whose signature has already been seen inside the window.
#[derive(Debug)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<SignatureId, Instant>>,
    schedule: Mutex<PruneSchedule>,
    window: Duration,
    prune_interval: Duration,
    capacity_backoff: Duration,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(crate::crypto::MAX_TIMESTAMP_SKEW_SECS)
    }
}

impl ReplayGuard {
    /// Builds a guard remembering signatures for `window_seconds`.
    #[must_use]
    pub fn new(window_seconds: i64) -> Self {
        let window = Duration::from_secs(window_seconds.clamp(1, 3600) as u64);
        let prune_interval = window / PRUNE_INTERVAL_DIVISOR;
        let capacity_backoff = window / CAPACITY_BACKOFF_DIVISOR;
        let now = Instant::now();
        Self {
            seen: Mutex::new(HashMap::new()),
            schedule: Mutex::new(PruneSchedule {
                next: now + prune_interval,
                next_capacity: now,
            }),
            window,
            prune_interval,
            capacity_backoff,
        }
    }

    /// Records a verified signature, reporting whether it had already been used.
    pub fn check_and_record(&self, key_id: Uuid, digest: &[u8]) -> bool {
        let now = Instant::now();
        self.prune_if_due(now);

        let Ok(mut seen) = self.seen.lock() else {
            tracing::error!(
                "Replay guard mutex is poisoned; rejecting the request rather than authenticating \
                 without replay protection."
            );
            return false;
        };

        let id = SignatureId {
            key_id,
            digest: digest.to_vec(),
        };
        match seen.get(&id) {
            Some(expires_at) if *expires_at > now => false,
            _ => {
                seen.insert(id, now + self.window);
                true
            }
        }
    }

    /// Removes a recorded signature digest so that a transiently failed request (e.g. 503 Service
    /// Unavailable due to temporary database locking or connection pool exhaustion) can be retried by
    /// the caller with the same signature without being falsely rejected as a replay.
    pub fn unrecord(&self, key_id: Uuid, digest: &[u8]) {
        if let Ok(mut seen) = self.seen.lock() {
            let id = SignatureId {
                key_id,
                digest: digest.to_vec(),
            };
            seen.remove(&id);
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.seen.lock().map(|seen| seen.len()).unwrap_or(0)
    }

    fn prune_if_due(&self, now: Instant) {
        let over_capacity =
            self.seen.lock().is_ok_and(|seen| seen.len() >= MAX_TRACKED_SIGNATURES);

        {
            let Ok(mut schedule) = self.schedule.lock() else {
                return;
            };
            let routine_due = now >= schedule.next;
            let capacity_due = over_capacity && now >= schedule.next_capacity;
            if !routine_due && !capacity_due {
                return;
            }
            schedule.next = now + self.prune_interval;
            if capacity_due {
                schedule.next_capacity = now + self.capacity_backoff;
            }
        }

        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        seen.retain(|_, expires_at| *expires_at > now);

        if seen.len() >= MAX_TRACKED_SIGNATURES {
            tracing::warn!(
                tracked = seen.len(),
                ceiling = MAX_TRACKED_SIGNATURES,
                "Replay guard is at capacity even after sweeping expired entries."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn a_signature_is_accepted_once_and_refused_afterwards() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)));
        assert!(!guard.check_and_record(key, &digest(1)));
    }

    #[test]
    fn distinct_signatures_and_distinct_keys_do_not_collide() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();
        let other_key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)));
        assert!(guard.check_and_record(key, &digest(2)));
        assert!(guard.check_and_record(other_key, &digest(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn entries_expire_and_are_swept() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)));
        assert_eq!(guard.tracked(), 1);

        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(guard.check_and_record(key, &digest(2)));
        assert_eq!(guard.tracked(), 1);
    }
}
