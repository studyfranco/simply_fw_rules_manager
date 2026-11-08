//! Anti-replay guard: records accepted signatures within the freshness window and refuses repeats.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SignatureId {
    key_id: Uuid,
    digest: Vec<u8>,
}

const MAX_TRACKED_SIGNATURES: usize = 100_000;

/// In-memory, single-use signature cache keyed on the monotonic clock.
pub struct ReplayGuard {
    seen: Mutex<HashMap<SignatureId, Instant>>,
    window: Duration,
    last_sweep: Mutex<Instant>,
}

impl ReplayGuard {
    /// Builds a guard with the given freshness window, clamped to `[1, 3600]` seconds.
    #[must_use]
    pub fn new(window_secs: i64) -> Self {
        let clamped = u64::try_from(window_secs.clamp(1, 3600)).unwrap_or(300);
        Self {
            seen: Mutex::new(HashMap::new()),
            window: Duration::from_secs(clamped),
            last_sweep: Mutex::new(Instant::now()),
        }
    }

    /// Checks whether `(key_id, digest)` has already been recorded within the window and records it.
    pub fn check_and_record(&self, key_id: Uuid, digest: &[u8]) -> bool {
        let now = Instant::now();
        self.prune_if_due(now);
        let Ok(mut seen) = self.seen.lock() else {
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

    fn prune_if_due(&self, now: Instant) {
        let routine_interval = self.window / 4;
        let due = match self.last_sweep.lock() {
            Ok(mut last) => {
                if now.duration_since(*last) >= routine_interval {
                    *last = now;
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        };
        let over_capacity = self
            .seen
            .lock()
            .is_ok_and(|seen| seen.len() >= MAX_TRACKED_SIGNATURES);
        if (due || over_capacity)
            && let Ok(mut seen) = self.seen.lock()
        {
            seen.retain(|_, expires_at| *expires_at > now);
        }
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(crate::crypto::MAX_TIMESTAMP_SKEW_SECS)
    }
}
