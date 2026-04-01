//! Per-device rate limiting with epoch-based reset.
//!
//! Devices are identified by a 32-byte hash derived from their attestation
//! key. Counts are reset lazily when the epoch duration has elapsed since the
//! device's epoch start — no background cleanup thread is required.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-device record stored in the rate-limiter map.
struct DeviceRecord {
    /// When the current epoch started for this device.
    epoch_start: Instant,
    /// Number of requests served in the current epoch.
    count: u32,
}

/// Thread-safe per-device rate limiter.
///
/// Uses lazy eviction: stale epochs are detected and reset on first access
/// after the epoch boundary, keeping the hot path lock-free-ish and avoiding
/// the need for a background cleanup goroutine.
pub struct RateLimiter {
    max_per_epoch: u32,
    epoch_duration: Duration,
    devices: Mutex<HashMap<[u8; 32], DeviceRecord>>,
}

impl RateLimiter {
    /// Create a new `RateLimiter`.
    ///
    /// # Parameters
    /// - `max_per_epoch`: maximum requests allowed per device per epoch.
    /// - `epoch_duration`: how long each epoch lasts before counts reset.
    pub fn new(max_per_epoch: u32, epoch_duration: Duration) -> Self {
        Self {
            max_per_epoch,
            epoch_duration,
            devices: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether `device_id` is within its rate limit and, if so,
    /// increment its counter atomically.
    ///
    /// # Returns
    /// - `Ok(())` if the request is allowed (counter has been incremented).
    /// - `Err(retry_after)` if the device has exceeded its limit. `retry_after`
    ///   is the `Duration` until the current epoch expires and the counter resets.
    pub fn check_and_increment(&self, device_id: &[u8; 32]) -> Result<(), Duration> {
        let now = Instant::now();
        let mut map = self.devices.lock().expect("rate limiter mutex poisoned");

        let record = map.entry(*device_id).or_insert_with(|| DeviceRecord {
            epoch_start: now,
            count: 0,
        });

        // Lazily reset if the epoch has expired.
        if now.duration_since(record.epoch_start) >= self.epoch_duration {
            record.epoch_start = now;
            record.count = 0;
        }

        if record.count < self.max_per_epoch {
            record.count += 1;
            Ok(())
        } else {
            // Time remaining in the current epoch.
            let elapsed = now.duration_since(record.epoch_start);
            let retry_after = self.epoch_duration.saturating_sub(elapsed);
            Err(retry_after)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn device(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn test_allows_under_limit() {
        let rl = RateLimiter::new(5, Duration::from_secs(3600));
        let id = device(1);
        for _ in 0..5 {
            assert!(rl.check_and_increment(&id).is_ok());
        }
    }

    #[test]
    fn test_rejects_over_limit() {
        let rl = RateLimiter::new(2, Duration::from_secs(3600));
        let id = device(2);
        assert!(rl.check_and_increment(&id).is_ok()); // 1st
        assert!(rl.check_and_increment(&id).is_ok()); // 2nd
        let result = rl.check_and_increment(&id);     // 3rd — should be rejected
        assert!(result.is_err(), "third request should be rate-limited");
        // retry_after should be positive and no more than the epoch duration
        let retry_after = result.unwrap_err();
        assert!(retry_after > Duration::ZERO);
        assert!(retry_after <= Duration::from_secs(3600));
    }

    #[test]
    fn test_different_devices_independent() {
        let rl = RateLimiter::new(1, Duration::from_secs(3600));
        let a = device(10);
        let b = device(20);
        // Both devices get their first (and only allowed) request.
        assert!(rl.check_and_increment(&a).is_ok());
        assert!(rl.check_and_increment(&b).is_ok());
        // Both are now at their limit.
        assert!(rl.check_and_increment(&a).is_err());
        assert!(rl.check_and_increment(&b).is_err());
    }

    #[test]
    fn test_epoch_reset() {
        // Use a very short epoch so the test completes quickly.
        let epoch = Duration::from_millis(50);
        let rl = RateLimiter::new(1, epoch);
        let id = device(3);

        assert!(rl.check_and_increment(&id).is_ok()); // within limit
        assert!(rl.check_and_increment(&id).is_err()); // at limit

        // Wait for the epoch to expire.
        thread::sleep(epoch + Duration::from_millis(10));

        // After the epoch resets, the device should be allowed again.
        assert!(
            rl.check_and_increment(&id).is_ok(),
            "limit should reset after epoch expiry"
        );
    }
}
