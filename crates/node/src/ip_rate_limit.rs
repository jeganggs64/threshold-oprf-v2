//! IP-based rate limiting middleware.
//!
//! Per-route configurable limits. Uses a simple in-memory HashMap with
//! lazy epoch reset (same pattern as the device rate limiter).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct IpRecord {
    epoch_start: Instant,
    count: u32,
}

pub struct IpRateLimiter {
    max_per_epoch: u32,
    epoch_duration: Duration,
    ips: Mutex<HashMap<IpAddr, IpRecord>>,
}

impl IpRateLimiter {
    pub fn new(max_per_epoch: u32, epoch_duration: Duration) -> Self {
        Self {
            max_per_epoch,
            epoch_duration,
            ips: Mutex::new(HashMap::new()),
        }
    }

    /// Check if the IP is allowed. Returns Ok(()) or Err with remaining seconds.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let mut ips = self.ips.lock().unwrap();
        let now = Instant::now();

        let record = ips.entry(ip).or_insert(IpRecord {
            epoch_start: now,
            count: 0,
        });

        // Reset epoch if expired
        if now.duration_since(record.epoch_start) >= self.epoch_duration {
            record.epoch_start = now;
            record.count = 0;
        }

        if record.count >= self.max_per_epoch {
            let remaining = self
                .epoch_duration
                .saturating_sub(now.duration_since(record.epoch_start));
            return Err(remaining.as_secs());
        }

        record.count += 1;
        Ok(())
    }
}

/// Per-route rate limiters.
pub struct RateLimiters {
    /// /partial-evaluate: 20/day/IP
    pub partial_evaluate: IpRateLimiter,
    /// /attestation, /health, /join-info: 10/min/IP
    pub general: IpRateLimiter,
    /// /reshare, /reshare/receive, /dkg/*: 10/day/IP
    pub reshare: IpRateLimiter,
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiters {
    pub fn new() -> Self {
        Self {
            partial_evaluate: IpRateLimiter::new(20, Duration::from_secs(86400)),
            general: IpRateLimiter::new(10, Duration::from_secs(60)),
            reshare: IpRateLimiter::new(10, Duration::from_secs(86400)),
        }
    }
}
