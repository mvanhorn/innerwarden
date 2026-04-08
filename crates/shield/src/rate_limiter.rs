// rate_limiter.rs — Per-IP Adaptive Rate Limiting
//
// Three algorithms combined: Token Bucket, Sliding Window, and Exponential
// Moving Average (EMA). Based on arXiv:2508.00851 (eBPF-Based DDoS Mitigation),
// FlowSentryX, and ScienceDirect 2025 (Kernel-level LDoS Detection).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// The outcome for a single packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitDecision {
    Allow,
    Drop,
    Challenge, // e.g. SYN cookie or JS challenge
}

// ---------------------------------------------------------------------------
// Token Bucket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: DateTime<Utc>,
}

impl TokenBucket {
    pub fn new(max_tokens: f64, refill_rate: f64, now: DateTime<Utc>) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: now,
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one.
    /// Returns `true` if the packet is allowed.
    pub fn consume(&mut self, now: DateTime<Utc>) -> bool {
        let elapsed_ms = (now - self.last_refill).num_milliseconds().max(0) as f64;
        let elapsed_secs = elapsed_ms / 1000.0;
        self.tokens = (self.tokens + self.refill_rate * elapsed_secs).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

// ---------------------------------------------------------------------------
// Sliding Window
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlidingWindow {
    counts: VecDeque<(DateTime<Utc>, u64)>,
    window_size: Duration,
    sub_window_count: usize,
    max_rate: u64,
}

impl SlidingWindow {
    pub fn new(window_secs: i64, sub_window_count: usize, max_rate: u64) -> Self {
        Self {
            counts: VecDeque::new(),
            window_size: Duration::seconds(window_secs),
            sub_window_count,
            max_rate,
        }
    }

    /// Record a packet arrival, returns `true` if within rate.
    pub fn record(&mut self, now: DateTime<Utc>) -> bool {
        let sub_window_dur = self.window_size / self.sub_window_count as i32;
        self.expire(now);

        // Find or create the current sub-window bucket.
        let sub_start = self.sub_window_start(now, sub_window_dur);
        if let Some(last) = self.counts.back_mut() {
            if last.0 == sub_start {
                last.1 += 1;
            } else {
                self.counts.push_back((sub_start, 1));
            }
        } else {
            self.counts.push_back((sub_start, 1));
        }

        self.weighted_count(now, sub_window_dur) <= self.max_rate
    }

    /// Current weighted count across the window.
    pub fn current_rate(&self, now: DateTime<Utc>) -> u64 {
        let sub_window_dur = self.window_size / self.sub_window_count as i32;
        self.weighted_count(now, sub_window_dur)
    }

    fn sub_window_start(&self, now: DateTime<Utc>, sub_dur: Duration) -> DateTime<Utc> {
        let millis = sub_dur.num_milliseconds().max(1);
        let now_ms = now.timestamp_millis();
        let aligned = now_ms - (now_ms % millis);
        DateTime::from_timestamp_millis(aligned).unwrap_or(now)
    }

    fn expire(&mut self, now: DateTime<Utc>) {
        let cutoff = now - self.window_size;
        while let Some(front) = self.counts.front() {
            if front.0 < cutoff {
                self.counts.pop_front();
            } else {
                break;
            }
        }
    }

    fn weighted_count(&self, now: DateTime<Utc>, sub_dur: Duration) -> u64 {
        let sub_millis = sub_dur.num_milliseconds().max(1) as f64;
        let current_sub = self.sub_window_start(now, sub_dur);
        let elapsed_in_sub = (now - current_sub).num_milliseconds().max(0) as f64;
        // Weight for the current (partial) sub-window. If we are at the very
        // start of a sub-window (elapsed=0), count all packets fully to avoid
        // a zero-weight blind spot.
        let weight = if elapsed_in_sub < 1.0 {
            1.0
        } else {
            elapsed_in_sub / sub_millis
        };

        let mut total: f64 = 0.0;
        for (ts, count) in &self.counts {
            if *ts == current_sub {
                total += *count as f64 * weight;
            } else {
                total += *count as f64;
            }
        }
        total.ceil() as u64
    }
}

// ---------------------------------------------------------------------------
// Exponential Moving Average (EMA) with variance tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmaTracker {
    ema: f64,
    alpha: f64,
    variance_ema: f64,
    alpha_var: f64,
    threshold_multiplier: f64,
    samples: u64,
}

impl EmaTracker {
    pub fn new(alpha: f64, alpha_var: f64, threshold_multiplier: f64) -> Self {
        Self {
            ema: 0.0,
            alpha: alpha.clamp(0.01, 1.0),
            variance_ema: 0.0,
            alpha_var: alpha_var.clamp(0.01, 1.0),
            threshold_multiplier,
            samples: 0,
        }
    }

    /// Update with a new sample. Returns `true` if the sample exceeds the
    /// adaptive threshold (EMA + multiplier * stddev) computed BEFORE
    /// incorporating the new sample.
    pub fn update(&mut self, current: f64) -> bool {
        self.samples += 1;
        if self.samples == 1 {
            self.ema = current;
            self.variance_ema = 0.0;
            return false; // first sample, never anomalous
        }

        // Compute threshold from previous EMA/variance.
        let threshold = self.ema + self.threshold_multiplier * self.variance_ema.sqrt();
        let anomalous = current > threshold;

        // Now update EMA and variance with the new sample.
        let deviation = current - self.ema;
        self.ema = self.alpha * current + (1.0 - self.alpha) * self.ema;
        self.variance_ema =
            self.alpha_var * (deviation * deviation) + (1.0 - self.alpha_var) * self.variance_ema;

        anomalous
    }

    pub fn ema(&self) -> f64 {
        self.ema
    }

    pub fn threshold(&self) -> f64 {
        self.ema + self.threshold_multiplier * self.variance_ema.sqrt()
    }

    pub fn variance(&self) -> f64 {
        self.variance_ema
    }
}

// ---------------------------------------------------------------------------
// Per-IP Tracker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpTracker {
    pub ip: String,
    pub token_bucket: TokenBucket,
    pub sliding_window: SlidingWindow,
    pub ema: EmaTracker,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_packets: u64,
    pub total_bytes: u64,
}

// ---------------------------------------------------------------------------
// Block info
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub ip: String,
    pub reason: String,
    pub blocked_at: DateTime<Utc>,
    pub packets_at_block: u64,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    /// Token bucket: max burst size.
    pub bucket_max_tokens: f64,
    /// Token bucket: refill rate (tokens/sec).
    pub bucket_refill_rate: f64,
    /// Sliding window: total window in seconds.
    pub window_secs: i64,
    /// Sliding window: number of sub-windows.
    pub sub_window_count: usize,
    /// Sliding window: max packets per window.
    pub window_max_rate: u64,
    /// EMA smoothing factor.
    pub ema_alpha: f64,
    /// EMA variance smoothing factor.
    pub ema_alpha_var: f64,
    /// EMA threshold multiplier (sigma).
    pub ema_threshold_multiplier: f64,
    /// Minimum events before EMA blocking kicks in.
    pub ema_min_samples: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            bucket_max_tokens: 50.0,
            bucket_refill_rate: 10.0,
            window_secs: 10,
            sub_window_count: 10,
            window_max_rate: 100,
            ema_alpha: 0.3,
            ema_alpha_var: 0.1,
            ema_threshold_multiplier: 3.0,
            ema_min_samples: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterMetrics {
    pub tracked_ips: usize,
    pub blocked_ips: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_allowed: u64,
    pub total_dropped: u64,
    pub total_challenged: u64,
}

// ---------------------------------------------------------------------------
// Blocked IP summary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIp {
    pub ip: String,
    pub reason: String,
    pub blocked_at: DateTime<Utc>,
    pub total_packets: u64,
    pub total_bytes: u64,
}

// ---------------------------------------------------------------------------
// IpRateLimiter — combines all three algorithms
// ---------------------------------------------------------------------------

pub struct IpRateLimiter {
    trackers: HashMap<String, IpTracker>,
    config: RateLimiterConfig,
    blocked: HashMap<String, BlockInfo>,
    total_allowed: u64,
    total_dropped: u64,
    total_challenged: u64,
}

impl IpRateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            trackers: HashMap::new(),
            config,
            blocked: HashMap::new(),
            total_allowed: 0,
            total_dropped: 0,
            total_challenged: 0,
        }
    }

    /// Process a single packet from `ip` carrying `bytes` at timestamp `ts`.
    pub fn process_packet(&mut self, ip: &str, bytes: u64, ts: DateTime<Utc>) -> RateLimitDecision {
        // If already blocked, short-circuit.
        if self.blocked.contains_key(ip) {
            self.total_dropped += 1;
            return RateLimitDecision::Drop;
        }

        let config = &self.config;
        let tracker = self
            .trackers
            .entry(ip.to_string())
            .or_insert_with(|| IpTracker {
                ip: ip.to_string(),
                token_bucket: TokenBucket::new(
                    config.bucket_max_tokens,
                    config.bucket_refill_rate,
                    ts,
                ),
                sliding_window: SlidingWindow::new(
                    config.window_secs,
                    config.sub_window_count,
                    config.window_max_rate,
                ),
                ema: EmaTracker::new(
                    config.ema_alpha,
                    config.ema_alpha_var,
                    config.ema_threshold_multiplier,
                ),
                first_seen: ts,
                last_seen: ts,
                total_packets: 0,
                total_bytes: 0,
            });

        tracker.last_seen = ts;
        tracker.total_packets += 1;
        tracker.total_bytes += bytes;

        // -- Token bucket --
        let bucket_ok = tracker.token_bucket.consume(ts);

        // -- Sliding window --
        let window_ok = tracker.sliding_window.record(ts);

        // -- EMA anomaly --
        let rate_since_first = if tracker.total_packets > 1 {
            let elapsed_secs = (ts - tracker.first_seen).num_milliseconds().max(1) as f64 / 1000.0;
            tracker.total_packets as f64 / elapsed_secs
        } else {
            1.0
        };
        let ema_anomaly = if tracker.ema.samples >= self.config.ema_min_samples {
            tracker.ema.update(rate_since_first)
        } else {
            tracker.ema.update(rate_since_first);
            false
        };

        // Decision logic: combine all three signals.
        // Drop: token bucket empty AND sliding window exceeded.
        // Challenge: only one limiter tripped (or EMA anomaly alone).
        // Allow: all OK.
        let decision = if !bucket_ok && !window_ok {
            RateLimitDecision::Drop
        } else if !bucket_ok || !window_ok || ema_anomaly {
            RateLimitDecision::Challenge
        } else {
            RateLimitDecision::Allow
        };

        match decision {
            RateLimitDecision::Drop => {
                self.total_dropped += 1;
                self.blocked.insert(
                    ip.to_string(),
                    BlockInfo {
                        ip: ip.to_string(),
                        reason: format!(
                            "bucket={} window={} ema_anomaly={}",
                            bucket_ok, window_ok, ema_anomaly
                        ),
                        blocked_at: ts,
                        packets_at_block: tracker.total_packets,
                    },
                );
                tracing::warn!(
                    ip,
                    packets = tracker.total_packets,
                    "IP blocked: rate limit exceeded"
                );
            }
            RateLimitDecision::Challenge => {
                self.total_challenged += 1;
            }
            RateLimitDecision::Allow => {
                self.total_allowed += 1;
            }
        }

        decision
    }

    /// Return all currently blocked IPs.
    pub fn get_blocked_ips(&self) -> Vec<BlockedIp> {
        self.blocked
            .values()
            .map(|b| {
                let tracker = self.trackers.get(&b.ip);
                BlockedIp {
                    ip: b.ip.clone(),
                    reason: b.reason.clone(),
                    blocked_at: b.blocked_at,
                    total_packets: tracker.map(|t| t.total_packets).unwrap_or(0),
                    total_bytes: tracker.map(|t| t.total_bytes).unwrap_or(0),
                }
            })
            .collect()
    }

    /// Return aggregate metrics.
    pub fn get_metrics(&self) -> RateLimiterMetrics {
        let total_packets: u64 = self.trackers.values().map(|t| t.total_packets).sum();
        let total_bytes: u64 = self.trackers.values().map(|t| t.total_bytes).sum();
        RateLimiterMetrics {
            tracked_ips: self.trackers.len(),
            blocked_ips: self.blocked.len(),
            total_packets,
            total_bytes,
            total_allowed: self.total_allowed,
            total_dropped: self.total_dropped,
            total_challenged: self.total_challenged,
        }
    }

    /// Remove trackers (and blocks) for IPs not seen within `max_age`.
    pub fn cleanup_stale(&mut self, max_age: std::time::Duration, now: DateTime<Utc>) {
        let cutoff_millis = max_age.as_millis() as i64;
        let stale_ips: Vec<String> = self
            .trackers
            .iter()
            .filter(|(_, t)| (now - t.last_seen).num_milliseconds() > cutoff_millis)
            .map(|(ip, _)| ip.clone())
            .collect();

        for ip in &stale_ips {
            self.trackers.remove(ip);
            self.blocked.remove(ip);
        }
    }

    /// Unblock an IP (e.g. after cooldown).
    pub fn unblock(&mut self, ip: &str) {
        self.blocked.remove(ip);
    }

    /// Apply an escalation multiplier to tighten thresholds.
    /// `factor` in (0.0, 1.0] — smaller means tighter.
    pub fn apply_escalation(&mut self, factor: f64) {
        let factor = factor.clamp(0.01, 1.0);
        self.config.bucket_max_tokens *= factor;
        self.config.bucket_refill_rate *= factor;
        self.config.window_max_rate =
            ((self.config.window_max_rate as f64) * factor).max(1.0) as u64;
    }

    /// Reset config to given defaults.
    pub fn reset_config(&mut self, config: RateLimiterConfig) {
        self.config = config;
    }

    pub fn config(&self) -> &RateLimiterConfig {
        &self.config
    }

    pub fn tracked_count(&self) -> usize {
        self.trackers.len()
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as CDur;

    fn default_config() -> RateLimiterConfig {
        RateLimiterConfig::default()
    }

    fn ts(offset_ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_700_000_000_000 + offset_ms).unwrap()
    }

    // -- Token Bucket tests --

    #[test]
    fn token_bucket_allows_burst_up_to_max() {
        let now = ts(0);
        let mut tb = TokenBucket::new(5.0, 1.0, now);
        for _ in 0..5 {
            assert!(tb.consume(now));
        }
        assert!(!tb.consume(now)); // 6th should fail
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let now = ts(0);
        let mut tb = TokenBucket::new(5.0, 10.0, now);
        // Drain all tokens.
        for _ in 0..5 {
            tb.consume(now);
        }
        assert!(!tb.consume(now));
        // Wait 1 second — should refill 10 tokens (capped at 5).
        let later = now + CDur::seconds(1);
        assert!(tb.consume(later));
    }

    #[test]
    fn token_bucket_refill_caps_at_max() {
        let now = ts(0);
        let mut tb = TokenBucket::new(3.0, 100.0, now);
        let later = now + CDur::seconds(10);
        tb.consume(later); // triggers refill
                           // Tokens should be at most max_tokens - 1 after consume.
        assert!(tb.tokens() <= 3.0);
    }

    // -- Sliding Window tests --

    #[test]
    fn sliding_window_allows_within_rate() {
        let mut sw = SlidingWindow::new(10, 10, 100);
        let now = ts(0);
        for _ in 0..100 {
            assert!(sw.record(now));
        }
    }

    #[test]
    fn sliding_window_rejects_above_rate() {
        let mut sw = SlidingWindow::new(10, 10, 50);
        let now = ts(0);
        let mut rejected = false;
        for _ in 0..200 {
            if !sw.record(now) {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
    }

    #[test]
    fn sliding_window_expires_old_buckets() {
        let mut sw = SlidingWindow::new(2, 2, 10);
        let now = ts(0);
        for _ in 0..10 {
            sw.record(now);
        }
        // After the window passes, old counts expire.
        let later = now + CDur::seconds(3);
        assert!(sw.record(later)); // should be within rate again
    }

    // -- EMA tests --

    #[test]
    fn ema_first_sample_never_anomalous() {
        let mut ema = EmaTracker::new(0.3, 0.1, 3.0);
        assert!(!ema.update(1000.0));
    }

    #[test]
    fn ema_detects_spike() {
        let mut ema = EmaTracker::new(0.3, 0.1, 3.0);
        for _ in 0..20 {
            ema.update(10.0);
        }
        // A large spike should trigger.
        assert!(ema.update(1000.0));
    }

    #[test]
    fn ema_stable_traffic_no_alarm() {
        let mut ema = EmaTracker::new(0.3, 0.1, 3.0);
        for _ in 0..100 {
            assert!(!ema.update(10.0));
        }
    }

    // -- IpRateLimiter integration tests --

    #[test]
    fn limiter_allows_normal_traffic() {
        let mut limiter = IpRateLimiter::new(default_config());
        let now = ts(0);
        for i in 0..10 {
            let t = now + CDur::milliseconds(i * 500);
            let d = limiter.process_packet("10.0.0.1", 100, t);
            assert_ne!(
                d,
                RateLimitDecision::Drop,
                "packet {} should not be dropped",
                i
            );
        }
    }

    #[test]
    fn limiter_drops_flood() {
        let config = RateLimiterConfig {
            bucket_max_tokens: 10.0,
            bucket_refill_rate: 2.0,
            window_max_rate: 20,
            ..default_config()
        };
        let mut limiter = IpRateLimiter::new(config);
        let now = ts(0);
        let mut dropped = false;
        for i in 0..200 {
            let d = limiter.process_packet("10.0.0.1", 100, now);
            if d == RateLimitDecision::Drop {
                dropped = true;
                break;
            }
        }
        assert!(dropped, "flood should have triggered a drop");
    }

    #[test]
    fn limiter_blocked_ip_stays_dropped() {
        let config = RateLimiterConfig {
            bucket_max_tokens: 5.0,
            bucket_refill_rate: 1.0,
            window_max_rate: 10,
            ..default_config()
        };
        let mut limiter = IpRateLimiter::new(config);
        let now = ts(0);
        // Exhaust tokens.
        for _ in 0..200 {
            limiter.process_packet("10.0.0.99", 100, now);
        }
        // Once blocked, subsequent packets are dropped immediately.
        let later = now + CDur::milliseconds(100);
        assert_eq!(
            limiter.process_packet("10.0.0.99", 100, later),
            RateLimitDecision::Drop
        );
    }

    #[test]
    fn limiter_get_blocked_ips_returns_blocked() {
        let config = RateLimiterConfig {
            bucket_max_tokens: 3.0,
            bucket_refill_rate: 0.1,
            window_max_rate: 5,
            ..default_config()
        };
        let mut limiter = IpRateLimiter::new(config);
        let now = ts(0);
        for _ in 0..100 {
            limiter.process_packet("10.0.0.50", 100, now);
        }
        let blocked = limiter.get_blocked_ips();
        assert!(!blocked.is_empty());
        assert_eq!(blocked[0].ip, "10.0.0.50");
    }

    #[test]
    fn limiter_metrics_correct() {
        let mut limiter = IpRateLimiter::new(default_config());
        let now = ts(0);
        limiter.process_packet("10.0.0.1", 200, now);
        limiter.process_packet("10.0.0.2", 300, now);
        let m = limiter.get_metrics();
        assert_eq!(m.tracked_ips, 2);
        assert!(m.total_packets >= 2);
    }

    #[test]
    fn limiter_cleanup_stale_removes_old() {
        let mut limiter = IpRateLimiter::new(default_config());
        let now = ts(0);
        limiter.process_packet("10.0.0.1", 100, now);
        assert_eq!(limiter.tracked_count(), 1);

        let future = now + CDur::seconds(600);
        limiter.cleanup_stale(std::time::Duration::from_secs(300), future);
        assert_eq!(limiter.tracked_count(), 0);
    }

    #[test]
    fn limiter_cleanup_keeps_recent() {
        let mut limiter = IpRateLimiter::new(default_config());
        let now = ts(0);
        limiter.process_packet("10.0.0.1", 100, now);

        let future = now + CDur::seconds(60);
        limiter.cleanup_stale(std::time::Duration::from_secs(300), future);
        assert_eq!(limiter.tracked_count(), 1);
    }

    #[test]
    fn limiter_unblock_allows_ip_again() {
        let config = RateLimiterConfig {
            bucket_max_tokens: 3.0,
            bucket_refill_rate: 0.1,
            window_max_rate: 5,
            ..default_config()
        };
        let mut limiter = IpRateLimiter::new(config);
        let now = ts(0);
        for _ in 0..100 {
            limiter.process_packet("10.0.0.1", 100, now);
        }
        assert!(limiter.blocked_count() > 0);
        limiter.unblock("10.0.0.1");
        assert_eq!(limiter.blocked_count(), 0);
    }

    #[test]
    fn limiter_apply_escalation_tightens() {
        let mut limiter = IpRateLimiter::new(default_config());
        let original_max = limiter.config().bucket_max_tokens;
        limiter.apply_escalation(0.5);
        assert!(limiter.config().bucket_max_tokens < original_max);
    }

    #[test]
    fn limiter_separate_ips_independent() {
        let mut limiter = IpRateLimiter::new(default_config());
        let now = ts(0);
        limiter.process_packet("10.0.0.1", 100, now);
        limiter.process_packet("10.0.0.2", 100, now);
        assert_eq!(limiter.tracked_count(), 2);
        let m = limiter.get_metrics();
        assert_eq!(m.tracked_ips, 2);
    }
}
