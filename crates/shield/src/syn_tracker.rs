// syn_tracker.rs — SYN Flood Detection
//
// Based on "Me Love (SYN-)Cookies" (arXiv) and
// FedeParola/ebpf-synflood-detector.
//
// Tracks per-IP SYN vs SYN-ACK counts inside a sliding window and
// estimates global half-open connections.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Result of checking an IP for SYN flood behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynVerdict {
    Normal,
    SynFloodFromIp(String),
    GlobalSynFlood,
}

/// Configuration for the SYN flood detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynFloodConfig {
    pub window_secs: i64,
    pub syn_threshold: u64,
    pub completion_ratio: f64,
    pub half_open_threshold: u64,
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        Self {
            window_secs: 30,
            syn_threshold: 100,
            completion_ratio: 0.1,
            half_open_threshold: 5000,
        }
    }
}

pub struct SynFloodDetector {
    syn_counts: HashMap<String, VecDeque<DateTime<Utc>>>,
    ack_counts: HashMap<String, VecDeque<DateTime<Utc>>>,
    half_open_estimate: u64,
    config: SynFloodConfig,
}

impl SynFloodDetector {
    pub fn new(config: SynFloodConfig) -> Self {
        Self {
            syn_counts: HashMap::new(),
            ack_counts: HashMap::new(),
            half_open_estimate: 0,
            config,
        }
    }

    /// Record a SYN event from `ip` at `ts`.
    pub fn record_syn(&mut self, ip: &str, ts: DateTime<Utc>) {
        let window = Duration::seconds(self.config.window_secs);
        let entry = self.syn_counts.entry(ip.to_string()).or_default();
        entry.push_back(ts);
        Self::expire_deque(entry, ts, window);

        self.half_open_estimate = self.half_open_estimate.saturating_add(1);
    }

    /// Record a completed connection (SYN-ACK) from `ip` at `ts`.
    pub fn record_ack(&mut self, ip: &str, ts: DateTime<Utc>) {
        let window = Duration::seconds(self.config.window_secs);
        let entry = self.ack_counts.entry(ip.to_string()).or_default();
        entry.push_back(ts);
        Self::expire_deque(entry, ts, window);

        self.half_open_estimate = self.half_open_estimate.saturating_sub(1);
    }

    /// Evaluate whether `ip` is conducting a SYN flood. Returns a verdict.
    pub fn check_ip(&self, ip: &str) -> SynVerdict {
        let syn_count = self.syn_counts.get(ip).map(|d| d.len() as u64).unwrap_or(0);
        let ack_count = self.ack_counts.get(ip).map(|d| d.len() as u64).unwrap_or(0);

        if syn_count >= self.config.syn_threshold {
            let ratio = if syn_count == 0 {
                1.0
            } else {
                ack_count as f64 / syn_count as f64
            };
            if ratio < self.config.completion_ratio {
                return SynVerdict::SynFloodFromIp(ip.to_string());
            }
        }

        SynVerdict::Normal
    }

    /// Check global half-open threshold.
    pub fn check_global(&self) -> SynVerdict {
        if self.half_open_estimate > self.config.half_open_threshold {
            SynVerdict::GlobalSynFlood
        } else {
            SynVerdict::Normal
        }
    }

    /// Return all IPs currently flagged as SYN flooding.
    pub fn get_flagged_ips(&self) -> Vec<String> {
        let mut flagged = Vec::new();
        for ip in self.syn_counts.keys() {
            if let SynVerdict::SynFloodFromIp(_) = self.check_ip(ip) {
                flagged.push(ip.clone());
            }
        }
        flagged
    }

    /// Global half-open estimate.
    pub fn half_open_estimate(&self) -> u64 {
        self.half_open_estimate
    }

    /// Expire all deques and recalculate half-open estimate.
    pub fn expire_all(&mut self, now: DateTime<Utc>) {
        let window = Duration::seconds(self.config.window_secs);
        for deque in self.syn_counts.values_mut() {
            Self::expire_deque(deque, now, window);
        }
        for deque in self.ack_counts.values_mut() {
            Self::expire_deque(deque, now, window);
        }
        // Remove empty entries.
        self.syn_counts.retain(|_, d| !d.is_empty());
        self.ack_counts.retain(|_, d| !d.is_empty());

        // Recalculate half-open.
        let total_syns: u64 = self.syn_counts.values().map(|d| d.len() as u64).sum();
        let total_acks: u64 = self.ack_counts.values().map(|d| d.len() as u64).sum();
        self.half_open_estimate = total_syns.saturating_sub(total_acks);
    }

    pub fn tracked_count(&self) -> usize {
        self.syn_counts.len()
    }

    pub fn syn_count_for(&self, ip: &str) -> u64 {
        self.syn_counts.get(ip).map(|d| d.len() as u64).unwrap_or(0)
    }

    pub fn ack_count_for(&self, ip: &str) -> u64 {
        self.ack_counts.get(ip).map(|d| d.len() as u64).unwrap_or(0)
    }

    fn expire_deque(deque: &mut VecDeque<DateTime<Utc>>, now: DateTime<Utc>, window: Duration) {
        let cutoff = now - window;
        while let Some(front) = deque.front() {
            if *front < cutoff {
                deque.pop_front();
            } else {
                break;
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as CDur;

    fn ts(offset_ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_700_000_000_000 + offset_ms).unwrap()
    }

    #[test]
    fn normal_connections_not_flagged() {
        let mut det = SynFloodDetector::new(SynFloodConfig::default());
        let now = ts(0);
        for i in 0..50 {
            let t = now + CDur::milliseconds(i * 10);
            det.record_syn("10.0.0.1", t);
            det.record_ack("10.0.0.1", t);
        }
        assert_eq!(det.check_ip("10.0.0.1"), SynVerdict::Normal);
        assert!(det.get_flagged_ips().is_empty());
    }

    #[test]
    fn syn_flood_detected_per_ip() {
        let mut det = SynFloodDetector::new(SynFloodConfig {
            syn_threshold: 50,
            ..Default::default()
        });
        let now = ts(0);
        // 100 SYNs, 0 ACKs.
        for i in 0..100 {
            det.record_syn("10.0.0.2", now + CDur::milliseconds(i * 10));
        }
        match det.check_ip("10.0.0.2") {
            SynVerdict::SynFloodFromIp(ip) => assert_eq!(ip, "10.0.0.2"),
            other => panic!("expected SynFloodFromIp, got {:?}", other),
        }
    }

    #[test]
    fn global_syn_flood_detected() {
        let mut det = SynFloodDetector::new(SynFloodConfig {
            half_open_threshold: 50,
            ..Default::default()
        });
        let now = ts(0);
        for i in 0..60u32 {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            det.record_syn(&ip, now);
        }
        assert_eq!(det.check_global(), SynVerdict::GlobalSynFlood);
    }

    #[test]
    fn ack_reduces_half_open() {
        let mut det = SynFloodDetector::new(SynFloodConfig::default());
        let now = ts(0);
        det.record_syn("10.0.0.1", now);
        assert_eq!(det.half_open_estimate(), 1);
        det.record_ack("10.0.0.1", now);
        assert_eq!(det.half_open_estimate(), 0);
    }

    #[test]
    fn ratio_above_threshold_not_flagged() {
        let mut det = SynFloodDetector::new(SynFloodConfig {
            syn_threshold: 10,
            completion_ratio: 0.1,
            ..Default::default()
        });
        let now = ts(0);
        // 20 SYNs, 5 ACKs → ratio 0.25, above 0.1 threshold.
        for i in 0..20 {
            det.record_syn("10.0.0.3", now + CDur::milliseconds(i * 10));
        }
        for i in 0..5 {
            det.record_ack("10.0.0.3", now + CDur::milliseconds(i * 10));
        }
        assert_eq!(det.check_ip("10.0.0.3"), SynVerdict::Normal);
    }

    #[test]
    fn expire_all_clears_old_data() {
        let mut det = SynFloodDetector::new(SynFloodConfig {
            window_secs: 10,
            ..Default::default()
        });
        let now = ts(0);
        det.record_syn("10.0.0.1", now);
        assert_eq!(det.tracked_count(), 1);

        let future = now + CDur::seconds(20);
        det.expire_all(future);
        assert_eq!(det.tracked_count(), 0);
    }

    #[test]
    fn get_flagged_ips_returns_all() {
        let mut det = SynFloodDetector::new(SynFloodConfig {
            syn_threshold: 10,
            ..Default::default()
        });
        let now = ts(0);
        for i in 0..20 {
            det.record_syn("10.0.0.1", now + CDur::milliseconds(i * 5));
            det.record_syn("10.0.0.2", now + CDur::milliseconds(i * 5));
        }
        let flagged = det.get_flagged_ips();
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn below_threshold_not_flagged() {
        let mut det = SynFloodDetector::new(SynFloodConfig {
            syn_threshold: 100,
            ..Default::default()
        });
        let now = ts(0);
        for i in 0..5 {
            det.record_syn("10.0.0.1", now + CDur::milliseconds(i * 10));
        }
        assert_eq!(det.check_ip("10.0.0.1"), SynVerdict::Normal);
    }
}
