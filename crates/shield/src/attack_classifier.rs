// attack_classifier.rs — Multi-Vector Attack Classification
//
// Based on iKern (MDPI 2024). Maintains a set of active attack
// incidents and classifies them by type using heuristic rules fed
// by the rate limiter, SYN tracker, and event metadata.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Attack types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    SynFlood,
    UdpFlood,
    DnsAmplification,
    HttpFlood,
    Slowloris,
    NtpAmplification,
    MultiVector(Vec<AttackType>),
    Unknown,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SynFlood => write!(f, "SYN Flood"),
            Self::UdpFlood => write!(f, "UDP Flood"),
            Self::DnsAmplification => write!(f, "DNS Amplification"),
            Self::HttpFlood => write!(f, "HTTP Flood"),
            Self::Slowloris => write!(f, "Slowloris"),
            Self::NtpAmplification => write!(f, "NTP Amplification"),
            Self::MultiVector(types) => {
                let names: Vec<String> = types.iter().map(|t| format!("{}", t)).collect();
                write!(f, "Multi-Vector({})", names.join(", "))
            }
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Attack incident
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackIncident {
    pub id: String,
    pub attack_type: AttackType,
    pub started: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source_ips: HashSet<String>,
    pub packets_dropped: u64,
    pub peak_pps: u64,
    pub confidence: f64,
}

impl AttackIncident {
    /// Duration since attack started.
    pub fn duration_secs(&self) -> i64 {
        (self.last_seen - self.started).num_seconds()
    }

    /// Whether this incident is still active (seen within the last 60s).
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        (now - self.last_seen).num_seconds() < 60
    }
}

// ---------------------------------------------------------------------------
// Signals fed to the classifier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ClassifierSignals {
    pub syn_flood_active: bool,
    pub syn_flood_ips: Vec<String>,
    pub udp_high_rate: bool,
    pub udp_source_count: usize,
    pub dns_response_count: u64,
    pub dns_source_count: usize,
    pub http_request_count: u64,
    pub http_source_count: usize,
    pub long_held_connections: u64,
    pub long_held_source_count: usize,
    pub ntp_response_count: u64,
    pub ntp_source_count: usize,
    pub total_dropped: u64,
    pub peak_pps: u64,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

pub struct AttackClassifier {
    active_attacks: Vec<AttackIncident>,
    closed_attacks: Vec<AttackIncident>,
    incident_counter: u64,
}

impl AttackClassifier {
    pub fn new() -> Self {
        Self {
            active_attacks: Vec::new(),
            closed_attacks: Vec::new(),
            incident_counter: 0,
        }
    }

    /// Process new signals and update active attacks.
    pub fn classify(&mut self, signals: &ClassifierSignals) {
        let now = signals.timestamp;

        // Detect individual attack types.
        let mut detected: Vec<(AttackType, Vec<String>, f64)> = Vec::new();

        if signals.syn_flood_active && !signals.syn_flood_ips.is_empty() {
            detected.push((AttackType::SynFlood, signals.syn_flood_ips.clone(), 0.9));
        }

        if signals.udp_high_rate && signals.udp_source_count > 5 {
            let ips: Vec<String> = (0..signals.udp_source_count)
                .map(|i| format!("udp_src_{}", i))
                .collect();
            detected.push((AttackType::UdpFlood, ips, 0.8));
        }

        if signals.dns_response_count > 100 && signals.dns_source_count > 5 {
            let ips: Vec<String> = (0..signals.dns_source_count)
                .map(|i| format!("dns_src_{}", i))
                .collect();
            detected.push((AttackType::DnsAmplification, ips, 0.85));
        }

        if signals.http_request_count > 500 && signals.http_source_count > 10 {
            let ips: Vec<String> = (0..signals.http_source_count)
                .map(|i| format!("http_src_{}", i))
                .collect();
            detected.push((AttackType::HttpFlood, ips, 0.75));
        }

        if signals.long_held_connections > 50 && signals.long_held_source_count <= 5 {
            let ips: Vec<String> = (0..signals.long_held_source_count)
                .map(|i| format!("slow_src_{}", i))
                .collect();
            detected.push((AttackType::Slowloris, ips, 0.7));
        }

        if signals.ntp_response_count > 100 && signals.ntp_source_count > 3 {
            let ips: Vec<String> = (0..signals.ntp_source_count)
                .map(|i| format!("ntp_src_{}", i))
                .collect();
            detected.push((AttackType::NtpAmplification, ips, 0.8));
        }

        // If 2+ types detected simultaneously → MultiVector.
        if detected.len() >= 2 {
            let types: Vec<AttackType> = detected.iter().map(|(t, _, _)| t.clone()).collect();
            let all_ips: HashSet<String> = detected
                .iter()
                .flat_map(|(_, ips, _)| ips.iter().cloned())
                .collect();
            let max_conf = detected.iter().map(|(_, _, c)| *c).fold(0.0f64, f64::max);

            self.upsert_attack(
                AttackType::MultiVector(types),
                all_ips,
                signals.total_dropped,
                signals.peak_pps,
                max_conf,
                now,
            );
        } else if let Some((attack_type, ips, conf)) = detected.into_iter().next() {
            let ip_set: HashSet<String> = ips.into_iter().collect();
            self.upsert_attack(
                attack_type,
                ip_set,
                signals.total_dropped,
                signals.peak_pps,
                conf,
                now,
            );
        }

        // Close stale attacks.
        self.close_stale(now);
    }

    /// Return active attacks.
    pub fn active_attacks(&self) -> &[AttackIncident] {
        &self.active_attacks
    }

    /// Return closed/historical attacks.
    pub fn closed_attacks(&self) -> &[AttackIncident] {
        &self.closed_attacks
    }

    /// All attacks (active + closed).
    pub fn all_attacks(&self) -> Vec<&AttackIncident> {
        self.active_attacks
            .iter()
            .chain(self.closed_attacks.iter())
            .collect()
    }

    /// Check if any specific attack type is currently active.
    pub fn is_type_active(&self, attack_type: &AttackType) -> bool {
        self.active_attacks
            .iter()
            .any(|a| match (&a.attack_type, attack_type) {
                (AttackType::MultiVector(types), t) => types.contains(t),
                (a, b) => a == b,
            })
    }

    /// Recent incidents within the last N hours.
    pub fn recent_incidents(&self, hours: i64) -> Vec<&AttackIncident> {
        let cutoff = Utc::now() - Duration::hours(hours);
        self.all_attacks()
            .into_iter()
            .filter(|a| a.started > cutoff)
            .collect()
    }

    // -- internal --

    fn upsert_attack(
        &mut self,
        attack_type: AttackType,
        source_ips: HashSet<String>,
        total_dropped: u64,
        peak_pps: u64,
        confidence: f64,
        now: DateTime<Utc>,
    ) {
        // Try to update an existing active attack of the same type.
        for attack in &mut self.active_attacks {
            let same_type = match (&attack.attack_type, &attack_type) {
                (AttackType::MultiVector(_), AttackType::MultiVector(_)) => true,
                (a, b) => a == b,
            };
            if same_type {
                attack.last_seen = now;
                attack.source_ips.extend(source_ips.clone());
                attack.packets_dropped = total_dropped;
                if peak_pps > attack.peak_pps {
                    attack.peak_pps = peak_pps;
                }
                if confidence > attack.confidence {
                    attack.confidence = confidence;
                }
                return;
            }
        }

        // New attack.
        self.incident_counter += 1;
        self.active_attacks.push(AttackIncident {
            id: format!("atk-{}", self.incident_counter),
            attack_type,
            started: now,
            last_seen: now,
            source_ips,
            packets_dropped: total_dropped,
            peak_pps,
            confidence,
        });
    }

    fn close_stale(&mut self, now: DateTime<Utc>) {
        let mut i = 0;
        while i < self.active_attacks.len() {
            if !self.active_attacks[i].is_active(now) {
                let closed = self.active_attacks.remove(i);
                self.closed_attacks.push(closed);
            } else {
                i += 1;
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

    fn ts(offset_secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + offset_secs, 0).unwrap()
    }

    #[test]
    fn syn_flood_classified() {
        let mut c = AttackClassifier::new();
        c.classify(&ClassifierSignals {
            syn_flood_active: true,
            syn_flood_ips: vec!["10.0.0.1".into(), "10.0.0.2".into()],
            total_dropped: 1000,
            peak_pps: 5000,
            timestamp: ts(0),
            ..Default::default()
        });
        assert_eq!(c.active_attacks().len(), 1);
        assert_eq!(c.active_attacks()[0].attack_type, AttackType::SynFlood);
    }

    #[test]
    fn udp_flood_classified() {
        let mut c = AttackClassifier::new();
        c.classify(&ClassifierSignals {
            udp_high_rate: true,
            udp_source_count: 20,
            total_dropped: 500,
            peak_pps: 3000,
            timestamp: ts(0),
            ..Default::default()
        });
        assert_eq!(c.active_attacks().len(), 1);
        assert_eq!(c.active_attacks()[0].attack_type, AttackType::UdpFlood);
    }

    #[test]
    fn dns_amplification_classified() {
        let mut c = AttackClassifier::new();
        c.classify(&ClassifierSignals {
            dns_response_count: 200,
            dns_source_count: 10,
            total_dropped: 300,
            peak_pps: 2000,
            timestamp: ts(0),
            ..Default::default()
        });
        assert_eq!(c.active_attacks().len(), 1);
        assert_eq!(
            c.active_attacks()[0].attack_type,
            AttackType::DnsAmplification
        );
    }

    #[test]
    fn http_flood_classified() {
        let mut c = AttackClassifier::new();
        c.classify(&ClassifierSignals {
            http_request_count: 1000,
            http_source_count: 50,
            total_dropped: 800,
            peak_pps: 4000,
            timestamp: ts(0),
            ..Default::default()
        });
        assert_eq!(c.active_attacks().len(), 1);
        assert_eq!(c.active_attacks()[0].attack_type, AttackType::HttpFlood);
    }

    #[test]
    fn slowloris_classified() {
        let mut c = AttackClassifier::new();
        c.classify(&ClassifierSignals {
            long_held_connections: 100,
            long_held_source_count: 3,
            total_dropped: 100,
            peak_pps: 500,
            timestamp: ts(0),
            ..Default::default()
        });
        assert_eq!(c.active_attacks().len(), 1);
        assert_eq!(c.active_attacks()[0].attack_type, AttackType::Slowloris);
    }

    #[test]
    fn multi_vector_detected() {
        let mut c = AttackClassifier::new();
        c.classify(&ClassifierSignals {
            syn_flood_active: true,
            syn_flood_ips: vec!["10.0.0.1".into()],
            udp_high_rate: true,
            udp_source_count: 10,
            total_dropped: 2000,
            peak_pps: 10000,
            timestamp: ts(0),
            ..Default::default()
        });
        assert_eq!(c.active_attacks().len(), 1);
        match &c.active_attacks()[0].attack_type {
            AttackType::MultiVector(types) => {
                assert!(types.contains(&AttackType::SynFlood));
                assert!(types.contains(&AttackType::UdpFlood));
            }
            other => panic!("expected MultiVector, got {:?}", other),
        }
    }

    #[test]
    fn stale_attack_closed() {
        let mut c = AttackClassifier::new();
        c.classify(&ClassifierSignals {
            syn_flood_active: true,
            syn_flood_ips: vec!["10.0.0.1".into()],
            total_dropped: 100,
            peak_pps: 500,
            timestamp: ts(0),
            ..Default::default()
        });
        assert_eq!(c.active_attacks().len(), 1);
        assert_eq!(c.closed_attacks().len(), 0);

        // 90 seconds later with no signals — should close.
        c.classify(&ClassifierSignals {
            timestamp: ts(90),
            ..Default::default()
        });
        assert_eq!(c.active_attacks().len(), 0);
        assert_eq!(c.closed_attacks().len(), 1);
    }

    #[test]
    fn is_type_active_works() {
        let mut c = AttackClassifier::new();
        c.classify(&ClassifierSignals {
            syn_flood_active: true,
            syn_flood_ips: vec!["10.0.0.1".into()],
            total_dropped: 100,
            peak_pps: 500,
            timestamp: ts(0),
            ..Default::default()
        });
        assert!(c.is_type_active(&AttackType::SynFlood));
        assert!(!c.is_type_active(&AttackType::UdpFlood));
    }
}
