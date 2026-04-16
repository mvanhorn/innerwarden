//! Continuous Trust Scoring Engine (spec 020 Phase C).
//!
//! Every entity (IP, User, Process) gets a trust score 0.0–100.0 that
//! adjusts based on behavioural factors.  The score informs but does not
//! enforce — enforcement is a paid feature (Phase F).
//!
//! All scoring functions are pure: they take factors and return a score.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Trust factors ───────────────────────────────────────────────────────

/// A factor contributing to an entity's trust score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustFactor {
    /// Binary is known to the package manager (hash verified).
    KnownBinary { hash_verified: bool },
    /// Entity behaviour conforms to established baseline.
    /// deviation: 0.0 = perfect match, 1.0 = completely novel.
    BaselineConformity { deviation: f32 },
    /// Login occurred during normal hours for this user.
    LoginHours { within_normal: bool },
    /// Number of new/unseen destinations connected to in the last 24h.
    NewDestinations { count: u32 },
    /// Process has an unknown/untrusted parent lineage.
    UnknownLineage { parent: String },
    /// External reputation score (e.g., AbuseIPDB).
    ReputationScore { score: f32 },
    /// Operator explicitly verified this entity as trusted.
    OperatorVerified { when: DateTime<Utc> },
    /// Number of incidents involving this entity in the last 7 days.
    IncidentHistory { count_7d: u32 },
}

/// Calculate the score delta for a single trust factor.
///
/// Returns a value that adjusts the trust score (positive = more trusted,
/// negative = less trusted).
pub fn factor_delta(factor: &TrustFactor) -> f32 {
    match factor {
        TrustFactor::KnownBinary { hash_verified } => {
            if *hash_verified {
                30.0
            } else {
                -10.0
            }
        }
        TrustFactor::BaselineConformity { deviation } => {
            // 0.0 deviation → +20, 1.0 deviation → -20
            20.0 - (deviation.clamp(0.0, 1.0) * 40.0)
        }
        TrustFactor::LoginHours { within_normal } => {
            if *within_normal {
                10.0
            } else {
                -10.0
            }
        }
        TrustFactor::NewDestinations { count } => {
            // -5 per new destination, capped at -30
            -((*count as f32) * 5.0).min(30.0)
        }
        TrustFactor::UnknownLineage { .. } => -20.0,
        TrustFactor::ReputationScore { score } => {
            // AbuseIPDB: 0 = clean, 100 = malicious
            // Map: 0 → +0, 100 → -40
            -(score.clamp(0.0, 100.0) * 0.4)
        }
        TrustFactor::OperatorVerified { when } => {
            // Decays over 7 days: +30 → +0
            let age_hours = (Utc::now() - *when).num_hours() as f32;
            let decay = (age_hours / (7.0 * 24.0)).clamp(0.0, 1.0);
            30.0 * (1.0 - decay)
        }
        TrustFactor::IncidentHistory { count_7d } => {
            // -5 per incident, capped at -40
            -((*count_7d as f32) * 5.0).min(40.0)
        }
    }
}

// ── Trust score ─────────────────────────────────────────────────────────

/// Computed trust score for an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Entity identifier (IP address, username, or process comm).
    pub entity: String,
    /// Entity type: "ip", "user", or "process".
    pub entity_type: String,
    /// Computed score 0.0 – 100.0.
    pub score: f32,
    /// Active factors contributing to the score.
    pub factors: Vec<TrustFactor>,
    /// When the score was last computed.
    pub last_updated: DateTime<Utc>,
}

/// Compute a trust score from a set of factors.
///
/// Starts at a base of 50 and adjusts by factor deltas.
/// The final score is clamped to 0.0–100.0.
pub fn compute_score(factors: &[TrustFactor]) -> f32 {
    let base = 50.0f32;
    let total_delta: f32 = factors.iter().map(factor_delta).sum();
    (base + total_delta).clamp(0.0, 100.0)
}

/// Trust level classification based on score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// 80–100: highly trusted, minimal monitoring.
    Trusted,
    /// 50–79: normal, standard monitoring.
    Normal,
    /// 20–49: suspicious, enhanced monitoring + AI triage.
    Suspicious,
    /// 0–19: untrusted, immediate attention required.
    Untrusted,
}

/// Classify a trust score into a trust level.
pub fn classify(score: f32) -> TrustLevel {
    match score as u32 {
        80..=100 => TrustLevel::Trusted,
        50..=79 => TrustLevel::Normal,
        20..=49 => TrustLevel::Suspicious,
        _ => TrustLevel::Untrusted,
    }
}

/// Format the trust level as a human-readable string.
pub fn level_label(level: TrustLevel) -> &'static str {
    match level {
        TrustLevel::Trusted => "Trusted",
        TrustLevel::Normal => "Normal",
        TrustLevel::Suspicious => "Suspicious",
        TrustLevel::Untrusted => "Untrusted",
    }
}

// ── Config ──────────────────────────────────────────────────────────────

/// Configuration for the trust scoring engine.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustScoringConfig {
    /// Enable trust scoring (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for TrustScoringConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── factor_delta: 3+ tests per factor ───────────────────────────────

    #[test]
    fn known_binary_verified_positive() {
        let f = TrustFactor::KnownBinary {
            hash_verified: true,
        };
        assert_eq!(factor_delta(&f), 30.0);
    }

    #[test]
    fn known_binary_unverified_negative() {
        let f = TrustFactor::KnownBinary {
            hash_verified: false,
        };
        assert_eq!(factor_delta(&f), -10.0);
    }

    #[test]
    fn baseline_conformity_perfect() {
        let f = TrustFactor::BaselineConformity { deviation: 0.0 };
        assert_eq!(factor_delta(&f), 20.0);
    }

    #[test]
    fn baseline_conformity_total_deviation() {
        let f = TrustFactor::BaselineConformity { deviation: 1.0 };
        assert_eq!(factor_delta(&f), -20.0);
    }

    #[test]
    fn baseline_conformity_half_deviation() {
        let f = TrustFactor::BaselineConformity { deviation: 0.5 };
        assert!((factor_delta(&f) - 0.0).abs() < 0.01);
    }

    #[test]
    fn baseline_conformity_clamped_above_one() {
        let f = TrustFactor::BaselineConformity { deviation: 2.0 };
        assert_eq!(factor_delta(&f), -20.0); // clamped to 1.0
    }

    #[test]
    fn login_hours_within_normal() {
        let f = TrustFactor::LoginHours {
            within_normal: true,
        };
        assert_eq!(factor_delta(&f), 10.0);
    }

    #[test]
    fn login_hours_outside_normal() {
        let f = TrustFactor::LoginHours {
            within_normal: false,
        };
        assert_eq!(factor_delta(&f), -10.0);
    }

    #[test]
    fn new_destinations_zero() {
        let f = TrustFactor::NewDestinations { count: 0 };
        assert_eq!(factor_delta(&f), 0.0);
    }

    #[test]
    fn new_destinations_three() {
        let f = TrustFactor::NewDestinations { count: 3 };
        assert_eq!(factor_delta(&f), -15.0);
    }

    #[test]
    fn new_destinations_capped() {
        let f = TrustFactor::NewDestinations { count: 100 };
        assert_eq!(factor_delta(&f), -30.0); // capped
    }

    #[test]
    fn unknown_lineage_penalty() {
        let f = TrustFactor::UnknownLineage {
            parent: "exploit".into(),
        };
        assert_eq!(factor_delta(&f), -20.0);
    }

    #[test]
    fn reputation_clean() {
        let f = TrustFactor::ReputationScore { score: 0.0 };
        assert_eq!(factor_delta(&f), 0.0);
    }

    #[test]
    fn reputation_malicious() {
        let f = TrustFactor::ReputationScore { score: 100.0 };
        assert_eq!(factor_delta(&f), -40.0);
    }

    #[test]
    fn reputation_moderate() {
        let f = TrustFactor::ReputationScore { score: 50.0 };
        assert_eq!(factor_delta(&f), -20.0);
    }

    #[test]
    fn operator_verified_fresh() {
        let f = TrustFactor::OperatorVerified { when: Utc::now() };
        let d = factor_delta(&f);
        assert!(d > 29.0 && d <= 30.0, "expected ~30, got {d}");
    }

    #[test]
    fn operator_verified_stale() {
        let f = TrustFactor::OperatorVerified {
            when: Utc::now() - chrono::Duration::days(14),
        };
        let d = factor_delta(&f);
        assert_eq!(d, 0.0); // fully decayed
    }

    #[test]
    fn operator_verified_half_life() {
        let f = TrustFactor::OperatorVerified {
            when: Utc::now() - chrono::Duration::hours(84), // 3.5 days = half of 7
        };
        let d = factor_delta(&f);
        assert!(d > 14.0 && d < 16.0, "expected ~15, got {d}");
    }

    #[test]
    fn incident_history_zero() {
        let f = TrustFactor::IncidentHistory { count_7d: 0 };
        assert_eq!(factor_delta(&f), 0.0);
    }

    #[test]
    fn incident_history_three() {
        let f = TrustFactor::IncidentHistory { count_7d: 3 };
        assert_eq!(factor_delta(&f), -15.0);
    }

    #[test]
    fn incident_history_capped() {
        let f = TrustFactor::IncidentHistory { count_7d: 20 };
        assert_eq!(factor_delta(&f), -40.0); // capped
    }

    // ── compute_score tests ─────────────────────────────────────────────

    #[test]
    fn compute_score_no_factors() {
        assert_eq!(compute_score(&[]), 50.0);
    }

    #[test]
    fn compute_score_all_positive() {
        let factors = vec![
            TrustFactor::KnownBinary {
                hash_verified: true,
            },
            TrustFactor::BaselineConformity { deviation: 0.0 },
            TrustFactor::LoginHours {
                within_normal: true,
            },
            TrustFactor::OperatorVerified { when: Utc::now() },
        ];
        let score = compute_score(&factors);
        // 50 + 30 + 20 + 10 + 30 = 140, clamped to 100
        assert_eq!(score, 100.0);
    }

    #[test]
    fn compute_score_all_negative() {
        let factors = vec![
            TrustFactor::KnownBinary {
                hash_verified: false,
            },
            TrustFactor::BaselineConformity { deviation: 1.0 },
            TrustFactor::UnknownLineage {
                parent: "exploit".into(),
            },
            TrustFactor::ReputationScore { score: 100.0 },
        ];
        let score = compute_score(&factors);
        // 50 + (-10) + (-20) + (-20) + (-40) = -40, clamped to 0
        assert_eq!(score, 0.0);
    }

    #[test]
    fn compute_score_mixed() {
        let factors = vec![
            TrustFactor::KnownBinary {
                hash_verified: true,
            }, // +30
            TrustFactor::NewDestinations { count: 2 }, // -10
            TrustFactor::LoginHours {
                within_normal: true,
            }, // +10
        ];
        let score = compute_score(&factors);
        // 50 + 30 - 10 + 10 = 80
        assert_eq!(score, 80.0);
    }

    // ── classify tests ──────────────────────────────────────────────────

    #[test]
    fn classify_trusted() {
        assert_eq!(classify(90.0), TrustLevel::Trusted);
        assert_eq!(classify(80.0), TrustLevel::Trusted);
        assert_eq!(classify(100.0), TrustLevel::Trusted);
    }

    #[test]
    fn classify_normal() {
        assert_eq!(classify(50.0), TrustLevel::Normal);
        assert_eq!(classify(79.0), TrustLevel::Normal);
    }

    #[test]
    fn classify_suspicious() {
        assert_eq!(classify(20.0), TrustLevel::Suspicious);
        assert_eq!(classify(49.0), TrustLevel::Suspicious);
    }

    #[test]
    fn classify_untrusted() {
        assert_eq!(classify(0.0), TrustLevel::Untrusted);
        assert_eq!(classify(19.0), TrustLevel::Untrusted);
    }

    // ── level_label tests ───────────────────────────────────────────────

    #[test]
    fn level_labels() {
        assert_eq!(level_label(TrustLevel::Trusted), "Trusted");
        assert_eq!(level_label(TrustLevel::Normal), "Normal");
        assert_eq!(level_label(TrustLevel::Suspicious), "Suspicious");
        assert_eq!(level_label(TrustLevel::Untrusted), "Untrusted");
    }

    // ── TrustScore struct tests ─────────────────────────────────────────

    #[test]
    fn trust_score_serializes() {
        let ts = TrustScore {
            entity: "10.0.0.1".into(),
            entity_type: "ip".into(),
            score: 75.5,
            factors: vec![TrustFactor::KnownBinary {
                hash_verified: true,
            }],
            last_updated: Utc::now(),
        };
        let json = serde_json::to_string(&ts).unwrap();
        assert!(json.contains("75.5"));
        assert!(json.contains("10.0.0.1"));
    }

    #[test]
    fn trust_score_deserializes() {
        let json = r#"{"entity":"root","entity_type":"user","score":40.0,"factors":[],"last_updated":"2026-04-16T00:00:00Z"}"#;
        let ts: TrustScore = serde_json::from_str(json).unwrap();
        assert_eq!(ts.entity, "root");
        assert_eq!(ts.score, 40.0);
    }

    #[test]
    fn trust_score_default_factors_empty() {
        let ts = TrustScore {
            entity: "test".into(),
            entity_type: "process".into(),
            score: compute_score(&[]),
            factors: vec![],
            last_updated: Utc::now(),
        };
        assert_eq!(ts.score, 50.0);
    }

    // ── Config tests ────────────────────────────────────────────────────

    #[test]
    fn config_default() {
        let cfg = TrustScoringConfig::default();
        assert!(cfg.enabled);
    }

    #[test]
    fn config_deserialize() {
        let toml = r#"enabled = false"#;
        let cfg: TrustScoringConfig = toml::from_str(toml).unwrap();
        assert!(!cfg.enabled);
    }

    #[test]
    fn config_deserialize_default() {
        let toml = "";
        let cfg: TrustScoringConfig = toml::from_str(toml).unwrap();
        assert!(cfg.enabled);
    }
}
