//! Spec 049 PR10 — case recurrence block for the Cases drill-down.
//!
//! Reads from `attacker_intel::AttackerProfile` (already maintained
//! by the agent — `attacker_intel::classify_pattern` populates
//! `dna.pattern_class` at ingest time). This module is the read-time
//! adapter: maps the agent's existing pattern string into the
//! `RecurrencePattern` enum the drill-down keys on, and packages
//! the recurrence-relevant fields into the operator-facing block.
//!
//! Lets the operator answer spec 049 §8.2.E item 6 questions
//! without leaving the case:
//!
//!   - "Esse atacante já apareceu antes?" → `visit_count`
//!   - "Quando foi a primeira vez?" → `first_seen`
//!   - "Quantos dias ativos no total?" → `total_days_active`
//!   - "Voltou depois de ser bloqueado?" → `returns_after_unblock`
//!   - "Que tipo de atacante é?" → `pattern`
//!   - "Quero ver o perfil completo." → `profile_link`
//!
//! Pure derivation. No I/O. Same input always produces the same
//! output. The pattern classifier lives in `attacker_intel.rs`;
//! this module is intentionally NOT a second source of
//! classification — single source of truth keeps drift bugs away.

use crate::attacker_intel::AttackerProfile;
use chrono::{DateTime, Utc};
use serde::Serialize;

/// Operator-facing recurrence-pattern label. Snake-case wire format
/// keyed on by the frontend (`RECURRENCE_PATTERN_LABELS` analogue in
/// `journey.js`). Wire strings deliberately mirror what
/// `attacker_intel::classify_pattern` writes into `dna.pattern_class`
/// plus a single addition (`single_burst` for visit_count <= 1, where
/// the agent currently writes `unknown`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecurrencePattern {
    /// One visit (or zero). The classic "fired once, never came back"
    /// attacker. Agent currently labels these `unknown` because its
    /// `classify_pattern` returns early on `visit_count < 2`; the
    /// drill-down promotes that to a more honest operator-facing
    /// label.
    SingleBurst,
    /// 2+ visits but no strong rhythm or targeting signal. Default
    /// agent label for repeat attackers without a clean signature.
    Opportunistic,
    /// 3+ visits with low inter-visit-interval variance. Agent label
    /// for automated scanners (cron-like cadence).
    RegularScanner,
    /// 5+ visits AND 4+ distinct detectors. Agent label for attackers
    /// that pivot across surfaces — looks human or hand-tuned.
    Targeted,
    /// Agent could not classify (e.g. first-ever ingestion mid-build).
    /// Surface honestly rather than mislabel.
    Unknown,
}

impl RecurrencePattern {
    /// Wire string. Pinned by serialization tests; do not change
    /// without updating the frontend label map.
    #[allow(dead_code)]
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::SingleBurst => "single_burst",
            Self::Opportunistic => "opportunistic",
            Self::RegularScanner => "regular_scanner",
            Self::Targeted => "targeted",
            Self::Unknown => "unknown",
        }
    }

    /// Map the agent's stored `dna.pattern_class` string to the
    /// `RecurrencePattern` enum. Conservative: anything that does
    /// not match a known label falls through to `Unknown`. A future
    /// agent classifier that introduces a new label without
    /// updating this map renders as `Unknown` — visible, not
    /// silently misclassified.
    fn from_agent_label(label: &str) -> Self {
        match label.trim() {
            "regular_scanner" => Self::RegularScanner,
            "opportunistic" => Self::Opportunistic,
            "targeted" => Self::Targeted,
            "single_burst" => Self::SingleBurst,
            _ => Self::Unknown,
        }
    }
}

/// Recurrence summary surfaced on the journey response for IP
/// subjects. Frontend keys directly on this shape.
#[derive(Debug, Clone, Serialize)]
pub(super) struct RecurrenceBlock {
    pub(super) first_seen: DateTime<Utc>,
    pub(super) last_seen: DateTime<Utc>,
    pub(super) visit_count: u32,
    pub(super) total_days_active: u32,
    /// Approximation: cases where the agent issued a block but the
    /// attacker came back. Derived as
    /// `min(visit_count - 1, total_blocks)` when both are positive;
    /// zero otherwise. The agent does not currently record the
    /// causal link between a specific unblock event and a follow-up
    /// visit — a future PR may track this precisely. Until then the
    /// frontend label says "approximation" so the operator does not
    /// over-read the number.
    pub(super) returns_after_unblock: u32,
    pub(super) pattern: RecurrencePattern,
    /// Bidirectional link to the full attacker profile in the
    /// Intelligence > Profiles tab. Operator clicks to drill out
    /// from the case into the per-attacker view.
    pub(super) profile_link: String,
    /// Pre-formatted human label for the pattern. Frontend echoes
    /// this directly — keeps the operator-readable name colocated
    /// with the wire-format key so a refactor of the labels in
    /// `journey.js` cannot drift from this list.
    pub(super) pattern_label: &'static str,
}

/// Resolve the drill-down recurrence pattern for `profile`.
///
/// Maps the agent's pre-computed `dna.pattern_class` string into a
/// `RecurrencePattern`. Promotes the agent's `unknown` to
/// `SingleBurst` when `visit_count <= 1` — the agent's classifier
/// returns "unknown" for one-visit attackers (early-return on
/// `visit_count < 2`); the drill-down's operator-facing label is
/// more honest as "Single burst" in that case.
pub(super) fn resolve_recurrence_pattern(profile: &AttackerProfile) -> RecurrencePattern {
    let mapped = RecurrencePattern::from_agent_label(&profile.dna.pattern_class);
    // Promote agent's `unknown` → `SingleBurst` for one-visit
    // attackers, where the agent simply has not had a second visit
    // yet to compute intervals.
    if mapped == RecurrencePattern::Unknown && profile.visit_count <= 1 {
        return RecurrencePattern::SingleBurst;
    }
    mapped
}

/// Human-readable label for a `RecurrencePattern`. Surfaced on
/// `RecurrenceBlock.pattern_label` so the frontend echoes the same
/// canonical name without a duplicate label table in JS.
pub(super) fn pattern_label(pattern: RecurrencePattern) -> &'static str {
    match pattern {
        RecurrencePattern::SingleBurst => "Single burst",
        RecurrencePattern::Opportunistic => "Opportunistic",
        RecurrencePattern::RegularScanner => "Regular scanner",
        RecurrencePattern::Targeted => "Targeted",
        RecurrencePattern::Unknown => "Unknown",
    }
}

/// Build a `RecurrenceBlock` from an `AttackerProfile`. Pure
/// derivation; no fields read from disk or network.
pub(super) fn recurrence_from_profile(profile: &AttackerProfile) -> RecurrenceBlock {
    let pattern = resolve_recurrence_pattern(profile);
    let returns_after_unblock = if profile.visit_count > 1 && profile.total_blocks > 0 {
        std::cmp::min(profile.visit_count.saturating_sub(1), profile.total_blocks)
    } else {
        0
    };
    RecurrenceBlock {
        first_seen: profile.first_seen,
        last_seen: profile.last_seen,
        visit_count: profile.visit_count,
        total_days_active: profile.total_days_active,
        returns_after_unblock,
        pattern,
        profile_link: format!("/api/attacker-profiles/{}", profile.ip),
        pattern_label: pattern_label(pattern),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attacker_intel::{AttackerDna, AttackerProfile, IocsCompact};
    use chrono::TimeZone;
    use std::collections::BTreeSet;

    fn make_profile(visit_count: u32, days_active: u32, pattern_class: &str) -> AttackerProfile {
        AttackerProfile {
            ip: "203.0.113.10".to_string(),
            geo: None,
            abuseipdb_score: None,
            crowdsec_listed: false,
            is_tor: false,
            first_seen: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            last_seen: Utc.with_ymd_and_hms(2026, 5, 12, 0, 0, 0).unwrap(),
            visit_count,
            visit_dates: vec![],
            total_days_active: days_active,
            detectors_triggered: BTreeSet::new(),
            mitre_techniques: BTreeSet::new(),
            max_severity: "high".to_string(),
            total_incidents: 0,
            total_events: 0,
            total_decisions: 0,
            total_blocks: 0,
            total_honeypot_diversions: 0,
            total_monitors: 0,
            honeypot_sessions: 0,
            credentials_attempted: vec![],
            commands_executed: vec![],
            iocs: IocsCompact::default(),
            dna: AttackerDna {
                hash: "x".to_string(),
                hour_distribution: [0u8; 24],
                target_users: vec![],
                target_ports: vec![],
                tool_signatures: vec![],
                inter_visit_intervals: vec![],
                pattern_class: pattern_class.to_string(),
            },
            shield_blocks: 0,
            shield_escalation_hits: 0,
            shield_last_blocked: None,
            mesh_peer_confirmations: 0,
            mesh_signals_received: 0,
            risk_score: 0,
            profile_version: 1,
            updated_at: Utc::now(),
        }
    }

    // ── Agent label → RecurrencePattern mapping ───────────────────

    #[test]
    fn regular_scanner_label_maps_to_regular_scanner() {
        let p = make_profile(5, 3, "regular_scanner");
        assert_eq!(
            resolve_recurrence_pattern(&p),
            RecurrencePattern::RegularScanner
        );
    }

    #[test]
    fn targeted_label_maps_to_targeted() {
        let p = make_profile(7, 4, "targeted");
        assert_eq!(resolve_recurrence_pattern(&p), RecurrencePattern::Targeted);
    }

    #[test]
    fn opportunistic_label_maps_to_opportunistic() {
        let p = make_profile(3, 2, "opportunistic");
        assert_eq!(
            resolve_recurrence_pattern(&p),
            RecurrencePattern::Opportunistic
        );
    }

    #[test]
    fn single_burst_label_maps_to_single_burst() {
        let p = make_profile(1, 1, "single_burst");
        assert_eq!(
            resolve_recurrence_pattern(&p),
            RecurrencePattern::SingleBurst
        );
    }

    // ── Agent `unknown` promotion to SingleBurst ───────────────────

    #[test]
    fn agent_unknown_with_one_visit_promotes_to_single_burst() {
        // Agent's classify_pattern returns "unknown" on visit_count
        // < 2 (early-return). The drill-down is more honest: one
        // visit IS a single burst.
        let p = make_profile(1, 1, "unknown");
        assert_eq!(
            resolve_recurrence_pattern(&p),
            RecurrencePattern::SingleBurst
        );
    }

    #[test]
    fn agent_unknown_with_zero_visits_promotes_to_single_burst() {
        // Edge case: profile initialised before first ingestion.
        let p = make_profile(0, 0, "unknown");
        assert_eq!(
            resolve_recurrence_pattern(&p),
            RecurrencePattern::SingleBurst
        );
    }

    #[test]
    fn agent_unknown_with_many_visits_stays_unknown_honestly() {
        // If the agent labeled an attacker `unknown` despite many
        // visits (data anomaly), the drill-down surfaces the
        // mismatch instead of forcing a classification.
        let p = make_profile(10, 5, "unknown");
        assert_eq!(resolve_recurrence_pattern(&p), RecurrencePattern::Unknown);
    }

    // ── Unknown agent labels (forward compatibility) ───────────────

    #[test]
    fn future_agent_label_falls_through_to_unknown() {
        // A future agent classifier that introduces a new label
        // (e.g. "swarm") without updating this module's map must
        // render as Unknown — visible, not silently misclassified.
        let p = make_profile(5, 3, "swarm");
        assert_eq!(resolve_recurrence_pattern(&p), RecurrencePattern::Unknown);
    }

    #[test]
    fn empty_agent_label_falls_through_to_unknown() {
        let p = make_profile(5, 3, "");
        assert_eq!(resolve_recurrence_pattern(&p), RecurrencePattern::Unknown);
    }

    #[test]
    fn agent_label_is_trimmed_before_matching() {
        // Defensive: a stray whitespace in the stored label should
        // not flip a known pattern to Unknown.
        let p = make_profile(5, 3, "  regular_scanner  ");
        assert_eq!(
            resolve_recurrence_pattern(&p),
            RecurrencePattern::RegularScanner
        );
    }

    // ── returns_after_unblock derivation ──────────────────────────

    #[test]
    fn returns_after_unblock_is_zero_when_no_blocks() {
        let mut p = make_profile(3, 2, "opportunistic");
        p.total_blocks = 0;
        let b = recurrence_from_profile(&p);
        assert_eq!(b.returns_after_unblock, 0);
    }

    #[test]
    fn returns_after_unblock_is_zero_when_visit_count_one() {
        let mut p = make_profile(1, 1, "single_burst");
        p.total_blocks = 1;
        let b = recurrence_from_profile(&p);
        assert_eq!(
            b.returns_after_unblock, 0,
            "single visit cannot have returned after unblock"
        );
    }

    #[test]
    fn returns_after_unblock_uses_min_when_both_visits_and_blocks_positive() {
        let mut p = make_profile(5, 3, "regular_scanner");
        p.total_blocks = 2;
        let b = recurrence_from_profile(&p);
        // min(visit_count - 1 = 4, total_blocks = 2) = 2.
        assert_eq!(b.returns_after_unblock, 2);
    }

    #[test]
    fn returns_after_unblock_caps_at_visit_count_minus_one() {
        let mut p = make_profile(3, 2, "opportunistic");
        p.total_blocks = 99;
        let b = recurrence_from_profile(&p);
        assert_eq!(b.returns_after_unblock, 2);
    }

    // ── Block shape + link ─────────────────────────────────────────

    #[test]
    fn recurrence_block_carries_profile_deeplink() {
        let p = make_profile(1, 1, "single_burst");
        let b = recurrence_from_profile(&p);
        assert_eq!(b.profile_link, "/api/attacker-profiles/203.0.113.10");
    }

    #[test]
    fn recurrence_block_carries_pattern_label() {
        let p = make_profile(1, 1, "single_burst");
        let b = recurrence_from_profile(&p);
        assert_eq!(b.pattern_label, "Single burst");
        assert_eq!(b.pattern, RecurrencePattern::SingleBurst);
    }

    #[test]
    fn recurrence_block_preserves_timeline_fields() {
        let p = make_profile(3, 2, "opportunistic");
        let b = recurrence_from_profile(&p);
        assert_eq!(b.first_seen, p.first_seen);
        assert_eq!(b.last_seen, p.last_seen);
        assert_eq!(b.visit_count, p.visit_count);
        assert_eq!(b.total_days_active, p.total_days_active);
    }

    // ── Serialization wire contract ────────────────────────────────

    #[test]
    fn recurrence_pattern_serializes_as_snake_case() {
        for (pattern, wire) in [
            (RecurrencePattern::SingleBurst, "single_burst"),
            (RecurrencePattern::Opportunistic, "opportunistic"),
            (RecurrencePattern::RegularScanner, "regular_scanner"),
            (RecurrencePattern::Targeted, "targeted"),
            (RecurrencePattern::Unknown, "unknown"),
        ] {
            let json = serde_json::to_string(&pattern).unwrap();
            assert_eq!(json, format!("\"{wire}\""), "pattern {pattern:?}");
            assert_eq!(pattern.as_str(), wire);
        }
    }

    #[test]
    fn recurrence_block_serializes_with_expected_field_names() {
        let p = make_profile(3, 2, "opportunistic");
        let b = recurrence_from_profile(&p);
        let v = serde_json::to_value(&b).unwrap();
        assert!(v.get("first_seen").is_some());
        assert!(v.get("last_seen").is_some());
        assert!(v.get("visit_count").is_some());
        assert!(v.get("total_days_active").is_some());
        assert!(v.get("returns_after_unblock").is_some());
        assert!(v.get("pattern").is_some());
        assert!(v.get("profile_link").is_some());
        assert!(v.get("pattern_label").is_some());
    }
}
