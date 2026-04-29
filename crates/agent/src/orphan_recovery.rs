//! Phase 7B (audit RC-2 / 2026-04-29): orphan-incident recovery sweep.
//!
//! Why this module exists:
//!
//! The agent's standard incident processing path (`process/incidents.rs`)
//! reads incidents via a SQLite cursor (`agent_cursors` table), runs them
//! through the AI router, and writes a decision row. When the agent
//! restarts (deploy, crash, manual restart), the cursor advances past
//! incidents that were in-flight at the moment of restart but never got
//! their decision committed. Those incidents stay in the `incidents`
//! table forever without a corresponding `decisions` row — orphans.
//!
//! Pre-Phase-7 these orphans were invisible to the operator: the dashboard
//! read from the lossy in-memory KG which TTL-evicted them after ~12h.
//! Phase 7 surfaced them as the "Stuck >1h" pending-breakdown bucket —
//! useful health signal, but the bucket grows unboundedly because nothing
//! ever clears the orphans. The dashboard ended up showing "AI pipeline
//! may be wedged" with 37 stuck incidents while the AI was healthily
//! processing the steady stream.
//!
//! The recovery pass closes the loop:
//! 1. Every 10 minutes, query SQLite for incidents whose `ts` is >1h ago
//!    and have no `decisions` row joined.
//! 2. For each, write a `dismiss` decision with
//!    `ai_provider="orphan-recovery"` and a clear reason explaining the
//!    sweep took it. The hash chain stays intact (the standard
//!    `Store::insert_decision` is used) and the audit trail is honest.
//! 3. The Stuck bucket on the next dashboard tick reflects only NEW
//!    >1h-old orphans (which themselves get swept within 10 minutes).
//!
//! Bounded scope:
//! - Limited to 200 orphans per sweep so the dashboard's stuck count
//!   trends down across multiple ticks rather than disappearing in one
//!   burst (operator-visible behaviour: "stuck went from 37 to 0
//!   instantly" looks like a bug; "stuck went 37 → 17 → 0" reads as a
//!   cleanup pass running).
//! - Skips allowlisted incidents (those already have their own group).
//! - Skips incidents that already have a decision (idempotent).

use crate::decisions::DecisionEntry;
use crate::AgentState;
use chrono::Utc;
use std::path::Path;
use tracing::{info, warn};

/// Best-effort machine hostname for the decision row's `host` field.
/// Mirrors the helper in `dashboard::actions::hostname` so the
/// orphan-recovery decisions look identical to operator-initiated
/// ones in the audit log.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Threshold: incidents older than this with no decision are
/// considered orphans. Same value the dashboard uses for the "Stuck"
/// bucket, kept in sync intentionally — if the dashboard says stuck=N,
/// the recovery pass will sweep the same N.
const ORPHAN_AGE_SECS: i64 = 3600;

/// Cap per sweep — see module doc.
const ORPHAN_SWEEP_LIMIT: usize = 200;

/// AI-provider label written on the dismiss decision so the audit
/// trail clearly shows which decisions came from the recovery pass
/// (vs. the standard AI router or the noise gate).
pub(crate) const ORPHAN_AI_PROVIDER: &str = "orphan-recovery";

/// Run one orphan-recovery sweep. Returns the number of decisions
/// written. Best-effort: SQL or store errors are logged at `warn!` and
/// do not propagate.
pub(crate) fn run_sweep(state: &mut AgentState, data_dir: &Path) -> usize {
    let Some(store) = state.sqlite_store.as_ref() else {
        return 0;
    };
    let now = Utc::now();
    let cutoff = now - chrono::Duration::seconds(ORPHAN_AGE_SECS);
    let cutoff_iso = cutoff.to_rfc3339();

    // Query all orphans via the store crate's typed helper.
    let orphans: Vec<(String, String, String)> =
        match store.find_orphan_incidents(&cutoff_iso, ORPHAN_SWEEP_LIMIT) {
            Ok(rs) => rs,
            Err(e) => {
                warn!(error = %e, "orphan_recovery: failed to query orphans");
                return 0;
            }
        };

    if orphans.is_empty() {
        return 0;
    }

    let mut written = 0usize;
    for (incident_id, incident_ts_iso, incident_data_json) in orphans {
        // Extract target_ip from incident JSON entities (best-effort —
        // missing target IP is acceptable, the decision still records).
        let target_ip = extract_target_ip(&incident_data_json);
        let age_seconds = chrono::DateTime::parse_from_rfc3339(&incident_ts_iso)
            .map(|t| (now - t.with_timezone(&Utc)).num_seconds())
            .unwrap_or(0);
        let age_human = format!("{}h{}m", age_seconds / 3600, (age_seconds % 3600) / 60);
        let entry = DecisionEntry {
            ts: now,
            incident_id: incident_id.clone(),
            host: hostname(),
            ai_provider: ORPHAN_AI_PROVIDER.to_string(),
            action_type: "dismiss".to_string(),
            target_ip,
            target_user: None,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason: format!(
                "Auto-dismissed by orphan-recovery sweep: incident is {age_human} old with no AI \
                 decision. Likely deploy orphan or AI provider skip. Operator can re-trigger \
                 manual review via Threats list."
            ),
            estimated_threat: "none".to_string(),
            execution_result: "dismissed".to_string(),
            prev_hash: None,
        };
        match crate::decisions::append_chained(data_dir, &entry, Some(store)) {
            Ok(()) => written += 1,
            Err(e) => warn!(
                incident_id = %incident_id,
                error = %e,
                "orphan_recovery: failed to write dismiss decision"
            ),
        }
    }

    if written > 0 {
        info!(
            written,
            "orphan_recovery: swept abandoned incidents into dismiss decisions"
        );
    }
    written
}

/// Extract the first IP entity from the incident's JSON `data` blob.
/// Returns `None` when the JSON is malformed or has no IP entity (the
/// dismiss decision is still written without a target IP).
fn extract_target_ip(incident_data_json: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(incident_data_json).ok()?;
    let entities = parsed.get("entities")?.as_array()?;
    for entity in entities {
        let kind = entity.get("type")?.as_str()?;
        if kind.eq_ignore_ascii_case("ip") {
            let value = entity.get("value")?.as_str()?;
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_target_ip_finds_first_external_ip() {
        let json = serde_json::json!({
            "entities": [
                {"type": "user", "value": "alice"},
                {"type": "ip", "value": "203.0.113.10"},
                {"type": "ip", "value": "203.0.113.20"},
            ]
        })
        .to_string();
        assert_eq!(extract_target_ip(&json), Some("203.0.113.10".to_string()));
    }

    #[test]
    fn extract_target_ip_returns_none_when_no_ip() {
        let json = serde_json::json!({
            "entities": [{"type": "user", "value": "alice"}]
        })
        .to_string();
        assert_eq!(extract_target_ip(&json), None);
    }

    #[test]
    fn extract_target_ip_returns_none_on_malformed_json() {
        assert_eq!(extract_target_ip("not json"), None);
    }

    #[test]
    fn find_orphan_incidents_returns_only_decisionless_old_rows() {
        // The store-level helper is what the slow_loop sweep iterates.
        // Anchor end-to-end here so a future schema change to incidents
        // or decisions surfaces as a test failure instead of as a
        // silently-broken recovery pass on prod.
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;

        let store = innerwarden_store::Store::open_memory().expect("open_memory");
        let now = chrono::Utc::now();
        let two_hours_ago = now - chrono::Duration::hours(2);
        let two_min_ago = now - chrono::Duration::minutes(2);

        let make = |id: &str, ts: chrono::DateTime<chrono::Utc>| Incident {
            ts,
            host: "h".into(),
            incident_id: id.into(),
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };

        // Old orphan -> SHOULD be returned.
        store
            .insert_incident(&make("old:orphan", two_hours_ago))
            .unwrap();

        // Old, but already has a decision -> SHOULD NOT be returned.
        store
            .insert_incident(&make("old:decided", two_hours_ago))
            .unwrap();
        let decided = innerwarden_store::decisions::DecisionRow {
            ts: now.to_rfc3339(),
            incident_id: "old:decided".into(),
            action_type: "block_ip".into(),
            target_ip: Some("203.0.113.10".into()),
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("test".into()),
            data: "{}".to_string(),
        };
        store.insert_decision(&decided).expect("insert decision");

        // Fresh, decisionless -> SHOULD NOT be returned (still in-flight).
        store
            .insert_incident(&make("fresh:1", two_min_ago))
            .unwrap();

        // Old, decisionless, but allowlisted -> SHOULD NOT be returned.
        store
            .insert_incident(&make("old:trusted", two_hours_ago))
            .unwrap();
        store.set_incident_allowlisted("old:trusted").unwrap();

        let cutoff = (now - chrono::Duration::hours(1)).to_rfc3339();
        let orphans = store.find_orphan_incidents(&cutoff, 100).unwrap();
        let ids: Vec<&str> = orphans.iter().map(|(id, _, _)| id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["old:orphan"],
            "only old + decisionless + non-allowlisted incidents qualify"
        );
    }
}
