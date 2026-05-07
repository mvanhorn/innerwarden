use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use tracing::{info, warn};

use crate::dashboard::AdvisoryEntry;
use crate::AgentState;

pub(crate) async fn handle_advisory_violation(
    incident: &innerwarden_core::incident::Incident,
    advisory_cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
    state: &AgentState,
) {
    // Advisory correlation - check if this execution incident matches
    // a recent advisory denial from the /api/advisor/check-command endpoint.
    // If so, the AI agent ignored Inner Warden's security recommendation.
    if !incident.tags.contains(&"execution".to_string())
        && !incident.tags.contains(&"suspicious".to_string())
    {
        return;
    }

    let Some(advisory) = check_advisory_match(advisory_cache, incident) else {
        return;
    };

    info!(
        advisory_id = %advisory.advisory_id,
        command = %advisory.command_preview,
        risk_score = advisory.risk_score,
        "AI agent ignored security advisory"
    );

    // Send Telegram notification about the advisory violation (gated).
    if let Some(tg) = &state.telegram_client {
        let ctx = crate::notification_gate::NotificationContext::for_advisory_ignored(
            advisory.risk_score,
        );
        let gate_counter = state.telemetry.gate_suppressed_counter();
        let verdict =
            crate::notification_gate::should_notify_with_counter(&ctx, gate_counter.as_ref());
        match verdict {
            crate::notification_gate::NotificationVerdict::SendNow => {
                let msg = format!(
                    "\u{26a0}\u{fe0f} <b>Advisory Ignored</b>\n\n\
                    Your AI agent executed a command that Inner Warden recommended <b>{}</b>.\n\n\
                    <b>Command:</b> <code>{}</code>\n\
                    <b>Risk score:</b> {}/100\n\
                    <b>Signals:</b> {}\n\
                    <b>Advisory ID:</b> <code>{}</code>\n\n\
                    The command was executed despite the warning. Review the audit trail.",
                    advisory.recommendation,
                    advisory
                        .command_preview
                        .replace('<', "&lt;")
                        .replace('>', "&gt;"),
                    advisory.risk_score,
                    advisory.signals.join(", "),
                    advisory.advisory_id,
                );
                if let Err(e) = tg.send_alert_html(&msg).await {
                    warn!("failed to send advisory ignored alert: {e:#}");
                }
            }
            crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                info!(
                    advisory_id = %advisory.advisory_id,
                    "advisory ignored notification deferred to daily briefing"
                );
            }
            crate::notification_gate::NotificationVerdict::Drop => {}
        }
    }

    // Remove the matched entry from cache (consumed)
    if let Ok(mut cache) = advisory_cache.write() {
        cache.retain(|e| e.advisory_id != advisory.advisory_id);
    }
}

fn check_advisory_match(
    cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
    incident: &innerwarden_core::incident::Incident,
) -> Option<AdvisoryEntry> {
    // Extract command from incident evidence (array of evidence objects)
    let command = incident
        .evidence
        .as_array()?
        .iter()
        .find_map(|e| e.get("command").and_then(|c| c.as_str()))?;

    let command_hash = innerwarden_core::audit::sha256_hex(&command.to_lowercase());

    let cache = cache.read().ok()?;
    cache
        .iter()
        .find(|e| e.command_hash == command_hash)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn advisory_entry(id: &str, command: &str) -> AdvisoryEntry {
        AdvisoryEntry {
            advisory_id: id.to_string(),
            command_hash: innerwarden_core::audit::sha256_hex(&command.to_lowercase()),
            command_preview: command.to_string(),
            risk_score: 87,
            recommendation: "blocked".to_string(),
            signals: vec!["dangerous-command".to_string()],
            ts: Utc::now(),
        }
    }

    #[tokio::test]
    async fn handle_advisory_violation_consumes_matching_advisory_entry() {
        // Invariant: a matching advisory must be consumed exactly once after a tagged incident.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let command = "rm -rf /tmp/suspicious";
        let cache = Arc::new(RwLock::new(VecDeque::from([advisory_entry(
            "adv-1", command,
        )])));
        let mut incident = crate::tests::test_incident("203.0.113.21");
        incident.tags = vec!["execution".to_string()];
        incident.evidence = serde_json::json!([{ "command": command }]);

        handle_advisory_violation(&incident, &cache, &state).await;

        let remaining = cache.read().expect("cache read lock");
        assert!(remaining.is_empty());
    }

    #[tokio::test]
    async fn handle_advisory_violation_skips_when_trigger_tags_are_absent() {
        // Invariant: incidents without `execution`/`suspicious` tags must not touch advisory cache.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cache = Arc::new(RwLock::new(VecDeque::from([advisory_entry(
            "adv-2",
            "cat /etc/shadow",
        )])));
        let mut incident = crate::tests::test_incident("203.0.113.22");
        incident.tags = vec!["ssh".to_string()];
        incident.evidence = serde_json::json!([{ "command": "cat /etc/shadow" }]);

        handle_advisory_violation(&incident, &cache, &state).await;

        let remaining = cache.read().expect("cache read lock");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].advisory_id, "adv-2");
    }

    #[tokio::test]
    async fn handle_advisory_violation_keeps_cache_when_no_advisory_match_exists() {
        // Invariant: upstream `None` matches must be a no-op and leave advisory entries intact.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cache = Arc::new(RwLock::new(VecDeque::from([advisory_entry(
            "adv-3", "whoami",
        )])));
        let mut incident = crate::tests::test_incident("203.0.113.23");
        incident.tags = vec!["execution".to_string()];
        incident.evidence = serde_json::json!([{ "command": "ls -la /tmp" }]);

        handle_advisory_violation(&incident, &cache, &state).await;

        let remaining = cache.read().expect("cache read lock");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].advisory_id, "adv-3");
    }

    /// Coverage anchor (test/coverage-batch-3 — 2026-05-07): when
    /// telegram_client is Some AND a matching advisory exists, the
    /// notification-gate verdict is computed and the advisory is
    /// consumed regardless of the verdict (Drop / DailyBriefingOnly /
    /// SendNow). Pins the cache-consume contract: even if the alert
    /// is suppressed by the gate, the matched entry must be removed
    /// from the cache (otherwise duplicate executions would re-fire
    /// the same advisory). The HTML send_alert call may fail because
    /// the test telegram client has no network access; that's
    /// expected — the function logs a warn and continues, the
    /// cache-consume runs unconditionally.
    #[tokio::test]
    async fn handle_advisory_violation_consumes_advisory_even_when_telegram_client_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let tg = crate::telegram::TelegramClient::new("token", "chat-id", None)
            .expect("telegram client");
        state.telegram_client = Some(Arc::new(tg));

        let command = "rm -rf /";
        let cache = Arc::new(RwLock::new(VecDeque::from([advisory_entry(
            "adv-tg", command,
        )])));
        let mut incident = crate::tests::test_incident("203.0.113.50");
        incident.tags = vec!["execution".to_string()];
        incident.evidence = serde_json::json!([{ "command": command }]);

        handle_advisory_violation(&incident, &cache, &state).await;

        let remaining = cache.read().expect("cache read lock");
        assert!(
            remaining.is_empty(),
            "matched advisory must be consumed regardless of telegram outcome"
        );
    }

    /// Coverage anchor: incidents with non-array evidence fall through
    /// to the no-match branch of `check_advisory_match`. Pins the
    /// schema-defensive Option-chain (`evidence.as_array()?`).
    #[tokio::test]
    async fn handle_advisory_violation_skips_when_evidence_is_not_array() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cache = Arc::new(RwLock::new(VecDeque::from([advisory_entry(
            "adv-shape",
            "whoami",
        )])));
        let mut incident = crate::tests::test_incident("203.0.113.51");
        incident.tags = vec!["execution".to_string()];
        // Object instead of array — `as_array()` returns None
        incident.evidence = serde_json::json!({ "command": "whoami" });

        handle_advisory_violation(&incident, &cache, &state).await;

        let remaining = cache.read().expect("cache read lock");
        assert_eq!(
            remaining.len(),
            1,
            "non-array evidence must not consume the advisory"
        );
    }
}
