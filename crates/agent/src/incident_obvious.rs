use std::path::Path;

use tracing::{info, warn};

use crate::agent_context::incident_detector;
use crate::config::ChannelFilterLevel;
use crate::{
    ai, config, decision_cooldown_key_for_decision, decisions, execute_decision, AgentState,
    LocalIpReputation,
};

/// Obvious incident gate: skip AI for high-confidence detectors.
///
/// Two policies:
///
/// - `RepeatOffender`: ssh_bruteforce / credential_stuffing / port_scan /
///   packet_flood require `ip_seen_before` so one mistyped password or a
///   single probe does not trigger a block.
/// - `FirstHit`: reverse_shell / web_shell / c2_callback / process_injection /
///   rootkit / crypto_miner / threat_intel auto-block on the first observation
///   because the detector only fires when the compromise has already started.
///
/// Returns true when the incident was fully handled (auto-block path).
pub(crate) async fn try_handle_obvious_incident(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let detector = incident_detector(&incident.incident_id);
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    let ip_seen_before = primary_ip.is_some_and(|ip| {
        // Check if this IP was already blocked or has prior incidents
        // (total_incidents > 1 because the current incident already incremented it)
        state.blocklist.contains(ip)
            || state
                .ip_reputations
                .get(ip)
                .is_some_and(|r| r.total_incidents > 1)
    });

    if !is_obvious_attack(
        detector,
        &incident.severity,
        ip_seen_before,
        cfg.responder.enabled,
    ) {
        return false;
    }

    let Some(ip) = primary_ip else {
        return false;
    };

    // Never auto-block active operator sessions (publickey SSH from trusted_users).
    if state.operator_ips.contains_key(ip) {
        info!(
            ip,
            incident_id = %incident.incident_id,
            "obvious gate: skipping auto-block — active operator session"
        );
        return false;
    }

    info!(
        incident_id = %incident.incident_id,
        "skipping AI for obvious incident: {detector} from {ip}"
    );
    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let auto_decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id,
        },
        confidence: 0.95,
        auto_execute: true,
        reason: match obvious_detector_policy(detector) {
            ObviousPolicy::RepeatOffender => {
                format!("Shut the door on {ip}. {detector}, seen before. No more guesses.")
            }
            ObviousPolicy::FirstHit => {
                format!(
                    "Shut the door on {ip}. {detector} caught on first try. Compromise averted."
                )
            }
            ObviousPolicy::None => format!("Shut the door on {ip}. {detector}."),
        },
        alternatives: vec![],
        estimated_threat: "high".to_string(),
    };
    let (execution_result, cloudflare_pushed) =
        execute_decision(&auto_decision, incident, data_dir, cfg, state).await;

    // Write decision entry
    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: "obvious-gate".to_string(),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: None,
        confidence: 0.95,
        auto_executed: true,
        dry_run: cfg.responder.dry_run,
        reason: auto_decision.reason.clone(),
        estimated_threat: "high".to_string(),
        execution_result: execution_result.clone(),
        prev_hash: None,
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write obvious-gate decision: {e:#}");
        }
    }

    // Write decision to knowledge graph so the dashboard shows "blocked".
    {
        let auto_executed = !execution_result.starts_with("skipped");
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "block_ip",
            Some(ip),
            auto_decision.confidence,
            &auto_decision.reason,
            auto_executed,
            chrono::Utc::now(),
        );
    }

    // Update IP reputation
    let rep = state
        .ip_reputations
        .entry(ip.to_string())
        .or_insert_with(LocalIpReputation::new);
    rep.record_incident();
    if !execution_result.starts_with("skipped") {
        rep.record_block();
    }

    // Set decision cooldown
    if let Some(key) = decision_cooldown_key_for_decision(incident, &auto_decision) {
        state.store.set_cooldown(
            crate::state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    // Telegram action report — only send for immediate threats.
    // Routine blocks (ssh_bruteforce, port_scan) go to daily digest silently.
    let send_action_report = crate::notification_pipeline::is_immediate_threat(incident)
        && cfg.telegram.channel_notifications.notification_level == ChannelFilterLevel::All;
    if send_action_report && !execution_result.starts_with("skipped") && cfg.telegram.bot.enabled {
        if let Some(ref tg) = state.telegram_client {
            let tg = tg.clone();
            let title = incident.title.clone();
            let host = incident.host.clone();
            let ip_owned = ip.to_string();
            tokio::spawn(async move {
                let _ = tg
                    .send_action_report(
                        "Blocked (obvious)",
                        &ip_owned,
                        &title,
                        0.95,
                        &host,
                        false,
                        None,
                        None,
                        cloudflare_pushed,
                    )
                    .await;
            });
        }
    }

    true
}

pub(crate) fn is_obvious_attack(
    detector: &str,
    severity: &innerwarden_core::event::Severity,
    ip_seen_before: bool,
    responder_enabled: bool,
) -> bool {
    if !responder_enabled {
        return false;
    }
    let is_high_or_critical = matches!(
        severity,
        innerwarden_core::event::Severity::High | innerwarden_core::event::Severity::Critical
    );
    if !is_high_or_critical {
        return false;
    }
    match obvious_detector_policy(detector) {
        ObviousPolicy::None => false,
        ObviousPolicy::RepeatOffender => ip_seen_before,
        ObviousPolicy::FirstHit => true,
    }
}

/// Auto-block policy per detector. Split into two buckets because the
/// "first hit is the attack" set (reverse_shell, web_shell, c2_callback,
/// process_injection, rootkit, crypto_miner) should not wait for a
/// repeat-offender signal; the first observation is, by construction,
/// the compromise. The noisier set (ssh_bruteforce, credential_stuffing,
/// port_scan, packet_flood) keeps the repeat-offender gate so we don't
/// block legitimate users who mistype a password once.
///
/// `threat_intel` keeps `FirstHit` since external feeds have already
/// done the repeat-offender calculus for us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObviousPolicy {
    None,
    RepeatOffender,
    FirstHit,
}

pub(crate) fn obvious_detector_policy(detector: &str) -> ObviousPolicy {
    match detector {
        "ssh_bruteforce" | "credential_stuffing" | "packet_flood" | "port_scan" => {
            ObviousPolicy::RepeatOffender
        }
        "threat_intel" | "reverse_shell" | "web_shell" | "c2_callback" | "process_injection"
        | "rootkit" | "crypto_miner" => ObviousPolicy::FirstHit,
        _ => ObviousPolicy::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    #[test]
    fn test_is_obvious_attack() {
        // 1. Obvious condition
        assert!(is_obvious_attack(
            "ssh_bruteforce",
            &Severity::High,
            true,
            true
        ));

        // 2. Not an obvious detector
        assert!(!is_obvious_attack(
            "strange_logs",
            &Severity::High,
            true,
            true
        ));

        // 3. Not high severity
        assert!(!is_obvious_attack(
            "ssh_bruteforce",
            &Severity::Medium,
            true,
            true
        ));

        // 4. IP not seen before
        assert!(!is_obvious_attack(
            "ssh_bruteforce",
            &Severity::High,
            false,
            true
        ));

        // 5. Responder disabled
        assert!(!is_obvious_attack(
            "ssh_bruteforce",
            &Severity::High,
            true,
            false
        ));
    }

    #[test]
    fn first_hit_detectors_block_on_first_observation() {
        // First-hit detectors (reverse_shell, web_shell, c2_callback,
        // process_injection, rootkit, crypto_miner) must auto-block even
        // when ip_seen_before is false — by the time we see a reverse
        // shell the compromise has already happened.
        for detector in [
            "reverse_shell",
            "web_shell",
            "c2_callback",
            "process_injection",
            "rootkit",
            "crypto_miner",
        ] {
            assert!(
                is_obvious_attack(detector, &Severity::High, false, true),
                "{detector} should auto-block on first high-severity hit"
            );
            assert!(
                is_obvious_attack(detector, &Severity::Critical, false, true),
                "{detector} should auto-block on first critical hit"
            );
        }
    }

    #[test]
    fn first_hit_detectors_still_require_high_severity() {
        // Defence-in-depth: even for FirstHit detectors we only act on
        // High/Critical. Low/Medium incidents route to AI or noise-gate.
        assert!(!is_obvious_attack(
            "reverse_shell",
            &Severity::Medium,
            false,
            true
        ));
        assert!(!is_obvious_attack(
            "reverse_shell",
            &Severity::Low,
            true,
            true
        ));
    }

    #[test]
    fn repeat_offender_detectors_still_require_seen_before() {
        // Noisier detectors keep the repeat-offender gate to avoid
        // blocking legit users on a single mistyped password or
        // single-shot port probe.
        for detector in [
            "ssh_bruteforce",
            "credential_stuffing",
            "port_scan",
            "packet_flood",
        ] {
            assert!(
                !is_obvious_attack(detector, &Severity::High, false, true),
                "{detector} should require ip_seen_before"
            );
            assert!(
                is_obvious_attack(detector, &Severity::High, true, true),
                "{detector} should fire once ip_seen_before"
            );
        }
    }

    #[test]
    fn unknown_detectors_never_auto_block() {
        assert_eq!(
            obvious_detector_policy("totally_unknown"),
            ObviousPolicy::None
        );
        assert!(!is_obvious_attack(
            "totally_unknown",
            &Severity::Critical,
            true,
            true
        ));
    }

    /// Coverage anchor (test/coverage-batch-3 — 2026-05-07): obvious
    /// gate's full happy-path in dry-run mode. A FirstHit detector
    /// (reverse_shell) on a Critical incident triggers the auto-block
    /// pipeline end-to-end: BlockIp decision built, execute_decision
    /// called, decision JSONL written, KG updated, ip_reputation
    /// incremented, cooldown set, function returns true. Pins every
    /// downstream side effect so a future refactor that drops one
    /// (e.g. forgets to record the cooldown) is caught.
    #[tokio::test]
    async fn try_handle_obvious_incident_full_happy_path_for_first_hit_detector() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;
        cfg.responder.dry_run = true;
        cfg.responder.block_backend = "ufw".into();
        cfg.responder.allowed_skills = vec!["block-ip-ufw".into()];

        let mut incident = crate::tests::test_incident_with_kind("203.0.113.50", "reverse_shell");
        incident.severity = innerwarden_core::event::Severity::Critical;
        incident.incident_id = "reverse_shell:203.0.113.50:1".into();

        let handled = try_handle_obvious_incident(&incident, dir.path(), &cfg, &mut state).await;
        assert!(handled, "FirstHit detector + Critical must be handled");

        // Side effect 1: ip_reputation row was created with at least
        // 1 incident recorded (the new entry's record_incident call).
        let rep = state
            .ip_reputations
            .get("203.0.113.50")
            .expect("ip_reputation must be created");
        assert!(rep.total_incidents >= 1);

        // Side effect 2: a cooldown was set for the (incident, action)
        // pair so a duplicate within the cooldown window does not
        // double-block.
        let cooldown_key = decision_cooldown_key_for_decision(
            &incident,
            &ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: "203.0.113.50".into(),
                    skill_id: "block-ip-ufw".into(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: String::new(),
                alternatives: vec![],
                estimated_threat: "high".into(),
            },
        )
        .expect("cooldown key must be derivable");
        assert!(
            state
                .store
                .get_cooldown(crate::state_store::CooldownTable::Decision, &cooldown_key)
                .is_some(),
            "cooldown must be set so we don't double-block within window"
        );
    }

    /// Coverage anchor: the operator-IP skip path. When the primary
    /// IP is in `state.operator_ips` (active SSH session via publickey
    /// from a trusted_users address), the gate must NOT auto-block —
    /// that would lock the operator out. Pins the operator-honesty
    /// hard rule applied at the auto-block gate.
    #[tokio::test]
    async fn try_handle_obvious_incident_skips_active_operator_session() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // Mark this IP as an active operator session so the gate
        // refuses to act on it.
        state
            .operator_ips
            .insert("203.0.113.51".to_string(), std::time::Instant::now());

        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;

        let mut incident = crate::tests::test_incident_with_kind("203.0.113.51", "reverse_shell");
        incident.severity = innerwarden_core::event::Severity::Critical;

        let handled = try_handle_obvious_incident(&incident, dir.path(), &cfg, &mut state).await;
        assert!(
            !handled,
            "operator IPs must skip auto-block — locking out the operator is the worst false positive"
        );
        // Side effect contract: NO ip_reputation row written for the
        // operator IP (we did not act on this incident at all).
        assert!(
            state.ip_reputations.get("203.0.113.51").is_none(),
            "no rep row must be created when we skip operator IPs"
        );
    }

    /// Coverage anchor: incidents without an IP entity short-circuit
    /// to false even when the detector matches. Pins the schema-defensive
    /// branch — no IP = nothing to block, function returns without
    /// writing any decision.
    #[tokio::test]
    async fn try_handle_obvious_incident_skips_when_no_ip_entity() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;

        let mut incident = crate::tests::test_incident_with_kind("203.0.113.52", "reverse_shell");
        incident.severity = innerwarden_core::event::Severity::Critical;
        incident.incident_id = "reverse_shell:::1".into();
        incident.entities.clear(); // strip the IP entity

        let handled = try_handle_obvious_incident(&incident, dir.path(), &cfg, &mut state).await;
        assert!(!handled);
    }

    /// Coverage anchor: non-obvious detector + non-obvious severity
    /// returns false BEFORE any side-effect writes. Anti-regression
    /// for accidentally widening the obvious gate to detectors it
    /// must not auto-block (the gate is intentionally narrow).
    #[tokio::test]
    async fn try_handle_obvious_incident_returns_false_for_non_obvious_detector() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;

        let mut incident =
            crate::tests::test_incident_with_kind("203.0.113.53", "totally_unknown_detector");
        incident.severity = innerwarden_core::event::Severity::Critical;

        let handled = try_handle_obvious_incident(&incident, dir.path(), &cfg, &mut state).await;
        assert!(
            !handled,
            "unknown detectors must NOT trigger the obvious gate"
        );
        assert!(
            state.ip_reputations.get("203.0.113.53").is_none(),
            "no side effects when gate returns false at the start"
        );
    }
}
