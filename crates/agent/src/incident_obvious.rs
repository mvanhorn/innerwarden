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
}
