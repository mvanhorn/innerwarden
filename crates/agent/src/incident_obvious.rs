use std::path::Path;

use tracing::{info, warn};

use crate::agent_context::incident_detector;
use crate::config::ChannelFilterLevel;
use crate::{
    ai, config, decision_cooldown_key_for_decision, decisions, execute_decision, AgentState,
    LocalIpReputation,
};

/// Obvious incident gate: skip AI for high-confidence detectors + known attacker IP.
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
        reason: format!("Auto-blocked: obvious {detector} from repeat offender {ip}"),
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
    let is_obvious_detector = matches!(
        detector,
        "ssh_bruteforce" | "credential_stuffing" | "packet_flood" | "port_scan" | "threat_intel"
    );
    let is_high_or_critical = matches!(
        severity,
        innerwarden_core::event::Severity::High | innerwarden_core::event::Severity::Critical
    );
    is_obvious_detector && is_high_or_critical && ip_seen_before && responder_enabled
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
}
