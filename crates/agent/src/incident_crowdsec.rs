use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::{
    ai, allowlist, attacker_intel, config, decision_cooldown_key_for_decision, decisions,
    execute_decision, state_store, AgentState,
};

/// CrowdSec gate: auto-block IPs already listed as known community threats.
/// Returns true when the incident is fully handled (auto-block path).
pub(crate) async fn try_handle_crowdsec_autoblock(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    blocked_set: &mut HashSet<String>,
) -> bool {
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());
    let Some(ip) = primary_ip else {
        return false;
    };

    let is_known_threat = state
        .crowdsec
        .as_ref()
        .is_some_and(|cs| cs.is_known_threat(&ip));
    if !is_known_threat
        || blocked_set.contains(&ip)
        || state.blocklist.contains(&ip)
        || allowlist::is_ip_allowlisted(&ip, &cfg.ai.protected_ips)
    {
        return false;
    }

    // Never auto-block active operator sessions (publickey SSH from trusted_users).
    if state.operator_ips.contains_key(&ip) {
        info!(
            ip = %ip,
            incident_id = %incident.incident_id,
            "CrowdSec auto-block skipped: active operator session"
        );
        return false;
    }

    info!(
        incident_id = %incident.incident_id,
        ip,
        "CrowdSec threat list match - auto-blocking, skipping AI"
    );

    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let auto_decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.clone(),
            skill_id,
        },
        confidence: 1.0,
        auto_execute: true,
        reason: "CrowdSec community threat list match".to_string(),
        alternatives: vec![],
        estimated_threat: "high".into(),
    };

    blocked_set.insert(ip.clone());
    state.blocklist.insert(ip.clone());

    if let Some(key) = decision_cooldown_key_for_decision(incident, &auto_decision) {
        state.store.set_cooldown(
            state_store::CooldownTable::Decision,
            &key,
            chrono::Utc::now(),
        );
    }

    let (execution_result, _cf_pushed) = if cfg.responder.enabled {
        execute_decision(&auto_decision, incident, data_dir, cfg, state).await
    } else {
        ("skipped: responder disabled".to_string(), false)
    };

    // Write decision to knowledge graph so the dashboard shows "blocked".
    {
        let auto_executed = !execution_result.starts_with("skipped");
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "block_ip",
            Some(&ip),
            auto_decision.confidence,
            &auto_decision.reason,
            auto_executed,
            chrono::Utc::now(),
        );
    }

    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::build_entry(
            &incident.incident_id,
            &incident.host,
            "crowdsec",
            &auto_decision,
            cfg.responder.dry_run,
            &execution_result,
        );
        if let Some(profile) = state.attacker_profiles.get_mut(ip.as_str()) {
            attacker_intel::observe_decision(profile, &entry);
        }
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write CrowdSec decision: {e:#}");
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn try_handle_crowdsec_autoblock_auto_blocks_known_threat_ips() {
        // Invariant: CrowdSec-known threat IPs should bypass AI and be auto-blocked once.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let ip = "203.0.113.41";
        let incident = crate::tests::test_incident(ip);
        let mut crowdsec = crate::crowdsec::CrowdSecState::new(&cfg.crowdsec);
        crowdsec.insert_known_threat_for_test(ip);
        state.crowdsec = Some(crowdsec);
        state.attacker_profiles.insert(
            ip.to_string(),
            crate::attacker_intel::new_profile(ip, incident.ts),
        );
        let mut blocked_set = HashSet::new();

        let handled = try_handle_crowdsec_autoblock(
            &incident,
            dir.path(),
            &cfg,
            &mut state,
            &mut blocked_set,
        )
        .await;

        assert!(handled);
        assert!(blocked_set.contains(ip));
        assert!(state.blocklist.contains(ip));

        let profile = state
            .attacker_profiles
            .get(ip)
            .expect("attacker profile should exist");
        assert_eq!(profile.total_decisions, 1);
        assert_eq!(profile.total_blocks, 1);

        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        let decision = crate::ai::AiDecision {
            action: crate::ai::AiAction::BlockIp {
                ip: ip.to_string(),
                skill_id,
            },
            confidence: 1.0,
            auto_execute: true,
            reason: "CrowdSec community threat list match".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        };
        let key = crate::decision_cooldown_key_for_decision(&incident, &decision)
            .expect("block decision should produce cooldown key");
        assert!(state
            .store
            .has_cooldown(crate::state_store::CooldownTable::Decision, &key));
    }

    #[tokio::test]
    async fn try_handle_crowdsec_autoblock_returns_false_when_feature_is_disabled() {
        // Invariant: when CrowdSec state is disabled (`None`), auto-block must never trigger.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let incident = crate::tests::test_incident("203.0.113.42");
        let mut blocked_set = HashSet::new();

        let handled = try_handle_crowdsec_autoblock(
            &incident,
            dir.path(),
            &cfg,
            &mut state,
            &mut blocked_set,
        )
        .await;

        assert!(!handled);
        assert!(blocked_set.is_empty());
        assert!(!state.blocklist.contains("203.0.113.42"));
    }

    #[tokio::test]
    async fn try_handle_crowdsec_autoblock_returns_false_when_upstream_has_no_threat_match() {
        // Invariant: an enabled CrowdSec adapter with no threat hit must return `false` and avoid mutations.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        state.crowdsec = Some(crate::crowdsec::CrowdSecState::new(&cfg.crowdsec));
        let incident = crate::tests::test_incident("203.0.113.43");
        let mut blocked_set = HashSet::new();

        let handled = try_handle_crowdsec_autoblock(
            &incident,
            dir.path(),
            &cfg,
            &mut state,
            &mut blocked_set,
        )
        .await;

        assert!(!handled);
        assert!(blocked_set.is_empty());
        assert!(!state.blocklist.contains("203.0.113.43"));
    }
}
