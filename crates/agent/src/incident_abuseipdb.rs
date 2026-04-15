use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::{
    abuseipdb, ai, allowlist, attacker_intel, cloud_safelist, config,
    decision_cooldown_key_for_decision, decisions, execute_decision, state_store, AgentState,
};

/// AbuseIPDB gate: auto-block high-confidence malicious IPs before AI analysis.
/// Returns true when the incident is fully handled (auto-block path).
pub(crate) async fn try_handle_abuseipdb_autoblock(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    ip_reputation: Option<&abuseipdb::IpReputation>,
    blocked_set: &mut HashSet<String>,
) -> bool {
    let Some(rep) = ip_reputation else {
        return false;
    };

    let threshold = cfg.abuseipdb.auto_block_threshold;

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());
    let Some(ip) = primary_ip else {
        return false;
    };

    if let Some(reason) = is_eligible_for_abuseipdb_autoblock(
        &ip,
        rep.confidence_score,
        threshold,
        &cfg.ai.protected_ips,
        &state.operator_ips,
    ) {
        match reason {
            AbuseIpDbBlockResult::Eligible => {}
            AbuseIpDbBlockResult::BelowScoreThreshold => return false,
            AbuseIpDbBlockResult::SkipProtectedIp => {
                warn!(
                    ip = %ip,
                    incident_id = %incident.incident_id,
                    "AbuseIPDB auto-block tried to block protected IP {ip} - skipped"
                );
                return false;
            }
            AbuseIpDbBlockResult::SkipOperator => {
                info!(
                    ip = %ip,
                    incident_id = %incident.incident_id,
                    "AbuseIPDB auto-block skipped: active operator session"
                );
                return false;
            }
            AbuseIpDbBlockResult::SkipCloudSafelist => {
                let provider = cloud_safelist::identify_provider(&ip).unwrap_or("Unknown Cloud");
                warn!(
                    ip = %ip,
                    provider,
                    score = rep.confidence_score,
                    incident_id = %incident.incident_id,
                    "AbuseIPDB auto-block skipped: {ip} belongs to {provider}. \
                     Sending to AI for evaluation instead."
                );
                return false;
            }
        }
    } else {
        return false;
    }

    info!(
        incident_id = %incident.incident_id,
        ip,
        score = rep.confidence_score,
        threshold,
        "AbuseIPDB auto-block: score exceeds threshold, skipping AI"
    );

    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let auto_decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.clone(),
            skill_id,
        },
        confidence: 1.0,
        auto_execute: true,
        reason: format!(
            "AbuseIPDB auto-block: score={}/100 (threshold={})",
            rep.confidence_score, threshold
        ),
        alternatives: vec![],
        estimated_threat: "high".into(),
    };

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

    // Only mark as blocked if the execution actually succeeded.
    // Previously this was BEFORE execute_decision, so failed blocks
    // (e.g., XDP map missing) still marked the IP as "blocked",
    // causing the AI gate to skip all future detections for this IP.
    if !execution_result.starts_with("skipped") && !execution_result.starts_with("rate-limited") {
        blocked_set.insert(ip.clone());
        state.blocklist.insert(ip.clone());
    } else {
        warn!(
            ip,
            execution_result, "AbuseIPDB auto-block: execution failed, IP NOT marked as blocked"
        );
    }

    // Write decision to knowledge graph so the dashboard shows "Blocked".
    // Previously this was missing — the IP was blocked at the firewall
    // but the graph incident had decision=null, so the Threats tab showed
    // "Observing" instead of "Blocked". Observed 2026-04-12: 3 auto-blocked
    // IPs (149.56.102.185, 196.196.253.20, 103.189.235.30) appeared as
    // "Observing" despite being blocked.
    {
        let auto_executed = !execution_result.starts_with("skipped")
            && !execution_result.starts_with("rate-limited");
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
            "abuseipdb",
            &auto_decision,
            cfg.responder.dry_run,
            &execution_result,
        );
        if let Some(profile) = state.attacker_profiles.get_mut(&ip) {
            attacker_intel::observe_decision(profile, &entry);
        }
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write abuseipdb auto-block decision: {e:#}");
        }
    }

    // Telegram notification for auto-block — only for immediate threats.
    // Routine auto-blocks (ssh_bruteforce, port_scan) go to daily digest.
    if cfg.telegram.bot.enabled && crate::notification_pipeline::is_immediate_threat(incident) {
        if let Some(ref tg) = state.telegram_client {
            let tg = tg.clone();
            let ip_clone = ip.clone();
            let score = rep.confidence_score;
            let total_reports = rep.total_reports;
            let title_clone = incident.title.clone();
            let dry_run = cfg.responder.dry_run;
            let dashboard_url = if cfg.telegram.dashboard_url.is_empty() {
                None
            } else {
                Some(cfg.telegram.dashboard_url.clone())
            };
            // Resolve GeoIP synchronously (already have client ref).
            let geo = if let Some(ref gc) = state.geoip_client {
                gc.lookup(&ip).await
            } else {
                None
            };
            // Enrich attacker profile with AbuseIPDB + GeoIP.
            if let Some(profile) = state.attacker_profiles.get_mut(&ip) {
                if profile.geo.is_none() {
                    let crowdsec_listed = state
                        .crowdsec
                        .as_ref()
                        .is_some_and(|cs| cs.is_known_threat(&ip));
                    attacker_intel::enrich_identity(
                        profile,
                        geo.as_ref(),
                        Some(rep),
                        crowdsec_listed,
                    );
                }
            }
            let country = geo.as_ref().map(|g| g.country_code.clone());
            let isp = geo.as_ref().map(|g| g.isp.clone());
            tokio::spawn(async move {
                let _ = tg
                    .send_abuseipdb_autoblock(
                        &ip_clone,
                        score,
                        threshold,
                        total_reports,
                        country.as_deref(),
                        isp.as_deref(),
                        &title_clone,
                        dry_run,
                        dashboard_url.as_deref(),
                    )
                    .await;
            });
        }
    }

    true
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AbuseIpDbBlockResult {
    Eligible,
    BelowScoreThreshold,
    SkipProtectedIp,
    SkipOperator,
    SkipCloudSafelist,
}

pub(crate) fn is_eligible_for_abuseipdb_autoblock(
    ip: &str,
    score: u8,
    threshold: u8,
    protected_ips: &[String],
    operator_ips: &std::collections::HashMap<String, std::time::Instant>,
) -> Option<AbuseIpDbBlockResult> {
    if threshold == 0 || score < threshold {
        return Some(AbuseIpDbBlockResult::BelowScoreThreshold);
    }

    // Protected IP check: skip auto-block for protected ranges.
    if allowlist::is_ip_allowlisted(ip, protected_ips) {
        return Some(AbuseIpDbBlockResult::SkipProtectedIp);
    }

    // Never auto-block active operator sessions.
    if operator_ips.contains_key(ip) {
        return Some(AbuseIpDbBlockResult::SkipOperator);
    }

    if cloud_safelist::is_cloud_provider_ip(ip) {
        return Some(AbuseIpDbBlockResult::SkipCloudSafelist);
    }

    Some(AbuseIpDbBlockResult::Eligible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Test 7: Valid block scenario — score exceeds threshold
    #[test]
    fn test_eligible_when_score_exceeds_threshold() {
        let operators = HashMap::new();
        let protected: Vec<String> = vec![];
        assert_eq!(
            is_eligible_for_abuseipdb_autoblock("8.8.8.8", 100, 90, &protected, &operators),
            Some(AbuseIpDbBlockResult::Eligible)
        );
    }

    // Test 8: Below threshold — score is lower than threshold
    #[test]
    fn test_below_threshold_returns_skip() {
        let operators = HashMap::new();
        let protected: Vec<String> = vec![];
        assert_eq!(
            is_eligible_for_abuseipdb_autoblock("8.8.8.8", 50, 90, &protected, &operators),
            Some(AbuseIpDbBlockResult::BelowScoreThreshold)
        );
    }

    // Test 9: Zero threshold disables auto-blocking entirely
    #[test]
    fn test_zero_threshold_disables_autoblock() {
        let operators = HashMap::new();
        let protected: Vec<String> = vec![];
        assert_eq!(
            is_eligible_for_abuseipdb_autoblock("8.8.8.8", 100, 0, &protected, &operators),
            Some(AbuseIpDbBlockResult::BelowScoreThreshold)
        );
    }

    // Test 10: Score exactly AT threshold is still eligible
    #[test]
    fn test_score_at_threshold_boundary_is_eligible() {
        let operators = HashMap::new();
        let protected: Vec<String> = vec![];
        assert_eq!(
            is_eligible_for_abuseipdb_autoblock("1.1.1.1", 90, 90, &protected, &operators),
            Some(AbuseIpDbBlockResult::Eligible)
        );
    }

    // Test 11: Score one below threshold is NOT eligible
    #[test]
    fn test_score_one_below_threshold_not_eligible() {
        let operators = HashMap::new();
        let protected: Vec<String> = vec![];
        assert_eq!(
            is_eligible_for_abuseipdb_autoblock("1.1.1.1", 89, 90, &protected, &operators),
            Some(AbuseIpDbBlockResult::BelowScoreThreshold)
        );
    }

    // Test 12: Operator session IP is never auto-blocked
    #[test]
    fn test_operator_ip_skipped() {
        let protected: Vec<String> = vec![];
        let mut op_map = HashMap::new();
        op_map.insert("10.0.0.1".to_string(), std::time::Instant::now());
        assert_eq!(
            is_eligible_for_abuseipdb_autoblock("10.0.0.1", 100, 90, &protected, &op_map),
            Some(AbuseIpDbBlockResult::SkipOperator)
        );
    }

    // Test 13: Protected IP is skipped
    #[test]
    fn test_protected_ip_skipped() {
        let protected = vec!["1.2.3.4".to_string()];
        assert_eq!(
            is_eligible_for_abuseipdb_autoblock("1.2.3.4", 100, 90, &protected, &HashMap::new()),
            Some(AbuseIpDbBlockResult::SkipProtectedIp)
        );
    }

    // Test 14: Non-protected IP is NOT skipped
    #[test]
    fn test_non_protected_ip_eligible() {
        let protected = vec!["1.2.3.4".to_string()];
        assert_eq!(
            is_eligible_for_abuseipdb_autoblock("5.6.7.8", 100, 90, &protected, &HashMap::new()),
            Some(AbuseIpDbBlockResult::Eligible)
        );
    }
}
