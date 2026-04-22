//! Spec 018 — Layer 1: Deterministic auto-response rules.
//!
//! These rules execute without AI, external APIs, or operator intervention.
//! They run BEFORE the noise-gate so they see ALL incidents regardless of severity.
//!
//! Invariants:
//! - Allowlist always wins (checked first)
//! - Operator IPs never blocked
//! - Internal IPs (RFC 1918) never blocked
//! - dry_run respected
//! - Cooldown per IP prevents storms

use std::path::Path;

use tracing::{info, warn};

use crate::agent_context::incident_detector;
use crate::config::ChannelFilterLevel;
use crate::{ai, allowlist, config, decisions, execute_decision, AgentState, LocalIpReputation};

/// A built-in auto-response rule definition.
struct AutoRule {
    /// Which detector triggers this rule.
    detector: &'static str,
    /// Block duration label for the reason string.
    duration_label: &'static str,
}

const AUTO_RULES: &[AutoRule] = &[
    AutoRule {
        detector: "ssh_bruteforce",
        duration_label: "24h",
    },
    AutoRule {
        detector: "credential_stuffing",
        duration_label: "24h",
    },
    // `packet_flood` is intentionally NOT in this list. The rate-anomaly
    // sub-pattern (`packet_flood:rate_anomaly`) is too prone to per-IP
    // false positives — the prod 2026-04-22 incident with IP
    // 160.119.76.50 fired a 24h block from 4 HTTP GETs to public paths
    // (`/`, `/favicon.ico`, `/robots.txt`, `/.well-known/security.txt`).
    // packet_flood incidents still flow through the normal AI pipeline
    // (and through the Layer-1 attribution gates in the detector itself);
    // they just no longer auto-block without an AI gate review.
    AutoRule {
        detector: "port_scan",
        duration_label: "12h",
    },
    AutoRule {
        detector: "web_scan",
        duration_label: "12h",
    },
];

/// Try to handle an incident via deterministic auto-response rules.
/// Returns true when the incident was fully handled (blocked or dry-run logged).
///
/// Runs BEFORE the noise-gate and AI pipeline. Does not require AI to be configured.
pub(crate) async fn try_handle_auto_rule(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    // Auto-rules must be explicitly enabled in config.
    if !cfg.responder.enabled {
        return false;
    }
    if !cfg.responder.auto_rules_enabled {
        return false;
    }

    let detector = incident_detector(&incident.incident_id);

    // Find matching rule
    let rule = match AUTO_RULES.iter().find(|r| r.detector == detector) {
        Some(r) => r,
        None => return false,
    };

    // Extract primary IP
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());

    let Some(ip) = primary_ip else {
        return false;
    };

    // Never block internal IPs (RFC 1918 + loopback)
    if is_internal_ip(ip) {
        return false;
    }

    // Allowlist always wins
    if allowlist::is_ip_allowlisted(ip, &cfg.allowlist.trusted_ips)
        || allowlist::is_ip_allowlisted(ip, &state.dynamic_trusted_ips)
    {
        info!(ip, detector, "auto-rule: skipping — IP is allowlisted");
        return false;
    }

    // Never block active operator sessions
    if state.operator_ips.contains_key(ip) {
        info!(
            ip,
            detector, "auto-rule: skipping — active operator session"
        );
        return false;
    }

    // Cooldown: don't re-block the same IP within the cooldown window
    let cooldown_key = format!("auto-rule:block_ip:{ip}");
    let cooldown_cutoff =
        chrono::Utc::now() - chrono::Duration::seconds(crate::DECISION_COOLDOWN_SECS);
    if state
        .store
        .get_cooldown(crate::state_store::CooldownTable::Decision, &cooldown_key)
        .is_some_and(|ts| ts > cooldown_cutoff)
    {
        return false;
    }

    // Rule matched — create decision
    info!(
        incident_id = %incident.incident_id,
        ip,
        detector,
        "auto-rule: {} detected from {} — blocking ({})",
        detector,
        ip,
        rule.duration_label
    );

    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let auto_decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id: skill_id.clone(),
        },
        confidence: 0.95,
        auto_execute: true,
        reason: format!(
            "Auto-blocked: {detector} from {ip} (rule-based, no AI needed, block {duration})",
            detector = detector,
            ip = ip,
            duration = rule.duration_label,
        ),
        alternatives: vec![],
        estimated_threat: "high".to_string(),
    };

    let (execution_result, cloudflare_pushed) =
        execute_decision(&auto_decision, incident, data_dir, cfg, state).await;

    // Write decision audit trail
    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: format!("auto-rule:{detector}"),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: Some(skill_id.clone()),
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
            warn!("failed to write auto-rule decision: {e:#}");
        }
    }

    // Knowledge graph
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

    // Set cooldown
    state.store.set_cooldown(
        crate::state_store::CooldownTable::Decision,
        &cooldown_key,
        chrono::Utc::now(),
    );

    // Telegram notification for immediate threats
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
                        "Blocked (auto-rule)",
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

    // Only mark as handled if execution was not skipped (or dry-run logged it)
    !execution_result.starts_with("skipped")
}

/// Check if an IP is RFC 1918 / loopback / link-local / ULA (public wrapper).
pub(crate) fn is_internal_ip_pub(ip: &str) -> bool {
    is_internal_ip(ip)
}

/// Check if an IP is RFC 1918 / loopback / link-local / ULA.
fn is_internal_ip(ip: &str) -> bool {
    use std::net::IpAddr;
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
            // 169.254.0.0/16 (link-local)
            || (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
            // fe80::/10 (link-local)
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            // fc00::/7 (ULA)
            || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_ip_detection() {
        // RFC 1918
        assert!(is_internal_ip("10.0.0.1"));
        assert!(is_internal_ip("192.168.1.1"));
        assert!(is_internal_ip("172.16.0.1"));
        assert!(is_internal_ip("172.31.255.255"));
        // Loopback
        assert!(is_internal_ip("127.0.0.1"));
        assert!(is_internal_ip("::1"));
        // Link-local
        assert!(is_internal_ip("169.254.1.1"));
        assert!(is_internal_ip("fe80::1"));
        // ULA
        assert!(is_internal_ip("fd00::1"));
        assert!(is_internal_ip("fc00::1"));
        // Public — must NOT match
        assert!(!is_internal_ip("8.8.8.8"));
        assert!(!is_internal_ip("185.220.101.1"));
        assert!(!is_internal_ip("172.15.0.1")); // just below 172.16/12
        assert!(!is_internal_ip("172.32.0.1")); // just above 172.31
                                                // Invalid
        assert!(!is_internal_ip("not-an-ip"));
    }

    #[test]
    fn auto_rules_cover_expected_detectors() {
        let detectors: Vec<&str> = AUTO_RULES.iter().map(|r| r.detector).collect();
        assert!(detectors.contains(&"ssh_bruteforce"));
        assert!(detectors.contains(&"credential_stuffing"));
        assert!(detectors.contains(&"port_scan"));
        assert!(detectors.contains(&"web_scan"));
    }

    #[test]
    fn auto_rules_must_not_include_packet_flood() {
        // Regression guard for the prod 2026-04-22 false positive
        // (IP 160.119.76.50): the `packet_flood:rate_anomaly` sub-pattern
        // is too noisy to auto-block without an AI gate review. The
        // detector still fires; the AI pipeline still sees it; only the
        // Layer-1 deterministic auto-block path is removed.
        let detectors: Vec<&str> = AUTO_RULES.iter().map(|r| r.detector).collect();
        assert!(
            !detectors.contains(&"packet_flood"),
            "packet_flood must not auto-block; review the AI pipeline path"
        );
    }
}
