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
    let rule = match matching_auto_rule(detector) {
        Some(r) => r,
        None => return false,
    };

    // Extract primary IP
    let Some(ip) = primary_incident_ip(incident) else {
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

fn matching_auto_rule(detector: &str) -> Option<&'static AutoRule> {
    AUTO_RULES.iter().find(|rule| rule.detector == detector)
}

fn primary_incident_ip(incident: &innerwarden_core::incident::Incident) -> Option<&str> {
    incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str())
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
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    fn incident(incident_id: &str, entities: Vec<EntityRef>) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: incident_id.to_string(),
            severity: Severity::High,
            title: "test incident".to_string(),
            summary: "synthetic auto-rule fixture".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities,
        }
    }

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

    #[test]
    fn matching_auto_rule_accepts_detector_prefix_from_incident_id() {
        let inc = incident(
            "ssh_bruteforce:203.0.113.10:window",
            vec![EntityRef::ip("203.0.113.10")],
        );
        let detector = incident_detector(&inc.incident_id);
        let rule = matching_auto_rule(detector).expect("ssh brute force should match");
        assert_eq!(rule.detector, "ssh_bruteforce");
        assert_eq!(rule.duration_label, "24h");
    }

    #[test]
    fn matching_auto_rule_accepts_exact_detector_id() {
        let rule = matching_auto_rule("web_scan").expect("web scan rule should exist");
        assert_eq!(rule.detector, "web_scan");
        assert_eq!(rule.duration_label, "12h");
    }

    #[test]
    fn matching_auto_rule_rejects_unknown_and_noisy_detectors() {
        assert!(matching_auto_rule("unknown_detector").is_none());
        assert!(matching_auto_rule("packet_flood").is_none());
        assert!(matching_auto_rule("packet_flood:rate_anomaly").is_none());
    }

    #[test]
    fn primary_incident_ip_returns_first_ip_entity() {
        let inc = incident(
            "port_scan:203.0.113.10",
            vec![
                EntityRef::user("root"),
                EntityRef::ip("203.0.113.10"),
                EntityRef::ip("198.51.100.7"),
            ],
        );
        assert_eq!(primary_incident_ip(&inc), Some("203.0.113.10"));
    }

    #[test]
    fn primary_incident_ip_returns_none_without_ip_entity() {
        let inc = incident(
            "port_scan:no-ip",
            vec![EntityRef::user("root"), EntityRef::service("ssh")],
        );
        assert_eq!(primary_incident_ip(&inc), None);
    }

    #[test]
    fn auto_rule_internal_ip_guard_covers_ipv4_and_ipv6_boundaries() {
        for ip in [
            "10.1.2.3",
            "172.20.1.1",
            "192.168.42.9",
            "127.0.0.1",
            "fe80::1",
            "fd00::5",
        ] {
            assert!(is_internal_ip(ip), "{ip} should be internal");
        }
        for ip in [
            "11.1.2.3",
            "172.15.255.255",
            "172.32.0.1",
            "203.0.113.10",
            "2001:db8::1",
        ] {
            assert!(
                !is_internal_ip(ip),
                "{ip} should not be treated as internal"
            );
        }
    }

    fn cfg_with_auto_rules() -> config::AgentConfig {
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;
        cfg.responder.auto_rules_enabled = true;
        cfg.responder.dry_run = true;
        cfg.responder.block_backend = "ufw".into();
        cfg.responder.allowed_skills = vec!["block-ip-ufw".into()];
        cfg
    }

    /// Coverage anchor (test/coverage-batch-3): auto-rule short-circuit
    /// when responder is disabled. Pre-fix any ssh_bruteforce incident
    /// would have written a decision row even with `responder.enabled
    /// = false`. Pins the operator opt-in contract.
    #[tokio::test]
    async fn try_handle_auto_rule_short_circuits_when_responder_disabled() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = cfg_with_auto_rules();
        cfg.responder.enabled = false;

        let inc = incident(
            "ssh_bruteforce:203.0.113.10:1",
            vec![EntityRef::ip("203.0.113.10")],
        );
        let handled = try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await;
        assert!(!handled);
    }

    /// Coverage anchor: auto-rule gated on the dedicated
    /// `auto_rules_enabled` flag — a future operator who flips
    /// `responder.enabled = true` but leaves `auto_rules_enabled =
    /// false` keeps the AI pipeline active without auto-rules.
    #[tokio::test]
    async fn try_handle_auto_rule_short_circuits_when_auto_rules_disabled() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = cfg_with_auto_rules();
        cfg.responder.auto_rules_enabled = false;

        let inc = incident(
            "ssh_bruteforce:203.0.113.10:1",
            vec![EntityRef::ip("203.0.113.10")],
        );
        let handled = try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await;
        assert!(!handled);
        assert!(state.ip_reputations.get("203.0.113.10").is_none());
    }

    /// Coverage anchor: detectors NOT in AUTO_RULES (e.g. packet_flood,
    /// reverse_shell) skip the auto-rule path even with all flags
    /// enabled. Pins that the AUTO_RULES whitelist is the single
    /// source of truth.
    #[tokio::test]
    async fn try_handle_auto_rule_returns_false_for_non_auto_rule_detector() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = cfg_with_auto_rules();

        // packet_flood is intentionally absent from AUTO_RULES.
        let inc = incident(
            "packet_flood:203.0.113.11:1",
            vec![EntityRef::ip("203.0.113.11")],
        );
        assert!(!try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await);
    }

    /// Coverage anchor: internal IPs (RFC 1918) must NEVER be
    /// auto-blocked. Pins the gate one layer up (operator-honesty:
    /// blocking the operator's own LAN IP is the worst false positive).
    #[tokio::test]
    async fn try_handle_auto_rule_skips_internal_ips() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = cfg_with_auto_rules();

        let inc = incident("ssh_bruteforce:10.0.0.5:1", vec![EntityRef::ip("10.0.0.5")]);
        assert!(!try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await);
        assert!(state.ip_reputations.get("10.0.0.5").is_none());
    }

    /// Coverage anchor: allowlisted IPs (configured trusted_ips OR
    /// dynamic_trusted_ips) skip auto-rule. Pins both lists as gates.
    #[tokio::test]
    async fn try_handle_auto_rule_skips_allowlisted_ips() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = cfg_with_auto_rules();
        cfg.allowlist.trusted_ips = vec!["203.0.113.20".into()];

        let inc = incident(
            "ssh_bruteforce:203.0.113.20:1",
            vec![EntityRef::ip("203.0.113.20")],
        );
        assert!(!try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await);

        // Also test dynamic_trusted_ips path
        let mut cfg2 = cfg_with_auto_rules();
        let _ = cfg2; // keep cfg2 untouched but cover dynamic path:
        state.dynamic_trusted_ips = vec!["203.0.113.21".into()];
        let inc2 = incident(
            "ssh_bruteforce:203.0.113.21:1",
            vec![EntityRef::ip("203.0.113.21")],
        );
        let cfg = cfg_with_auto_rules();
        assert!(!try_handle_auto_rule(&inc2, dir.path(), &cfg, &mut state).await);
    }

    /// Coverage anchor: active operator session IPs are skipped — same
    /// hard rule as obvious-incident gate. Locking out an operator is
    /// always the wrong call.
    #[tokio::test]
    async fn try_handle_auto_rule_skips_active_operator_sessions() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state
            .operator_ips
            .insert("203.0.113.22".to_string(), std::time::Instant::now());

        let cfg = cfg_with_auto_rules();
        let inc = incident(
            "ssh_bruteforce:203.0.113.22:1",
            vec![EntityRef::ip("203.0.113.22")],
        );
        assert!(!try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await);
    }

    /// Coverage anchor: full happy-path. ssh_bruteforce on a public IP
    /// with all gates passing writes a decision tagged
    /// `ai_provider="auto-rule:ssh_bruteforce"`, sets the cooldown,
    /// updates ip_reputation, and returns true. Pins the
    /// operator-visible audit-trail shape.
    #[tokio::test]
    async fn try_handle_auto_rule_happy_path_writes_decision_and_sets_cooldown() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = cfg_with_auto_rules();

        let inc = incident(
            "ssh_bruteforce:203.0.113.30:1",
            vec![EntityRef::ip("203.0.113.30")],
        );
        let handled = try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await;
        assert!(
            handled,
            "ssh_bruteforce on a public IP with all gates passing must be handled"
        );

        // Cooldown set under the auto-rule:block_ip:<ip> key.
        let cooldown_key = "auto-rule:block_ip:203.0.113.30";
        assert!(
            state
                .store
                .get_cooldown(crate::state_store::CooldownTable::Decision, cooldown_key)
                .is_some(),
            "auto-rule cooldown must be persisted"
        );

        // ip_reputation row created and incident recorded.
        let rep = state
            .ip_reputations
            .get("203.0.113.30")
            .expect("rep row must be created");
        assert!(rep.total_incidents >= 1);
    }

    /// Coverage anchor: a second auto-rule run on the same IP within
    /// the cooldown window returns false (no double-block).
    #[tokio::test]
    async fn try_handle_auto_rule_respects_cooldown_window() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = cfg_with_auto_rules();

        let inc = incident(
            "ssh_bruteforce:203.0.113.40:1",
            vec![EntityRef::ip("203.0.113.40")],
        );
        // First call sets the cooldown.
        try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await;

        // Second call within the cooldown window must return false
        // BEFORE writing another decision.
        let handled = try_handle_auto_rule(&inc, dir.path(), &cfg, &mut state).await;
        assert!(
            !handled,
            "second auto-rule fire within cooldown window must short-circuit"
        );
    }
}
