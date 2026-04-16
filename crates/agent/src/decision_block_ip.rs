use std::path::Path;

use tracing::{info, warn};

use crate::{
    abuseipdb, ai, config,
    response_lifecycle::{ResponseBackend, ResponseType},
    skills, AgentState,
};

/// Execute the layered `BlockIp` decision path (XDP + firewall + Cloudflare + AbuseIPDB report).
pub(crate) async fn execute_block_ip_decision(
    ip: &str,
    skill_id: &str,
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    // Purge stale entries BEFORE eligibility check so rate limit uses accurate count.
    let now_utc = chrono::Utc::now();
    state
        .recent_blocks
        .retain(|ts| *ts > now_utc - chrono::Duration::seconds(60));

    // Safeguard: pure eligibility checks (empty IP, operator session, rate limit).
    if let Err(reason) = check_block_eligibility(
        ip,
        &state.operator_ips,
        state.recent_blocks.len(),
        crate::MAX_BLOCKS_PER_MINUTE,
    ) {
        if reason.starts_with("skipped:") {
            info!(ip, "{}", reason);
        } else {
            warn!(ip, "{}", reason);
        }
        return (reason, false);
    }

    state.recent_blocks.push_back(now_utc);

    // Adaptive TTL: use local IP reputation to escalate block duration.
    let block_ttl_secs = {
        let total_blocks = state
            .ip_reputations
            .get(ip)
            .map(|r| r.total_blocks)
            .unwrap_or(0);
        crate::adaptive_block_ttl_secs(total_blocks)
    };

    let ctx = skills::SkillContext {
        incident: incident.clone(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        target_container: None,
        duration_secs: Some(block_ttl_secs as u64),
        host: incident.host.clone(),
        data_dir: data_dir.to_path_buf(),
        honeypot: crate::honeypot_runtime(cfg),
        ai_provider: state.ai_provider.clone(),
    };

    let mut layers_applied = Vec::new();
    let mut any_success = false;

    // Layer 1: XDP wire-speed drop (if available).
    // Prefer shield's XdpManager (unified blocklist) over standalone skill.
    let xdp_blocked = if let Some(ref mut shield) = state.shield_state {
        let reason = format!("agent:block:{}", incident.incident_id);
        match shield.xdp.add_to_blocklist(ip, &reason) {
            Ok(()) => {
                layers_applied.push("XDP");
                any_success = true;
                state
                    .xdp_block_times
                    .insert(ip.to_string(), (chrono::Utc::now(), block_ttl_secs));
                true
            }
            Err(e) => {
                warn!(ip, error = %e, "shield XDP blocklist add failed, falling back to skill");
                false
            }
        }
    } else {
        false
    };
    // Fallback: use standalone XDP skill if shield is not active.
    if !xdp_blocked {
        if let Some(xdp_skill) = state.skill_registry.get("block-ip-xdp") {
            let xdp_result = xdp_skill.execute(&ctx, cfg.responder.dry_run).await;
            if xdp_result.success {
                layers_applied.push("XDP");
                any_success = true;
                state
                    .xdp_block_times
                    .insert(ip.to_string(), (chrono::Utc::now(), block_ttl_secs));
            }
        }
    }

    // Layer 2: Firewall rule (ufw/iptables/nftables - configured backend).
    // The configured block_backend is always allowed, regardless of allowed_skills.
    let effective_id: String = if cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
        skill_id.to_string()
    } else {
        format!("block-ip-{}", cfg.responder.block_backend)
    };
    // Don't double-execute if the configured backend IS xdp.
    if effective_id != "block-ip-xdp" {
        if let Some(fw_skill) = state.skill_registry.get(&effective_id).or_else(|| {
            state
                .skill_registry
                .block_skill_for_backend(&cfg.responder.block_backend)
        }) {
            let fw_result = fw_skill.execute(&ctx, cfg.responder.dry_run).await;
            if fw_result.success {
                let backend = cfg.responder.block_backend.as_str();
                layers_applied.push(match backend {
                    "iptables" => "iptables",
                    "nftables" => "nftables",
                    _ => "ufw",
                });
                any_success = true;
            } else {
                warn!(
                    ip,
                    skill = effective_id,
                    reason = fw_result.message,
                    "firewall block skill execution failed"
                );
            }
        } else {
            warn!(
                ip,
                skill = effective_id,
                "firewall block skill not found in registry"
            );
        }
    }

    if any_success {
        state.blocklist.insert(ip.to_string());

        // Register firewall blocks in the response lifecycle for TTL-based auto-revert.
        // XDP is already tracked via xdp_block_times; the lifecycle tracks ufw/iptables/nftables
        // which previously had no auto-revert (rules persisted until reboot).
        for layer in &layers_applied {
            let backend = match *layer {
                "ufw" => Some(ResponseBackend::Ufw),
                "iptables" => Some(ResponseBackend::Iptables),
                "nftables" => Some(ResponseBackend::Nftables),
                "XDP" => Some(ResponseBackend::Xdp),
                _ => None,
            };
            if let Some(backend) = backend {
                if !state.response_lifecycle.is_tracked(ip, &backend) {
                    state.response_lifecycle.register(
                        ResponseType::BlockIp,
                        backend,
                        ip,
                        &incident.incident_id,
                        block_ttl_secs,
                        None, // TODO: store nftables handle when available
                    );
                }
            }
        }

        // Feedback loop: write blocked IP to file so the sensor can
        // skip events from this IP, reducing noise.
        crate::append_blocked_ip(data_dir, ip);

        // Layer 2.5: Mesh broadcast -- share with peer nodes.
        if let Some(ref mesh) = state.mesh {
            let detector = incident.incident_id.split(':').next().unwrap_or("unknown");
            let evidence = decision.reason.as_bytes();
            mesh.broadcast_local_block(
                ip,
                detector,
                decision.confidence,
                evidence,
                block_ttl_secs as u64,
            )
            .await;
            layers_applied.push("Mesh");
        }
    }

    // Layer 3: Cloudflare edge block.
    let mut cf_pushed = false;
    if any_success && cfg.cloudflare.enabled && cfg.cloudflare.auto_push_blocks {
        if let Some(ref cf) = state.cloudflare_client {
            let reason = format!("{}: {}", incident.incident_id, decision.reason);
            if let Some(rule_id) = cf.push_block(ip, &reason).await {
                info!(ip, rule_id, "Cloudflare edge block pushed");
                layers_applied.push("Cloudflare");
                cf_pushed = true;
            }
        }
    }

    // Layer 4: AbuseIPDB community report (delayed - 5 min grace period).
    // Reports are queued and sent after ABUSEIPDB_REPORT_DELAY_SECS to allow
    // false-positive correction before permanently marking an IP as malicious.
    if any_success && cfg.abuseipdb.enabled && cfg.abuseipdb.report_blocks {
        let detector = incident.incident_id.split(':').next().unwrap_or("unknown");
        let categories = abuseipdb::detector_to_categories(detector);
        let comment = format!(
            "InnerWarden auto-block: {} (confidence {:.0}%)",
            decision.reason,
            decision.confidence * 100.0
        );
        state.abuseipdb_report_queue.push((
            ip.to_string(),
            comment,
            categories.to_string(),
            chrono::Utc::now(),
        ));
        layers_applied.push("AbuseIPDB(queued)");
    }

    if any_success {
        let layers = layers_applied.join(" + ");
        (format!("Blocked {ip} via {layers}"), cf_pushed)
    } else {
        (format!("skipped: no block skill available for {ip}"), false)
    }
}

/// Returns true if `s` is a single IPv4/IPv6 address **or** a valid
/// CIDR (`<ip>/<prefix>`) that ufw / iptables / nftables will accept.
///
/// Must be called at every boundary where external data (configs,
/// ip-reputation cache, correlation decisions, AI output) could deliver a
/// string to the firewall skills. A single missed boundary reintroduces the
/// "zombie active response" bug where an invalid rule gets registered in
/// the lifecycle but cannot be reverted.
pub(crate) fn is_valid_block_target(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    match s.split_once('/') {
        Some((ip_part, prefix_part)) => match (
            ip_part.parse::<std::net::IpAddr>(),
            prefix_part.parse::<u8>(),
        ) {
            (Ok(std::net::IpAddr::V4(_)), Ok(p)) => p <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(p)) => p <= 128,
            _ => false,
        },
        None => s.parse::<std::net::IpAddr>().is_ok(),
    }
}

pub(crate) fn check_block_eligibility(
    ip: &str,
    operator_ips: &std::collections::HashMap<String, std::time::Instant>,
    recent_blocks_len: usize,
    max_blocks_per_min: usize,
) -> Result<(), String> {
    if ip.is_empty() {
        return Err("skipped: block decision has empty IP".to_string());
    }
    // Reject malformed targets — prevents ufw/iptables "Bad source address"
    // errors that otherwise leak into the response lifecycle as zombie
    // "active" entries that can never be reverted.
    if !is_valid_block_target(ip) {
        return Err(format!("skipped: {ip} is not a valid IP address"));
    }
    if operator_ips.contains_key(ip) {
        return Err(format!("skipped: {ip} is an active operator session"));
    }
    if recent_blocks_len >= max_blocks_per_min {
        return Err(format!(
            "rate-limited: {ip} (>{max_blocks_per_min} blocks/min)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Instant;

    #[test]
    fn test_check_block_eligibility() {
        let mut operator_ips = HashMap::new();
        operator_ips.insert("10.0.0.5".to_string(), Instant::now());

        // 1. empty ip
        assert_eq!(
            check_block_eligibility("", &operator_ips, 0, 20),
            Err("skipped: block decision has empty IP".to_string())
        );

        // 2. operator ip
        assert_eq!(
            check_block_eligibility("10.0.0.5", &operator_ips, 0, 20),
            Err("skipped: 10.0.0.5 is an active operator session".to_string())
        );

        // 3. rate limited
        assert_eq!(
            check_block_eligibility("1.2.3.4", &operator_ips, 20, 20),
            Err("rate-limited: 1.2.3.4 (>20 blocks/min)".to_string())
        );

        // 4. normal
        assert_eq!(
            check_block_eligibility("8.8.8.8", &operator_ips, 5, 20),
            Ok(())
        );

        // 5. invalid IP (octet > 255) — must reject
        assert_eq!(
            check_block_eligibility("129.950.5.0", &operator_ips, 0, 20),
            Err("skipped: 129.950.5.0 is not a valid IP address".to_string())
        );

        // 6. garbage string — must reject
        assert_eq!(
            check_block_eligibility("not-an-ip", &operator_ips, 0, 20),
            Err("skipped: not-an-ip is not a valid IP address".to_string())
        );

        // 7. valid IPv6
        assert_eq!(
            check_block_eligibility("2001:db8::1", &operator_ips, 0, 20),
            Ok(())
        );

        // 8. valid IPv4 CIDR — ufw accepts these and revert is symmetric
        assert_eq!(
            check_block_eligibility("10.0.0.0/8", &operator_ips, 0, 20),
            Ok(())
        );
        assert_eq!(
            check_block_eligibility("136.216.0.0/16", &operator_ips, 0, 20),
            Ok(())
        );
        assert_eq!(
            check_block_eligibility("192.168.1.1/32", &operator_ips, 0, 20),
            Ok(())
        );

        // 9. valid IPv6 CIDR
        assert_eq!(
            check_block_eligibility("2001:db8::/48", &operator_ips, 0, 20),
            Ok(())
        );

        // 10. CIDR with invalid IP part must fail
        assert_eq!(
            check_block_eligibility("129.950.5.0/24", &operator_ips, 0, 20),
            Err("skipped: 129.950.5.0/24 is not a valid IP address".to_string())
        );

        // 11. CIDR with out-of-range prefix must fail
        assert_eq!(
            check_block_eligibility("10.0.0.0/33", &operator_ips, 0, 20),
            Err("skipped: 10.0.0.0/33 is not a valid IP address".to_string())
        );
        assert_eq!(
            check_block_eligibility("2001:db8::/129", &operator_ips, 0, 20),
            Err("skipped: 2001:db8::/129 is not a valid IP address".to_string())
        );

        // 12. CIDR with malformed prefix
        assert_eq!(
            check_block_eligibility("10.0.0.0/abc", &operator_ips, 0, 20),
            Err("skipped: 10.0.0.0/abc is not a valid IP address".to_string())
        );
    }

    // Exhaustive validation of `is_valid_block_target` at the helper level so
    // future callers don't have to synthesize HashMap<operator_ips> just to
    // probe target parsing behaviour.
    #[test]
    fn is_valid_block_target_accepts_plain_ips() {
        assert!(is_valid_block_target("1.2.3.4"));
        assert!(is_valid_block_target("255.255.255.255"));
        assert!(is_valid_block_target("0.0.0.0"));
        assert!(is_valid_block_target("::1"));
        assert!(is_valid_block_target("2001:db8::1"));
    }

    #[test]
    fn is_valid_block_target_accepts_valid_cidrs() {
        assert!(is_valid_block_target("10.0.0.0/8"));
        assert!(is_valid_block_target("192.168.0.0/16"));
        assert!(is_valid_block_target("192.168.1.1/32"));
        assert!(is_valid_block_target("172.16.0.0/12"));
        assert!(is_valid_block_target("::/0"));
        assert!(is_valid_block_target("2001:db8::/32"));
        assert!(is_valid_block_target("fe80::/10"));
    }

    #[test]
    fn is_valid_block_target_rejects_empty_and_garbage() {
        assert!(!is_valid_block_target(""));
        assert!(!is_valid_block_target("not-an-ip"));
        assert!(!is_valid_block_target("abc"));
        assert!(!is_valid_block_target(" "));
        assert!(!is_valid_block_target("/"));
    }

    #[test]
    fn is_valid_block_target_rejects_out_of_range_octets() {
        // Exact production samples that generated the orphaned-response alerts.
        assert!(!is_valid_block_target("129.950.5.0"));
        assert!(!is_valid_block_target("129.525.8.0"));
        assert!(!is_valid_block_target("130.890.9.0"));
        assert!(!is_valid_block_target("130.932.0.0"));
        assert!(!is_valid_block_target("130.806.3.0"));
        assert!(!is_valid_block_target("130.806.1.17"));
        assert!(!is_valid_block_target("129.491.8.0"));
        assert!(!is_valid_block_target("129.952.2.0"));
        assert!(!is_valid_block_target("129.950.5.15"));
        assert!(!is_valid_block_target("129.950.5.5"));
    }

    #[test]
    fn is_valid_block_target_rejects_short_and_long_ipv4() {
        assert!(!is_valid_block_target("137.274.6"));  // 3 octets
        assert!(!is_valid_block_target("1.2.3"));
        assert!(!is_valid_block_target("1.2.3.4.5"));
    }

    #[test]
    fn is_valid_block_target_rejects_invalid_cidr() {
        assert!(!is_valid_block_target("129.950.5.0/24")); // bad IP
        assert!(!is_valid_block_target("10.0.0.0/33"));    // prefix > 32 on v4
        assert!(!is_valid_block_target("2001:db8::/129")); // prefix > 128 on v6
        assert!(!is_valid_block_target("10.0.0.0/"));      // empty prefix
        assert!(!is_valid_block_target("10.0.0.0/-1"));    // negative prefix
        assert!(!is_valid_block_target("10.0.0.0/abc"));   // non-numeric
        assert!(!is_valid_block_target("/16"));            // empty IP
    }
}
