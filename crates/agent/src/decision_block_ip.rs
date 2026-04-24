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

    // Circuit breaker: hard ceiling on auto-blocks per UTC hour. Catches
    // the CL-008 *class* of regression — any future correlation rule that
    // starts cascading against unrelated IPs trips this pause regardless
    // of signal source. Runs BEFORE per-minute rate limit and safelist so
    // the counter reflects attempts, not just survivors.
    if let Some(ref sq) = state.sqlite_store {
        if let Some(reason) = consult_circuit_breaker(
            sq.as_ref(),
            chrono::Utc::now(),
            ip,
            cfg.responder.max_blocks_per_hour,
            &cfg.responder.circuit_breaker_mode,
        ) {
            return (reason, false);
        }
    }

    // Safeguard: pure eligibility checks (empty IP, operator session, rate
    // limit) + cloud-provider / CDN safelist. Operator incident 2026-04-18:
    // `correlation:CL-008` + `repeat-offender` were auto-blocking Cloudflare
    // ranges (104.16.0.0/12, 104.26.0.0/15, 172.66.0.0/15, …) as a cascade —
    // a file read followed by any outbound connect within 60s triggered
    // CL-008, the response targeted the outbound IP, and the repeat-offender
    // loop multiplied the damage. The global guard here catches every block
    // path (correlation, repeat-offender, auto-rule, AbuseIPDB, AI triage,
    // honeypot) with a single check.
    if let Err(reason) = check_block_eligibility_with_safelist(
        ip,
        &state.operator_ips,
        state.recent_blocks.len(),
        crate::MAX_BLOCKS_PER_MINUTE,
        crate::cloud_safelist::identify_provider,
    ) {
        if reason.starts_with("skipped:") {
            info!(ip, "{}", reason);
        } else {
            warn!(ip, "{}", reason);
        }
        // Stop the repeat-offender cascade: if we ever bumped this IP's
        // reputation by mistake (pre-fix production data), wipe it so the
        // next correlation burst doesn't escalate based on stale counts.
        if reason.contains("cloud provider safelist") {
            state.ip_reputations.remove(ip);
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
        ai_provider: state.ai_router.any_llm(),
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
                // Spec 037 PR-1: runtime first (immediate protection),
                // persist second (SQLite canonical for warm-cache on
                // restart). `set_xdp_block_time` already swallows
                // errors with a `warn!` — a persistence failure
                // degrades to pre-I-02 behaviour (TTL accounting lost
                // on restart) but never derruba the block itself.
                let blocked_at = chrono::Utc::now();
                state
                    .xdp_block_times
                    .insert(ip.to_string(), (blocked_at, block_ttl_secs));
                state
                    .store
                    .set_xdp_block_time(ip, blocked_at, block_ttl_secs);
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
                // Spec 037 PR-1: same ordering as the shield path —
                // runtime first, persist second with swallowed errors.
                let blocked_at = chrono::Utc::now();
                state
                    .xdp_block_times
                    .insert(ip.to_string(), (blocked_at, block_ttl_secs));
                state
                    .store
                    .set_xdp_block_time(ip, blocked_at, block_ttl_secs);
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

/// Pure-predicate variant used by the in-tree test suite to exercise
/// eligibility rules without constructing a cloud-safelist closure. Prod
/// code routes through `check_block_eligibility_with_safelist`.
#[allow(dead_code)]
/// Consult the block-rate circuit breaker. Returns `None` when the block
/// may proceed, `Some(reason)` when it must be refused (breaker tripped,
/// already tripped this hour, or log-only mode silently counting).
///
/// Pulled out of `execute_block_ip_decision` so the decision table + all
/// four `Decision` branches are covered by plain sync unit tests below —
/// the full `execute_block_ip_decision` is async + depends on shield,
/// skills, firewall, mesh, Cloudflare, which makes direct testing of the
/// wire-in impractical.
pub(crate) fn consult_circuit_breaker(
    store: &innerwarden_store::Store,
    now: chrono::DateTime<chrono::Utc>,
    ip: &str,
    limit: u64,
    mode_label: &str,
) -> Option<String> {
    let mode = crate::circuit_breaker::Mode::from_str_or_default(mode_label);
    let decision = crate::circuit_breaker::check_and_record(store, now, limit, mode);
    match &decision {
        crate::circuit_breaker::Decision::TripAndRefuse { count, limit, hour } => {
            warn!(
                ip,
                count,
                limit,
                hour = %hour,
                mode = mode.as_label(),
                "circuit breaker tripped. Block pipeline paused until next UTC hour (or run `innerwarden system circuit-reset`)."
            );
        }
        crate::circuit_breaker::Decision::RefuseAfterTrip { count, limit, hour } => {
            info!(
                ip,
                count,
                limit,
                hour = %hour,
                "circuit breaker still tripped. Block refused silently."
            );
        }
        crate::circuit_breaker::Decision::AutoRearm { count, limit, hour } => {
            info!(
                ip,
                count,
                limit,
                hour = %hour,
                "circuit breaker auto-rearmed. New UTC hour, counters reset."
            );
        }
        crate::circuit_breaker::Decision::Allow { .. } => {}
    }
    if decision.should_block() {
        None
    } else {
        Some(format!(
            "skipped: circuit breaker tripped (blocks this hour exceed {limit})",
            limit = limit
        ))
    }
}

#[cfg(test)]
pub(crate) fn check_block_eligibility(
    ip: &str,
    operator_ips: &std::collections::HashMap<String, std::time::Instant>,
    recent_blocks_len: usize,
    max_blocks_per_min: usize,
) -> Result<(), String> {
    check_block_eligibility_with_safelist(
        ip,
        operator_ips,
        recent_blocks_len,
        max_blocks_per_min,
        |_| None,
    )
}

/// Variant that also consults a cloud-provider / CDN safelist. The safelist
/// predicate receives the candidate IP and returns `Some(provider_label)` when
/// the IP is part of a known CDN / cloud range (Cloudflare, AWS, Oracle, …);
/// in that case the block is refused outright. Keeps the base eligibility
/// check pure-testable while every production code path that routes through
/// `execute_block_ip_decision` inherits the guard.
pub(crate) fn check_block_eligibility_with_safelist<F>(
    ip: &str,
    operator_ips: &std::collections::HashMap<String, std::time::Instant>,
    recent_blocks_len: usize,
    max_blocks_per_min: usize,
    safelist_provider: F,
) -> Result<(), String>
where
    F: Fn(&str) -> Option<&'static str>,
{
    if ip.is_empty() {
        return Err("skipped: block decision has empty IP".to_string());
    }
    // Reject malformed targets — prevents ufw/iptables "Bad source address"
    // errors that otherwise leak into the response lifecycle as zombie
    // "active" entries that can never be reverted.
    if !is_valid_block_target(ip) {
        return Err(format!("skipped: {ip} is not a valid IP address"));
    }
    if let Some(provider) = safelist_provider(ip) {
        return Err(format!(
            "skipped: {ip} is in cloud provider safelist ({provider})"
        ));
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

    fn mem_store() -> innerwarden_store::Store {
        innerwarden_store::Store::open_memory().expect("memory store")
    }

    fn ts(iso: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(iso)
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn consult_circuit_breaker_allows_under_threshold() {
        let store = mem_store();
        let out =
            consult_circuit_breaker(&store, ts("2026-04-19T12:00:00Z"), "1.2.3.4", 100, "pause");
        assert!(out.is_none(), "fresh breaker must allow");
    }

    #[test]
    fn consult_circuit_breaker_refuses_after_trip_with_reason() {
        // Drive the breaker to trip then verify the next call refuses with
        // a reason the audit trail can use verbatim.
        let store = mem_store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..100 {
            let _ = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "pause");
        }
        let tripped = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "pause")
            .expect("101st attempt must trip");
        assert!(tripped.contains("circuit breaker tripped"));
        assert!(tripped.contains("100"), "reason must carry the limit");

        let silent = consult_circuit_breaker(&store, now, "5.6.7.8", 100, "pause")
            .expect("subsequent attempts stay refused");
        assert!(silent.contains("circuit breaker tripped"));
    }

    #[test]
    fn consult_circuit_breaker_log_only_never_refuses() {
        // Calibration mode: breaker counts but must NOT refuse even far
        // above the nominal threshold.
        let store = mem_store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..1000 {
            assert!(
                consult_circuit_breaker(&store, now, "1.2.3.4", 100, "log_only").is_none(),
                "log_only must always allow"
            );
        }
    }

    #[test]
    fn consult_circuit_breaker_unknown_mode_falls_back_to_pause() {
        // Garbage value in `responder.circuit_breaker_mode` must not disable
        // the breaker — `Mode::from_str_or_default` treats unknown tokens
        // as pause so the operator never ends up with a no-op breaker from
        // a typo.
        let store = mem_store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..101 {
            let _ = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "garbage-token");
        }
        let refused = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "garbage-token");
        assert!(refused.is_some(), "unknown mode must still enforce pause");
    }

    #[test]
    fn consult_circuit_breaker_auto_rearm_allows_on_hour_rollover() {
        // Trip the breaker in hour A, confirm hour B's first call allows.
        let store = mem_store();
        let hour_a = ts("2026-04-19T12:00:00Z");
        for _ in 0..101 {
            let _ = consult_circuit_breaker(&store, hour_a, "1.2.3.4", 100, "pause");
        }
        let hour_b = ts("2026-04-19T13:05:00Z");
        let after = consult_circuit_breaker(&store, hour_b, "9.9.9.9", 100, "pause");
        assert!(after.is_none(), "new hour must rearm and allow the block");
    }

    #[test]
    fn consult_circuit_breaker_dry_run_mode_refuses_after_trip() {
        // Dry-run refuses at the executor layer same as pause; the
        // audit trail (decision_writer) still runs upstream — this test
        // verifies the executor-side signal.
        let store = mem_store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..100 {
            let _ = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "dry_run");
        }
        let refused = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "dry_run");
        assert!(refused.is_some());
    }

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

    #[test]
    fn check_block_eligibility_with_safelist_refuses_cloud_ranges() {
        // Regression guard for the operator incident on 2026-04-18:
        // correlation:CL-008 + repeat-offender kept auto-blocking Cloudflare
        // CIDRs. With the safelist predicate in play every eligibility check
        // refuses a matching IP with an explanatory reason before the
        // firewall skill ever sees it.
        let operator_ips: HashMap<String, Instant> = HashMap::new();
        let safelist = |ip: &str| -> Option<&'static str> {
            if ip.starts_with("104.26.") || ip.starts_with("172.66.") {
                Some("Cloudflare")
            } else {
                None
            }
        };

        let err =
            check_block_eligibility_with_safelist("104.26.12.38", &operator_ips, 0, 20, &safelist)
                .expect_err("cloudflare IP must be refused");
        assert!(err.contains("cloud provider safelist"), "got {err}");
        assert!(err.contains("Cloudflare"), "got {err}");

        // IP outside the safelist still passes (sanity).
        assert_eq!(
            check_block_eligibility_with_safelist("198.51.100.7", &operator_ips, 0, 20, &safelist,),
            Ok(())
        );
    }

    #[test]
    fn check_block_eligibility_with_safelist_wraps_non_safelist_gates() {
        // The safelist predicate only refuses matches; empty / invalid /
        // operator / rate-limit checks must keep working exactly like the
        // pure `check_block_eligibility` variant. Using a never-match
        // predicate makes the wrapper behaviourally identical.
        let mut operator_ips: HashMap<String, Instant> = HashMap::new();
        operator_ips.insert("10.0.0.5".to_string(), Instant::now());
        let no_match = |_: &str| None;

        assert!(
            check_block_eligibility_with_safelist("", &operator_ips, 0, 20, &no_match)
                .unwrap_err()
                .contains("empty IP")
        );
        assert!(
            check_block_eligibility_with_safelist("bad-ip", &operator_ips, 0, 20, &no_match)
                .unwrap_err()
                .contains("not a valid IP")
        );
        assert!(
            check_block_eligibility_with_safelist("10.0.0.5", &operator_ips, 0, 20, &no_match)
                .unwrap_err()
                .contains("operator session")
        );
        assert!(
            check_block_eligibility_with_safelist("1.2.3.4", &operator_ips, 20, 20, &no_match)
                .unwrap_err()
                .contains("rate-limited")
        );
        assert_eq!(
            check_block_eligibility_with_safelist("8.8.8.8", &operator_ips, 0, 20, &no_match),
            Ok(())
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
        assert!(!is_valid_block_target("137.274.6")); // 3 octets
        assert!(!is_valid_block_target("1.2.3"));
        assert!(!is_valid_block_target("1.2.3.4.5"));
    }

    #[test]
    fn is_valid_block_target_rejects_invalid_cidr() {
        assert!(!is_valid_block_target("129.950.5.0/24")); // bad IP
        assert!(!is_valid_block_target("10.0.0.0/33")); // prefix > 32 on v4
        assert!(!is_valid_block_target("2001:db8::/129")); // prefix > 128 on v6
        assert!(!is_valid_block_target("10.0.0.0/")); // empty prefix
        assert!(!is_valid_block_target("10.0.0.0/-1")); // negative prefix
        assert!(!is_valid_block_target("10.0.0.0/abc")); // non-numeric
        assert!(!is_valid_block_target("/16")); // empty IP
    }
}
