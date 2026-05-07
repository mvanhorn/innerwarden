use tracing::info;

use crate::{config, decisions, AgentState};

/// Auto-dismiss gate for low-severity noise when Guard mode is ON.
///
/// Called when `evaluate_pre_ai_flow` returns `SkipBelowSeverity` — the
/// incident's severity is below the AI threshold, so no AI call will be made.
/// Instead of leaving the incident without a decision (which shows as
/// "needs attention" / "monitoring" in the dashboard), write a rule-based
/// dismiss decision so every incident has a clear outcome.
///
/// Returns true when the incident was handled (dismiss decision written).
pub(crate) fn try_autodismiss_noise(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    // Only auto-dismiss when the responder is active (Guard mode ON).
    // In Watch/DryRun mode the operator wants to see everything.
    if !is_noise_gate_eligible(cfg.responder.enabled, cfg.responder.dry_run) {
        return false;
    }

    let detector = detector_from_incident_id(&incident.incident_id);

    let reason = autodismiss_reason(detector, &incident.severity);

    info!(
        incident_id = %incident.incident_id,
        detector,
        severity = ?incident.severity,
        "noise gate: auto-dismissing low-severity incident"
    );

    // Write decision entry to audit trail
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());

    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: "noise-gate".to_string(),
        action_type: "dismiss".to_string(),
        target_ip: primary_ip,
        target_user: None,
        skill_id: None,
        confidence: 1.0,
        auto_executed: true,
        dry_run: false,
        reason: reason.clone(),
        estimated_threat: "none".to_string(),
        execution_result: "dismissed".to_string(),
        prev_hash: None,
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            tracing::warn!("failed to write noise-gate decision: {e:#}");
        }
    }

    // Feed into knowledge graph so dashboard picks it up
    {
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "dismiss",
            None,
            1.0,
            &reason,
            true,
            chrono::Utc::now(),
        );
    }

    true
}

pub(crate) fn is_noise_gate_eligible(responder_enabled: bool, responder_dry_run: bool) -> bool {
    responder_enabled && !responder_dry_run
}

/// 2026-04-30: defense-in-depth for the sensor's NSS-init suppression.
///
/// PR #350 added `ssh` (and scp/sftp/rsync/git-remote) to
/// `NSS_INIT_CLI_TOOLS` in the sensor's `data_exfil_ebpf` detector so
/// `git fetch` -> ssh git@github.com (Azure 20.x) no longer fires
/// Critical FP. But the sensor binary on prod was deployed AFTER the
/// PR landed; in the gap, the old sensor kept emitting these
/// incidents. Worse: the agent's `dismiss_self_traffic_incidents`
/// only handles `kill_chain` incidents — `data_exfil_ebpf` from the
/// sensor falls through to the AI router and ends up stuck in
/// "needs attention" until the 1h orphan-recovery sweep.
///
/// This helper mirrors the sensor's NSS_INIT_CLI_TOOLS contract on
/// the agent side so even if the sensor regresses (or a different
/// detector starts emitting the same shape), the agent dismisses the
/// incident inline. Defense-in-depth, not the primary fix — the
/// primary fix is the sensor suppression.
///
/// Match conditions (ALL required):
///   1. detector prefix is one of the known sensor detectors that
///      can emit the NSS-init pattern (`data_exfil_ebpf` for now).
///   2. evidence[0].comm starts with a known operator/system tool
///      (matches `NSS_INIT_CLI_TOOLS` in
///      `crates/sensor/src/detectors/data_exfil_ebpf.rs`).
///   3. evidence[0].sensitive_file == "/etc/passwd" exactly.
///
/// /etc/passwd is world-readable and contains no secrets — only
/// `username:x:uid:gid:gecos:home:shell`. Real exfil reads
/// /etc/shadow / ~/.ssh/* / .env, none of which match this filter.
///
/// Returns true when the incident was handled (dismiss written).
pub(crate) fn try_autodismiss_sensor_self_traffic_fp(
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
) -> bool {
    // Sensor detectors that emit the NSS-init pattern. Add detector
    // prefixes here when extending the suppression to a new sensor.
    //
    // 2026-05-01: added "reverse_shell" — the eBPF reverse-shell
    // detector fires on `connect + dup2(socket, stdin/stdout)`, which
    // is bit-identical to ssh client multiplexing I/O over an SSH
    // socket. `git fetch git@github.com` therefore triggers a
    // Critical reverse_shell incident with comm=ssh / target_port=22
    // / target_ip=github.com (Azure 20.x). Same FP class as the
    // kill_chain DATA_EXFIL and data_exfil_ebpf paths.
    const SENSOR_NSS_INIT_DETECTORS: &[&str] = &["data_exfil_ebpf", "reverse_shell"];
    // Mirror of `NSS_INIT_CLI_TOOLS` in
    // `crates/sensor/src/detectors/data_exfil_ebpf.rs`. Keep this list
    // in lock-step — a tool prefix in one side but not the other
    // creates an asymmetric suppression where the agent dismisses
    // something the sensor emitted from a code path the sensor
    // believes should have been suppressed already (or vice versa).
    const NSS_INIT_TOOL_PREFIXES: &[&str] = &[
        "wget",
        "curl",
        "git",
        "git-remote",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "apt",
        "apt-get",
        "apt-check",
        "dpkg",
        "snap",
        "snapd",
        "pip",
        "pip3",
        "npm",
        "yarn",
        "cargo",
        "rustup",
        "gem",
        "composer",
        "mvn",
        "gradle",
    ];
    let detector = detector_from_incident_id(&incident.incident_id);
    if !SENSOR_NSS_INIT_DETECTORS.contains(&detector) {
        return false;
    }
    let evidence = match incident.evidence.as_array().and_then(|arr| arr.first()) {
        Some(v) => v,
        None => return false,
    };
    // 2026-05-01: prefer `source_comm` (connect-time, reliable) over
    // `comm` (fd_redirect-time, observed corrupted in prod for the
    // reverse_shell detector). Falls back to `comm` for older sensor
    // builds that don't emit source_comm yet.
    let comm = evidence
        .get("source_comm")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| evidence.get("comm").and_then(|v| v.as_str()))
        .unwrap_or("");
    let dst_ip = evidence
        .get("dst_ip")
        .or_else(|| evidence.get("target_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pid = evidence.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);

    // Detector-specific signatures. Each is a NARROW positive — wide
    // enough to catch the operator-tool FP, never wide enough to
    // dismiss a real attacker shape.
    let signature_match = match detector {
        "data_exfil_ebpf" => {
            // ssh + read("/etc/passwd") + outbound connect.
            // /etc/passwd is the NSS user-lookup file every libc
            // binary opens at startup; world-readable; no secrets.
            evidence
                .get("sensitive_file")
                .and_then(|v| v.as_str())
                .map(|f| f == "/etc/passwd")
                .unwrap_or(false)
        }
        "reverse_shell" => {
            // ssh client + connect + dup2(socket, stdin/stdout) on
            // port 22. Sensor already does this filter pre-emit
            // (PR #047 reverse_shell.rs), but a sensor that predates
            // the fix may still emit; agent dismisses defensively.
            let target_port = evidence
                .get("target_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            target_port == 22
        }
        _ => false,
    };
    if !signature_match {
        return false;
    }

    let comm_match = NSS_INIT_TOOL_PREFIXES
        .iter()
        .any(|prefix| comm == *prefix || comm.starts_with(prefix));
    if !comm_match {
        return false;
    }
    info!(
        incident_id = %incident.incident_id,
        detector,
        comm,
        dst_ip,
        pid,
        "sensor self-traffic FP: auto-dismissing NSS-init pattern \
         (defense-in-depth for sensor NSS_INIT_CLI_TOOLS suppression)"
    );
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());
    let reason = match detector {
        "data_exfil_ebpf" => format!(
            "Auto-dismissed: {detector} fired on {comm} reading /etc/passwd \
             then connecting to {dst_ip}. /etc/passwd is the NSS user-lookup \
             file every libc binary opens at startup; this is the \
             standard CLI startup signature, not data exfiltration. Mirrors \
             the sensor's NSS_INIT_CLI_TOOLS suppression \
             (data_exfil_ebpf.rs)."
        ),
        "reverse_shell" => format!(
            "Auto-dismissed: {detector} fired on {comm} (connect + \
             dup2(socket, stdin/stdout)) to {dst_ip}:22. ssh client multiplexes \
             shell I/O over the SSH socket, which is bit-identical to a \
             reverse-shell at the kernel level. Real reverse shells use \
             non-22 ports (4444, 1337, ...). Mirrors the sensor's NSS-init \
             suppression in reverse_shell.rs."
        ),
        _ => format!(
            "Auto-dismissed: {detector} fired on {comm} (NSS-init \
             operator-tool pattern). Defense-in-depth for sensor \
             NSS_INIT_CLI_TOOLS suppression."
        ),
    };
    let entry = crate::decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: "sensor-self-traffic-fp".to_string(),
        action_type: "dismiss".to_string(),
        target_ip: primary_ip,
        target_user: None,
        skill_id: None,
        confidence: 1.0,
        auto_executed: true,
        dry_run: false,
        reason: reason.clone(),
        estimated_threat: "none".to_string(),
        execution_result: "dismissed".to_string(),
        prev_hash: None,
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            tracing::warn!("failed to write sensor-self-traffic-fp dismiss: {e:#}");
            return false;
        }
    }
    {
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "dismiss",
            None,
            1.0,
            &reason,
            true,
            chrono::Utc::now(),
        );
    }
    true
}

/// Spec 043 Phase 3 (CDN-noise companion fix, 2026-05-06): the
/// sensor's `proto_anomaly` detector emits "Suspicious connection"
/// incidents on every TCP-level oddity (slow connect, weird sequence,
/// SYN flood-shape, etc). On hosts that put nginx behind Cloudflare
/// (or any cloud LB / CDN), each edge IP in the load-balancer
/// rotation produces its own incident. Operator's 2026-05-06
/// dashboard read showed 24 of 25 "needs attention" entries were
/// individual Cloudflare edge IPs from the same scanner — pure noise.
///
/// Wave 9 (PR #469) fixed the HTTP-layer attribution by trusting
/// `CF-Connecting-IP` for events that carry that header. But
/// `proto_anomaly` fires from the `tcp_stream` collector — there's
/// no HTTP header to read; we only see the raw socket peer.
///
/// Fix: at agent intake, if a `proto_anomaly` (or threat-intel
/// "known malicious IP" alike) incident's primary IP is in the
/// existing `cloud_safelist::is_cloud_provider_ip` set (CF + AWS +
/// Azure + GCP + OCI + DO + Hetzner — same helper Wave 9g et al
/// already use), auto-dismiss it. The IP is a known CDN/cloud
/// edge, not a real attacker; the LLM hadn't promoted them to
/// auto-block anyway, so the practical effect is "remove from
/// dashboard noise without losing forensic record" (the dismiss
/// decision is still in the JSONL audit trail).
///
/// Trade-off: CDN edges are theoretically reachable by a determined
/// attacker who has compromised CF / AWS infra. We accept that risk
/// because (a) such an attacker has bigger problems than us, (b)
/// proto_anomaly is a low-fidelity signal anyway (Medium severity
/// at best), (c) other detectors (kill_chain, reverse_shell,
/// data_exfil_ebpf) would still fire on the actual exploitation.
///
/// Returns true when handled (dismiss written).
pub(crate) fn try_dismiss_cdn_noise(
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
) -> bool {
    // Detector kinds known to over-fire on CDN edges. Conservative
    // list — only detectors whose entire reason for existing is
    // "weird TCP behaviour" that CDN load-balancers naturally exhibit.
    // Adding `threat_intel` here would be wrong: threat_intel feeds
    // include real malicious IPs that happen to share a CIDR with a
    // CDN, and we want those visible.
    const CDN_NOISY_DETECTORS: &[&str] = &["proto_anomaly"];
    let detector = detector_from_incident_id(&incident.incident_id);
    if !CDN_NOISY_DETECTORS.contains(&detector) {
        return false;
    }
    let primary_ip_owned = match incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone())
    {
        Some(ip) => ip,
        None => return false,
    };
    let primary_ip: &str = &primary_ip_owned;
    let provider = match crate::cloud_safelist::identify_provider(primary_ip) {
        Some(p) => p,
        None => return false,
    };

    // Spec 043 Phase 5 hardening: BEFORE auto-dismissing, check the KG
    // for OTHER detector hits on this same IP in the last 24h. The
    // initial Phase 3 fix would have suppressed proto_anomaly on ANY
    // cloud-provider edge, opening a small but real attack vector: an
    // attacker on Azure / AWS who triggers a slowloris-style proto
    // anomaly while ALSO running ssh_bruteforce / port_scan / threat
    // intel hits would have the noisy half silently dropped from the
    // dashboard, even though the IP was clearly under attack. The
    // hardening: if the IP has any non-proto_anomaly incident in the
    // last 24h, KEEP the proto_anomaly visible (don't dismiss). CDN
    // edges with pure proxy traffic never trigger other detectors so
    // they still get the suppression.
    let other_hits = match state.knowledge_graph.read() {
        Ok(kg) => crate::kg_decide_features::incidents_24h_excluding_detectors(
            &kg,
            primary_ip,
            &["proto_anomaly"],
            chrono::Utc::now(),
        ),
        Err(e) => {
            tracing::warn!(
                "cdn-noise-fp: knowledge_graph lock poisoned: {e}; skipping hardening check"
            );
            // Without history, fall through to dismiss to preserve
            // pre-hardening behaviour. Lock-poisoning is a separate
            // alarm operator should chase via watchdog metrics, not
            // a reason to spam the dashboard.
            0
        }
    };
    if other_hits > 0 {
        info!(
            incident_id = %incident.incident_id,
            ip = %primary_ip,
            provider,
            other_hits,
            "CDN-noise: NOT dismissing proto_anomaly — IP has {other_hits} \
             non-proto_anomaly incident(s) in last 24h; the proto anomaly is \
             likely the noisy half of a real attack, must stay visible"
        );
        return false;
    }

    info!(
        incident_id = %incident.incident_id,
        detector,
        ip = %primary_ip,
        provider,
        "CDN-noise FP: auto-dismissing proto_anomaly on cloud-provider edge IP \
         (Wave-9 follow-up — sensor sees raw socket peer, not the real client)"
    );
    let reason = format!(
        "Auto-dismissed: {detector} fired on {provider} edge IP {primary_ip}. \
         CDN/cloud-provider load-balancer edges naturally exhibit TCP-level \
         oddities (slow connects, sequence drift) that this detector flags. \
         Real exploitation through these edges still fires kill_chain / \
         reverse_shell / data_exfil_ebpf, which are not suppressed by this \
         path. See Wave 9 (PR #469) for the HTTP-layer companion fix."
    );
    let entry = crate::decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: "cdn-noise-fp".to_string(),
        action_type: "dismiss".to_string(),
        target_ip: Some(primary_ip_owned.clone()),
        target_user: None,
        skill_id: None,
        confidence: 1.0,
        auto_executed: true,
        dry_run: false,
        reason: reason.clone(),
        estimated_threat: "none".to_string(),
        execution_result: "dismissed".to_string(),
        prev_hash: None,
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            tracing::warn!("failed to write cdn-noise-fp dismiss: {e:#}");
            return false;
        }
    }
    {
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "dismiss",
            None,
            1.0,
            &reason,
            true,
            chrono::Utc::now(),
        );
    }
    true
}

fn detector_from_incident_id(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("")
}

fn autodismiss_reason(detector: &str, severity: &innerwarden_core::event::Severity) -> String {
    format!(
        "Low-priority {detector} ({:?}). Filed, not firing.",
        severity,
    )
}

// Integration tests for autodismiss live in main.rs test harness where
// AgentState can be constructed via triage_test_state().

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    #[test]
    fn test_is_noise_gate_eligible() {
        // Ensures the gate is active only in Guard mode (enabled and not dry-run).
        assert!(is_noise_gate_eligible(true, false));
        assert!(!is_noise_gate_eligible(false, false));
        assert!(!is_noise_gate_eligible(true, true));
        assert!(!is_noise_gate_eligible(false, true));
    }

    #[test]
    fn detector_from_incident_id_extracts_prefix_before_colon() {
        // Verifies detector extraction stays consistent for routing and audit reason text.
        assert_eq!(
            detector_from_incident_id("ssh_bruteforce:abc"),
            "ssh_bruteforce"
        );
        assert_eq!(detector_from_incident_id("single-token"), "single-token");
    }

    fn make_data_exfil_ebpf_incident(
        comm: &str,
        sensitive_file: &str,
        dst_ip: &str,
    ) -> innerwarden_core::incident::Incident {
        use chrono::Utc;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::incident::Incident;
        Incident {
            ts: Utc::now(),
            host: "test-host".into(),
            incident_id: format!(
                "data_exfil_ebpf:1234:{}",
                Utc::now().format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "Data exfiltration: {comm} read {sensitive_file} then connected to {dst_ip}:22"
            ),
            summary: "test".into(),
            evidence: serde_json::json!([{
                "kind": "data_exfil_ebpf",
                "detection": "read_then_connect",
                "comm": comm,
                "pid": 1234,
                "sensitive_file": sensitive_file,
                "file_read_ts": "2026-04-30T17:00:00Z",
                "connect_ts": "2026-04-30T17:00:00Z",
                "dst_ip": dst_ip,
                "dst_port": 22,
                "elapsed_seconds": 0,
            }]),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_matches_ssh_passwd_pattern() {
        // RC-2 follow-up (2026-04-30): defense-in-depth for the
        // sensor's NSS-init suppression. ssh + /etc/passwd + outbound
        // is the canonical FP shape. The function must short-circuit
        // and return true so the caller knows to skip AI routing.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_data_exfil_ebpf_incident("ssh", "/etc/passwd", "20.26.156.215");
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(dismissed, "ssh + /etc/passwd MUST be auto-dismissed");
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_matches_git_passwd_pattern() {
        // git invokes ssh internally for git@github.com but the
        // detector may also see comm=git for other transports.
        // Cover that path explicitly.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_data_exfil_ebpf_incident("git", "/etc/passwd", "20.26.156.215");
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(dismissed, "git + /etc/passwd MUST be auto-dismissed");
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_does_not_match_shadow() {
        // The suppression is INTENTIONALLY narrow: only /etc/passwd
        // is dismissed (NSS uid lookup, world-readable, no secrets).
        // /etc/shadow is real exfil signal — must still fire Critical
        // through the AI router.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_data_exfil_ebpf_incident("ssh", "/etc/shadow", "20.26.156.215");
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(
            !dismissed,
            "ssh + /etc/shadow must reach AI router (real exfil signal)"
        );
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_does_not_match_ssh_keys() {
        // ssh reading ~/.ssh/id_ed25519 then connecting outbound is
        // the canonical SSH-key exfil pattern. The exact-match check
        // on /etc/passwd ensures this fires.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_data_exfil_ebpf_incident("ssh", "/home/ubuntu/.ssh/id_ed25519", "8.8.8.8");
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(!dismissed, "ssh reading id_ed25519 must reach AI router");
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_does_not_match_unknown_comm() {
        // A binary whose comm is not in the NSS_INIT_TOOL_PREFIXES
        // list (e.g. an attacker's bespoke tool) reading /etc/passwd
        // before connecting out is suspicious enough to warrant the
        // AI router. We do not implicitly trust unknown binaries.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_data_exfil_ebpf_incident("badtool", "/etc/passwd", "8.8.8.8");
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(
            !dismissed,
            "unknown comm reading /etc/passwd must reach AI router"
        );
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_does_not_match_other_detector() {
        // Only sensor detectors that emit the NSS-init pattern are
        // covered. Prevent over-broad dismiss when a future detector
        // emits the same evidence shape but a different incident_id
        // prefix.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let mut inc = make_data_exfil_ebpf_incident("ssh", "/etc/passwd", "20.26.156.215");
        inc.incident_id = "credential_harvest:1234:2026-04-30T17:00Z".into();
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(
            !dismissed,
            "non-NSS-init detector must not be auto-dismissed by this filter"
        );
    }

    fn make_reverse_shell_incident(
        source_comm: Option<&str>,
        comm: &str,
        target_ip: &str,
        target_port: u64,
    ) -> innerwarden_core::incident::Incident {
        use chrono::Utc;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::incident::Incident;
        let mut ev = serde_json::json!({
            "kind": "reverse_shell",
            "pattern": "ebpf_reverse_shell",
            "detection": "ebpf_sequence",
            "comm": comm,
            "pid": 5555,
            "target_ip": target_ip,
            "target_port": target_port,
            "redirected_fd": 0,
        });
        if let Some(sc) = source_comm {
            ev["source_comm"] = serde_json::Value::String(sc.to_string());
        }
        Incident {
            ts: Utc::now(),
            host: "test-host".into(),
            incident_id: format!(
                "reverse_shell:ebpf_reverse_shell:5555:{}",
                Utc::now().format("%Y-%m-%dT%H:%MZ")
            ),
            severity: innerwarden_core::event::Severity::Critical,
            title: format!("Reverse shell via eBPF: {comm} -> {target_ip}:{target_port}"),
            summary: "test".into(),
            evidence: serde_json::Value::Array(vec![ev]),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(target_ip)],
        }
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_matches_reverse_shell_ssh_port_22() {
        // 2026-05-01 (PR #047): operator hit a Critical reverse_shell
        // FP on `git fetch git@github.com` because ssh client's
        // dup2(socket, stdin/stdout) is bit-identical to a reverse
        // shell signature at the kernel level. Agent dismisses it
        // when comm=ssh-family AND target_port=22 — defense-in-depth
        // for the sensor-side suppression added in the same PR.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_reverse_shell_incident(Some("ssh"), "ssh", "20.26.156.215", 22);
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(
            dismissed,
            "ssh + reverse_shell + port 22 MUST be auto-dismissed"
        );
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_does_not_match_reverse_shell_non_22_port() {
        // The exclusion is narrow: only port 22 (SSH). Real reverse
        // shells use 4444 / 1337 / etc. — those must reach AI router.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_reverse_shell_incident(Some("ssh"), "ssh", "10.0.0.5", 4444);
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(
            !dismissed,
            "reverse_shell on non-22 port must reach AI router (real reverse shell)"
        );
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_does_not_match_reverse_shell_unknown_comm() {
        // Unknown comm + port 22 still fires — only known operator
        // tools get the exclusion.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_reverse_shell_incident(Some("evil-tool"), "evil-tool", "10.0.0.5", 22);
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(!dismissed, "unknown comm to port 22 must reach AI router");
    }

    #[test]
    fn try_autodismiss_sensor_self_traffic_fp_prefers_source_comm_over_corrupted_comm() {
        // Prod observation 2026-05-01: the sensor's reverse_shell
        // detector emitted comm="\u{0}\u{5}" (corrupted bytes from
        // task->comm at fd_redirect time). The new `source_comm`
        // field captures comm at CONNECT time, which is reliable.
        // Agent must use source_comm preferentially.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let inc = make_reverse_shell_incident(
            Some("ssh"),
            "\u{0}\u{5}\u{ff}", // corrupted task->comm
            "20.26.156.215",
            22,
        );
        let dismissed = try_autodismiss_sensor_self_traffic_fp(&inc, &mut state);
        assert!(
            dismissed,
            "agent must use source_comm when comm is corrupted"
        );
    }

    #[test]
    fn autodismiss_reason_mentions_detector_and_severity() {
        // Guards explanatory reason formatting stored in decision audit entries.
        let reason = autodismiss_reason("suspicious_login", &Severity::Low);
        assert!(reason.contains("suspicious_login"));
        assert!(reason.contains("Low"));
    }

    // ── Spec 043 Phase 3 CDN-noise anchors (AUDIT-SPEC043-CDN-NOISE) ───
    //
    // Operator observation 2026-05-06: dashboard "needs attention" had
    // 24 of 25 entries from individual Cloudflare edge IPs (172.71.x,
    // 104.23.x, 141.101.76.x, 162.159.x). The proto_anomaly detector
    // fires per-edge because each TCP connect from a CDN load-balancer
    // looks like a fresh "Suspicious connection". Wave 9 (PR #469)
    // covered the HTTP-layer attribution but proto_anomaly fires on
    // raw TCP — no header to read. These anchors pin the network-layer
    // companion fix.

    fn make_proto_anomaly_incident(
        addr: &str,
        sev: Severity,
    ) -> innerwarden_core::incident::Incident {
        use chrono::Utc;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::incident::Incident;
        Incident {
            ts: Utc::now(),
            host: "test-host".into(),
            incident_id: format!(
                "proto_anomaly:SlowConnection:{}:{}",
                addr,
                Utc::now().format("%Y-%m-%dT%H:%MZ")
            ),
            severity: sev,
            title: format!("Protocol anomaly from {addr}"),
            summary: "test".into(),
            evidence: serde_json::json!([{}]),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(addr)],
        }
    }

    #[test]
    fn try_dismiss_cdn_noise_dismisses_cloudflare_edge() {
        // The exact prod failure shape: proto_anomaly on a Cloudflare
        // edge IP (172.71.95.141 was in the operator's dashboard read).
        // Pre-Phase-3 the agent never auto-dismissed these; they
        // accumulated in "needs attention" indefinitely.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        crate::cloud_safelist::init();
        let inc = make_proto_anomaly_incident("172.71.95.141", Severity::Medium);
        let dismissed = try_dismiss_cdn_noise(&inc, &mut state);
        assert!(
            dismissed,
            "proto_anomaly on Cloudflare edge IP MUST be auto-dismissed"
        );
    }

    #[test]
    fn try_dismiss_cdn_noise_dismisses_aws_edge() {
        // Mirror anchor for AWS — same helper covers AWS / Azure / GCP /
        // OCI / Hetzner / DO via cloud_safelist::is_cloud_provider_ip.
        // Pre-fix this would have escaped the suppression because the
        // earlier draft (rejected) only checked CLOUDFLARE_RANGES.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        crate::cloud_safelist::init();
        // 18.200.x.x is in the AWS eu-west-1 ELB range per CLOUD_PROVIDER_RANGES.
        let inc = make_proto_anomaly_incident("18.200.5.5", Severity::Medium);
        let dismissed = try_dismiss_cdn_noise(&inc, &mut state);
        assert!(
            dismissed,
            "proto_anomaly on AWS cloud-provider IP MUST be auto-dismissed"
        );
    }

    #[test]
    fn try_dismiss_cdn_noise_does_not_dismiss_real_attacker_ip() {
        // Anti-regression bound: real attacker IPs (203.0.113.x is
        // TEST-NET-3, RFC 5737, never on a CDN) MUST stay in
        // "needs attention". The whole point of the suppression is to
        // remove CDN noise without losing real attacker visibility.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        crate::cloud_safelist::init();
        let inc = make_proto_anomaly_incident("203.0.113.42", Severity::Medium);
        let dismissed = try_dismiss_cdn_noise(&inc, &mut state);
        assert!(
            !dismissed,
            "non-cloud-provider IP MUST NOT be auto-dismissed by CDN-noise filter"
        );
    }

    #[test]
    fn try_dismiss_cdn_noise_does_not_touch_other_detectors() {
        // Conservative scope: only proto_anomaly is in
        // CDN_NOISY_DETECTORS. data_exfil_ebpf / kill_chain /
        // reverse_shell on a CF edge are still real concerns —
        // those signals carry actual exploitation evidence.
        // Anti-regression for accidentally widening CDN_NOISY_DETECTORS
        // and silencing real attacks.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        crate::cloud_safelist::init();
        let inc = make_data_exfil_ebpf_incident("ssh", "/etc/shadow", "172.71.95.141");
        let dismissed = try_dismiss_cdn_noise(&inc, &mut state);
        assert!(
            !dismissed,
            "data_exfil_ebpf on a Cloudflare IP MUST still surface — \
             real exploitation through a CDN edge is still real"
        );
    }

    // ── Spec 043 Phase 5 CDN-noise hardening anchor ────────────────────
    //
    // Operator's safety question 2026-05-06: "se fosse Akamai funcionaria?
    // não podemos ficar vulneráveis a alguém nos invadir usando a Azure".
    //
    // Initial Phase 3 fix would have suppressed proto_anomaly on ANY
    // cloud-provider edge. An attacker on Azure / AWS / GCP / OCI who
    // triggers slowloris-style proto anomaly WHILE ALSO running
    // ssh_bruteforce / port_scan / threat_intel hits would have the
    // noisy half silently dismissed even though the IP was clearly
    // under attack — small but real attack vector.
    //
    // The hardening: dismiss proto_anomaly on a cloud-provider edge
    // ONLY when the IP has zero non-proto_anomaly incidents in last
    // 24h. CDN edges with pure proxy traffic stay suppressed; cloud
    // VMs running a real attack stay visible.

    fn seed_kg_with_ssh_bruteforce(
        kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
        ip: &str,
    ) {
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        use chrono::{Duration, Utc};
        let mut g = kg.write().unwrap();
        let now = Utc::now();
        let ip_id = g.add_node(Node::Ip {
            addr: ip.to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 30,
            is_tor: false,
            first_seen: now - Duration::hours(2),
            last_seen: now,
            attempted_usernames: vec![],
        });
        // One ssh_bruteforce incident in the last hour — proves attack
        // is in progress; CDN-noise dismiss MUST hold off.
        let inc_id = g.add_node(Node::Incident {
            incident_id: format!("ssh_bruteforce:{ip}:test"),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "SSH brute force".to_string(),
            summary: "test".to_string(),
            ts: now - Duration::minutes(15),
            mitre_ids: vec![],
            decision: None,
            confidence: None,
            decision_reason: None,
            decision_target: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(
            inc_id,
            ip_id,
            Relation::TriggeredBy,
            now - Duration::minutes(15),
        ));
    }

    /// Coverage anchor (test/coverage-batch-3 — 2026-05-07): when
    /// `cfg.responder.enabled = false`, `try_autodismiss_noise`
    /// short-circuits and returns false WITHOUT writing a decision
    /// or touching the knowledge graph. Pins the
    /// `is_noise_gate_eligible` early return — the operator wants
    /// to see every low-severity incident in Watch mode.
    #[test]
    fn try_autodismiss_noise_returns_false_when_responder_disabled() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = false;
        cfg.responder.dry_run = false;
        let incident = crate::tests::test_incident_with_kind("203.0.113.70", "port_scan");

        let handled = try_autodismiss_noise(&incident, &cfg, &mut state);

        assert!(!handled, "responder disabled must skip auto-dismiss");
    }

    /// Coverage anchor: when responder is enabled but in dry-run
    /// mode (Watch/DryRun), the gate is also skipped — operator
    /// asked for visibility into every incident, so noise gate
    /// stays off.
    #[test]
    fn try_autodismiss_noise_returns_false_when_dry_run() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;
        cfg.responder.dry_run = true;
        let incident = crate::tests::test_incident_with_kind("203.0.113.71", "port_scan");

        let handled = try_autodismiss_noise(&incident, &cfg, &mut state);

        assert!(!handled, "dry_run must skip auto-dismiss");
    }

    /// Coverage anchor: in Guard mode (responder enabled, not
    /// dry_run), the gate fires — `try_autodismiss_noise` returns
    /// true and walks the full body (decision-writer attempt + KG
    /// ingest_decision call) without panicking, even when the
    /// incident isn't yet a KG node (ingest_decision then no-ops on
    /// the missing-incident branch). Pins the Guard-mode happy path.
    #[test]
    fn try_autodismiss_noise_returns_true_in_guard_mode() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = true;
        cfg.responder.dry_run = false;
        let incident = crate::tests::test_incident_with_kind("203.0.113.72", "port_scan");

        let handled = try_autodismiss_noise(&incident, &cfg, &mut state);

        assert!(handled, "Guard mode must auto-dismiss low-severity noise");
    }

    #[test]
    fn try_dismiss_cdn_noise_does_not_dismiss_when_ip_has_other_recent_attack_history() {
        // The exact safety case the operator raised: an Azure / AWS /
        // CDN-edge IP that ALSO has ssh_bruteforce hits in the last 24h
        // MUST keep the proto_anomaly visible. Pre-hardening this
        // would have been silently dismissed.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(tmp.path());
        crate::cloud_safelist::init();
        // 20.x.x.x is in CLOUD_PROVIDER_RANGES (Azure).
        let attacker_ip = "20.50.100.42";
        seed_kg_with_ssh_bruteforce(&state.knowledge_graph, attacker_ip);

        let inc = make_proto_anomaly_incident(attacker_ip, Severity::Medium);
        let dismissed = try_dismiss_cdn_noise(&inc, &mut state);
        assert!(
            !dismissed,
            "proto_anomaly on Azure IP with prior ssh_bruteforce in last 24h \
             MUST NOT be auto-dismissed — operator's 2026-05-06 safety case \
             (real attacker on cloud VM)"
        );
    }
}
