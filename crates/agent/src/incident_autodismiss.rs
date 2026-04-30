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
    const SENSOR_NSS_INIT_DETECTORS: &[&str] = &["data_exfil_ebpf"];
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
    let comm = evidence.get("comm").and_then(|v| v.as_str()).unwrap_or("");
    let sensitive_file = evidence
        .get("sensitive_file")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if sensitive_file != "/etc/passwd" {
        return false;
    }
    let comm_match = NSS_INIT_TOOL_PREFIXES
        .iter()
        .any(|prefix| comm == *prefix || comm.starts_with(prefix));
    if !comm_match {
        return false;
    }
    let dst_ip = evidence
        .get("dst_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pid = evidence.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
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
    let reason = format!(
        "Auto-dismissed: {detector} fired on {comm} reading /etc/passwd \
         then connecting to {dst_ip}. /etc/passwd is the NSS user-lookup \
         file every libc binary opens at startup; this is the \
         standard CLI startup signature, not data exfiltration. Mirrors \
         the sensor's NSS_INIT_CLI_TOOLS suppression \
         (data_exfil_ebpf.rs)."
    );
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

    #[test]
    fn autodismiss_reason_mentions_detector_and_severity() {
        // Guards explanatory reason formatting stored in decision audit entries.
        let reason = autodismiss_reason("suspicious_login", &Severity::Low);
        assert!(reason.contains("suspicious_login"));
        assert!(reason.contains("Low"));
    }
}
