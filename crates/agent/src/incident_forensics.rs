use tracing::info;

use crate::AgentState;

fn capture_incident_forensics_with<
    F: FnMut(u32, &str) -> Option<crate::forensics::ForensicsReport>,
    P: FnMut(&str, &str) -> Option<crate::pcap_capture::CaptureResult>,
>(
    incident: &innerwarden_core::incident::Incident,
    mut capture_forensics: F,
    mut capture_pcap: P,
) {
    if !matches!(
        incident.severity,
        innerwarden_core::event::Severity::High | innerwarden_core::event::Severity::Critical
    ) {
        return;
    }

    if let Some(pid) = incident.evidence.get("pid").and_then(|v| v.as_u64()) {
        let pid = pid as u32;
        if let Some(report) = capture_forensics(pid, &incident.incident_id) {
            info!(
                pid = report.pid,
                incident_id = %incident.incident_id,
                exe = ?report.exe,
                "forensics: process state captured"
            );
        }
    }

    // Selective pcap capture: capture traffic for the attacker IP.
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        if let Some(result) = capture_pcap(ip, &incident.incident_id) {
            info!(
                ip = %result.ip,
                pcap = %result.pcap_path.display(),
                duration = result.duration_secs,
                "pcap: capture initiated for incident"
            );
        }
    }
}

/// Best-effort forensics capture for high-severity incidents.
/// Captures /proc state by PID and selective pcap by primary attacker IP.
pub(crate) fn maybe_capture_incident_forensics(
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
) {
    let forensics = &mut state.forensics;
    let pcap_capture = &mut state.pcap_capture;
    capture_incident_forensics_with(
        incident,
        |pid, incident_id| forensics.try_capture(pid, incident_id),
        |ip, incident_id| pcap_capture.try_capture(ip, incident_id),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::cell::Cell;
    use std::path::PathBuf;

    fn forensics_report(pid: u32, incident_id: &str) -> crate::forensics::ForensicsReport {
        crate::forensics::ForensicsReport {
            pid,
            incident_id: incident_id.to_string(),
            timestamp: Utc::now(),
            cmdline: Some("cmd".to_string()),
            exe: Some("/bin/echo".to_string()),
            cwd: Some("/tmp".to_string()),
            status: Some("Running".to_string()),
            open_fds: vec![],
            network_connections: vec![],
            memory_maps: vec![],
            env_redacted: vec![],
        }
    }

    fn pcap_result(ip: &str) -> crate::pcap_capture::CaptureResult {
        crate::pcap_capture::CaptureResult {
            pcap_path: PathBuf::from("/tmp/mock.pcap"),
            ip: ip.to_string(),
            duration_secs: 60,
        }
    }

    #[test]
    fn capture_incident_forensics_with_invokes_both_captures_on_high_severity() {
        // Invariant: high-severity incidents with PID and IP must trigger both capture adapters.
        let mut incident = crate::tests::test_incident("203.0.113.31");
        incident.evidence = serde_json::json!({ "pid": 42 });
        let forensics_calls = Cell::new(0u32);
        let pcap_calls = Cell::new(0u32);

        capture_incident_forensics_with(
            &incident,
            |pid, incident_id| {
                forensics_calls.set(forensics_calls.get() + 1);
                assert_eq!(pid, 42);
                Some(forensics_report(pid, incident_id))
            },
            |ip, _incident_id| {
                pcap_calls.set(pcap_calls.get() + 1);
                assert_eq!(ip, "203.0.113.31");
                Some(pcap_result(ip))
            },
        );

        assert_eq!(forensics_calls.get(), 1);
        assert_eq!(pcap_calls.get(), 1);
    }

    #[test]
    fn capture_incident_forensics_with_skips_when_severity_below_high() {
        // Invariant: medium/low incidents must never call forensics or pcap capture backends.
        let mut incident = crate::tests::test_incident("203.0.113.32");
        incident.severity = innerwarden_core::event::Severity::Low;
        incident.evidence = serde_json::json!({ "pid": 7 });
        let forensics_calls = Cell::new(0u32);
        let pcap_calls = Cell::new(0u32);

        capture_incident_forensics_with(
            &incident,
            |_pid, _incident_id| {
                forensics_calls.set(forensics_calls.get() + 1);
                Some(forensics_report(7, "unused"))
            },
            |_ip, _incident_id| {
                pcap_calls.set(pcap_calls.get() + 1);
                Some(pcap_result("203.0.113.32"))
            },
        );

        assert_eq!(forensics_calls.get(), 0);
        assert_eq!(pcap_calls.get(), 0);
    }

    #[test]
    fn capture_incident_forensics_with_tolerates_upstream_none_results() {
        // Invariant: upstream capture adapters returning `None` must not panic and keep flow alive.
        let mut incident = crate::tests::test_incident("203.0.113.33");
        incident.evidence = serde_json::json!({ "pid": 99999 });
        let forensics_calls = Cell::new(0u32);
        let pcap_calls = Cell::new(0u32);

        capture_incident_forensics_with(
            &incident,
            |_pid, _incident_id| {
                forensics_calls.set(forensics_calls.get() + 1);
                None
            },
            |_ip, _incident_id| {
                pcap_calls.set(pcap_calls.get() + 1);
                None
            },
        );

        assert_eq!(forensics_calls.get(), 1);
        assert_eq!(pcap_calls.get(), 1);
    }

    #[test]
    fn maybe_capture_incident_forensics_returns_early_for_low_severity_incidents() {
        // Invariant: runtime adapter wrapper should no-op when incident severity is below High.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut incident = crate::tests::test_incident("203.0.113.34");
        incident.severity = innerwarden_core::event::Severity::Low;
        incident.evidence = serde_json::json!({ "pid": std::process::id() });

        maybe_capture_incident_forensics(&incident, &mut state);
    }
}
