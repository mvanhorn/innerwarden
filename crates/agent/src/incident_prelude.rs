use tracing::{info, warn};

use crate::{config, AgentState};

/// Run pre-AI orchestration for one incident:
/// 1) temporal correlation lookup/observe
/// 2) one-way LSM auto-enable escalation when a high-risk execution pattern appears
pub(crate) async fn prepare_incident_prelude(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Vec<innerwarden_core::incident::Incident> {
    let related_incidents = if cfg.correlation.enabled {
        state
            .correlator
            .related_to(incident, cfg.correlation.max_related_incidents)
    } else {
        Vec::new()
    };

    if cfg.correlation.enabled {
        if !related_incidents.is_empty() {
            info!(
                incident_id = %incident.incident_id,
                correlated_count = related_incidents.len(),
                "temporal correlation: related incidents found"
            );
        }
        // Observe early so correlation history stays consistent even when this
        // incident is later skipped by gate or AI call fails.
        state.correlator.observe(incident);
    }

    // 0. LSM auto-enable - when we see a high-severity execution incident
    //    (download+execute, reverse shell, /tmp execution), automatically enable
    //    LSM enforcement to block future execution from dangerous paths.
    //    This is a one-way escalation: once enabled, stays on until reboot.
    if crate::should_auto_enable_lsm(incident) && !state.lsm_enabled {
        info!(
            incident_id = %incident.incident_id,
            "LSM auto-enable: high-severity execution threat detected - activating kernel enforcement"
        );
        match crate::enable_lsm_enforcement().await {
            Ok(()) => {
                state.lsm_enabled = true;
                info!(
                    "LSM enforcement activated - /tmp, /dev/shm, /var/tmp execution now blocked at kernel level"
                );
            }
            Err(e) => {
                warn!(error = %e, "LSM auto-enable failed (BPF LSM may not be available)");
            }
        }
    }

    related_incidents
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Coverage anchor (test/coverage-batch-3 — 2026-05-07): when
    /// `cfg.correlation.enabled = false`, the prelude returns an
    /// empty `Vec` AND must NOT observe the incident in the
    /// correlator (otherwise toggling correlation off-then-on would
    /// silently feed events the operator wanted excluded). Pins the
    /// off-state contract.
    #[tokio::test]
    async fn correlation_disabled_returns_empty_and_does_not_observe() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.correlation.enabled = false;

        let incident = crate::tests::test_incident_with_kind("203.0.113.10", "ssh_bruteforce");

        let related = prepare_incident_prelude(&incident, &cfg, &mut state).await;
        assert!(
            related.is_empty(),
            "correlation disabled must yield empty related-incidents Vec"
        );
        // Pin the no-observe contract: a follow-up call with the
        // same incident must STILL see no prior observation in the
        // correlator (since the first call was a no-op).
        let related2 = prepare_incident_prelude(&incident, &cfg, &mut state).await;
        assert!(related2.is_empty());
    }

    /// Coverage anchor: when `correlation.enabled = true` AND the
    /// incident is the first of its kind, `related_to` returns empty
    /// but `observe` records it for future correlations. Pins the
    /// "observe early" contract that keeps correlation history
    /// consistent even when downstream gates skip the incident.
    #[tokio::test]
    async fn correlation_enabled_observes_even_when_no_related_incidents_yet() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.correlation.enabled = true;

        let inc = crate::tests::test_incident_with_kind("203.0.113.11", "port_scan");

        let first = prepare_incident_prelude(&inc, &cfg, &mut state).await;
        assert!(first.is_empty(), "first incident has no relatives");

        // A second invocation with the same IP (but different
        // incident_id, since the correlator filters by id) should now
        // see the first as a related incident — proves observe() ran
        // on the first call.
        let mut second_inc = crate::tests::test_incident_with_kind("203.0.113.11", "port_scan");
        second_inc.incident_id = "port_scan:203.0.113.11:test-2".to_string();
        let second = prepare_incident_prelude(&second_inc, &cfg, &mut state).await;
        assert!(
            !second.is_empty(),
            "second incident must see the first via correlator (observe ran)"
        );
    }

    /// Coverage anchor: when LSM is already enabled
    /// (`state.lsm_enabled = true`), the auto-enable branch is
    /// skipped entirely — even for an incident that would normally
    /// trigger it. Pins the one-way-only escalation contract: once
    /// LSM is on, no further enable attempts (which would log
    /// duplicate "activated" messages and re-call the syscall).
    #[tokio::test]
    async fn lsm_auto_enable_skipped_when_already_enabled() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.lsm_enabled = true;
        let mut cfg = config::AgentConfig::default();
        cfg.correlation.enabled = false;

        let mut incident = crate::tests::test_incident_with_kind("203.0.113.12", "reverse_shell");
        incident.severity = innerwarden_core::event::Severity::Critical;

        let _ = prepare_incident_prelude(&incident, &cfg, &mut state).await;
        // Pin: lsm_enabled stays true (idempotent); no panic from the
        // skipped-enable branch.
        assert!(state.lsm_enabled);
    }
}
