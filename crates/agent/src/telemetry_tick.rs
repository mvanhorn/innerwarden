use tracing::warn;

use crate::AgentState;

/// Persist a telemetry snapshot for a loop tick and record writer failures.
pub(crate) fn write_tick_snapshot(state: &mut AgentState, tick_name: &str) {
    let snapshot = state.telemetry.snapshot(tick_name);
    let mut telemetry_write_failed = false;
    if let Some(writer) = &mut state.telemetry_writer {
        if let Err(e) = writer.write(&snapshot) {
            warn!("failed to write telemetry snapshot: {e:#}");
            telemetry_write_failed = true;
        }
    }
    if telemetry_write_failed {
        state.telemetry.observe_error("telemetry_writer");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn write_tick_snapshot_emits_snapshot_when_writer_present() {
        // Invariant: when a writer is configured, each tick must persist a telemetry snapshot.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telemetry_writer =
            Some(crate::telemetry::TelemetryWriter::new(dir.path()).expect("telemetry writer"));

        write_tick_snapshot(&mut state, "incident_tick");

        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let latest = crate::telemetry::read_latest_snapshot(dir.path(), &date)
            .expect("snapshot should be written");
        assert_eq!(latest.tick, "incident_tick");
    }

    #[test]
    fn write_tick_snapshot_no_snapshot_this_tick_when_writer_absent() {
        // Invariant: if no writer is configured, the tick must not create telemetry files or errors.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let before_errors = state.telemetry.snapshot("before").errors_by_component;

        write_tick_snapshot(&mut state, "incident_tick");

        let after_errors = state.telemetry.snapshot("after").errors_by_component;
        assert_eq!(before_errors, after_errors);
        assert_eq!(after_errors, BTreeMap::new());

        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("telemetry-{date}.jsonl"));
        assert!(!path.exists());
    }
}
