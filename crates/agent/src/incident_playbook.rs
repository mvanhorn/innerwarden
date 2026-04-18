use std::path::Path;

use tracing::{info, warn};

use crate::AgentState;

/// Evaluate playbooks for an incident and persist recent executions to JSON log.
pub(crate) fn maybe_evaluate_and_persist_playbook(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    state: &mut AgentState,
) {
    // Playbook evaluation: check if this incident triggers a playbook.
    if let Some(exec) = state.playbook_engine.evaluate(incident) {
        info!(
            playbook = %exec.playbook_id,
            incident = %exec.incident_id,
            steps = exec.steps.len(),
            "playbook triggered: {}",
            exec.playbook_name
        );

        // Persist playbook execution to JSON log.
        let log_path = data_dir.join("playbook-log.json");
        let mut log: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if let Ok(val) = serde_json::to_value(&exec) {
            log.push(val);
        }
        if log.len() > 100 {
            log = log.split_off(log.len() - 100);
        }
        let json_str = serde_json::to_string(&log).unwrap_or_default();
        // Dual-write: SQLite blob + JSON file
        if let Some(ref sq) = state.sqlite_store {
            if let Err(e) = sq.set_blob("playbook_log", &json_str) {
                warn!("failed to write playbook_log blob: {e}");
            }
        }
        let _ = std::fs::write(&log_path, json_str);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_playbook_rule(
        rules_dir: &std::path::Path,
        playbook_id: &str,
        detector: &str,
        min_severity: &str,
    ) {
        let playbooks_dir = rules_dir.join("playbooks");
        std::fs::create_dir_all(&playbooks_dir).expect("playbooks dir");
        let content = format!(
            r#"[playbook.{playbook_id}]
name = "Unit Test Playbook"
trigger = {{ detector = "{detector}", min_severity = "{min_severity}" }}
steps = [{{ action = "notify" }}]
"#
        );
        std::fs::write(playbooks_dir.join("unit.toml"), content).expect("write rule");
    }

    #[test]
    fn maybe_evaluate_and_persist_playbook_persists_log_and_sqlite_blob_on_match() {
        // Invariant: matching playbooks must be persisted to both JSON log and SQLite blob.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-enabled");
        write_playbook_rule(&rules_dir, "pb-unit", "ssh_bruteforce", "high");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let store = crate::tests::test_sqlite_store(dir.path());
        state.sqlite_store = Some(store.clone());
        let incident = crate::tests::test_incident("203.0.113.51");

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &mut state);

        let log_path = dir.path().join("playbook-log.json");
        let raw = std::fs::read_to_string(&log_path).expect("playbook log");
        let entries: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("valid json log");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["playbook_id"], "pb-unit");

        let blob = store
            .get_blob("playbook_log")
            .expect("blob read")
            .expect("blob value");
        assert!(blob.contains("\"playbook_id\":\"pb-unit\""));
    }

    #[test]
    fn maybe_evaluate_and_persist_playbook_skips_when_no_playbook_matches() {
        // Invariant: when playbook evaluation returns `None`, no persistence side effects should occur.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-disabled");
        write_playbook_rule(&rules_dir, "pb-never", "never_match", "critical");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let incident = crate::tests::test_incident("203.0.113.52");

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &mut state);

        assert!(!dir.path().join("playbook-log.json").exists());
    }

    #[test]
    fn maybe_evaluate_and_persist_playbook_recovers_from_corrupted_existing_log() {
        // Invariant: malformed on-disk playbook log must be treated as empty and replaced with valid JSON.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-recovery");
        write_playbook_rule(&rules_dir, "pb-recover", "ssh_bruteforce", "high");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let incident = crate::tests::test_incident("203.0.113.53");
        let log_path = dir.path().join("playbook-log.json");
        std::fs::write(&log_path, "{not-valid-json").expect("seed corrupted log");

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &mut state);

        let raw = std::fs::read_to_string(&log_path).expect("playbook log");
        let entries: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("valid json log");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["playbook_id"], "pb-recover");
    }
}
