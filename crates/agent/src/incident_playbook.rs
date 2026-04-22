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

        // Persist playbook execution to JSON log via the shared
        // atomic-rename helper. Pre-2026-04-23 each call site had its
        // own RMW loop; a crash mid-write left dashboard readers with
        // half-written JSON. `append_with_cap` uses temp-file + rename
        // so observers see either old or new content, never a partial
        // file. Dual-write to SQLite blob preserved for back-compat.
        let log_path = data_dir.join("playbook-log.json");
        if let Err(e) = crate::capped_log::append_with_cap(&log_path, &exec, 100) {
            warn!("failed to append playbook-log: {e}");
        }
        if let Some(ref sq) = state.sqlite_store {
            // Re-read the file we just wrote so the SQLite blob always
            // mirrors the on-disk JSON exactly. Cheaper than re-doing
            // the read+merge in two places.
            if let Ok(content) = std::fs::read_to_string(&log_path) {
                if let Err(e) = sq.set_blob("playbook_log", &content) {
                    warn!("failed to write playbook_log blob: {e}");
                }
            }
        }
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
