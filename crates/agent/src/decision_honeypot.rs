use std::path::Path;

use tracing::warn;

use crate::{config, skills, AgentState};

/// Execute honeypot action, including post-session tasks and marker event write.
pub(crate) async fn execute_honeypot_decision(
    ip: &str,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    if let Some(skill) = state.skill_registry.get("honeypot") {
        let mut runtime = crate::honeypot_runtime(cfg);
        // Thread the AI provider into the runtime so llm_shell interaction works.
        let skill_ai = state.ai_router.any_llm();
        runtime.ai_provider = skill_ai.clone();
        let ctx = skills::SkillContext {
            incident: incident.clone(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: incident.host.clone(),
            data_dir: data_dir.to_path_buf(),
            honeypot: runtime.clone(),
            ai_provider: skill_ai,
        };
        let result = skill.execute(&ctx, cfg.responder.dry_run).await;
        if result.success {
            // Extract session_id from the skill result message for post-session tasks.
            let session_id =
                crate::honeypot_post_session::extract_session_id_from_message(&result.message)
                    .unwrap_or_else(|| {
                        format!("unknown-{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"))
                    });

            // Spawn post-session tasks in the background (non-blocking).
            let post_ip = ip.to_string();
            let post_session_id = session_id.clone();
            let post_data_dir = data_dir.to_path_buf();
            let post_store = state.sqlite_store.clone();
            let post_ai = state.ai_router.any_llm();
            let post_tg = state.telegram_client.clone();
            let post_gate_counter = state.telemetry.gate_suppressed_counter();
            let post_responder_enabled = cfg.responder.enabled;
            let post_dry_run = cfg.responder.dry_run;
            let post_block_backend = cfg.responder.block_backend.clone();
            let post_allowed_skills = cfg.responder.allowed_skills.clone();
            let post_blocklist_has = state.blocklist.contains(ip);
            tokio::spawn(async move {
                crate::honeypot_post_session::spawn_post_session_tasks(
                    &post_ip,
                    &post_session_id,
                    &post_data_dir,
                    post_store,
                    post_ai,
                    post_tg,
                    post_gate_counter,
                    post_responder_enabled,
                    post_dry_run,
                    &post_block_backend,
                    &post_allowed_skills,
                    post_blocklist_has,
                )
                .await;
            });

            match crate::append_honeypot_marker_event(
                data_dir,
                incident,
                ip,
                cfg.responder.dry_run,
                &runtime,
            )
            .await
            {
                Ok(path) => (
                    format!(
                        "{} | honeypot marker written to {}",
                        result.message,
                        path.display()
                    ),
                    false,
                ),
                Err(e) => {
                    state.telemetry.observe_error("honeypot_marker_writer");
                    warn!("failed to write honeypot marker event: {e:#}");
                    (
                        format!(
                            "{} | warning: failed to write honeypot marker event: {e}",
                            result.message
                        ),
                        false,
                    )
                }
            }
        } else {
            (result.message, false)
        }
    } else {
        ("skipped: honeypot skill not available".to_string(), false)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Local;
    use innerwarden_core::{event::Severity, incident::Incident};

    use super::execute_honeypot_decision;

    fn make_test_incident() -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: "honeypot:test".to_string(),
            severity: Severity::High,
            title: "Test honeypot incident".to_string(),
            summary: "fixture".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["honeypot".to_string()],
            entities: vec![],
        }
    }

    fn honeypot_events_path(data_dir: &std::path::Path) -> std::path::PathBuf {
        let today = Local::now().date_naive().format("%Y-%m-%d");
        data_dir.join(format!("events-{today}.jsonl"))
    }

    fn blank_skill_registry(state: &mut crate::AgentState) {
        // Use the public `empty()` constructor so the test exercises the
        // no-honeypot branch without reaching into `SkillRegistry`'s
        // private fields.
        state.skill_registry = crate::skills::SkillRegistry::empty();
    }

    #[tokio::test]
    async fn execute_honeypot_decision_returns_skipped_when_no_honeypot_skill() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        blank_skill_registry(&mut state);

        let cfg = crate::config::AgentConfig::default();
        let incident = make_test_incident();

        let (msg, auto_executed) =
            execute_honeypot_decision("192.0.2.1", &incident, dir.path(), &cfg, &mut state).await;

        assert_eq!(msg, "skipped: honeypot skill not available");
        assert!(!auto_executed, "auto_executed should stay false");
    }

    #[tokio::test]
    async fn execute_honeypot_decision_skipped_message_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        blank_skill_registry(&mut state);

        let cfg = crate::config::AgentConfig::default();
        let incident = make_test_incident();

        let (msg, _) =
            execute_honeypot_decision("192.0.2.2", &incident, dir.path(), &cfg, &mut state).await;

        assert!(
            msg.contains("honeypot skill not available"),
            "expected stable skip message text, got: {msg}"
        );
    }

    #[tokio::test]
    async fn execute_honeypot_decision_auto_executed_is_false_on_early_return() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        blank_skill_registry(&mut state);

        let cfg = crate::config::AgentConfig::default();
        let incident = make_test_incident();

        let (_, auto_executed) =
            execute_honeypot_decision("192.0.2.3", &incident, dir.path(), &cfg, &mut state).await;

        assert!(!auto_executed);
    }

    #[tokio::test]
    async fn execute_honeypot_decision_writes_one_marker_for_listener_dry_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        let mut cfg = crate::config::AgentConfig::default();
        cfg.responder.dry_run = true;
        cfg.honeypot.mode = "listener".to_string();
        cfg.honeypot.duration_secs = 1;

        let incident = make_test_incident();

        let (msg, auto_executed) =
            execute_honeypot_decision("192.0.2.4", &incident, dir.path(), &cfg, &mut state).await;

        let events_path = honeypot_events_path(dir.path());
        let contents = std::fs::read_to_string(&events_path).expect("read events file");

        assert!(msg.contains("honeypot marker written to"));
        assert!(!auto_executed);
        assert_eq!(
            contents.lines().count(),
            1,
            "marker event must be written exactly once per honeypot invocation"
        );
        assert!(contents.contains("\"kind\":\"honeypot.demo_decoy_hit\""));
        assert!(contents.contains("\"incident_id\":\"honeypot:test\""));
    }

    #[tokio::test]
    async fn execute_honeypot_decision_returns_clear_error_when_listener_guard_rejects_bind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        let mut cfg = crate::config::AgentConfig::default();
        cfg.responder.dry_run = false;
        cfg.honeypot.mode = "listener".to_string();
        cfg.honeypot.bind_addr = "0.0.0.0".to_string();

        let incident = make_test_incident();

        let (msg, auto_executed) =
            execute_honeypot_decision("192.0.2.5", &incident, dir.path(), &cfg, &mut state).await;

        assert!(
            msg.contains("rejected by isolation guard"),
            "expected a clear guard rejection message, got: {msg}"
        );
        assert!(!auto_executed);
        assert!(
            !honeypot_events_path(dir.path()).exists(),
            "marker event should not be written when listener startup is rejected"
        );
    }
}
