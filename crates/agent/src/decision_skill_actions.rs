use std::path::Path;

use crate::{ai, config, skills, AgentState};

/// Execute simple skill-backed AI actions.
/// Returns `Some(result)` when the action is handled here; `None` otherwise.
pub(crate) async fn execute_simple_action(
    action: &ai::AiAction,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Option<(String, bool)> {
    match action {
        ai::AiAction::Monitor { ip } => {
            if let Some(skill) = state.skill_registry.get("monitor-ip") {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    target_container: None,
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_router.any_llm(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some(("skipped: monitor-ip skill not available".to_string(), false))
            }
        }
        ai::AiAction::SuspendUserSudo {
            user,
            duration_secs,
        } => {
            let skill_id = "suspend-user-sudo";
            if let Err(msg) = check_skill_allowed(skill_id, &cfg.responder.allowed_skills) {
                return Some((msg, false));
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    target_container: None,
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_router.any_llm(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some((
                    "skipped: suspend-user-sudo skill not available".to_string(),
                    false,
                ))
            }
        }
        ai::AiAction::KillProcess {
            user,
            duration_secs,
        } => {
            let skill_id = "kill-process";
            if let Err(msg) = check_skill_allowed(skill_id, &cfg.responder.allowed_skills) {
                return Some((msg, false));
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: Some(user.clone()),
                    target_container: None,
                    duration_secs: Some(*duration_secs),
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_router.any_llm(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some((
                    "skipped: kill-process skill not available".to_string(),
                    false,
                ))
            }
        }
        ai::AiAction::BlockContainer {
            container_id,
            action: _,
        } => {
            let skill_id = "block-container";
            if let Err(msg) = check_skill_allowed(skill_id, &cfg.responder.allowed_skills) {
                return Some((msg, false));
            }
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: None,
                    target_container: Some(container_id.clone()),
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_router.any_llm(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some((
                    "skipped: block-container skill not available".to_string(),
                    false,
                ))
            }
        }
        ai::AiAction::KillChainResponse { .. } => {
            let skill_id = "kill-chain-response";
            if let Some(skill) = state.skill_registry.get(skill_id) {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: None,
                    target_user: None,
                    target_container: None,
                    duration_secs: None,
                    host: incident.host.clone(),
                    data_dir: data_dir.to_path_buf(),
                    honeypot: crate::honeypot_runtime(cfg),
                    ai_provider: state.ai_router.any_llm(),
                };
                Some((
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                ))
            } else {
                Some((
                    "skipped: kill-chain-response skill not available".to_string(),
                    false,
                ))
            }
        }
        ai::AiAction::Ignore { reason } => Some((format!("ignored: {reason}"), false)),
        ai::AiAction::Dismiss { reason } => Some((format!("dismissed: {reason}"), false)),
        _ => None,
    }
}

pub(crate) fn check_skill_allowed(skill_id: &str, allowed_skills: &[String]) -> Result<(), String> {
    if allowed_skills.iter().any(|id| id == skill_id) {
        Ok(())
    } else {
        Err(format!("skipped: skill '{skill_id}' not in allowed_skills"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_check_skill_allowed() {
        let allowed = vec!["suspend-user-sudo".to_string(), "block-ip".to_string()];

        assert_eq!(check_skill_allowed("suspend-user-sudo", &allowed), Ok(()));

        assert_eq!(
            check_skill_allowed("kill-process", &allowed),
            Err("skipped: skill 'kill-process' not in allowed_skills".to_string())
        );

        let empty: Vec<String> = vec![];
        assert_eq!(
            check_skill_allowed("block-container", &empty),
            Err("skipped: skill 'block-container' not in allowed_skills".to_string())
        );
    }

    fn dry_run_cfg(allowed: &[&str]) -> config::AgentConfig {
        let mut cfg = config::AgentConfig::default();
        cfg.responder.dry_run = true;
        cfg.responder.allowed_skills = allowed.iter().map(|s| s.to_string()).collect();
        cfg
    }

    fn incident_for(ip: &str) -> innerwarden_core::incident::Incident {
        crate::tests::test_incident(ip)
    }

    /// Coverage anchor (test/coverage-batch-3): Ignore action returns
    /// formatted "ignored: <reason>". Pure pass-through; pins the
    /// operator-visible audit reason verbatim.
    #[tokio::test]
    async fn ignore_action_returns_formatted_reason() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = dry_run_cfg(&[]);
        let inc = incident_for("203.0.113.10");

        let action = ai::AiAction::Ignore {
            reason: "noise floor".into(),
        };
        let out = execute_simple_action(&action, &inc, dir.path(), &cfg, &mut state).await;
        let (msg, executed) = out.expect("Ignore must be Some");
        assert_eq!(msg, "ignored: noise floor");
        assert!(!executed);
    }

    /// Coverage anchor: Dismiss action returns "dismissed: <reason>".
    /// Same shape as Ignore. Distinct match arm so a future refactor
    /// that collapses Ignore + Dismiss must update both anchors.
    #[tokio::test]
    async fn dismiss_action_returns_formatted_reason() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = dry_run_cfg(&[]);
        let inc = incident_for("203.0.113.10");

        let action = ai::AiAction::Dismiss {
            reason: "false positive".into(),
        };
        let out = execute_simple_action(&action, &inc, dir.path(), &cfg, &mut state).await;
        let (msg, _) = out.expect("Dismiss must be Some");
        assert_eq!(msg, "dismissed: false positive");
    }

    /// Coverage anchor: actions this module does NOT handle (BlockIp,
    /// Honeypot, RequestConfirmation) return None so the caller routes
    /// them through their dedicated path. Anti-regression for
    /// accidentally widening this match.
    #[tokio::test]
    async fn unhandled_actions_return_none() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = dry_run_cfg(&[]);
        let inc = incident_for("203.0.113.10");

        let block_ip = ai::AiAction::BlockIp {
            ip: "203.0.113.10".into(),
            skill_id: "block-ip-ufw".into(),
        };
        assert!(
            execute_simple_action(&block_ip, &inc, dir.path(), &cfg, &mut state)
                .await
                .is_none()
        );

        let honeypot = ai::AiAction::Honeypot {
            ip: "203.0.113.10".into(),
        };
        assert!(
            execute_simple_action(&honeypot, &inc, dir.path(), &cfg, &mut state)
                .await
                .is_none()
        );

        let req = ai::AiAction::RequestConfirmation {
            summary: "needs review".into(),
        };
        assert!(
            execute_simple_action(&req, &inc, dir.path(), &cfg, &mut state)
                .await
                .is_none()
        );
    }

    /// Coverage anchor: SuspendUserSudo with skill NOT in
    /// allowed_skills returns the operator-facing skipped reason
    /// before touching the registry. Pins the order: allowed-list
    /// gate runs first (faster, no registry lookup), and the message
    /// format includes the skill_id verbatim so operators can grep
    /// for it.
    #[tokio::test]
    async fn suspend_user_sudo_blocks_when_not_in_allowed_skills() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = dry_run_cfg(&[]); // empty allowed list
        let inc = incident_for("203.0.113.10");

        let action = ai::AiAction::SuspendUserSudo {
            user: "attacker".into(),
            duration_secs: 300,
        };
        let (msg, executed) = execute_simple_action(&action, &inc, dir.path(), &cfg, &mut state)
            .await
            .expect("SuspendUserSudo must be Some");
        assert!(
            msg.contains("not in allowed_skills"),
            "expected allowed-list skip message, got: {msg}"
        );
        assert!(msg.contains("suspend-user-sudo"));
        assert!(!executed);
    }

    /// Coverage anchor: KillProcess with skill NOT in allowed_skills
    /// returns skipped (mirror of suspend test). Pins both branches
    /// of the action-specific allowed-list gate independently.
    #[tokio::test]
    async fn kill_process_blocks_when_not_in_allowed_skills() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = dry_run_cfg(&[]);
        let inc = incident_for("203.0.113.10");

        let action = ai::AiAction::KillProcess {
            user: "attacker".into(),
            duration_secs: 60,
        };
        let (msg, _) = execute_simple_action(&action, &inc, dir.path(), &cfg, &mut state)
            .await
            .expect("KillProcess must be Some");
        assert!(msg.contains("not in allowed_skills"));
        assert!(msg.contains("kill-process"));
    }

    /// Coverage anchor: BlockContainer with skill NOT in
    /// allowed_skills returns skipped. The `action` field on
    /// BlockContainer ("pause"/"stop") is intentionally ignored at
    /// this layer — the gate only cares about the skill_id.
    #[tokio::test]
    async fn block_container_blocks_when_not_in_allowed_skills() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = dry_run_cfg(&[]);
        let inc = incident_for("203.0.113.10");

        let action = ai::AiAction::BlockContainer {
            container_id: "abc123".into(),
            action: "pause".into(),
        };
        let (msg, _) = execute_simple_action(&action, &inc, dir.path(), &cfg, &mut state)
            .await
            .expect("BlockContainer must be Some");
        assert!(msg.contains("not in allowed_skills"));
        assert!(msg.contains("block-container"));
    }

    /// Coverage anchor: SuspendUserSudo with the skill in
    /// allowed_skills AND in the default registry returns Some with
    /// the skill's execute message (dry-run path; no actual sudoers
    /// edit). Pins the happy-path wiring end-to-end.
    #[tokio::test]
    async fn suspend_user_sudo_executes_in_dry_run_when_allowed_and_registered() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = dry_run_cfg(&["suspend-user-sudo"]);
        let inc = incident_for("203.0.113.10");

        let action = ai::AiAction::SuspendUserSudo {
            user: "attacker".into(),
            duration_secs: 300,
        };
        let out = execute_simple_action(&action, &inc, dir.path(), &cfg, &mut state).await;
        let (msg, executed) = out.expect("SuspendUserSudo allowed must be Some");
        assert!(
            !msg.contains("not in allowed_skills"),
            "skill was allowed, should not have been gated"
        );
        // Dry-run skill output shape: not asserted strictly because
        // the suspend-user-sudo skill's dry-run message is its own
        // contract. Pin only that the function reached the execute
        // path (no allowed-list bail) and returned executed=false
        // (this layer always returns false; the caller decides).
        assert!(!executed);
    }

    /// Coverage anchor: KillChainResponse has NO allowed_skills gate
    /// (chain responses are emergency stops; the gate is upstream in
    /// the AI's own decision). Skill-not-in-registry returns skipped.
    /// Pins the asymmetry — KCR is the only handler that skips the
    /// allowed-list check.
    #[tokio::test]
    async fn kill_chain_response_skips_when_skill_missing_without_allowlist_gate() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // Empty registry to hit the not-in-registry branch.
        state.skill_registry = skills::SkillRegistry::empty();
        let cfg = dry_run_cfg(&[]); // empty allowed list — KCR ignores it

        let action = ai::AiAction::KillChainResponse {
            reason: "data exfil chain".into(),
        };
        let inc = incident_for("203.0.113.10");
        let (msg, _) = execute_simple_action(&action, &inc, dir.path(), &cfg, &mut state)
            .await
            .expect("KillChainResponse must be Some");
        assert!(
            msg.contains("kill-chain-response skill not available"),
            "expected registry-miss message, got: {msg}"
        );
        assert!(
            !msg.contains("not in allowed_skills"),
            "KCR must NOT gate on allowed_skills (emergency response)"
        );
    }

    /// Coverage anchor: Monitor has NO allowed_skills gate either —
    /// it is purely observational, no firewall mutation. Pin the
    /// not-in-registry branch returns the skipped message.
    #[tokio::test]
    async fn monitor_skips_when_skill_missing() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.skill_registry = skills::SkillRegistry::empty();
        let cfg = dry_run_cfg(&[]);

        let action = ai::AiAction::Monitor {
            ip: "203.0.113.10".into(),
        };
        let inc = incident_for("203.0.113.10");
        let (msg, _) = execute_simple_action(&action, &inc, dir.path(), &cfg, &mut state)
            .await
            .expect("Monitor must be Some");
        assert!(msg.contains("monitor-ip skill not available"));
    }
}
