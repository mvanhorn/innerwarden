use crate::{abuseipdb, ai, config, geoip, AgentState};

/// Send a post-execution action report to Telegram when an action was executed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn maybe_send_post_execution_telegram_report(
    incident: &innerwarden_core::incident::Incident,
    decision: &ai::AiDecision,
    execution_result: &str,
    cloudflare_pushed: bool,
    cfg: &config::AgentConfig,
    state: &AgentState,
    ip_reputation: Option<&abuseipdb::IpReputation>,
    ip_geo: Option<&geoip::GeoInfo>,
) {
    // In GUARD/DryRun mode, send a post-execution Telegram report so the
    // operator knows what was done (action report replaces a manual ask).
    let was_executed = !execution_result.starts_with("skipped");
    if !was_executed || !cfg.telegram.bot.enabled {
        return;
    }

    // Only send action reports for immediate threats — routine blocks
    // (ssh_bruteforce, port_scan, etc.) go to the daily digest silently.
    if !crate::notification_pipeline::is_immediate_threat(incident) {
        return;
    }

    let Some(ref tg) = state.telegram_client else {
        return;
    };

    use ai::AiAction;
    let (action_label, target) = match &decision.action {
        AiAction::BlockIp { ip, .. } => ("Blocked".to_string(), ip.clone()),
        AiAction::Monitor { ip } => ("Monitoring traffic from".to_string(), ip.clone()),
        AiAction::Honeypot { ip } => ("Redirected to honeypot".to_string(), ip.clone()),
        AiAction::SuspendUserSudo { user, .. } => ("Suspended sudo for".to_string(), user.clone()),
        AiAction::KillProcess { user, .. } => ("Killed processes for".to_string(), user.clone()),
        AiAction::BlockContainer { container_id, .. } => {
            ("Paused container".to_string(), container_id.clone())
        }
        AiAction::KillChainResponse { .. } => (
            "Kill chain response".to_string(),
            format!(
                "PID {}",
                incident.incident_id.split(':').nth(2).unwrap_or("-")
            ),
        ),
        AiAction::Ignore { .. } => ("Ignored".to_string(), "-".to_string()),
        AiAction::Dismiss { .. } => ("Dismissed".to_string(), "-".to_string()),
        AiAction::RequestConfirmation { .. } => {
            ("Requested confirmation for".to_string(), "-".to_string())
        }
    };

    let tg = tg.clone();
    let title = incident.title.clone();
    let host = incident.host.clone();
    let confidence = decision.confidence;
    let dry_run = cfg.responder.dry_run;
    let rep_clone = ip_reputation.cloned();
    let geo_clone = ip_geo.cloned();
    tokio::spawn(async move {
        let _ = tg
            .send_action_report(
                &action_label,
                &target,
                &title,
                confidence,
                &host,
                dry_run,
                rep_clone.as_ref(),
                geo_clone.as_ref(),
                cloudflare_pushed,
            )
            .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn base_decision(action: ai::AiAction) -> ai::AiDecision {
        ai::AiDecision {
            action,
            confidence: 0.91,
            auto_execute: true,
            reason: "unit test".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        }
    }

    fn state_with_telegram(dir: &std::path::Path) -> AgentState {
        let mut state = crate::tests::triage_test_state(dir);
        let tg = crate::telegram::TelegramClient::new("token", "chat-id", None)
            .expect("telegram client");
        state.telegram_client = Some(Arc::new(tg));
        state
    }

    #[tokio::test]
    async fn skips_when_execution_was_not_performed_or_bot_disabled() {
        let dir = TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.telegram.bot.enabled = false;
        let mut incident = crate::tests::test_incident("203.0.113.30");
        incident.severity = innerwarden_core::event::Severity::Critical;
        let decision = base_decision(ai::AiAction::BlockIp {
            ip: "203.0.113.30".to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });

        maybe_send_post_execution_telegram_report(
            &incident,
            &decision,
            "skipped: confidence below threshold",
            false,
            &cfg,
            &state,
            None,
            None,
        );

        cfg.telegram.bot.enabled = true;
        maybe_send_post_execution_telegram_report(
            &incident, &decision, "ok", false, &cfg, &state, None, None,
        );
    }

    #[tokio::test]
    async fn skips_non_immediate_threats_even_when_executed() {
        let dir = TempDir::new().expect("tempdir");
        let state = state_with_telegram(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.telegram.bot.enabled = true;
        let incident = crate::tests::test_incident_with_kind("203.0.113.31", "benign_detector");
        let decision = base_decision(ai::AiAction::Monitor {
            ip: "203.0.113.31".to_string(),
        });

        maybe_send_post_execution_telegram_report(
            &incident, &decision, "ok", false, &cfg, &state, None, None,
        );
    }

    #[tokio::test]
    async fn maps_all_action_variants_into_report_labels_and_targets() {
        let dir = TempDir::new().expect("tempdir");
        let state = state_with_telegram(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.telegram.bot.enabled = true;
        cfg.responder.dry_run = true;

        let mut incident = crate::tests::test_incident("203.0.113.32");
        incident.severity = innerwarden_core::event::Severity::Critical;
        incident.incident_id = "kill_chain:203.0.113.32:4242".to_string();

        let actions = vec![
            ai::AiAction::BlockIp {
                ip: "203.0.113.32".to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            ai::AiAction::Monitor {
                ip: "203.0.113.32".to_string(),
            },
            ai::AiAction::Honeypot {
                ip: "203.0.113.32".to_string(),
            },
            ai::AiAction::SuspendUserSudo {
                user: "root".to_string(),
                duration_secs: 300,
            },
            ai::AiAction::KillProcess {
                user: "root".to_string(),
                duration_secs: 120,
            },
            ai::AiAction::BlockContainer {
                container_id: "abc123".to_string(),
                action: "pause".to_string(),
            },
            ai::AiAction::KillChainResponse {
                reason: "chain complete".to_string(),
            },
            ai::AiAction::Ignore {
                reason: "false positive".to_string(),
            },
            ai::AiAction::Dismiss {
                reason: "below noise floor".to_string(),
            },
            ai::AiAction::RequestConfirmation {
                summary: "needs approval".to_string(),
            },
        ];

        for action in actions {
            let decision = base_decision(action);
            maybe_send_post_execution_telegram_report(
                &incident, &decision, "executed", true, &cfg, &state, None, None,
            );
        }
    }
}
