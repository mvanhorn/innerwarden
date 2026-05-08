use anyhow::Result;
use std::path::Path;

use tracing::warn;

use crate::{
    ai, config, decision_block_ip, decision_confirmation, decision_honeypot,
    decision_skill_actions, skills, AgentState,
};

/// Execute an AI decision by finding and running the appropriate skill.
/// Returns (execution_message, cloudflare_pushed).
pub(crate) async fn execute_decision(
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    use ai::AiAction;

    // 2026-05-08 (fix/ai-router-cidr-guard): defensive guard at the
    // boundary between AI providers (Local Warden / OpenAI / Anthropic)
    // and the executor. PR #497 added `is_single_ip_block_target` to
    // the *automated* paths (repeat-offender, multi-technique). This
    // closes the AI router gap: if a model hallucinates a CIDR or
    // mis-parses an IP from prompt context, the BlockIp action gets
    // refused here BEFORE any reputation counter, blocklist mutation,
    // or firewall call. Operator-visible: the audit trail records a
    // `skipped:` outcome with the bad target, instead of a real block
    // against a /16 of public IPs.
    if let AiAction::BlockIp { ip, .. } = &decision.action {
        if !decision_block_ip::is_single_ip_block_target(ip) {
            warn!(
                ip = %ip,
                provider = ?decision.action,
                "AI router: refusing BlockIp on invalid or CIDR target — \
                 most likely an LLM hallucination or malformed parse. \
                 Decision downgraded to skipped at the execute boundary."
            );
            return (
                format!(
                    "skipped: AI router emitted BlockIp on invalid or CIDR target {ip} — \
                     refused at execute_decision boundary"
                ),
                false,
            );
        }
    }

    if let Some(result) = decision_skill_actions::execute_simple_action(
        &decision.action,
        incident,
        data_dir,
        cfg,
        state,
    )
    .await
    {
        return result;
    }

    match &decision.action {
        AiAction::BlockIp { ip, skill_id } => {
            decision_block_ip::execute_block_ip_decision(
                ip, skill_id, decision, incident, data_dir, cfg, state,
            )
            .await
        }
        AiAction::Honeypot { ip } => {
            decision_honeypot::execute_honeypot_decision(ip, incident, data_dir, cfg, state).await
        }
        AiAction::SuspendUserSudo {
            user,
            duration_secs,
        } => {
            let skill_id = "suspend-user-sudo";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
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
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_router.any_llm(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: suspend-user-sudo skill not available".to_string(),
                    false,
                )
            }
        }
        AiAction::KillProcess {
            user,
            duration_secs,
        } => {
            let skill_id = "kill-process";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
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
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_router.any_llm(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: kill-process skill not available".to_string(),
                    false,
                )
            }
        }
        AiAction::BlockContainer {
            container_id,
            action: _,
        } => {
            let skill_id = "block-container";
            if !cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
                return (
                    format!("skipped: skill '{skill_id}' not in allowed_skills"),
                    false,
                );
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
                    honeypot: honeypot_runtime(cfg),
                    ai_provider: state.ai_router.any_llm(),
                };
                (
                    skill.execute(&ctx, cfg.responder.dry_run).await.message,
                    false,
                )
            } else {
                (
                    "skipped: block-container skill not available".to_string(),
                    false,
                )
            }
        }
        AiAction::RequestConfirmation { summary } => {
            decision_confirmation::execute_request_confirmation(
                summary, decision, incident, cfg, state,
            )
            .await
        }
        _ => unreachable!("unsupported action path in execute_decision"),
    }
}

pub(crate) fn honeypot_runtime(cfg: &config::AgentConfig) -> skills::HoneypotRuntimeConfig {
    let mode = cfg.honeypot.mode.trim().to_ascii_lowercase();
    let normalized_mode = match mode.as_str() {
        "demo" | "listener" => mode,
        // `always_on` keeps a permanent listener running from startup (handled
        // separately in `main`). When a skill-level honeypot action is
        // requested, it should behave like `listener` — a real listener, not
        // the demo text response — since that is the semantic the operator
        // opted into by enabling always-on mode.
        "always_on" => "listener".to_string(),
        other => {
            warn!(mode = other, "unknown honeypot mode; falling back to demo");
            "demo".to_string()
        }
    };
    skills::HoneypotRuntimeConfig {
        mode: normalized_mode,
        bind_addr: cfg.honeypot.bind_addr.clone(),
        port: cfg.honeypot.port,
        http_port: cfg.honeypot.http_port,
        duration_secs: cfg.honeypot.duration_secs,
        services: if cfg.honeypot.services.is_empty() {
            vec!["ssh".to_string()]
        } else {
            cfg.honeypot.services.clone()
        },
        strict_target_only: cfg.honeypot.strict_target_only,
        allow_public_listener: cfg.honeypot.allow_public_listener,
        max_connections: cfg.honeypot.max_connections,
        max_payload_bytes: cfg.honeypot.max_payload_bytes,
        isolation_profile: cfg.honeypot.isolation_profile.clone(),
        require_high_ports: cfg.honeypot.require_high_ports,
        forensics_keep_days: cfg.honeypot.forensics_keep_days,
        forensics_max_total_mb: cfg.honeypot.forensics_max_total_mb,
        transcript_preview_bytes: cfg.honeypot.transcript_preview_bytes,
        lock_stale_secs: cfg.honeypot.lock_stale_secs,
        sandbox_enabled: cfg.honeypot.sandbox.enabled,
        sandbox_runner_path: cfg.honeypot.sandbox.runner_path.clone(),
        sandbox_clear_env: cfg.honeypot.sandbox.clear_env,
        pcap_handoff_enabled: cfg.honeypot.pcap_handoff.enabled,
        pcap_handoff_timeout_secs: cfg.honeypot.pcap_handoff.timeout_secs,
        pcap_handoff_max_packets: cfg.honeypot.pcap_handoff.max_packets,
        containment_mode: cfg.honeypot.containment.mode.clone(),
        containment_require_success: cfg.honeypot.containment.require_success,
        containment_namespace_runner: cfg.honeypot.containment.namespace_runner.clone(),
        containment_namespace_args: cfg.honeypot.containment.namespace_args.clone(),
        containment_jail_runner: cfg.honeypot.containment.jail_runner.clone(),
        containment_jail_args: cfg.honeypot.containment.jail_args.clone(),
        containment_jail_profile: cfg.honeypot.containment.jail_profile.clone(),
        containment_allow_namespace_fallback: cfg.honeypot.containment.allow_namespace_fallback,
        external_handoff_enabled: cfg.honeypot.external_handoff.enabled,
        external_handoff_command: cfg.honeypot.external_handoff.command.clone(),
        external_handoff_args: cfg.honeypot.external_handoff.args.clone(),
        external_handoff_timeout_secs: cfg.honeypot.external_handoff.timeout_secs,
        external_handoff_require_success: cfg.honeypot.external_handoff.require_success,
        external_handoff_clear_env: cfg.honeypot.external_handoff.clear_env,
        external_handoff_allowed_commands: cfg.honeypot.external_handoff.allowed_commands.clone(),
        external_handoff_enforce_allowlist: cfg.honeypot.external_handoff.enforce_allowlist,
        external_handoff_signature_enabled: cfg.honeypot.external_handoff.signature_enabled,
        external_handoff_signature_key_env: cfg.honeypot.external_handoff.signature_key_env.clone(),
        external_handoff_attestation_enabled: cfg.honeypot.external_handoff.attestation_enabled,
        external_handoff_attestation_key_env: cfg
            .honeypot
            .external_handoff
            .attestation_key_env
            .clone(),
        external_handoff_attestation_prefix: cfg
            .honeypot
            .external_handoff
            .attestation_prefix
            .clone(),
        external_handoff_attestation_expected_receiver: cfg
            .honeypot
            .external_handoff
            .attestation_expected_receiver
            .clone(),
        redirect_enabled: cfg.honeypot.redirect.enabled,
        redirect_backend: cfg.honeypot.redirect.backend.clone(),
        interaction: cfg.honeypot.interaction.trim().to_ascii_lowercase(),
        ssh_max_auth_attempts: cfg.honeypot.ssh_max_auth_attempts,
        http_max_requests: cfg.honeypot.http_max_requests,
        // Populated at the call site when the AI provider is available.
        ai_provider: None,
    }
}

pub(crate) async fn append_honeypot_marker_event(
    data_dir: &Path,
    incident: &innerwarden_core::incident::Incident,
    ip: &str,
    dry_run: bool,
    runtime: &skills::HoneypotRuntimeConfig,
) -> Result<std::path::PathBuf> {
    use tokio::io::AsyncWriteExt;

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let events_path = data_dir.join(format!("events-{today}.jsonl"));

    let is_listener = runtime.mode == "listener" && !dry_run;
    let (source, kind, summary) = if is_listener {
        let mut endpoints = Vec::new();
        if runtime
            .services
            .iter()
            .any(|svc| svc.eq_ignore_ascii_case("ssh"))
        {
            endpoints.push(format!("ssh:{}:{}", runtime.bind_addr, runtime.port));
        }
        if runtime
            .services
            .iter()
            .any(|svc| svc.eq_ignore_ascii_case("http"))
        {
            endpoints.push(format!("http:{}:{}", runtime.bind_addr, runtime.http_port));
        }
        if endpoints.is_empty() {
            endpoints.push(format!("ssh:{}:{}", runtime.bind_addr, runtime.port));
        }
        (
            "agent.honeypot_listener",
            "honeypot.listener_session_started",
            format!(
                "Honeypot listener session started for attacker {ip} at {}",
                endpoints.join(", ")
            ),
        )
    } else {
        (
            "agent.honeypot_demo",
            "honeypot.demo_decoy_hit",
            format!(
                "DEMO/SIMULATION/DECOY: attacker {ip} marked as honeypot hit (controlled marker only)"
            ),
        )
    };

    let event = innerwarden_core::event::Event {
        ts: chrono::Utc::now(),
        host: incident.host.clone(),
        source: source.to_string(),
        kind: kind.to_string(),
        severity: innerwarden_core::event::Severity::Info,
        summary,
        details: serde_json::json!({
            "mode": runtime.mode,
            "simulation": !is_listener,
            "decoy": true,
            "target_ip": ip,
            "incident_id": incident.incident_id,
            "dry_run": dry_run,
            "listener_bind_addr": runtime.bind_addr,
            "listener_services": runtime.services.clone(),
            "listener_ssh_port": runtime.port,
            "listener_http_port": runtime.http_port,
            "listener_duration_secs": runtime.duration_secs,
            "listener_strict_target_only": runtime.strict_target_only,
            "listener_max_connections": runtime.max_connections,
            "listener_max_payload_bytes": runtime.max_payload_bytes,
            "listener_isolation_profile": runtime.isolation_profile,
            "listener_require_high_ports": runtime.require_high_ports,
            "listener_forensics_keep_days": runtime.forensics_keep_days,
            "listener_forensics_max_total_mb": runtime.forensics_max_total_mb,
            "listener_transcript_preview_bytes": runtime.transcript_preview_bytes,
            "listener_lock_stale_secs": runtime.lock_stale_secs,
            "listener_sandbox_enabled": runtime.sandbox_enabled,
            "listener_containment_mode": runtime.containment_mode,
            "listener_containment_jail_runner": runtime.containment_jail_runner,
            "listener_containment_jail_profile": runtime.containment_jail_profile,
            "listener_external_handoff_enabled": runtime.external_handoff_enabled,
            "listener_external_handoff_allowlist": runtime.external_handoff_enforce_allowlist,
            "listener_external_handoff_signature": runtime.external_handoff_signature_enabled,
            "listener_external_handoff_attestation": runtime.external_handoff_attestation_enabled,
            "listener_pcap_handoff_enabled": runtime.pcap_handoff_enabled,
            "listener_redirect_enabled": runtime.redirect_enabled,
            "listener_redirect_backend": runtime.redirect_backend,
            "note": if is_listener {
                "Real honeypot listener mode active with bounded decoys and local forensics."
            } else {
                "Demo-only marker; no real honeypot infrastructure is deployed in this mode."
            }
        }),
        tags: vec![
            "honeypot".to_string(),
            "decoy".to_string(),
            if is_listener {
                "listener".to_string()
            } else {
                "demo".to_string()
            },
            if is_listener {
                "real_mode".to_string()
            } else {
                "simulation".to_string()
            },
        ],
        entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
    };

    let line = serde_json::to_string(&event)?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&events_path)
        .await?;
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;

    Ok(events_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_decision(action: ai::AiAction) -> ai::AiDecision {
        ai::AiDecision {
            action,
            confidence: 0.9,
            auto_execute: true,
            reason: "unit test".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        }
    }

    #[test]
    fn honeypot_runtime_maps_always_on_to_listener() {
        let mut cfg = config::AgentConfig::default();
        cfg.honeypot.mode = "always_on".to_string();
        let runtime = honeypot_runtime(&cfg);
        assert_eq!(runtime.mode, "listener");
    }

    #[test]
    fn honeypot_runtime_preserves_listener_mode() {
        let mut cfg = config::AgentConfig::default();
        cfg.honeypot.mode = "listener".to_string();
        let runtime = honeypot_runtime(&cfg);
        assert_eq!(runtime.mode, "listener");
    }

    #[test]
    fn honeypot_runtime_unknown_mode_falls_back_to_demo() {
        let mut cfg = config::AgentConfig::default();
        cfg.honeypot.mode = "unknown_mode".to_string();
        let runtime = honeypot_runtime(&cfg);
        assert_eq!(runtime.mode, "demo");
    }

    #[tokio::test]
    async fn append_honeypot_marker_event_writes_demo_marker() {
        let dir = TempDir::new().expect("tempdir");
        let incident = crate::tests::test_incident("198.51.100.77");
        let mut cfg = config::AgentConfig::default();
        cfg.honeypot.mode = "demo".to_string();
        let runtime = honeypot_runtime(&cfg);

        let path =
            append_honeypot_marker_event(dir.path(), &incident, "198.51.100.77", false, &runtime)
                .await
                .expect("marker append");
        let contents = std::fs::read_to_string(path).expect("read events file");
        assert!(contents.contains("\"kind\":\"honeypot.demo_decoy_hit\""));
        assert!(contents.contains("\"simulation\":true"));
    }

    #[tokio::test]
    async fn append_honeypot_marker_event_writes_listener_marker_when_live() {
        let dir = TempDir::new().expect("tempdir");
        let incident = crate::tests::test_incident("203.0.113.88");
        let mut cfg = config::AgentConfig::default();
        cfg.honeypot.mode = "listener".to_string();
        cfg.honeypot.services = vec!["ssh".to_string(), "http".to_string()];
        let runtime = honeypot_runtime(&cfg);

        let path =
            append_honeypot_marker_event(dir.path(), &incident, "203.0.113.88", false, &runtime)
                .await
                .expect("marker append");
        let contents = std::fs::read_to_string(path).expect("read events file");
        assert!(contents.contains("\"kind\":\"honeypot.listener_session_started\""));
        assert!(contents.contains("\"simulation\":false"));
    }

    #[tokio::test]
    async fn execute_decision_skips_suspend_user_when_skill_not_allowed() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.12");
        let mut cfg = config::AgentConfig::default();
        cfg.responder.allowed_skills.clear();
        let decision = test_decision(ai::AiAction::SuspendUserSudo {
            user: "ubuntu".to_string(),
            duration_secs: 300,
        });

        let (message, cloudflare_pushed) =
            execute_decision(&decision, &incident, dir.path(), &cfg, &mut state).await;

        assert!(message.contains("not in allowed_skills"));
        assert!(!cloudflare_pushed);
    }

    #[tokio::test]
    async fn execute_decision_skips_container_block_when_skill_not_allowed() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.13");
        let mut cfg = config::AgentConfig::default();
        cfg.responder.allowed_skills.clear();
        let decision = test_decision(ai::AiAction::BlockContainer {
            container_id: "container-1".to_string(),
            action: "pause".to_string(),
        });

        let (message, cloudflare_pushed) =
            execute_decision(&decision, &incident, dir.path(), &cfg, &mut state).await;

        assert!(message.contains("not in allowed_skills"));
        assert!(!cloudflare_pushed);
    }

    /// 2026-05-08 anchor (fix/ai-router-cidr-guard-and-zombie-purge):
    /// AI providers (Local Warden / OpenAI / Anthropic) sometimes
    /// hallucinate CIDR targets in their `BlockIp` action — the
    /// prompt may have included a CIDR somewhere, the model
    /// pattern-matches and emits `BlockIp { ip: "X.Y.Z.W/N" }`. PR #497
    /// added the guard at the *automated* paths (repeat-offender,
    /// multi-technique). This pins the guard at the AI-router boundary:
    /// `execute_decision` refuses BlockIp on CIDR targets BEFORE any
    /// downstream mutation. The bad action becomes a `skipped:` row
    /// in the audit trail instead of a real /16 ban.
    #[tokio::test]
    async fn execute_decision_refuses_block_ip_on_cidr_target_with_skipped_outcome() {
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.10");

        let decision = test_decision(ai::AiAction::BlockIp {
            ip: "136.216.0.0/16".to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });

        let (message, cloudflare_pushed) =
            execute_decision(&decision, &incident, dir.path(), &cfg, &mut state).await;

        assert!(
            message.starts_with("skipped:"),
            "CIDR target must produce a skipped outcome (got: {message})"
        );
        assert!(
            message.contains("CIDR") || message.contains("invalid"),
            "skipped reason must mention the cause (got: {message})"
        );
        assert!(!cloudflare_pushed);
        // Anti-regression: the in-memory blocklist MUST NOT have
        // grown — the guard fired before any state mutation.
        assert!(
            !state.blocklist.contains("136.216.0.0/16"),
            "guard MUST run before state.blocklist mutation — pre-fix the AI \
             could push a /16 into the blocklist via the safeguards path"
        );
    }

    /// Mirror anchor: a plain IP target still flows through normally
    /// (the new guard only intercepts CIDR / invalid targets, not
    /// every BlockIp). Pins that the cheap-exit path doesn't break
    /// the happy-path semantics.
    #[tokio::test]
    async fn execute_decision_allows_block_ip_on_plain_ip_target() {
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.10");

        let decision = test_decision(ai::AiAction::BlockIp {
            ip: "203.0.113.10".to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });

        let (message, _) =
            execute_decision(&decision, &incident, dir.path(), &cfg, &mut state).await;

        assert!(
            !message.starts_with("skipped: AI router emitted BlockIp on invalid"),
            "plain IP must NOT trip the new CIDR guard (got: {message})"
        );
    }
}
