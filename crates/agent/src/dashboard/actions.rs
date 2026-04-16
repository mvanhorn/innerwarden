// Auto-extracted from mod.rs — dashboard actions handlers

use super::*;

// ---------------------------------------------------------------------------
// D3 - action handlers
// ---------------------------------------------------------------------------

/// GET /api/action/config - exposes the current action mode to the UI (read-only).
pub(super) async fn api_action_config(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let cfg = &state.action_cfg;
    let mode = if cfg.enabled {
        if cfg.dry_run {
            "watch"
        } else {
            "guard"
        }
    } else {
        "read_only"
    };
    Json(serde_json::json!({
        "enabled": cfg.enabled,
        "dry_run": cfg.dry_run,
        "block_backend": cfg.block_backend,
        "allowed_skills": cfg.allowed_skills,
        "ai_enabled": cfg.ai_enabled,
        "ai_provider": cfg.ai_provider,
        "ai_model": cfg.ai_model,
        "mode": mode,
        "version": env!("CARGO_PKG_VERSION"),
        "trusted_ips": cfg.trusted_ips,
        "trusted_users": cfg.trusted_users,
    }))
}
/// GET /api/quickwins - return actionable suggestions based on recent unblocked threats.
pub(super) async fn api_quickwins(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let data_dir = &state.data_dir;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();

    // Collect blocked IPs from decisions (today + yesterday)
    let mut blocked_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for date in &[today.as_str(), yesterday.as_str()] {
        let path = data_dir.join(format!("decisions-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if v["action"].as_str() == Some("block_ip") {
                        if let Some(ip) = v["target_ip"].as_str() {
                            blocked_ips.insert(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    // Collect unblocked High/Critical incidents from today + yesterday
    let mut suggestions: Vec<serde_json::Value> = Vec::new();
    let mut seen_ips: std::collections::HashSet<String> = blocked_ips.clone();
    for date in &[today.as_str(), yesterday.as_str()] {
        let path = data_dir.join(format!("incidents-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    let sev = v["severity"].as_str().unwrap_or("");
                    if sev != "High" && sev != "Critical" {
                        continue;
                    }
                    // Find IP entity
                    let ip = v["entities"].as_array().and_then(|arr| {
                        arr.iter()
                            .find(|e| e["type"].as_str() == Some("Ip"))
                            .and_then(|e| e["value"].as_str())
                            .map(|s| s.to_string())
                    });
                    if let Some(ip_str) = ip {
                        if seen_ips.contains(&ip_str) {
                            continue; // already handled or deduped
                        }
                        seen_ips.insert(ip_str.clone());
                        suggestions.push(serde_json::json!({
                            "type": "unblocked_attacker",
                            "severity": sev,
                            "ip": ip_str,
                            "title": v["title"].as_str().unwrap_or("Threat detected"),
                            "date": date,
                            "action": format!("Block {ip_str} at the firewall"),
                            "command": "innerwarden enable block-ip"
                        }));
                    }
                }
            }
        }
    }

    Json(serde_json::json!({
        "suggestions": suggestions,
        "count": suggestions.len()
    }))
}
/// POST /api/action/block-ip - operator-initiated IP block with mandatory reason.
pub(super) async fn api_action_block_ip(
    State(state): State<DashboardState>,
    Json(body): Json<BlockIpRequest>,
) -> Json<ActionResponse> {
    if state.insecure_http {
        warn!("action executed over HTTP without TLS — consider a reverse proxy with TLS");
    }

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id: String::new(),
        });
    }

    let ip = body.ip.trim().to_string();
    if ip.is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "ip is required".to_string(),
            skill_id: String::new(),
        });
    }
    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id: String::new(),
        });
    }

    // Select the right skill based on configured backend.
    let skill_id = format!("block-ip-{}", state.action_cfg.block_backend);
    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("skill '{skill_id}' is not in allowed_skills"),
            skill_id,
        });
    }

    let result = execute_block_ip(
        &state.data_dir,
        &state.action_cfg,
        &ip,
        &body.reason,
        body.incident_id.as_deref(),
    )
    .await;

    match result {
        Ok((success, message)) => Json(ActionResponse {
            success,
            dry_run: state.action_cfg.dry_run,
            message,
            skill_id,
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("internal error: {e}"),
            skill_id,
        }),
    }
}

/// POST /api/action/suspend-user - operator-initiated sudo suspension with mandatory reason.
pub(super) async fn api_action_suspend_user(
    State(state): State<DashboardState>,
    Json(body): Json<SuspendUserRequest>,
) -> Json<ActionResponse> {
    let skill_id = "suspend-user-sudo".to_string();

    if state.insecure_http {
        warn!("action executed over HTTP without TLS — consider a reverse proxy with TLS");
    }

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        });
    }

    let user = body.user.trim().to_string();
    if user.is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "user is required".to_string(),
            skill_id,
        });
    }
    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id,
        });
    }
    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("skill '{skill_id}' is not in allowed_skills"),
            skill_id,
        });
    }

    let result = execute_suspend_user(
        &state.data_dir,
        &state.action_cfg,
        &user,
        &body.reason,
        body.duration_secs.unwrap_or(3600),
        body.incident_id.as_deref(),
    )
    .await;

    match result {
        Ok((success, message)) => Json(ActionResponse {
            success,
            dry_run: state.action_cfg.dry_run,
            message,
            skill_id,
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("internal error: {e}"),
            skill_id,
        }),
    }
}

/// POST /api/action/honeypot - operator-initiated honeypot test session.
pub(super) async fn api_action_honeypot(
    State(state): State<DashboardState>,
    Json(body): Json<HoneypotTestRequest>,
) -> Json<ActionResponse> {
    let skill_id = "honeypot".to_string();

    if state.insecure_http {
        warn!("action executed over HTTP without TLS — consider a reverse proxy with TLS");
    }

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        });
    }

    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id,
        });
    }

    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "skill 'honeypot' is not in allowed_skills - add it to responder.allowed_skills in agent.toml".to_string(),
            skill_id,
        });
    }

    let duration_secs = body.duration_secs.unwrap_or(120);

    // Write a synthetic incident to today's incidents file so the agent's main
    // loop picks it up in the next 2-second tick and evaluates the honeypot skill.
    let result = inject_honeypot_test_incident(&state.data_dir, &body.reason, duration_secs).await;

    match result {
        Ok(()) => {
            let entry = DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: format!("honeypot_test:{}", chrono::Utc::now().timestamp()),
                host: hostname(),
                ai_provider: "dashboard:operator".to_string(),
                action_type: "honeypot".to_string(),
                target_ip: Some("0.0.0.0".to_string()),
                target_user: None,
                skill_id: Some(skill_id.clone()),
                confidence: 1.0,
                auto_executed: !state.action_cfg.dry_run,
                dry_run: state.action_cfg.dry_run,
                reason: body.reason.clone(),
                estimated_threat: "manual_test".to_string(),
                execution_result: if state.action_cfg.dry_run {
                    "ok (dry_run)".to_string()
                } else {
                    "incident_injected".to_string()
                },
                prev_hash: None,
            };
            if let Err(e) = append_decision_entry(&state.data_dir, &entry) {
                warn!("failed to write honeypot test decision entry: {e}");
            }

            // Admin action audit trail
            let mut audit = AdminActionEntry {
                ts: Utc::now(),
                operator: "dashboard:operator".to_string(),
                source: "dashboard".to_string(),
                action: "honeypot".to_string(),
                target: "honeypot_test".to_string(),
                parameters: serde_json::json!({
                    "skill": "honeypot",
                    "reason": body.reason,
                    "duration_secs": duration_secs,
                }),
                result: "success".to_string(),
                prev_hash: None,
            };
            if let Err(e) = append_admin_action(&state.data_dir, &mut audit) {
                warn!("failed to write admin audit: {e:#}");
            }

            info!(
                dry_run = state.action_cfg.dry_run,
                duration_secs, "dashboard action: honeypot test"
            );
            let mode_prefix = if state.action_cfg.dry_run {
                "[DRY RUN] "
            } else {
                ""
            };
            Json(ActionResponse {
                success: true,
                dry_run: state.action_cfg.dry_run,
                message: format!(
                    "{mode_prefix}Test honeypot incident injected - the agent will pick it up \
                     in the next tick (≤2 s). Connect via: ssh -p 2222 -o StrictHostKeyChecking=no root@<host>"
                ),
                skill_id,
            })
        }
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("failed to inject test incident: {e}"),
            skill_id,
        }),
    }
}

// ---------------------------------------------------------------------------
// D3 - execution helpers
// ---------------------------------------------------------------------------

/// Execute a block-ip skill and write the decision to the audit trail.
pub(super) async fn execute_block_ip(
    data_dir: &Path,
    cfg: &DashboardActionConfig,
    ip: &str,
    reason: &str,
    incident_id: Option<&str>,
) -> anyhow::Result<(bool, String)> {
    use crate::skills::{
        builtin::{BlockIpIptables, BlockIpNftables, BlockIpUfw},
        HoneypotRuntimeConfig, ResponseSkill, SkillContext,
    };

    let skill_id = format!("block-ip-{}", cfg.block_backend);
    let iid = incident_id.unwrap_or("unknown").to_string();
    let inc = make_synthetic_incident(&iid, ip, reason);

    let ctx = SkillContext {
        incident: inc,
        target_ip: Some(ip.to_string()),
        target_user: None,
        target_container: None,
        duration_secs: None,
        host: hostname(),
        data_dir: data_dir.to_path_buf(),
        honeypot: HoneypotRuntimeConfig::default(),
        ai_provider: None,
    };

    let skill: Box<dyn ResponseSkill> = match cfg.block_backend.as_str() {
        "iptables" => Box::new(BlockIpIptables),
        "nftables" => Box::new(BlockIpNftables),
        _ => Box::new(BlockIpUfw),
    };
    let result = skill.execute(&ctx, cfg.dry_run).await;
    let (success, message) = (result.success, result.message);

    let result_str = if success {
        if cfg.dry_run {
            "ok (dry_run)".to_string()
        } else {
            "ok".to_string()
        }
    } else {
        format!("failed: {message}")
    };

    let entry = DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.unwrap_or("dashboard:manual").to_string(),
        host: hostname(),
        ai_provider: "dashboard:operator".to_string(),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: Some(skill_id.clone()),
        confidence: 1.0,
        auto_executed: true,
        dry_run: cfg.dry_run,
        reason: reason.to_string(),
        estimated_threat: "manual".to_string(),
        execution_result: result_str,
        prev_hash: None,
    };

    append_decision_entry(data_dir, &entry)?;

    // Admin action audit trail
    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "block_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({
            "skill": skill_id,
            "reason": reason,
            "incident_id": incident_id,
        }),
        result: if success {
            "success".to_string()
        } else {
            format!("failure: {message}")
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(
        ip = %ip,
        dry_run = cfg.dry_run,
        skill_id = %skill_id,
        success,
        "dashboard action: block-ip"
    );
    Ok((success, message))
}

/// Execute a suspend-user skill and write the decision to the audit trail.
pub(super) async fn execute_suspend_user(
    data_dir: &Path,
    cfg: &DashboardActionConfig,
    user: &str,
    reason: &str,
    duration_secs: u64,
    incident_id: Option<&str>,
) -> anyhow::Result<(bool, String)> {
    use crate::skills::{
        builtin::SuspendUserSudo, HoneypotRuntimeConfig, ResponseSkill, SkillContext,
    };
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    let iid = incident_id.unwrap_or("unknown").to_string();
    let inc = Incident {
        ts: Utc::now(),
        host: hostname(),
        incident_id: format!("dashboard:manual:{iid}"),
        severity: Severity::High,
        title: "Dashboard Manual Action".to_string(),
        summary: reason.to_string(),
        evidence: serde_json::json!({}),
        recommended_checks: vec![],
        tags: vec!["dashboard".to_string(), "manual".to_string()],
        entities: vec![EntityRef::user(user)],
    };

    let ctx = SkillContext {
        incident: inc,
        target_ip: None,
        target_user: Some(user.to_string()),
        target_container: None,
        duration_secs: Some(duration_secs),
        host: hostname(),
        data_dir: data_dir.to_path_buf(),
        honeypot: HoneypotRuntimeConfig::default(),
        ai_provider: None,
    };

    let skill = SuspendUserSudo;
    let result = skill.execute(&ctx, cfg.dry_run).await;
    let (success, message) = (result.success, result.message);

    let result_str = if success {
        if cfg.dry_run {
            "ok (dry_run)".to_string()
        } else {
            "ok".to_string()
        }
    } else {
        format!("failed: {message}")
    };

    let entry = DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.unwrap_or("dashboard:manual").to_string(),
        host: hostname(),
        ai_provider: "dashboard:operator".to_string(),
        action_type: "suspend_user_sudo".to_string(),
        target_ip: None,
        target_user: Some(user.to_string()),
        skill_id: Some("suspend-user-sudo".to_string()),
        confidence: 1.0,
        auto_executed: true,
        dry_run: cfg.dry_run,
        reason: reason.to_string(),
        estimated_threat: "manual".to_string(),
        execution_result: result_str,
        prev_hash: None,
    };

    append_decision_entry(data_dir, &entry)?;

    // Admin action audit trail
    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "suspend_user".to_string(),
        target: user.to_string(),
        parameters: serde_json::json!({
            "skill": "suspend-user-sudo",
            "reason": reason,
            "duration_secs": duration_secs,
            "incident_id": incident_id,
        }),
        result: if success {
            "success".to_string()
        } else {
            format!("failure: {message}")
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(
        user = %user,
        dry_run = cfg.dry_run,
        duration_secs,
        success,
        "dashboard action: suspend-user"
    );
    Ok((success, message))
}

/// Build a minimal synthetic incident for skill execution context.
pub(super) fn make_synthetic_incident(
    incident_id_hint: &str,
    ip: &str,
    reason: &str,
) -> innerwarden_core::incident::Incident {
    use innerwarden_core::event::Severity;
    innerwarden_core::incident::Incident {
        ts: Utc::now(),
        host: hostname(),
        incident_id: format!("dashboard:manual:{incident_id_hint}"),
        severity: Severity::High,
        title: "Dashboard Manual Action".to_string(),
        summary: reason.to_string(),
        evidence: serde_json::json!({}),
        recommended_checks: vec![],
        tags: vec!["dashboard".to_string(), "manual".to_string()],
        entities: vec![EntityRef::ip(ip)],
    }
}

/// Append a single `DecisionEntry` to today's decisions JSONL file.
pub(super) fn append_decision_entry(data_dir: &Path, entry: &DecisionEntry) -> anyhow::Result<()> {
    crate::decisions::append_chained(data_dir, entry)
}

/// Inject a synthetic high-severity SSH brute-force incident so the agent's main
/// loop picks it up and evaluates the honeypot skill in the next tick.
pub(super) async fn inject_honeypot_test_incident(
    data_dir: &Path,
    reason: &str,
    duration_secs: u64,
) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    let now = chrono::Utc::now();
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("incidents-{today}.jsonl"));

    // Build a minimal Incident that looks like an SSH brute-force event so the
    // algorithm gate passes it through (severity=High, non-private IP).
    let incident = serde_json::json!({
        "ts": now.to_rfc3339(),
        "host": hostname(),
        "incident_id": format!("honeypot_test:{}", now.timestamp()),
        "severity": "high",
        "title": format!("Manual honeypot test - {} ({}s)", reason, duration_secs),
        "summary": format!(
            "50 failed SSH login attempts from 1.2.3.4 in the last 300 seconds (manual test via dashboard)"
        ),
        "evidence": [{"count": 50, "ip": "1.2.3.4", "kind": "ssh.login_failed", "window_seconds": 300}],
        "recommended_checks": [],
        "tags": ["auth", "ssh", "bruteforce", "test", "dashboard"],
        "entities": [{"type": "ip", "value": "1.2.3.4"}]
    });

    let line = serde_json::to_string(&incident).context("serialize test incident")?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    writeln!(f, "{line}").context("write test incident")?;
    f.flush().context("flush test incident")
}

/// Returns the machine hostname (best-effort).
pub(super) fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_synthetic_incident() {
        let incident = make_synthetic_incident("test1", "10.0.0.5", "Manual block test");

        assert_eq!(incident.incident_id, "dashboard:manual:test1");
        assert_eq!(incident.summary, "Manual block test");
        assert_eq!(incident.tags, vec!["dashboard", "manual"]);

        let has_ip = incident
            .entities
            .iter()
            .any(|e| e.value == "10.0.0.5" && format!("{:?}", e.r#type) == "Ip");
        assert!(has_ip);
    }
}
