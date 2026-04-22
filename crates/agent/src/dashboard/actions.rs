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
///
/// Source-of-truth contract (see `.claude-local/NUMBER_CONSISTENCY.md` row "quickwins
/// suggestions"): a suggestion is an `incidents-{today,yesterday}.jsonl` row with
/// severity ∈ {`high`, `critical`} (lowercase, per `Severity` `#[serde(rename_all =
/// "lowercase")]`) whose primary IP entity does NOT appear in `decisions-*.jsonl`
/// with `action_type == "block_ip"` (NOT `action`, which is not a writer field —
/// see `crates/agent/src/decisions.rs::DecisionEntry::action_type`).
///
/// Any change to `Severity` casing, `DecisionEntry::action_type`, or the JSONL
/// filename pattern MUST update this handler AND the regression test that pins
/// it (`tests::api_quickwins_*`).
///
/// The actual work (synchronous JSONL scan) runs on the blocking thread pool
/// via `tokio::task::spawn_blocking` so it does not stall the dashboard's async
/// worker threads — the JSONL scan can take tens of milliseconds on busy days
/// (`RECURRING_BUGS.md` "Dashboard handlers block tokio worker threads").
pub(super) async fn api_quickwins(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let data_dir = state.data_dir.clone();
    let payload = tokio::task::spawn_blocking(move || quickwins_payload(&data_dir))
        .await
        .unwrap_or_else(|_| serde_json::json!({"suggestions": [], "count": 0}));
    Json(payload)
}

/// Pure helper extracted from `api_quickwins` so the JSONL-based logic is
/// directly unit-testable against a tempdir without spinning up the dashboard
/// server.
pub(super) fn quickwins_payload(data_dir: &std::path::Path) -> serde_json::Value {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    let dates = [today.as_str(), yesterday.as_str()];

    // Collect blocked IPs from decisions (today + yesterday).
    // Field name MUST be `action_type` to match `DecisionEntry::action_type`
    // (decisions.rs:26). The previous reader used `action`, which never exists
    // in the writer schema and silently produced an empty set.
    let mut blocked_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for date in &dates {
        let path = data_dir.join(format!("decisions-{date}.jsonl"));
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if v["action_type"].as_str() == Some("block_ip") {
                if let Some(ip) = v["target_ip"].as_str() {
                    blocked_ips.insert(ip.to_string());
                }
            }
        }
    }

    // Collect high/critical incidents from today + yesterday.
    // Severity comparison is case-insensitive — the wire format is lowercase
    // (per Severity `#[serde(rename_all = "lowercase")]`), but the test fixture
    // and any future writer that violates that should still be filtered, not
    // silently included.
    let mut suggestions: Vec<serde_json::Value> = Vec::new();
    let mut seen_ips: std::collections::HashSet<String> = blocked_ips.clone();
    for date in &dates {
        let path = data_dir.join(format!("incidents-{date}.jsonl"));
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let sev = v["severity"].as_str().unwrap_or("");
            if !sev.eq_ignore_ascii_case("high") && !sev.eq_ignore_ascii_case("critical") {
                continue;
            }
            let ip = v["entities"].as_array().and_then(|arr| {
                arr.iter()
                    .find(|e| {
                        // Match either the original "Ip" capitalization or the
                        // serde-derived lowercase form. Defensive against future
                        // serde rename changes on EntityType.
                        e["type"]
                            .as_str()
                            .map(|s| s.eq_ignore_ascii_case("ip"))
                            .unwrap_or(false)
                    })
                    .and_then(|e| e["value"].as_str())
                    .map(|s| s.to_string())
            });
            let Some(ip_str) = ip else {
                continue;
            };
            if seen_ips.contains(&ip_str) {
                continue;
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

    serde_json::json!({
        "suggestions": suggestions,
        "count": suggestions.len()
    })
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
    if let Err(e) = validate_action_params(&ip, &body.reason) {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: e.to_string(),
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

pub(super) fn validate_action_params(target: &str, reason: &str) -> Result<(), &'static str> {
    if target.trim().is_empty() {
        return Err("target is required");
    }
    if reason.trim().is_empty() {
        return Err("reason is required");
    }
    let t = target.trim();
    if t == "127.0.0.1"
        || t == "::1"
        || t.starts_with("10.")
        || t.starts_with("192.168.")
        || (t.starts_with("172.")
            && t.len() >= 6
            && t[4..6].parse::<u8>().is_ok()
            && (16..=31).contains(&t[4..6].parse::<u8>().unwrap()))
    {
        return Err("cannot target internal IP");
    }
    Ok(())
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

    #[test]
    fn test_validate_action_params() {
        // Validates common guardrails for action parameter validation.
        // Vazio rejeita
        assert_eq!(
            validate_action_params("", "reason").unwrap_err(),
            "target is required"
        );
        assert_eq!(
            validate_action_params("1.2.3.4", "").unwrap_err(),
            "reason is required"
        );

        // Interno rejeita
        assert_eq!(
            validate_action_params("127.0.0.1", "test").unwrap_err(),
            "cannot target internal IP"
        );
        assert_eq!(
            validate_action_params("10.0.0.5", "test").unwrap_err(),
            "cannot target internal IP"
        );
        assert_eq!(
            validate_action_params("192.168.1.1", "test").unwrap_err(),
            "cannot target internal IP"
        );
        assert_eq!(
            validate_action_params("172.16.0.1", "test").unwrap_err(),
            "cannot target internal IP"
        );

        // Allowed
        assert!(validate_action_params("8.8.8.8", "reason").is_ok());
        assert!(validate_action_params("admin", "reason").is_ok());
    }

    #[test]
    fn test_block_ip_empty_string_is_rejected() {
        // Empty target string should be rejected for block-ip action.
        let result = validate_action_params("   ", "manual investigation");
        assert!(result.is_err());
        assert_eq!(result.err(), Some("target is required"));
    }

    #[test]
    fn test_block_ip_private_ranges_are_rejected() {
        // Internal RFC1918 ranges must not be accepted by block-ip.
        assert_eq!(
            validate_action_params("10.42.0.9", "internal should fail").err(),
            Some("cannot target internal IP")
        );
        assert_eq!(
            validate_action_params("192.168.10.20", "internal should fail").err(),
            Some("cannot target internal IP")
        );
    }

    #[test]
    fn test_unblock_nonexistent_ip_is_noop() {
        // Removing an IP that does not exist should be a safe no-op.
        let mut blocked = std::collections::HashSet::from(["8.8.8.8".to_string()]);
        let removed = blocked.remove("9.9.9.9");
        assert!(!removed);
        assert!(blocked.contains("8.8.8.8"));
    }

    // ── api_quickwins regression suite ───────────────────────────────
    //
    // Anchors for the bug surfaced 2026-04-22 (`.claude-local/RECURRING_BUGS.md`):
    //   1. Reader looked at JSON field `action`, but writer (`decisions.rs`)
    //      writes `action_type`. Blocked-IP set was always empty.
    //   2. Severity filter compared against "High"/"Critical" but on-disk values
    //      are lowercase per `Severity` `#[serde(rename_all = "lowercase")]`.
    //
    // Fixtures use the on-disk JSONL field names directly so a future schema
    // rename on either side will fail these tests.

    fn write_jsonl(dir: &std::path::Path, name: &str, lines: &[serde_json::Value]) {
        let path = dir.join(name);
        let mut buf = String::new();
        for v in lines {
            buf.push_str(&serde_json::to_string(v).unwrap());
            buf.push('\n');
        }
        std::fs::write(&path, buf).expect("write fixture jsonl");
    }

    fn today_str() -> String {
        chrono::Utc::now().format("%Y-%m-%d").to_string()
    }

    fn high_incident(ip: &str, title: &str) -> serde_json::Value {
        serde_json::json!({
            "severity": "high",
            "title": title,
            "entities": [{"type": "Ip", "value": ip}],
        })
    }

    fn critical_incident(ip: &str, title: &str) -> serde_json::Value {
        serde_json::json!({
            "severity": "critical",
            "title": title,
            "entities": [{"type": "Ip", "value": ip}],
        })
    }

    fn block_decision(ip: &str) -> serde_json::Value {
        // Use the writer's actual field names. If `decisions.rs::DecisionEntry`
        // ever renames `action_type`, this fixture and the production reader
        // both need to update — that is the contract.
        serde_json::json!({
            "action_type": "block_ip",
            "target_ip": ip,
        })
    }

    #[test]
    fn api_quickwins_returns_unblocked_high_severity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();

        // 1 high-severity incident from an unblocked IP, 1 high-severity from a
        // blocked IP, 1 low-severity (must be filtered out).
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[
                high_incident("203.0.113.10", "ssh bruteforce"),
                high_incident("198.51.100.5", "port scan"),
                serde_json::json!({
                    "severity": "low",
                    "title": "noise",
                    "entities": [{"type": "Ip", "value": "203.0.113.99"}],
                }),
            ],
        );
        write_jsonl(
            dir.path(),
            &format!("decisions-{date}.jsonl"),
            &[block_decision("198.51.100.5")],
        );

        let payload = quickwins_payload(dir.path());
        let suggestions = payload["suggestions"].as_array().expect("suggestions");
        assert_eq!(payload["count"].as_u64(), Some(1));
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0]["ip"].as_str(), Some("203.0.113.10"));
        assert_eq!(suggestions[0]["severity"].as_str(), Some("high"));
        assert_eq!(
            suggestions[0]["title"].as_str(),
            Some("ssh bruteforce"),
            "title should round-trip from incident"
        );
    }

    #[test]
    fn api_quickwins_accepts_critical_severity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[critical_incident("203.0.113.42", "ransomware burst")],
        );
        let payload = quickwins_payload(dir.path());
        assert_eq!(payload["count"].as_u64(), Some(1));
        assert_eq!(
            payload["suggestions"][0]["severity"].as_str(),
            Some("critical")
        );
    }

    #[test]
    fn api_quickwins_dedupes_blocked_ip_via_action_type_field() {
        // Regression for the field-name bug. The writer uses `action_type`,
        // the previous reader looked at `action`. If the reader reverts to
        // `action`, the blocked IP will not be removed and this test fails.
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[high_incident("203.0.113.99", "double-counted threat")],
        );
        write_jsonl(
            dir.path(),
            &format!("decisions-{date}.jsonl"),
            &[block_decision("203.0.113.99")],
        );

        let payload = quickwins_payload(dir.path());
        assert_eq!(
            payload["count"].as_u64(),
            Some(0),
            "blocked IP must be filtered out — if this fails, the action_type field name regressed"
        );
    }

    #[test]
    fn api_quickwins_ignores_low_severity_case_insensitive() {
        // Regression for the severity-case bug. Fixture writes both "high"
        // (correct) and "HIGH" (defensive — should still be accepted by a
        // case-insensitive comparison) and "low" (must be rejected).
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[
                serde_json::json!({
                    "severity": "HIGH",
                    "title": "uppercase wire format",
                    "entities": [{"type": "Ip", "value": "203.0.113.1"}],
                }),
                serde_json::json!({
                    "severity": "low",
                    "title": "noise",
                    "entities": [{"type": "Ip", "value": "203.0.113.2"}],
                }),
            ],
        );
        let payload = quickwins_payload(dir.path());
        assert_eq!(payload["count"].as_u64(), Some(1));
        assert_eq!(
            payload["suggestions"][0]["ip"].as_str(),
            Some("203.0.113.1")
        );
    }

    #[test]
    fn api_quickwins_dedupes_repeated_ip_within_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[
                high_incident("203.0.113.7", "first hit"),
                high_incident("203.0.113.7", "second hit same IP"),
            ],
        );
        let payload = quickwins_payload(dir.path());
        assert_eq!(payload["count"].as_u64(), Some(1));
    }

    #[test]
    fn api_quickwins_returns_empty_when_no_files_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = quickwins_payload(dir.path());
        assert_eq!(payload["count"].as_u64(), Some(0));
        assert!(payload["suggestions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn api_quickwins_skips_malformed_jsonl_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        let path = dir.path().join(format!("incidents-{date}.jsonl"));
        std::fs::write(
            &path,
            // first line is valid, second is broken JSON, third is valid again
            format!(
                "{}\nnot-json-at-all\n{}\n",
                serde_json::to_string(&high_incident("203.0.113.10", "valid 1")).unwrap(),
                serde_json::to_string(&high_incident("203.0.113.20", "valid 2")).unwrap(),
            ),
        )
        .unwrap();
        let payload = quickwins_payload(dir.path());
        assert_eq!(
            payload["count"].as_u64(),
            Some(2),
            "malformed lines must be skipped, not abort the scan"
        );
    }
}
