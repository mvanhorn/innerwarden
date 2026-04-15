use std::path::Path;

use tracing::{info, warn};

use crate::{config, decisions, knowledge_graph, telegram, two_factor, AgentState};

// ---------------------------------------------------------------------------
// Phase 6B: Graph-based bot helpers (no JSONL reads)
// ---------------------------------------------------------------------------

/// Count incidents or decisions from the knowledge graph.
/// `count_type` selects what to count: "incidents" or "decisions".
pub(crate) fn graph_count(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    count_type: &str,
) -> usize {
    use knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();
    match count_type {
        "incidents" => graph.nodes_of_type(NodeType::Incident).len(),
        "decisions" => {
            let mut n = 0;
            for id in graph.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    decision: Some(_), ..
                }) = graph.get_node(id)
                {
                    n += 1;
                }
            }
            n
        }
        _ => 0,
    }
}

/// Read the last N incidents from graph, formatted for Telegram display.
pub(crate) fn graph_last_incidents(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    n: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType, Relation};
    let graph = kg.read().unwrap();

    let mut items: Vec<(chrono::DateTime<chrono::Utc>, String, String, String)> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            severity,
            title,
            ts,
            ..
        }) = graph.get_node(id)
        {
            // Find first entity via TriggeredBy
            let entity = graph
                .outgoing_edges(id)
                .iter()
                .find(|e| e.relation == Relation::TriggeredBy)
                .and_then(|e| graph.get_node(e.to))
                .map(|n| n.label())
                .unwrap_or_else(|| "?".to_string());

            items.push((*ts, severity.to_lowercase(), title.clone(), entity));
        }
    }

    if items.is_empty() {
        return "\u{1f507} Clean slate - no intrusion attempts today.".to_string();
    }

    // Sort by ts descending, take last N
    items.sort_by(|a, b| b.0.cmp(&a.0));
    items.truncate(n);

    let now = chrono::Utc::now();
    let sev_icon = |s: &str| match s {
        "critical" => "\u{1f534}",
        "high" => "\u{1f7e0}",
        "medium" => "\u{1f7e1}",
        "low" => "\u{1f7e2}",
        _ => "\u{26aa}",
    };

    let formatted: Vec<String> = items
        .into_iter()
        .map(|(ts, severity, title, entity)| {
            let icon = sev_icon(&severity);
            let mins = now.signed_duration_since(ts).num_minutes();
            let age = if mins < 1 {
                "just now".to_string()
            } else if mins < 60 {
                format!("{mins}m ago")
            } else {
                format!("{}h ago", mins / 60)
            };
            format!("{icon} {title}\n   <code>{entity}</code> \u{b7} {age}")
        })
        .collect();

    format!(
        "\u{1f6a8} <b>Recent threats</b> (last {})\n\n{}",
        formatted.len(),
        formatted.join("\n\n")
    )
}

/// Row collected for the Telegram "last decisions" summary:
/// (timestamp, action, target, confidence, auto_executed).
type DecisionRow = (
    chrono::DateTime<chrono::Utc>,
    String,
    String,
    Option<f32>,
    bool,
);

/// Read the last N decisions from graph, formatted for Telegram display.
pub(crate) fn graph_last_decisions(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    n: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();

    let mut items: Vec<DecisionRow> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            ts,
            decision: Some(action),
            decision_target,
            confidence,
            auto_executed,
            ..
        }) = graph.get_node(id)
        {
            let target = decision_target.as_deref().unwrap_or("?").to_string();
            items.push((*ts, action.clone(), target, *confidence, *auto_executed));
        }
    }

    if items.is_empty() {
        return "\u{2696}\u{fe0f} No decisions yet today - standing by.".to_string();
    }

    items.sort_by(|a, b| b.0.cmp(&a.0));
    items.truncate(n);

    let action_icon = |a: &str| {
        if a.contains("block") {
            "\u{1f6ab}"
        } else if a.contains("suspend") {
            "\u{1f451}"
        } else if a.contains("honeypot") {
            "\u{1f36f}"
        } else if a.contains("monitor") {
            "\u{1f441}"
        } else if a.contains("kill") {
            "\u{1f480}"
        } else if a.contains("ignore") {
            "\u{1f648}"
        } else {
            "\u{26a1}"
        }
    };

    let formatted: Vec<String> = items
        .into_iter()
        .map(|(_, action, target, confidence, auto_executed)| {
            let icon = action_icon(&action);
            let pct = (confidence.unwrap_or(0.0) * 100.0) as u32;
            let mode = if auto_executed { "live" } else { "sim" };
            format!("{icon} {action} <code>{target}</code>\n   {pct}% confidence \u{b7} {mode}")
        })
        .collect();

    format!(
        "\u{2696}\u{fe0f} <b>Recent decisions</b> (last {})\n\n{}",
        formatted.len(),
        formatted.join("\n\n")
    )
}

/// Read the last N incidents as compact strings for AI context (graph-based).
pub(crate) fn graph_last_incidents_raw(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    n: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();

    let mut items: Vec<(chrono::DateTime<chrono::Utc>, String, String, String)> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            severity,
            title,
            summary,
            ts,
            ..
        }) = graph.get_node(id)
        {
            let short_summary: String = summary.chars().take(120).collect();
            items.push((*ts, severity.to_lowercase(), title.clone(), short_summary));
        }
    }

    if items.is_empty() {
        return String::new();
    }

    items.sort_by(|a, b| b.0.cmp(&a.0));
    items.truncate(n);

    items
        .into_iter()
        .map(|(_, sev, title, summary)| format!("[{sev}] {title} - {summary}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TelegramTriageAction<'a> {
    AllowProc(&'a str),
    AllowIp(&'a str),
    ReportFp(&'a str),
}

pub(crate) fn parse_telegram_triage_action(incident_id: &str) -> Option<TelegramTriageAction<'_>> {
    if let Some(rest) = incident_id.strip_prefix("__allow_proc__:") {
        Some(TelegramTriageAction::AllowProc(rest))
    } else if let Some(rest) = incident_id.strip_prefix("__allow_ip__:") {
        Some(TelegramTriageAction::AllowIp(rest))
    } else {
        incident_id
            .strip_prefix("__fp__:")
            .map(TelegramTriageAction::ReportFp)
    }
}

pub(crate) fn sanitize_allowlist_process_name(raw: &str) -> Option<String> {
    let cleaned = raw.replace('"', "").replace('\n', " ").trim().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Handle triage sentinels from Telegram callbacks:
/// "__allow_proc__", "__allow_ip__", "__fp__".
/// Returns true when a triage callback was matched and handled.
pub(crate) fn handle_telegram_triage_action(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let Some(action) = parse_telegram_triage_action(&result.incident_id) else {
        return false;
    };

    match action {
        TelegramTriageAction::AllowProc(comm_raw) => {
            let Some(comm) = sanitize_allowlist_process_name(comm_raw) else {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "allowlist_add",
                    None,
                    Some("process:(empty)".to_string()),
                    format!(
                        "Operator {} attempted to add empty process allowlist via Telegram",
                        result.operator_name
                    ),
                    "skipped:empty_process_name".to_string(),
                );
                tg_reply(state, "⚠️ Could not add empty process name to allowlist.");
                return true;
            };
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::AllowlistProcess(comm.clone()),
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let reason = format!("Allowed via Telegram ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "processes", &comm, &reason) {
                Ok(()) => {
                    // Log to allowlist history for undo support
                    telegram::log_allowlist_change(
                        data_dir,
                        &comm,
                        "processes",
                        &result.operator_name,
                        "add",
                    );
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        None,
                        Some(format!("process:{comm}")),
                        format!(
                            "Operator {} added process '{}' to allowlist via Telegram",
                            result.operator_name, comm
                        ),
                        format!("allowlist_process_added:{comm}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        comm = %comm,
                        path = %allowlist_path.display(),
                        "Telegram triage allowlist (process) applied"
                    );

                    // 2FA nudge if not enabled
                    let two_fa_enabled = cfg
                        .security
                        .as_ref()
                        .map(|s| s.two_factor_method != "none")
                        .unwrap_or(false);
                    let confirmation_suffix = if two_fa_enabled {
                        " (verified by TOTP)"
                    } else {
                        ""
                    };
                    let mut msg = format!(
                        "\u{2705} Allowed <code>{comm}</code>{confirmation_suffix}. Sensor will pick this up in up to 60s."
                    );
                    if !two_fa_enabled {
                        msg.push_str(
                            "\n\n\u{26a0}\u{fe0f} Allowlist changes are not protected by 2FA.\n\
                             Anyone with your bot token can silence alerts.",
                        );
                    }
                    if two_fa_enabled {
                        tg_reply(state, msg);
                    } else if let Some(ref tg) = state.telegram_client {
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let keyboard = serde_json::json!([
                                [
                                    { "text": "\u{1f510} Enable 2FA", "callback_data": "enable2fa" },
                                    { "text": "\u{1f44d} Dismiss", "callback_data": "dismiss2fa" }
                                ]
                            ]);
                            let _ = tg.send_text_with_keyboard(&msg, keyboard).await;
                        });
                    }
                }
                Err(e) => {
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        None,
                        Some(format!("process:{comm}")),
                        format!(
                            "Operator {} failed to add process '{}' to allowlist via Telegram",
                            result.operator_name, comm
                        ),
                        format!(
                            "failed:{}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                    warn!(
                        operator = %result.operator_name,
                        comm = %comm,
                        error = %e,
                        "failed to append process allowlist entry from Telegram"
                    );
                    tg_reply(
                        state,
                        format!(
                            "❌ Failed to allowlist <code>{comm}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        TelegramTriageAction::AllowIp(ip_raw) => {
            let ip = ip_raw.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_err() {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "allowlist_add",
                    Some(ip.clone()),
                    None,
                    format!(
                        "Operator {} attempted to add invalid IP '{}' to allowlist via Telegram",
                        result.operator_name, ip
                    ),
                    "skipped:invalid_ip".to_string(),
                );
                warn!(
                    operator = %result.operator_name,
                    ip = %ip,
                    "invalid ip in Telegram allowlist callback"
                );
                tg_reply(
                    state,
                    format!("⚠️ Invalid IP for allowlist: <code>{ip}</code>"),
                );
                return true;
            }
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::AllowlistIp(ip.clone()),
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let reason = format!("Allowed via Telegram ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "ips", &ip, &reason) {
                Ok(()) => {
                    // Log to allowlist history for undo support
                    telegram::log_allowlist_change(
                        data_dir,
                        &ip,
                        "ips",
                        &result.operator_name,
                        "add",
                    );
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!(
                            "Operator {} added IP '{}' to allowlist via Telegram",
                            result.operator_name, ip
                        ),
                        format!("allowlist_ip_added:{ip}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        ip = %ip,
                        path = %allowlist_path.display(),
                        "Telegram triage allowlist (ip) applied"
                    );

                    // 2FA nudge if not enabled
                    let two_fa_enabled = cfg
                        .security
                        .as_ref()
                        .map(|s| s.two_factor_method != "none")
                        .unwrap_or(false);
                    let confirmation_suffix = if two_fa_enabled {
                        " (verified by TOTP)"
                    } else {
                        ""
                    };
                    let mut msg = format!(
                        "\u{2705} Allowed <code>{ip}</code>{confirmation_suffix}. Sensor will pick this up in up to 60s."
                    );
                    if !two_fa_enabled {
                        msg.push_str(
                            "\n\n\u{26a0}\u{fe0f} Allowlist changes are not protected by 2FA.\n\
                             Anyone with your bot token can silence alerts.",
                        );
                    }
                    if two_fa_enabled {
                        tg_reply(state, msg);
                    } else if let Some(ref tg) = state.telegram_client {
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let keyboard = serde_json::json!([
                                [
                                    { "text": "\u{1f510} Enable 2FA", "callback_data": "enable2fa" },
                                    { "text": "\u{1f44d} Dismiss", "callback_data": "dismiss2fa" }
                                ]
                            ]);
                            let _ = tg.send_text_with_keyboard(&msg, keyboard).await;
                        });
                    }
                }
                Err(e) => {
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!(
                            "Operator {} failed to add IP '{}' to allowlist via Telegram",
                            result.operator_name, ip
                        ),
                        format!(
                            "failed:{}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                    warn!(
                        operator = %result.operator_name,
                        ip = %ip,
                        error = %e,
                        "failed to append ip allowlist entry from Telegram"
                    );
                    tg_reply(
                        state,
                        format!(
                            "❌ Failed to allowlist <code>{ip}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        TelegramTriageAction::ReportFp(raw_incident_id) => {
            let incident_id = raw_incident_id.trim();
            if incident_id.is_empty() {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "fp_report",
                    None,
                    None,
                    format!(
                        "Operator {} attempted to report FP with empty incident id",
                        result.operator_name
                    ),
                    "skipped:empty_incident_id".to_string(),
                );
                tg_reply(
                    state,
                    "⚠️ Could not report false positive: missing incident id.",
                );
                return true;
            }
            let detector = incident_id.split(':').next().unwrap_or("unknown");
            telegram::log_false_positive(data_dir, incident_id, detector, &result.operator_name);
            // Phase 7 Gap 1: mark incident as FP in the knowledge graph
            {
                let mut graph = state.knowledge_graph.write().unwrap();
                if let Some(node_id) = graph.find_by_incident(incident_id) {
                    graph.mark_false_positive(node_id, &result.operator_name);
                }
            }
            write_telegram_triage_audit(
                state,
                incident_id,
                &result.operator_name,
                "fp_report",
                None,
                None,
                format!(
                    "Operator {} reported incident '{}' as false positive via Telegram",
                    result.operator_name, incident_id
                ),
                format!("reported_fp:{detector}"),
            );
            info!(
                operator = %result.operator_name,
                incident_id = %incident_id,
                detector = %detector,
                "Telegram triage false-positive reported"
            );
            tg_reply(state, "📝 Reported. Thanks for the feedback.");
        }
    }

    true
}

// ---------------------------------------------------------------------------
// 2FA gate — intercepts sensitive actions when TOTP is enabled
// ---------------------------------------------------------------------------

/// Check if 2FA is enabled in config.
pub(crate) fn is_2fa_enabled(cfg: &config::AgentConfig) -> bool {
    cfg.security
        .as_ref()
        .map(|s| s.two_factor_method == "totp")
        .unwrap_or(false)
}

/// Get the TOTP secret from config (resolved from env var or toml).
fn totp_secret(cfg: &config::AgentConfig) -> Option<String> {
    // Check env var first (preferred), then config field
    std::env::var("INNERWARDEN_TOTP_SECRET")
        .ok()
        .or_else(|| cfg.security.as_ref().map(|s| s.totp_secret.clone()))
        .filter(|s| !s.is_empty())
}

/// If 2FA is enabled, intercept the action: store as pending and ask for TOTP code.
/// Returns `true` if the action was intercepted (caller should return without executing).
/// Returns `false` if 2FA is disabled (caller should proceed normally).
pub(crate) fn check_2fa_gate(
    state: &mut AgentState,
    cfg: &config::AgentConfig,
    operator: &str,
    action: two_factor::PendingActionType,
) -> bool {
    if !is_2fa_enabled(cfg) {
        return false;
    }

    // Check lockout before accepting a new action
    if state.two_factor_state.is_locked_out(operator) {
        tg_reply(
            state,
            "\u{1f6ab} Too many failed 2FA attempts. Try again later.",
        );
        return true;
    }

    let now = chrono::Utc::now();
    let pending = two_factor::PendingAction {
        action_type: action,
        operator: operator.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        method: two_factor::TwoFactorMethod::Totp,
    };
    state.two_factor_state.set_pending(operator, pending);

    tg_reply(
        state,
        "\u{1f510} Enter your 6-digit TOTP code (expires in 5 min):",
    );
    info!(operator = %operator, "2FA: pending action stored, waiting for TOTP code");
    true
}

/// Try to handle a Telegram message as a TOTP code response.
/// Returns `true` if it was recognized as a TOTP attempt (code or cancel).
pub(crate) fn handle_totp_response(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let text = result.incident_id.trim();

    // Cancel pending 2FA
    if text == "/cancel" {
        if state
            .two_factor_state
            .take_pending(&result.operator_name)
            .is_some()
        {
            tg_reply(state, "\u{274c} 2FA verification cancelled.");
            return true;
        }
        return false;
    }

    // Only intercept 6-digit numeric strings when there's a pending action
    let is_6_digits = text.len() == 6 && text.chars().all(|c| c.is_ascii_digit());
    if !is_6_digits {
        return false;
    }

    let pending = match state.two_factor_state.take_pending(&result.operator_name) {
        Some(p) => p,
        None => return false, // No pending action — not a TOTP attempt
    };

    // Check if expired
    if pending.expires_at < chrono::Utc::now() {
        tg_reply(state, "\u{23f0} 2FA code expired. Please retry the action.");
        return true;
    }

    // Verify TOTP code
    let secret = match totp_secret(cfg) {
        Some(s) => s,
        None => {
            warn!("2FA enabled but no TOTP secret configured");
            tg_reply(
                state,
                "\u{26a0}\u{fe0f} 2FA is enabled but no TOTP secret is configured. Run: innerwarden configure 2fa",
            );
            return true;
        }
    };

    let provider = match two_factor::TotpProvider::new(&secret) {
        Some(p) => p,
        None => {
            warn!("2FA: invalid TOTP secret in config");
            tg_reply(
                state,
                "\u{26a0}\u{fe0f} Invalid TOTP secret. Re-run: innerwarden configure 2fa",
            );
            return true;
        }
    };

    if !provider.verify(text) {
        state.two_factor_state.record_failure(&result.operator_name);
        if state.two_factor_state.is_locked_out(&result.operator_name) {
            tg_reply(
                state,
                "\u{274c} Wrong code. You are now locked out for 1 hour.",
            );
        } else {
            // Re-store the pending action so operator can retry
            state
                .two_factor_state
                .set_pending(&result.operator_name, pending);
            tg_reply(state, "\u{274c} Wrong code. Try again or /cancel.");
        }
        return true;
    }

    // Code verified — execute the pending action
    info!(
        operator = %result.operator_name,
        action = ?pending.action_type,
        "2FA: TOTP verified, executing pending action"
    );
    execute_verified_action(pending.action_type, &result.operator_name, data_dir, state);
    true
}

/// Execute a 2FA-verified action.
fn execute_verified_action(
    action: two_factor::PendingActionType,
    operator: &str,
    data_dir: &Path,
    state: &mut AgentState,
) {
    let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

    match action {
        two_factor::PendingActionType::AllowlistProcess(ref comm) => {
            let reason = format!("Allowed via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "processes", comm, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, comm, "processes", operator, "add");
                    write_telegram_triage_audit(
                        state, "__2fa_verified__", operator, "allowlist_add",
                        None, Some(format!("process:{comm}")),
                        format!("Operator {operator} added process '{comm}' to allowlist (2FA verified)"),
                        format!("allowlist_process_added:{comm}"),
                    );
                    tg_reply(state, format!(
                        "\u{2705} Allowed <code>{comm}</code> (verified by TOTP). Sensor will pick this up in up to 60s."
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to allowlist <code>{comm}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::AllowlistIp(ref ip) => {
            let reason = format!("Allowed via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "ips", ip, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, ip, "ips", operator, "add");
                    write_telegram_triage_audit(
                        state,
                        "__2fa_verified__",
                        operator,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!("Operator {operator} added IP '{ip}' to allowlist (2FA verified)"),
                        format!("allowlist_ip_added:{ip}"),
                    );
                    tg_reply(state, format!(
                        "\u{2705} Allowed <code>{ip}</code> (verified by TOTP). Sensor will pick this up in up to 60s."
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to allowlist <code>{ip}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::UndoAllowlist {
            ref section,
            ref key,
        } => match telegram::remove_from_allowlist(allowlist_path, section, key) {
            Ok(()) => {
                telegram::log_allowlist_change(data_dir, key, section, operator, "remove");
                write_telegram_triage_audit(
                        state, "__2fa_verified__", operator, "allowlist_remove",
                        None, None,
                        format!("Operator {operator} removed '{key}' from {section} allowlist (2FA verified)"),
                        format!("allowlist_removed:{key}"),
                    );
                tg_reply(
                    state,
                    format!(
                        "\u{2705} Removed <code>{}</code> from allowlist (verified by TOTP).",
                        telegram::escape_html_pub(key)
                    ),
                );
            }
            Err(e) => {
                tg_reply(
                    state,
                    format!(
                        "\u{274c} Failed to remove <code>{}</code>: {}",
                        telegram::escape_html_pub(key),
                        e.to_string().chars().take(180).collect::<String>()
                    ),
                );
            }
        },
        two_factor::PendingActionType::AutoFpAllowlist {
            ref section,
            ref entity,
        } => {
            let reason = format!("Auto-FP allowlist via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, section, entity, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, entity, section, operator, "add");
                    tg_reply(state, format!(
                        "\u{2705} Added <code>{}</code> to {} allowlist permanently (verified by TOTP).",
                        telegram::escape_html_pub(entity), section
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to add to allowlist: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format an RFC3339 timestamp as a human-readable "X ago" string.
pub(crate) fn format_time_ago(ts_str: &str) -> String {
    let ts = match chrono::DateTime::parse_from_rfc3339(ts_str) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(_) => return "recently".to_string(),
    };
    let diff = chrono::Utc::now() - ts;
    if diff.num_days() > 0 {
        format!("{}d ago", diff.num_days())
    } else if diff.num_hours() > 0 {
        format!("{}h ago", diff.num_hours())
    } else {
        format!("{}m ago", diff.num_minutes().max(1))
    }
}

pub(crate) fn local_hostname_for_audit() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn tg_reply(state: &AgentState, text: impl Into<String>) {
    if let Some(ref tg) = state.telegram_client {
        let tg = tg.clone();
        let text = text.into();
        tokio::spawn(async move {
            let _ = tg.send_text_message(&text).await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_telegram_triage_audit(
    state: &mut AgentState,
    incident_id: &str,
    operator: &str,
    action_type: &str,
    target_ip: Option<String>,
    target_user: Option<String>,
    reason: String,
    execution_result: String,
) {
    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: local_hostname_for_audit(),
            ai_provider: format!("operator:telegram:{operator}"),
            action_type: action_type.to_string(),
            target_ip,
            target_user,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason,
            estimated_threat: "manual".to_string(),
            execution_result,
            prev_hash: None,
        };
        if let Err(e) = writer.write(&entry) {
            warn!(
                error = %e,
                action_type,
                incident_id,
                operator,
                "failed to write Telegram triage audit entry"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_telegram_triage_action ---

    #[test]
    fn parse_allow_proc_action() {
        let action = parse_telegram_triage_action("__allow_proc__:sshd");
        assert_eq!(action, Some(TelegramTriageAction::AllowProc("sshd")));
    }

    #[test]
    fn parse_allow_ip_action() {
        let action = parse_telegram_triage_action("__allow_ip__:1.2.3.4");
        assert_eq!(action, Some(TelegramTriageAction::AllowIp("1.2.3.4")));
    }

    #[test]
    fn parse_fp_action() {
        let action = parse_telegram_triage_action("__fp__:ssh_bruteforce:1.2.3.4:abc");
        assert_eq!(
            action,
            Some(TelegramTriageAction::ReportFp("ssh_bruteforce:1.2.3.4:abc"))
        );
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert_eq!(parse_telegram_triage_action("some:normal:incident"), None);
        assert_eq!(parse_telegram_triage_action(""), None);
        assert_eq!(parse_telegram_triage_action("__unknown__:xyz"), None);
    }

    // --- sanitize_allowlist_process_name ---

    #[test]
    fn sanitize_normal_name() {
        assert_eq!(
            sanitize_allowlist_process_name("sshd"),
            Some("sshd".to_string())
        );
    }

    #[test]
    fn sanitize_strips_quotes_and_trims() {
        assert_eq!(
            sanitize_allowlist_process_name("  \"my_proc\"  "),
            Some("my_proc".to_string())
        );
    }

    #[test]
    fn sanitize_replaces_newlines() {
        assert_eq!(
            sanitize_allowlist_process_name("proc\nwith\nnewlines"),
            Some("proc with newlines".to_string())
        );
    }

    #[test]
    fn sanitize_empty_returns_none() {
        assert_eq!(sanitize_allowlist_process_name(""), None);
        assert_eq!(sanitize_allowlist_process_name("  "), None);
        assert_eq!(sanitize_allowlist_process_name("\"\""), None);
    }

    // --- is_2fa_enabled ---

    #[test]
    fn is_2fa_disabled_when_no_security_section() {
        let cfg = config::AgentConfig {
            security: None,
            ..Default::default()
        };
        assert!(!is_2fa_enabled(&cfg));
    }

    #[test]
    fn is_2fa_enabled_when_totp() {
        let cfg = config::AgentConfig {
            security: Some(config::SecurityConfig {
                two_factor_method: "totp".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(is_2fa_enabled(&cfg));
    }

    #[test]
    fn is_2fa_disabled_when_method_is_none() {
        let cfg = config::AgentConfig {
            security: Some(config::SecurityConfig {
                two_factor_method: "none".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!is_2fa_enabled(&cfg));
    }
}
