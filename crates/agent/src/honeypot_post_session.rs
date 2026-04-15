use std::path::Path;
use std::sync::Arc;

use crate::{ai, decisions, ioc, skills, telegram};

/// Extract session_id from honeypot skill result message.
/// The message format is: "Honeypot listeners started (session {session_id}, ...)"
pub(crate) fn extract_session_id_from_message(msg: &str) -> Option<String> {
    // Look for "session " followed by the session_id (ends at next ", " or ")")
    let marker = "session ";
    let start = msg.find(marker)? + marker.len();
    let rest = &msg[start..];
    let end = rest.find([',', ')']).unwrap_or(rest.len());
    let id = rest[..end].trim().to_string();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Read shell commands typed by the attacker from honeypot evidence JSONL.
async fn read_shell_commands_from_evidence(path: &Path) -> Vec<String> {
    use tokio::io::AsyncBufReadExt;
    let Ok(file) = tokio::fs::File::open(path).await else {
        return vec![];
    };
    let mut lines = tokio::io::BufReader::new(file).lines();
    let mut commands = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(mut extracted) = extract_commands_from_json(&val) {
                commands.append(&mut extracted);
            }
        }
    }
    commands
}

pub(crate) fn extract_commands_from_json(val: &serde_json::Value) -> Option<Vec<String>> {
    let mut commands = Vec::new();
    if val.get("type").and_then(|t| t.as_str()) == Some("ssh_connection") {
        if let Some(attempts) = val.get("shell_commands").and_then(|a| a.as_array()) {
            for a in attempts {
                if let Some(cmd) = a.get("command").and_then(|c| c.as_str()) {
                    if !cmd.is_empty() {
                        commands.push(cmd.to_string());
                    }
                }
            }
        }
    }
    if commands.is_empty() {
        None
    } else {
        Some(commands)
    }
}

async fn read_credentials_from_evidence(path: &Path) -> Vec<(String, Option<String>)> {
    use tokio::io::AsyncBufReadExt;
    let Ok(file) = tokio::fs::File::open(path).await else {
        return vec![];
    };
    let mut lines = tokio::io::BufReader::new(file).lines();
    let mut creds = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(mut extracted) = extract_credentials_from_json(&val) {
                creds.append(&mut extracted);
            }
        }
    }
    creds
}

pub(crate) fn extract_credentials_from_json(
    val: &serde_json::Value,
) -> Option<Vec<(String, Option<String>)>> {
    let mut creds = Vec::new();
    if val.get("type").and_then(|t| t.as_str()) == Some("ssh_connection") {
        if let Some(attempts) = val.get("auth_attempts").and_then(|a| a.as_array()) {
            for a in attempts {
                let user = a
                    .get("username")
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();
                let pass = a
                    .get("password")
                    .and_then(|p| p.as_str())
                    .map(|p| p.to_string());
                if !user.is_empty() {
                    creds.push((user, pass));
                }
            }
        }
    }
    if creds.is_empty() {
        None
    } else {
        Some(creds)
    }
}

/// Spawned in the background after a honeypot session starts.
/// Reads evidence, extracts IOCs, gets AI verdict, auto-blocks, sends Telegram report.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_post_session_tasks(
    ip: &str,
    session_id: &str,
    data_dir: &Path,
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    telegram_client: Option<Arc<telegram::TelegramClient>>,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: &str,
    allowed_skills: &[String],
    blocklist_already_has_ip: bool,
) {
    // Give the honeypot listener time to collect evidence (wait for session to end).
    // We wait for the configured duration or a reasonable maximum.
    // Since we don't have the duration here, sleep briefly then retry reading.
    // The session is async and runs in its own task; we poll the evidence file.
    let evidence_path = data_dir
        .join("honeypot")
        .join(format!("listener-session-{session_id}.jsonl"));

    // Wait up to 10 minutes for evidence to appear (polls every 30s)
    let mut commands = Vec::new();
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let cmds = read_shell_commands_from_evidence(&evidence_path).await;
        if !cmds.is_empty() {
            commands = cmds;
            break;
        }
        // Also check if metadata file shows "completed" status
        let metadata_path = data_dir
            .join("honeypot")
            .join(format!("listener-session-{session_id}.json"));
        if let Ok(content) = tokio::fs::read_to_string(&metadata_path).await {
            if content.contains("\"status\":\"completed\"")
                || content.contains("\"status\": \"completed\"")
            {
                commands = read_shell_commands_from_evidence(&evidence_path).await;
                break;
            }
        }
    }

    // Extract credentials from evidence
    let credentials = read_credentials_from_evidence(&evidence_path).await;

    // Extract IOCs from commands
    let iocs = ioc::extract_from_commands(&commands);

    // Get AI verdict
    let verdict = if let Some(ref ai) = ai_provider {
        let cmd_text = if commands.is_empty() {
            "No commands recorded.".to_string()
        } else {
            commands
                .iter()
                .take(20)
                .map(|c| format!("  $ {c}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let prompt = format!(
            "Attacker IP {ip} ran these commands in an SSH honeypot:\n{cmd_text}\n\n\
             In 1-2 sentences in English, what does this attacker appear to be doing? \
             Be specific and direct."
        );
        ai.chat(
            "You are a cybersecurity analyst. Be concise and specific.",
            &prompt,
        )
        .await
        .unwrap_or_else(|_| "Analysis unavailable.".to_string())
    } else {
        "AI analysis not configured.".to_string()
    };

    // Auto-block the attacker IP if responder is enabled and IP not already blocked
    let auto_blocked = if responder_enabled && !blocklist_already_has_ip {
        let skill_id = format!("block-ip-{block_backend}");
        if allowed_skills.iter().any(|s| s == &skill_id) {
            let iid = format!("honeypot:post-session:{session_id}");
            let inc = innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: std::env::var("HOSTNAME")
                    .or_else(|_| {
                        std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
                    })
                    .unwrap_or_else(|_| "unknown".to_string()),
                incident_id: iid.clone(),
                severity: innerwarden_core::event::Severity::High,
                title: "Honeypot Session Ended".to_string(),
                summary: format!("Attacker IP {ip} interacted with honeypot session {session_id}"),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec!["honeypot".to_string(), "post-session".to_string()],
                entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
            };
            let ctx = skills::SkillContext {
                incident: inc,
                target_ip: Some(ip.to_string()),
                target_user: None,
                target_container: None,
                duration_secs: None,
                host: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
                data_dir: data_dir.to_path_buf(),
                honeypot: skills::HoneypotRuntimeConfig::default(),
                ai_provider: None,
            };
            let skill_box: Option<Box<dyn skills::ResponseSkill>> = match block_backend {
                "iptables" => Some(Box::new(skills::builtin::BlockIpIptables)),
                "nftables" => Some(Box::new(skills::builtin::BlockIpNftables)),
                "pf" => Some(Box::new(skills::builtin::BlockIpPf)),
                _ => Some(Box::new(skills::builtin::BlockIpUfw)),
            };
            if let Some(skill) = skill_box {
                let result = skill.execute(&ctx, dry_run).await;
                if result.success {
                    // Write decision to audit trail (hash-chained)
                    let entry = decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: iid,
                        host: ctx.host.clone(),
                        ai_provider: "honeypot:post-session".to_string(),
                        action_type: "block_ip".to_string(),
                        target_ip: Some(ip.to_string()),
                        target_user: None,
                        skill_id: Some(skill_id),
                        confidence: 1.0,
                        auto_executed: true,
                        dry_run,
                        reason: format!(
                            "Attacker IP interacted with honeypot session {session_id}"
                        ),
                        estimated_threat: "confirmed-attacker".to_string(),
                        execution_result: if result.success {
                            "ok".to_string()
                        } else {
                            format!("failed: {}", result.message)
                        },
                        prev_hash: None,
                    };
                    if let Err(e) = decisions::append_chained(data_dir, &entry) {
                        tracing::warn!("honeypot post-session: failed to write decision: {e:#}");
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Send Telegram post-session report (gated through notification gate).
    let is_probe_only = commands.is_empty() && credentials.is_empty();
    if let Some(ref tg) = telegram_client {
        let duration = 300u64; // default; session duration stored in metadata
        let gate_ctx = crate::notification_gate::NotificationContext::for_honeypot_session(
            is_probe_only,
            auto_blocked,
        );
        let gate_verdict = crate::notification_gate::should_notify(&gate_ctx);
        match gate_verdict {
            crate::notification_gate::NotificationVerdict::SendNow => {
                if let Err(e) = tg
                    .send_honeypot_session_report(
                        ip,
                        session_id,
                        duration,
                        &commands,
                        &credentials,
                        &iocs,
                        &verdict,
                        auto_blocked,
                    )
                    .await
                {
                    tracing::warn!("failed to send honeypot session report via Telegram: {e:#}");
                }
            }
            crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                tracing::debug!(
                    ip,
                    session_id,
                    "honeypot: session deferred to daily briefing"
                );
            }
            crate::notification_gate::NotificationVerdict::Drop => {
                tracing::debug!(ip, session_id, "honeypot: probe-only session dropped");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_session_id_from_message() {
        let msg1 = "Honeypot listeners started (session xyz123, port 2222)";
        assert_eq!(
            extract_session_id_from_message(msg1),
            Some("xyz123".to_string())
        );

        let msg2 = "Honeypot session abc)";
        assert_eq!(
            extract_session_id_from_message(msg2),
            Some("abc".to_string())
        );

        let msg3 = "No connected instances here";
        assert_eq!(extract_session_id_from_message(msg3), None);
    }

    #[test]
    fn test_extract_commands_from_json() {
        let val = json!({
            "type": "ssh_connection",
            "shell_commands": [
                { "command": "uname -a" },
                { "command": "" },
                { "command": "whoami" }
            ]
        });

        let cmds = extract_commands_from_json(&val).unwrap();
        assert_eq!(cmds, vec!["uname -a".to_string(), "whoami".to_string()]);

        let empty_val = json!({ "type": "ssh_connection" });
        assert_eq!(extract_commands_from_json(&empty_val), None);
    }

    #[test]
    fn test_extract_credentials_from_json() {
        let val = json!({
            "type": "ssh_connection",
            "auth_attempts": [
                { "username": "root", "password": "123" },
                { "username": "admin" }, // no password
                { "password": "only" }   // no username should be skipped
            ]
        });

        let creds = extract_credentials_from_json(&val).unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0], ("root".to_string(), Some("123".to_string())));
        assert_eq!(creds[1], ("admin".to_string(), None));
    }

    // Test 18: Wrong event type returns None for commands
    #[test]
    fn test_extract_commands_wrong_type() {
        let val = json!({
            "type": "http_connection",
            "shell_commands": [
                { "command": "whoami" }
            ]
        });
        assert_eq!(extract_commands_from_json(&val), None);
    }

    // Test 19: Wrong event type returns None for credentials
    #[test]
    fn test_extract_credentials_wrong_type() {
        let val = json!({
            "type": "http_connection",
            "auth_attempts": [
                { "username": "root", "password": "pass" }
            ]
        });
        assert_eq!(extract_credentials_from_json(&val), None);
    }

    // Test 20: Session ID with trailing spaces is trimmed
    #[test]
    fn test_extract_session_id_trims_whitespace() {
        let msg = "Honeypot listeners started (session   abc123  , port 22)";
        assert_eq!(
            extract_session_id_from_message(msg),
            Some("abc123".to_string())
        );
    }
}
