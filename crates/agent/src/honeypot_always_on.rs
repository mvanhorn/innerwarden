use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use tracing::{debug, info, warn};

use crate::{abuseipdb, ai, decisions, ioc, skills, telegram};

#[derive(Debug, Clone, Copy)]
struct AlwaysOnSessionOutcome {
    had_interaction: bool,
    auto_blocked: bool,
}

fn should_auto_block_after_session(
    responder_enabled: bool,
    blocklist_already_has_ip: bool,
    had_interaction: bool,
    block_backend: &str,
    allowed_skills: &[String],
) -> bool {
    if !responder_enabled || blocklist_already_has_ip || !had_interaction {
        return false;
    }
    let skill_id = format!("block-ip-{block_backend}");
    allowed_skills.iter().any(|s| s == &skill_id)
}

fn elapsed_secs_for_report(started_at: std::time::Instant) -> u64 {
    let elapsed = started_at.elapsed();
    if elapsed.as_secs() > 0 {
        elapsed.as_secs()
    } else if elapsed.subsec_nanos() > 0 {
        1
    } else {
        0
    }
}

/// Handle a single always-on honeypot connection end-to-end:
/// SSH key exchange, credential capture, optional LLM shell, evidence write,
/// IOC extraction, AI verdict, auto-block, Telegram T.5 report.
#[allow(clippy::too_many_arguments)]
async fn handle_always_on_connection(
    stream: tokio::net::TcpStream,
    ip: String,
    ssh_cfg: Arc<russh::server::Config>,
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    telegram_client: Option<Arc<telegram::TelegramClient>>,
    gate_suppressed_counter: Arc<AtomicU64>,
    data_dir: PathBuf,
    sqlite_store: Option<Arc<innerwarden_store::Store>>,
    interaction: String,
    blocklist_already_has_ip: bool,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: String,
    allowed_skills: Vec<String>,
) -> AlwaysOnSessionOutcome {
    use skills::builtin::honeypot::ssh_interact::{
        handle_connection, SshConnectionEvidence, SshInteractionMode,
    };

    let mode = if interaction == "llm_shell" {
        if let Some(ref ai) = ai_provider {
            SshInteractionMode::LlmShell {
                ai: ai.clone(),
                hostname: "srv-prod-01".to_string(),
            }
        } else {
            SshInteractionMode::RejectAll
        }
    } else {
        // "medium" and any other value: capture creds, always reject auth
        SshInteractionMode::RejectAll
    };

    let conn_timeout = std::time::Duration::from_secs(120);
    let started_at = std::time::Instant::now();
    let evidence: SshConnectionEvidence =
        handle_connection(stream, ssh_cfg, conn_timeout, mode).await;

    // Build a unique session id.
    let session_id = format!(
        "always-on-{}-{}",
        ip.replace('.', "-"),
        chrono::Utc::now().timestamp()
    );

    // Write evidence to honeypot dir (append-only JSONL).
    let honeypot_dir = data_dir.join("honeypot");
    let _ = tokio::fs::create_dir_all(&honeypot_dir).await;
    let evidence_path = honeypot_dir.join(format!("listener-session-{session_id}.jsonl"));
    if let Ok(json) = serde_json::to_string(&serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "type": "ssh_connection",
        "session_id": &session_id,
        "peer_ip": &ip,
        "auth_attempts": evidence.auth_attempts,
        "auth_attempts_count": evidence.auth_attempts.len(),
        "shell_commands": evidence.shell_commands,
        "shell_commands_count": evidence.shell_commands.len(),
    })) {
        let line = format!("{json}\n");
        if let Ok(mut f) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&evidence_path)
            .await
        {
            use tokio::io::AsyncWriteExt;
            let _ = f.write_all(line.as_bytes()).await;
        }
    }

    // Extract shell commands for IOC analysis and AI verdict.
    let commands: Vec<String> = evidence
        .shell_commands
        .iter()
        .map(|s| s.command.clone())
        .collect();
    let had_interaction = !evidence.auth_attempts.is_empty() || !commands.is_empty();

    let iocs = ioc::extract_from_commands(&commands);

    // AI verdict (brief summary in Portuguese).
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
            "Attacker IP {ip} connected to an SSH honeypot.\n\
             Auth attempts: {}\n\
             Shell commands:\n{cmd_text}\n\n\
             In 1-2 sentences in English, what does this attacker appear to be doing? \
             Be specific and direct.",
            evidence.auth_attempts.len(),
        );
        ai.chat(
            "You are a cybersecurity analyst. Be concise and specific.",
            &prompt,
        )
        .await
        .unwrap_or_else(|_| "Analysis unavailable.".to_string())
    } else if evidence.auth_attempts.is_empty() {
        "Connection without authentication attempts - likely automated scanner.".to_string()
    } else {
        "AI not configured - no verdict available.".to_string()
    };

    // Auto-block after session only when there was real interaction
    // (auth attempts and/or shell commands). Pure connect+disconnect probes are
    // reported but not auto-blocked here.
    let auto_blocked = if should_auto_block_after_session(
        responder_enabled,
        blocklist_already_has_ip,
        had_interaction,
        &block_backend,
        &allowed_skills,
    ) {
        let skill_id = format!("block-ip-{block_backend}");
        let iid = format!("honeypot:always-on:{session_id}");
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: host.clone(),
            incident_id: iid.clone(),
            severity: innerwarden_core::event::Severity::High,
            title: "Always-on Honeypot Session Ended".to_string(),
            summary: format!(
                "Attacker IP {ip} connected to always-on honeypot session {session_id}"
            ),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["honeypot".to_string(), "always-on".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(&ip)],
        };
        let ctx = skills::SkillContext {
            incident: inc,
            target_ip: Some(ip.clone()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: host.clone(),
            data_dir: data_dir.clone(),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };
        let skill_box: Option<Box<dyn skills::ResponseSkill>> = match block_backend.as_str() {
            "iptables" => Some(Box::new(skills::builtin::BlockIpIptables)),
            "nftables" => Some(Box::new(skills::builtin::BlockIpNftables)),
            "pf" => Some(Box::new(skills::builtin::BlockIpPf)),
            _ => Some(Box::new(skills::builtin::BlockIpUfw)),
        };
        if let Some(skill) = skill_box {
            let result = skill.execute(&ctx, dry_run).await;
            if result.success {
                let entry = decisions::DecisionEntry {
                    ts: chrono::Utc::now(),
                    incident_id: iid,
                    host,
                    ai_provider: "honeypot:always-on".to_string(),
                    action_type: "block_ip".to_string(),
                    target_ip: Some(ip.clone()),
                    target_user: None,
                    skill_id: Some(skill_id),
                    confidence: 1.0,
                    auto_executed: true,
                    dry_run,
                    reason: format!(
                        "Attacker IP interacted with always-on honeypot session {session_id}"
                    ),
                    estimated_threat: "confirmed-attacker".to_string(),
                    execution_result: if result.success {
                        "ok".to_string()
                    } else {
                        format!("failed: {}", result.message)
                    },
                    prev_hash: None,
                };
                if let Err(e) = decisions::append_chained(&data_dir, &entry, sqlite_store.as_ref())
                {
                    warn!("honeypot: failed to write decision: {e:#}");
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
    };

    // Extract credentials from evidence
    let credentials: Vec<(String, Option<String>)> = evidence
        .auth_attempts
        .iter()
        .map(|a| (a.username.clone(), a.password.clone()))
        .collect();

    // Send Telegram T.5 post-session report (gated).
    // Probe-only sessions -> Drop. All others -> DailyBriefingOnly (honeypot is never SendNow).
    let duration = elapsed_secs_for_report(started_at);
    let is_probe_only = commands.is_empty() && credentials.is_empty() && duration <= 2;
    if let Some(ref tg) = telegram_client {
        let gate_ctx = crate::notification_gate::NotificationContext::for_honeypot_session(
            is_probe_only,
            auto_blocked,
        );
        let gate_verdict = crate::notification_gate::should_notify_with_counter(
            &gate_ctx,
            gate_suppressed_counter.as_ref(),
        );
        match gate_verdict {
            crate::notification_gate::NotificationVerdict::SendNow => {
                // Honeypot sessions are never SendNow per policy, but handle for completeness.
                if let Err(e) = tg
                    .send_honeypot_session_report(
                        &ip,
                        &session_id,
                        duration,
                        &commands,
                        &credentials,
                        &iocs,
                        &verdict,
                        auto_blocked,
                    )
                    .await
                {
                    warn!("always-on honeypot: failed to send Telegram session report: {e:#}");
                }
            }
            crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                tracing::debug!(ip = %ip, session = %session_id, "honeypot: session deferred to daily briefing");
            }
            crate::notification_gate::NotificationVerdict::Drop => {
                tracing::debug!(ip = %ip, session = %session_id, "honeypot: probe-only session dropped");
            }
        }
    }

    info!(
        ip,
        session_id,
        auth_attempts = evidence.auth_attempts.len(),
        shell_commands = evidence.shell_commands.len(),
        had_interaction,
        auto_blocked,
        "always-on honeypot session completed"
    );

    AlwaysOnSessionOutcome {
        had_interaction,
        auto_blocked,
    }
}

/// Permanent SSH listener that runs from agent startup until SIGTERM.
///
/// Filter per connection:
///   1. Already in blocklist → drop silently (no banner sent)
///   2. AbuseIPDB score ≥ threshold (when configured) → block + drop
///   3. Otherwise → accept into honeypot interaction (RejectAll or LlmShell)
///
/// `filter_blocklist` is a shared set of already-blocked IPs populated at startup
/// from recent decisions and updated in-place when new IPs are blocked via the gate.
///
/// Spec 036 PR-4: `token` replaces the pre-existing
/// `tokio::sync::watch::Receiver<bool>` parameter. Cancellation is
/// now driven by the agent's unified `state.task_group` — when
/// SIGTERM/SIGINT fires, `run_agent`'s shutdown path cancels the
/// token and waits for every registered task (including this
/// listener) to drain within the graceful deadline. Per-connection
/// handlers spawned inside the loop remain raw `tokio::spawn` on
/// purpose (bounded lifetime; out of scope for this PR).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_always_on_honeypot(
    port: u16,
    bind_addr: String,
    ssh_max_auth_attempts: usize,
    filter_blocklist: Arc<Mutex<HashSet<String>>>,
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    telegram_client: Option<Arc<telegram::TelegramClient>>,
    gate_suppressed_counter: Arc<AtomicU64>,
    abuseipdb_client: Option<Arc<abuseipdb::AbuseIpDbClient>>,
    abuseipdb_threshold: u8,
    data_dir: PathBuf,
    sqlite_store: Option<Arc<innerwarden_store::Store>>,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: String,
    allowed_skills: Vec<String>,
    interaction: String,
    token: tokio_util::sync::CancellationToken,
) {
    use skills::builtin::honeypot::ssh_interact::build_ssh_config;

    let ssh_cfg = build_ssh_config(ssh_max_auth_attempts);

    let addr = format!("{bind_addr}:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(addr, error = %e, "always-on honeypot: failed to bind listener - mode disabled");
            return;
        }
    };
    info!(port, bind_addr, "always-on honeypot listener started");

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = match accept_result {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "always-on honeypot: accept error");
                        continue;
                    }
                };

                let ip = peer.ip().to_string();

                // Filter 1: already in filter blocklist - drop silently.
                {
                    let bl = filter_blocklist.lock().unwrap_or_else(|e| e.into_inner());
                    if bl.contains(&ip) {
                        debug!(ip, "always-on honeypot: IP in blocklist - dropping silently");
                        continue;
                    }
                }

                // Filter 2: AbuseIPDB gate (async lookup before spawning handler).
                if abuseipdb_threshold > 0 {
                    if let Some(ref client) = abuseipdb_client {
                        if let Some(rep) = client.check(&ip).await {
                            if rep.confidence_score >= abuseipdb_threshold {
                                info!(
                                    ip,
                                    score = rep.confidence_score,
                                    "always-on honeypot: AbuseIPDB gate - blocking and dropping"
                                );
                                // Add to filter blocklist so future connections are dropped cheaply.
                                filter_blocklist
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(ip.clone());

                                // Write audit + execute block skill (background task).
                                let ip_c = ip.clone();
                                let dd = data_dir.clone();
                                let bb = block_backend.clone();
                                let sk = allowed_skills.clone();
                                let score = rep.confidence_score;
                                let threshold = abuseipdb_threshold;
                                let re = responder_enabled;
                                let dr = dry_run;
                                let store_c = sqlite_store.clone();
                                tokio::spawn(async move {
                                    always_on_abuseipdb_block(
                                        &ip_c, score, threshold, &dd, store_c.as_ref(), re, dr,
                                        &bb, &sk,
                                    )
                                    .await;
                                });
                                continue;
                            }
                        }
                    }
                }

                // Accept: snapshot blocklist membership, then spawn connection handler.
                let bl_has_ip = filter_blocklist
                    .lock()
                    .map(|bl| bl.contains(&ip))
                    .unwrap_or(false);

                let ssh_cfg_clone = ssh_cfg.clone();
                let ai_clone = ai_provider.clone();
                let tg_clone = telegram_client.clone();
                let gate_counter = gate_suppressed_counter.clone();
                let dd = data_dir.clone();
                let store_c = sqlite_store.clone();
                let ip_clone = ip.clone();
                let intr = interaction.clone();
                let bb = block_backend.clone();
                let sk = allowed_skills.clone();
                let re = responder_enabled;
                let dr = dry_run;
                let bl_ref = filter_blocklist.clone();

                tokio::spawn(async move {
                    let outcome = handle_always_on_connection(
                        stream,
                        ip_clone.clone(),
                        ssh_cfg_clone,
                        ai_clone,
                        tg_clone,
                        gate_counter,
                        dd,
                        store_c,
                        intr,
                        bl_has_ip,
                        re,
                        dr,
                        bb,
                        sk,
                    )
                    .await;
                    // After real interaction (or successful auto-block), mark IP as seen
                    // so the filter can drop quick reconnects.
                    if outcome.had_interaction || outcome.auto_blocked {
                        bl_ref
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(ip_clone);
                    }
                });
            }
            _ = token.cancelled() => {
                info!("always-on honeypot listener shutting down");
                break;
            }
        }
    }
}

/// Write an AbuseIPDB-triggered block audit entry and execute the block skill.
#[allow(clippy::too_many_arguments)]
async fn always_on_abuseipdb_block(
    ip: &str,
    score: u8,
    threshold: u8,
    data_dir: &Path,
    sqlite_store: Option<&Arc<innerwarden_store::Store>>,
    responder_enabled: bool,
    dry_run: bool,
    block_backend: &str,
    allowed_skills: &[String],
) {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());
    let iid = format!("honeypot:always-on:abuseipdb:{ip}");
    let skill_id = format!("block-ip-{block_backend}");

    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: iid.clone(),
        host: host.clone(),
        ai_provider: "honeypot:abuseipdb_gate".to_string(),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: Some(skill_id.clone()),
        confidence: 1.0,
        auto_executed: true,
        dry_run,
        reason: format!(
            "AbuseIPDB confidence score {score}/100 exceeded always-on honeypot gate threshold {threshold}"
        ),
        estimated_threat: "known-malicious".to_string(),
        execution_result: "ok".to_string(),
        prev_hash: None,
    };

    if let Err(e) = decisions::append_chained(data_dir, &entry, sqlite_store) {
        warn!("honeypot abuseipdb gate: failed to write decision: {e:#}");
    }

    if responder_enabled && allowed_skills.iter().any(|s| s == &skill_id) {
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: host.clone(),
            incident_id: iid,
            severity: innerwarden_core::event::Severity::High,
            title: "AbuseIPDB Gate Block (Always-on Honeypot)".to_string(),
            summary: format!(
                "IP {ip} blocked at always-on honeypot AbuseIPDB gate (score {score})"
            ),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["honeypot".to_string(), "abuseipdb".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        };
        let ctx = skills::SkillContext {
            incident: inc,
            target_ip: Some(ip.to_string()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host,
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
            let _ = skill.execute(&ctx, dry_run).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_autoblock_without_interaction() {
        // Decision path: probe-only sessions must never auto-block to avoid
        // poisoning the blocklist with harmless scan noise.
        let allowed = vec!["block-ip-ufw".to_string()];
        assert!(!should_auto_block_after_session(
            true, false, false, "ufw", &allowed
        ));
    }

    #[test]
    fn autoblock_with_interaction_and_skill_allowed() {
        // Happy path: when interaction happened and the backend skill is
        // enabled, the session should become auto-block eligible.
        let allowed = vec!["block-ip-ufw".to_string()];
        assert!(should_auto_block_after_session(
            true, false, true, "ufw", &allowed
        ));
    }

    #[test]
    fn elapsed_report_rounds_subsecond_to_one() {
        // Reporting path: sub-second sessions still report as 1 second so
        // operator-facing summaries avoid a confusing "0s" duration.
        let started = std::time::Instant::now() - std::time::Duration::from_millis(250);
        assert_eq!(elapsed_secs_for_report(started), 1);
    }

    #[test]
    fn no_autoblock_when_responder_is_disabled() {
        // Guard path: auto-blocking must stay off when responder mode is
        // disabled even if an interaction occurred.
        let allowed = vec!["block-ip-ufw".to_string()];
        assert!(!should_auto_block_after_session(
            false, false, true, "ufw", &allowed
        ));
    }

    #[test]
    fn no_autoblock_when_ip_already_blocked() {
        // Idempotency path: repeated sessions from an already blocked IP
        // should not trigger another auto-block workflow.
        let allowed = vec!["block-ip-ufw".to_string()];
        assert!(!should_auto_block_after_session(
            true, true, true, "ufw", &allowed
        ));
    }

    #[test]
    fn elapsed_report_keeps_whole_seconds() {
        // Precision path: whole-second durations must pass through unchanged.
        let started = std::time::Instant::now() - std::time::Duration::from_secs(3);
        assert!(elapsed_secs_for_report(started) >= 3);
    }

    // ─────────────────────────────────────────────────────────────────
    // Spec 036 PR-4 — CancellationToken shutdown contract
    // ─────────────────────────────────────────────────────────────────
    //
    // PR-4 replaced `tokio::sync::watch::Receiver<bool>` with
    // `tokio_util::sync::CancellationToken` as the shutdown signal
    // for the always-on listener. The swap is a contract change —
    // the listener used to observe a boolean-watch channel and only
    // exit when the payload was `true`; it now exits unconditionally
    // on `token.cancelled()`.
    //
    // These tests pin the NEW contract at two ends:
    //   1. A fresh, uncancelled token keeps the listener RUNNING
    //      (not spuriously-exiting the moment the loop starts).
    //   2. Cancelling the token drains the listener within a
    //      bounded deadline — the property the agent's
    //      `state.task_group.shutdown()` relies on.

    #[tokio::test]
    async fn listener_exits_promptly_when_token_cancelled() {
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;

        let token = CancellationToken::new();
        let token_for_task = token.clone();
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let data_dir = tmpdir.path().to_path_buf();

        // Bind to port 0 → kernel-assigned ephemeral port. No real
        // SSH client connects in this test; we only care that the
        // accept loop observes `token.cancelled()` and exits.
        let listener_task = tokio::spawn(async move {
            run_always_on_honeypot(
                0,                                    // port (OS-assigned)
                "127.0.0.1".to_string(),              // bind_addr
                3,                                    // ssh_max_auth_attempts
                Arc::new(Mutex::new(HashSet::new())), // filter_blocklist
                None,                                 // ai_provider
                None,                                 // telegram_client
                Arc::new(AtomicU64::new(0)),          // gate_suppressed_counter
                None,                                 // abuseipdb_client
                0,                                    // abuseipdb_threshold
                data_dir,
                None,                 // sqlite_store
                false,                // responder_enabled
                true,                 // dry_run
                "ufw".to_string(),    // block_backend
                vec![],               // allowed_skills
                "reject".to_string(), // interaction
                token_for_task,
            )
            .await;
        });

        // Let the listener reach its accept loop. 100 ms is ample
        // for binding + starting the select! on a dev laptop and CI.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !listener_task.is_finished(),
            "listener must NOT exit on its own with an uncancelled token — \
             a spurious-exit regression here would mean SIGTERM drain does \
             nothing because the listener is already gone"
        );

        // Trigger the shutdown contract.
        token.cancel();

        // Listener must observe `cancelled()` and exit within a
        // bounded window. 1 s is generous — the real select! arm
        // fires on the very next poll.
        let join_result = tokio::time::timeout(Duration::from_secs(1), listener_task).await;
        assert!(
            join_result.is_ok(),
            "listener must exit within 1 s of token.cancel() — a timeout here \
             means the shutdown contract regressed (the cancelled() arm is \
             gone from the select!, or the loop swallowed the signal)"
        );
        join_result
            .unwrap()
            .expect("listener task completed without panic");
    }
}
