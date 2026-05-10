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

/// Ensure the honeypot evidence directory exists, surfacing creation
/// failures via `warn!` with structured context. Replaces the prior
/// `let _ = tokio::fs::create_dir_all(..)` at the head of the
/// session-evidence write path (Spec 037 I-13 PR-6). `create_dir_all`
/// is idempotent on success — failure (perms, FS read-only) cascades
/// into a silent skip of the entire evidence write downstream.
/// Surfacing it pins the head of that cascade so the operator gets
/// one signal per failed connection instead of zero.
async fn ensure_honeypot_dir_or_warn(dir: &Path) {
    if let Err(e) = tokio::fs::create_dir_all(dir).await {
        warn!(
            path = %dir.display(),
            error = %e,
            "honeypot evidence dir creation failed (session evidence will be lost)"
        );
    }
}

/// Append one JSONL line to an already-open evidence file, surfacing
/// write failures via `warn!` with structured context. Replaces the
/// prior `let _ = f.write_all(..)` (Spec 037 I-13 PR-6). The file is
/// the session-specific JSONL that forensic analysis reads after the
/// session — silent loss of any line directly defeats the honeypot's
/// purpose.
///
/// Takes `&mut File` rather than the path because the open is still
/// the caller's concern (the wrapping `if let Ok(mut f) = ..open()`
/// in `handle_always_on_connection` is out of scope for this PR — it
/// is a different shape from `let _ =`).
async fn write_evidence_line_or_warn(
    file: &mut tokio::fs::File,
    path: &Path,
    session_id: &str,
    line: &[u8],
) {
    use tokio::io::AsyncWriteExt;
    if let Err(e) = file.write_all(line).await {
        warn!(
            path = %path.display(),
            session_id = %session_id,
            error = %e,
            "honeypot evidence write failed (session JSONL line lost)"
        );
    }
}

/// Open the honeypot session evidence file in append+create mode,
/// surfacing failure via `warn!` with structured context. Replaces
/// the prior `if let Ok(mut f) = OpenOptions::new()...open(..)`
/// silent skip at the second level of the honeypot evidence write
/// cascade (Spec 037 I-13 follow-up #1, smallest slice).
///
/// The cascade was three silent levels deep before I-13:
///   1. `ensure_honeypot_dir_or_warn`: fixed in PR-6 (#308).
///   2. `open_evidence_file_or_warn`: fixed here.
///   3. `write_evidence_line_or_warn`: fixed in PR-6 (#308).
///
/// Returns `Some(File)` on success so the caller can pass it to
/// `write_evidence_line_or_warn`; returns `None` on failure (after
/// warning). Failure here means the entire session evidence is
/// silently dropped: the operator gets nothing back from the
/// trapped attacker on this connection.
///
/// `session_id` and `ip` are carried in the warn so the operator
/// can correlate the lost evidence with the trapped session.
async fn open_evidence_file_or_warn(
    path: &Path,
    session_id: &str,
    ip: &str,
) -> Option<tokio::fs::File> {
    match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(f) => Some(f),
        Err(e) => {
            warn!(
                path = %path.display(),
                session_id,
                ip,
                error = %e,
                "honeypot evidence file open failed (session JSONL line lost)"
            );
            None
        }
    }
}

/// Execute a `ResponseSkill` and surface failure outcomes via `warn!`
/// with structured context. Replaces the prior
/// `let _ = skill.execute(&ctx, dry_run).await;` value-discard at the
/// AbuseIPDB-gate auto-block site (Spec 037 I-13 follow-up #2).
///
/// Why a helper rather than inlining: `ResponseSkill::execute` returns
/// `SkillResult { success: bool, message: String }` (a value type, not
/// `Result<_, Err>`), so the failure information lives in the value
/// rather than the type system. The previous `let _ =` threw away
/// both the outcome and the diagnostic — the operator had no signal
/// when the gate fired but the skill rejected the input or the
/// backend was unavailable, leaving the malicious IP unblocked.
///
/// The wrapper is silent on success (no per-call info-spam — the
/// upstream decision audit at `decisions::append_chained` already
/// records the gate decision) and emits a structured `warn!` on
/// `success == false` carrying `ip`, `skill_id`, `dry_run`, and the
/// skill's `message` for forensic context. Mirrors the established
/// pattern at `decision_block_ip.rs::execute_block_ip_decision` for
/// the firewall-skill failure path.
///
/// Returns `()` (infallible) so the call site stays one-line and the
/// calling auto-block flow continues regardless of the skill's
/// success — same observable shape as the prior `let _ =`.
async fn execute_block_skill_or_warn(
    skill: &dyn skills::ResponseSkill,
    ctx: &skills::SkillContext,
    dry_run: bool,
    ip: &str,
    skill_id: &str,
) {
    let result = skill.execute(ctx, dry_run).await;
    if !result.success {
        warn!(
            ip,
            skill_id,
            dry_run,
            reason = result.message,
            "honeypot abuseipdb gate: block skill execution failed"
        );
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
    ensure_honeypot_dir_or_warn(&honeypot_dir).await;
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
        if let Some(mut f) = open_evidence_file_or_warn(&evidence_path, &session_id, &ip).await {
            write_evidence_line_or_warn(&mut f, &evidence_path, &session_id, line.as_bytes()).await;
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

/// Spec 043 Phase 1b follow-up: read KG features for an IP at
/// block-time, returning `None` when there is no KG, the lock is
/// poisoned, or the IP has no node yet.
///
/// Scaffolding for the planned AbuseIPDB-gate audit hook: a future
/// PR threads `kg` through `run_always_on_honeypot` and calls this
/// helper from `always_on_abuseipdb_block` to emit a
/// `tracing::info!` snapshot of the IP's KG state at block-time.
/// Audit is observability-only (AbuseIPDB score=100 already maxes
/// out the modifier; no decision change). Shipped now as a tested
/// helper so the wiring PR is small and easy to review.
#[allow(dead_code)]
pub(crate) fn kg_audit_features_for_block(
    kg: Option<&Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>>,
    ip: &str,
) -> Option<crate::kg_decide_features::KgDecideFeatures> {
    let kg = kg?;
    let graph = kg.read().ok()?;
    let now = chrono::Utc::now();
    crate::kg_decide_features::extract_features_for_ip(&graph, ip, now)
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
            // Spec 037 I-13 follow-up #2: surface skill-execution
            // failures (`SkillResult.success == false`) via warn
            // with structured context. The decision audit row is
            // already written upstream; this closes the loop on
            // whether the auto-block actually applied.
            execute_block_skill_or_warn(skill.as_ref(), &ctx, dry_run, ip, &skill_id).await;
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

    fn unused_local_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.local_addr().expect("local addr").port()
    }

    struct AcceptAnyServerKey;

    impl russh::client::Handler for AcceptAnyServerKey {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn listener_accepts_probe_connection_and_writes_evidence() {
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;

        let token = CancellationToken::new();
        let token_for_task = token.clone();
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let data_dir = tmpdir.path().to_path_buf();
        let port = unused_local_port();

        let listener_task = tokio::spawn({
            let data_dir = data_dir.clone();
            async move {
                run_always_on_honeypot(
                    port,
                    "127.0.0.1".to_string(),
                    3,
                    Arc::new(Mutex::new(HashSet::new())),
                    None,
                    None,
                    Arc::new(AtomicU64::new(0)),
                    None,
                    0,
                    data_dir,
                    None,
                    false,
                    true,
                    "ufw".to_string(),
                    vec![],
                    "medium".to_string(),
                    token_for_task,
                )
                .await;
            }
        });

        let addr = format!("127.0.0.1:{port}");
        let mut stream = None;
        for _ in 0..20 {
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
        drop(stream.expect("listener should accept a local TCP probe"));

        let honeypot_dir = tmpdir.path().join("honeypot");
        let mut evidence = None;
        for _ in 0..40 {
            if let Ok(entries) = std::fs::read_dir(&honeypot_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|name| name.starts_with("listener-session-"))
                    {
                        let content = std::fs::read_to_string(&path).expect("read evidence");
                        if !content.trim().is_empty() {
                            evidence = Some(content);
                            break;
                        }
                    }
                }
            }
            if evidence.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        token.cancel();
        tokio::time::timeout(Duration::from_secs(1), listener_task)
            .await
            .expect("listener exits after cancellation")
            .expect("listener task");

        let evidence = evidence.expect("probe connection should write a session JSONL line");
        let row: serde_json::Value =
            serde_json::from_str(evidence.lines().next().expect("jsonl row")).expect("json");
        assert_eq!(row["type"], "ssh_connection");
        assert_eq!(row["peer_ip"], "127.0.0.1");
        assert_eq!(row["auth_attempts_count"], 0);
        assert_eq!(row["shell_commands_count"], 0);
    }

    #[tokio::test]
    async fn listener_password_attempt_writes_autoblock_audit_and_blocklist() {
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;

        let token = CancellationToken::new();
        let token_for_task = token.clone();
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let data_dir = tmpdir.path().to_path_buf();
        let port = unused_local_port();
        let filter_blocklist = Arc::new(Mutex::new(HashSet::new()));
        let listener_blocklist = filter_blocklist.clone();

        let listener_task = tokio::spawn({
            let data_dir = data_dir.clone();
            async move {
                run_always_on_honeypot(
                    port,
                    "127.0.0.1".to_string(),
                    3,
                    listener_blocklist,
                    None,
                    None,
                    Arc::new(AtomicU64::new(0)),
                    None,
                    0,
                    data_dir,
                    None,
                    true,
                    true,
                    "ufw".to_string(),
                    vec!["block-ip-ufw".to_string()],
                    "medium".to_string(),
                    token_for_task,
                )
                .await;
            }
        });

        let addr = format!("127.0.0.1:{port}");
        let mut client = None;
        for _ in 0..20 {
            match russh::client::connect(
                Arc::new(russh::client::Config::default()),
                addr.as_str(),
                AcceptAnyServerKey,
            )
            .await
            {
                Ok(handle) => {
                    client = Some(handle);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
        let mut client = client.expect("listener should accept an SSH client");
        let auth = client
            .authenticate_password("root", "toor")
            .await
            .expect("auth response");
        assert!(
            !auth.success(),
            "medium-interaction listener must capture and reject password auth"
        );
        let _ = client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(1), client).await;

        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let decision_path = tmpdir.path().join(format!("decisions-{today}.jsonl"));
        let mut decision = None;
        for _ in 0..40 {
            if filter_blocklist
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains("127.0.0.1")
            {
                if let Ok(content) = std::fs::read_to_string(&decision_path) {
                    if !content.trim().is_empty() {
                        decision = Some(content);
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        token.cancel();
        tokio::time::timeout(Duration::from_secs(1), listener_task)
            .await
            .expect("listener exits after cancellation")
            .expect("listener task");

        let decision = decision.expect("password attempt should write auto-block decision");
        let row: serde_json::Value =
            serde_json::from_str(decision.lines().next().expect("decision row")).expect("json");
        assert_eq!(row["ai_provider"], "honeypot:always-on");
        assert_eq!(row["action_type"], "block_ip");
        assert_eq!(row["target_ip"], "127.0.0.1");
        assert_eq!(row["skill_id"], "block-ip-ufw");
        assert_eq!(row["execution_result"], "ok");
        assert!(
            row["reason"]
                .as_str()
                .expect("reason")
                .contains("interacted with always-on honeypot session"),
            "auto-block reason must explain the honeypot interaction: {row}"
        );
    }

    // ── Spec 037 I-13 PR-6 — evidence-write helper anchors ────────
    //
    // PR-6 of I-13 converts the two `let _ =` swallows in the
    // honeypot session evidence path into `warn!`-on-failure helpers
    // (`ensure_honeypot_dir_or_warn`, `write_evidence_line_or_warn`).
    // These tests anchor the warn-vs-silent contract for each helper.
    // Added as a fix-after-fail measure: the first push hit
    // `codecov/patch` 0.00% because the call sites in
    // `handle_always_on_connection` are not exercised by any unit
    // test (only by replay-qa / scenario-qa, which do not contribute
    // to codecov/patch). Helper-level coverage carries the patch
    // ratio over 70%.

    #[tokio::test]
    async fn ensure_honeypot_dir_or_warn_creates_dir_silently_when_writable() {
        // Happy path: writable parent → dir is created, no panic.
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("honeypot");
        assert!(!target.exists(), "fixture must start with target absent");

        ensure_honeypot_dir_or_warn(&target).await;

        assert!(
            target.exists(),
            "create_dir_all must have produced the directory on the happy path"
        );
    }

    #[tokio::test]
    async fn ensure_honeypot_dir_or_warn_does_not_panic_on_unwritable_parent() {
        // Failure path: parent is a regular file, not a directory.
        // `create_dir_all` fails with `NotADirectory`/`AlreadyExists`
        // and the helper must absorb the error so the calling
        // session handler proceeds (matches the prior `let _ =`
        // no-panic property).
        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a file").expect("seed blocker");

        // `blocker/honeypot` cannot be created because `blocker` is a file.
        let target = blocking_file.join("honeypot");

        // Must not panic.
        ensure_honeypot_dir_or_warn(&target).await;
    }

    #[tokio::test]
    async fn write_evidence_line_or_warn_appends_line_silently_on_writable_file() {
        // Happy path: bytes land at the end of the file, no panic.
        // Note: tokio's File::drop does NOT synchronously flush
        // pending writes — we MUST `flush + sync_data` explicitly
        // before reading back via `std::fs::read`, or the read can
        // race the in-flight write and observe an empty file. This
        // is what the first CI run hit.
        use tokio::io::AsyncWriteExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("evidence.jsonl");

        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .expect("open writable");

        let line = b"{\"sid\":\"alpha\"}\n";
        write_evidence_line_or_warn(&mut f, &path, "alpha", line).await;
        // Force the bytes to disk before the synchronous read.
        f.flush().await.expect("flush");
        f.sync_data().await.expect("sync_data");
        drop(f);

        let on_disk = std::fs::read(&path).expect("read evidence file");
        assert_eq!(
            on_disk.as_slice(),
            line,
            "the helper must write the JSONL line verbatim on the happy path"
        );
    }

    #[tokio::test]
    async fn write_evidence_line_or_warn_does_not_panic_on_read_only_file() {
        // Failure path: open the file in read-only mode and pass it
        // to the helper. `write_all` returns
        // `io::ErrorKind::Unsupported` / `InvalidInput` (platform-
        // dependent), the helper must absorb it without panic and
        // leave the file untouched. Matches the prior `let _ =`
        // no-panic property.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("evidence.jsonl");
        // Seed a non-empty file so we can also assert it was NOT
        // mutated by the failed write.
        let pre = b"untouched";
        std::fs::write(&path, pre).expect("seed");

        let mut f = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .await
            .expect("open read-only");

        // Must not panic.
        write_evidence_line_or_warn(&mut f, &path, "alpha", b"hello\n").await;
        drop(f);

        let after = std::fs::read(&path).expect("read after");
        assert_eq!(
            after.as_slice(),
            pre,
            "a failed write must not somehow mutate the file"
        );
    }

    // ── Spec 037 I-13 follow-up #2 — execute_block_skill_or_warn anchors ──
    //
    // Follow-up #2 converts the prior `let _ = skill.execute(..).await`
    // value-discard at the AbuseIPDB-gate auto-block site into a
    // `warn!`-on-`success=false` pattern via `execute_block_skill_or_warn`.
    // Tests use real `BlockIpUfw` in dry-run with two contexts:
    //
    //   1. Valid `target_ip` → dry-run returns `success=true` →
    //      helper must NOT emit the failure warn.
    //   2. `target_ip = None` → `BlockIpUfw` returns `success=false`
    //      with message "block-ip-ufw: no target IP in context" →
    //      helper MUST emit the warn carrying ip + skill_id +
    //      dry_run + reason.
    //
    // No mock skill needed — `BlockIpUfw` is deterministic in dry-run.
    // Capture is via `crate::test_util` (global subscriber +
    // thread-local buffer) — see that module's rustdoc for why the
    // earlier per-test `set_default` + `MakeWriter` pattern was
    // flaky on CI.

    fn make_block_skill_ctx(target_ip: Option<&str>) -> skills::SkillContext {
        skills::SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: "test-host".into(),
                incident_id: "honeypot:always-on:abuseipdb:test".into(),
                severity: innerwarden_core::event::Severity::High,
                title: "test".into(),
                summary: "test".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: target_ip.map(str::to_string),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "test-host".into(),
            data_dir: std::env::temp_dir(),
            honeypot: skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn execute_block_skill_or_warn_silent_on_success() {
        // Happy path: BlockIpUfw + valid target_ip + dry_run=true
        // → success=true → helper must NOT emit the failure warn.
        let _guard = crate::test_util::arm_capture();

        let ctx = make_block_skill_ctx(Some("203.0.113.42"));
        let skill = skills::builtin::BlockIpUfw;

        execute_block_skill_or_warn(&skill, &ctx, true, "203.0.113.42", "block-ip-ufw").await;

        let captured_str = crate::test_util::drain_capture();
        assert!(
            !captured_str.contains("block skill execution failed"),
            "successful skill execution must not emit the failure warn — got: {captured_str}"
        );
    }

    #[tokio::test]
    async fn execute_block_skill_or_warn_emits_warn_on_failure() {
        // Failure path: BlockIpUfw with target_ip=None forces
        // success=false ("block-ip-ufw: no target IP in context").
        // Helper must emit the warn carrying ip + skill_id +
        // dry_run + reason.
        let _guard = crate::test_util::arm_capture();

        let ctx = make_block_skill_ctx(None);
        let skill = skills::builtin::BlockIpUfw;

        execute_block_skill_or_warn(&skill, &ctx, true, "198.51.100.1", "block-ip-ufw").await;

        let captured_str = crate::test_util::drain_capture();

        assert!(
            captured_str.contains("block skill execution failed"),
            "warn message missing on failed skill execution — got: {captured_str}"
        );
        // ip field carries the operator-relevant target identifier
        // (the IP that was supposed to be blocked).
        assert!(
            captured_str.contains("198.51.100.1"),
            "ip field missing — got: {captured_str}"
        );
        // skill_id field tells the operator which backend failed.
        assert!(
            captured_str.contains("block-ip-ufw"),
            "skill_id field missing — got: {captured_str}"
        );
        // dry_run flag distinguishes a real-world failure from a
        // test-mode rejection in the operator log.
        assert!(
            captured_str.contains("dry_run=true"),
            "dry_run field missing — got: {captured_str}"
        );
        // reason carries the SkillResult.message — needed to
        // diagnose WHY the skill rejected the input.
        assert!(
            captured_str.contains("no target IP in context"),
            "reason field missing skill-provided message — got: {captured_str}"
        );
    }

    #[tokio::test]
    async fn always_on_abuseipdb_block_writes_audit_and_executes_dry_run_skill() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowed = vec!["block-ip-ufw".to_string()];

        always_on_abuseipdb_block(
            "203.0.113.88",
            91,
            80,
            dir.path(),
            None,
            true,
            true,
            "ufw",
            &allowed,
        )
        .await;

        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&path).expect("decision audit jsonl");
        let row: serde_json::Value =
            serde_json::from_str(content.lines().next().expect("decision row")).expect("json");

        assert_eq!(
            row["incident_id"],
            "honeypot:always-on:abuseipdb:203.0.113.88"
        );
        assert_eq!(row["ai_provider"], "honeypot:abuseipdb_gate");
        assert_eq!(row["action_type"], "block_ip");
        assert_eq!(row["target_ip"], "203.0.113.88");
        assert_eq!(row["skill_id"], "block-ip-ufw");
        assert_eq!(row["auto_executed"], true);
        assert_eq!(row["dry_run"], true);
        assert_eq!(row["estimated_threat"], "known-malicious");
        assert!(
            row["reason"]
                .as_str()
                .expect("reason")
                .contains("91/100 exceeded always-on honeypot gate threshold 80"),
            "reason must preserve the AbuseIPDB score and threshold: {row}"
        );
    }

    // ── Spec 037 I-13 follow-up #1 (smallest slice): open_evidence_file_or_warn ──
    //
    // Wraps the second silent level of the honeypot evidence write
    // cascade (file open). The other two levels were fixed in PR-6
    // (#308). Two anchors:
    //   1. happy path: writable parent => returns Some, no warn
    //   2. failure path: parent is a regular file (not a dir) so
    //      `OpenOptions::open` cannot create the evidence file =>
    //      returns None and emits a warn carrying path + session_id
    //      + ip + error.
    //
    // The serde_json::to_string at L184 is left as-is (bucket B:
    // serializing a fixed-shape JSON struct with primitive values
    // does not realistically fail; a forced-failure test would need
    // contrived input the production cascade never produces).

    #[tokio::test]
    async fn open_evidence_file_or_warn_returns_some_silently_on_writable_path() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("listener-session-test.jsonl");

        let result = open_evidence_file_or_warn(&path, "always-on-test", "203.0.113.7").await;

        assert!(
            result.is_some(),
            "writable parent dir must yield Some(File)"
        );
        // The file must have been created on disk by `OpenOptions`
        // with `create(true)`.
        assert!(
            path.exists(),
            "OpenOptions(create=true) must produce the file on disk"
        );

        let captured_str = crate::test_util::drain_capture();
        assert!(
            !captured_str.contains("honeypot evidence file open failed"),
            "happy path must not emit the failure warn, got: {captured_str}"
        );
    }

    #[tokio::test]
    async fn open_evidence_file_or_warn_returns_none_and_warns_on_failure() {
        // Force `OpenOptions::open` to fail by parking the target
        // path beneath a regular file. `OpenOptions(create=true)`
        // returns `NotADirectory` (Linux) / `NotFound` (macOS) /
        // similar; either way, Err.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        // `blocker/listener-session-X.jsonl` cannot be created
        // because `blocker` is a file, not a directory.
        let path = blocking_file.join("listener-session-test.jsonl");

        let result = open_evidence_file_or_warn(&path, "always-on-failwarn", "198.51.100.5").await;

        assert!(
            result.is_none(),
            "open under a regular-file parent must yield None"
        );

        let captured_str = crate::test_util::drain_capture();
        assert!(
            captured_str.contains("honeypot evidence file open failed"),
            "failure path must emit the warn, got: {captured_str}"
        );
        // session_id + ip must be in the warn so the operator can
        // correlate the lost evidence with the trapped session.
        assert!(
            captured_str.contains("session_id=\"always-on-failwarn\"")
                || captured_str.contains("session_id=always-on-failwarn"),
            "session_id field missing, got: {captured_str}"
        );
        assert!(
            captured_str.contains("ip=\"198.51.100.5\"")
                || captured_str.contains("ip=198.51.100.5"),
            "ip field missing, got: {captured_str}"
        );
        assert!(
            captured_str.contains("error="),
            "error field missing, got: {captured_str}"
        );
    }

    /// Spec 043 Phase 1b follow-up: sync coverage of the audit helper
    /// with kg=None. Anchor for the no-KG branch.
    #[test]
    fn kg_audit_features_for_block_returns_none_when_kg_absent() {
        let out = kg_audit_features_for_block(None, "198.51.100.50");
        assert!(out.is_none(), "kg=None must short-circuit to None");
    }

    /// Spec 043 Phase 1b follow-up: sync coverage of the audit helper
    /// when the IP has no node yet (KG present, lookup miss).
    #[test]
    fn kg_audit_features_for_block_returns_none_for_unknown_ip() {
        let kg = Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let out = kg_audit_features_for_block(Some(&kg), "203.0.113.99");
        assert!(out.is_none(), "unknown IP must yield None");
    }

    /// Spec 043 Phase 1b follow-up: sync coverage of the audit helper
    /// happy path. IP seeded as Node::Ip with a 10-day-old first_seen
    /// → features must come back with a non-zero age and the seeded
    /// risk_score. Pins the field-level contract that the tracing
    /// macro consumes.
    #[test]
    fn kg_audit_features_for_block_returns_features_for_known_ip() {
        let kg = Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            g.add_node(crate::knowledge_graph::types::Node::Ip {
                addr: "198.51.100.42".to_string(),
                is_internal: false,
                datasets: vec![],
                risk_score: 73,
                is_tor: false,
                first_seen: chrono::Utc::now() - chrono::Duration::days(10),
                last_seen: chrono::Utc::now(),
                attempted_usernames: vec![],
            });
        }
        let features = kg_audit_features_for_block(Some(&kg), "198.51.100.42")
            .expect("seeded IP must yield Some(features)");
        assert_eq!(features.risk_score, 73);
        assert!(features.first_seen_age_days >= 9);
        assert_eq!(features.prior_incidents_24h, 0);
    }

    // ── Spec 046 — three real-world scenario integration tests ──
    //
    // These boot a fresh always-on listener on an ephemeral port with an
    // empty blocklist + a noop AI provider, then drive a real russh
    // client through three attacker profiles. They prove what Phase A
    // captures (bots with known-weak credentials) and DOCUMENT the
    // intentional gap (human-direct attackers typing unique creds), so
    // future PRs that close the gap have a regression line to flip.
    //
    // The handle each scenario is "did the russh client successfully
    // open a session channel after auth?" — the binary signal that
    // discriminates accept-vs-reject without needing the full LLM
    // shell roundtrip.
    //
    // The noop AI provider returns Ok("") for every chat call. The
    // fake_shell deterministic path covers the common reconnaissance
    // commands attackers run; LLM only fires for novel commands. For
    // these scenarios the LLM never fires (we just open the channel
    // and close it).

    /// Noop AI provider for scenario tests. Real LLM calls are not
    /// made — the scenarios assert the auth gate, not the shell I/O.
    struct ScenarioNoopAi;

    #[async_trait::async_trait]
    impl ai::AiProvider for ScenarioNoopAi {
        fn name(&self) -> &'static str {
            "scenario-noop"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            anyhow::bail!("noop")
        }
        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok(String::new())
        }
    }

    /// Boot a fresh listener for one scenario. Returns
    /// (port, blocklist, cancellation_token, listener_join_handle).
    /// All callers MUST cancel the token + await the handle in the
    /// same `tokio::test` (drop alone leaks the listener task).
    async fn boot_scenario_listener(
        data_dir: std::path::PathBuf,
    ) -> (
        u16,
        Arc<Mutex<HashSet<String>>>,
        tokio_util::sync::CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let port = unused_local_port();
        let blocklist = Arc::new(Mutex::new(HashSet::new()));
        let token = tokio_util::sync::CancellationToken::new();
        let token_for_task = token.clone();
        let bl = blocklist.clone();
        let ai: Arc<dyn ai::AiProvider> = Arc::new(ScenarioNoopAi);
        let handle = tokio::spawn(async move {
            run_always_on_honeypot(
                port,
                "127.0.0.1".to_string(),
                10, // generous max_auth_attempts
                bl,
                Some(ai),                    // LlmShell needs an AI provider
                None,                        // telegram_client
                Arc::new(AtomicU64::new(0)), // gate_suppressed_counter
                None,                        // abuseipdb_client
                0,                           // abuseipdb_threshold (off)
                data_dir,
                None,  // sqlite_store
                false, // responder_enabled — no auto-block
                true,  // dry_run
                "ufw".to_string(),
                vec![],                  // allowed_skills
                "llm_shell".to_string(), // <-- LlmShell mode
                token_for_task,
            )
            .await;
        });
        (port, blocklist, token, handle)
    }

    /// Drive one scenario: connect via russh client, try each password
    /// in order, return Ok(accepted_password) on first success or
    /// Err(()) if all rejected. Caller controls the password list.
    async fn drive_scenario(port: u16, username: &str, passwords: &[&str]) -> Result<String, ()> {
        let addr = format!("127.0.0.1:{port}");
        // Wait for the listener to bind.
        for _ in 0..20 {
            if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let mut client = russh::client::connect(
            Arc::new(russh::client::Config::default()),
            addr.as_str(),
            AcceptAnyServerKey,
        )
        .await
        .expect("scenario client should connect");
        for pw in passwords {
            let auth = client
                .authenticate_password(username, *pw)
                .await
                .expect("auth response");
            if auth.success() {
                let _ = client
                    .disconnect(russh::Disconnect::ByApplication, "test ok", "")
                    .await;
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), client).await;
                return Ok((*pw).to_string());
            }
        }
        let _ = client
            .disconnect(russh::Disconnect::ByApplication, "all rejected", "")
            .await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), client).await;
        Err(())
    }

    /// Scenario A — Mirai-class bot.
    /// Tries 3 garbage passwords, then `admin` on attempt 3.
    /// `admin/admin` is on KNOWN_WEAK_CREDENTIALS.
    /// Expected on Phase A: ACCEPT on attempt 3 (the wow moment).
    #[tokio::test]
    async fn scenario_a_mirai_bot_with_known_weak_password_opens_shell() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (port, _bl, token, handle) = boot_scenario_listener(dir.path().to_path_buf()).await;

        let result = drive_scenario(port, "admin", &["password123", "qwerty789", "admin"]).await;

        token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

        let accepted = result.expect(
            "Mirai-class scenario MUST accept admin/admin on attempt 3 — \
             this is the wow path Spec 046 Phase A is built for",
        );
        assert_eq!(
            accepted, "admin",
            "Mirai-class bot must succeed on the well-known cred admin/admin"
        );
    }

    /// Scenario B — Root brute bot. Tries 2 garbage passwords, then
    /// `root` on attempt 3. `root/root` is on KNOWN_WEAK_CREDENTIALS.
    #[tokio::test]
    async fn scenario_b_root_brute_bot_with_known_weak_password_opens_shell() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (port, _bl, token, handle) = boot_scenario_listener(dir.path().to_path_buf()).await;

        let result = drive_scenario(port, "root", &["abc123", "iloveyou", "root"]).await;

        token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

        let accepted = result.expect("root/root scenario must succeed on attempt 3");
        assert_eq!(accepted, "root");
    }

    /// Scenario C — Human-direct attacker. Three unique passwords,
    /// NONE on KNOWN_WEAK_CREDENTIALS (org-specific guesses). Spec
    /// 046 Phase A.5 closes this: after MIN_UNIQUE_CREDS_FOR_ADAPTIVE_ACCEPT
    /// (= 3) distinct creds on a single connection, the next attempt
    /// accepts via the adaptive branch. The 3rd attempt here triggers
    /// the rule (3 distinct entries seen → adaptive accept).
    #[tokio::test]
    async fn scenario_c_human_direct_three_unique_creds_opens_shell_via_adaptive_accept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (port, _bl, token, handle) = boot_scenario_listener(dir.path().to_path_buf()).await;

        let result = drive_scenario(
            port,
            "ubuntu",
            &["Welcome2024!", "OracleVM!", "Inn3rWarden_admin"],
        )
        .await;

        token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

        let accepted = result.expect(
            "Spec 046 Phase A.5 — human-direct attacker with 3 unique creds \
             MUST open shell on the 3rd attempt. If this fails, adaptive accept \
             regressed — re-check MIN_UNIQUE_CREDS_FOR_ADAPTIVE_ACCEPT and the \
             `seen_passwords` set in HandlerMode::LlmShell.",
        );
        assert_eq!(
            accepted, "Inn3rWarden_admin",
            "adaptive accept should fire on the 3rd unique credential"
        );
    }

    /// Scenario C-anti — Human attacker who repeats the SAME wrong
    /// credential 5 times must NOT open shell. Otherwise a buggy
    /// scanner stuck in a retry loop would defeat the trap. The
    /// adaptive rule depends on UNIQUE creds, not attempt count.
    #[tokio::test]
    async fn scenario_c_anti_repeated_same_password_does_not_open_shell() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (port, _bl, token, handle) = boot_scenario_listener(dir.path().to_path_buf()).await;

        // Same non-weak credential 5 times. unique_cred_count stays 1.
        let result = drive_scenario(
            port,
            "ubuntu",
            &[
                "MyOrg!2024",
                "MyOrg!2024",
                "MyOrg!2024",
                "MyOrg!2024",
                "MyOrg!2024",
            ],
        )
        .await;

        token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

        assert!(
            result.is_err(),
            "Adaptive accept must depend on UNIQUE creds, not attempt count. \
             A buggy scanner repeating the same wrong password 5× must NOT \
             trigger shell open."
        );
    }
}
