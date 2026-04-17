use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::{Datelike as _, Timelike as _};
use tracing::{info, warn};

use crate::dashboard::AdvisoryEntry;
use crate::*;

// ---------------------------------------------------------------------------
// Spec 015: one-shot cleanup of graph_user_creation false positives and
// brute-force User node pollution. Invoked via
// `innerwarden-agent --cleanup-015-graph-signal-quality`. Non-destructive
// outside that flag: the function below loads today's dated snapshot,
// writes a timestamped backup, applies the migration, and saves the result.
// ---------------------------------------------------------------------------
pub(crate) fn run_cleanup_015(data_dir: &std::path::Path) -> Result<()> {
    use chrono::Local;
    use std::fs;

    let snapshot_path = knowledge_graph::KnowledgeGraph::dated_snapshot_path(data_dir);
    if !snapshot_path.exists() {
        anyhow::bail!(
            "No dated snapshot found at {} — run the agent at least once first",
            snapshot_path.display()
        );
    }

    // Backup the raw snapshot bytes before touching anything, so the
    // operator can always roll back if the migration does something
    // unexpected. Name it with a timestamp so repeated runs don't clobber.
    let stamp = Local::now().format("%Y%m%dT%H%M%S");
    let backup_path = cleanup_015_backup_path(&snapshot_path, &stamp.to_string());
    fs::copy(&snapshot_path, &backup_path)
        .with_context(|| format!("failed to back up snapshot to {}", backup_path.display()))?;
    println!(
        "spec 015 cleanup: backed up snapshot to {}",
        backup_path.display()
    );

    // Load, mutate, save.
    let mut graph = knowledge_graph::KnowledgeGraph::load_snapshot(&snapshot_path);
    let report = knowledge_graph::migrations::cleanup_015_graph_signal_quality(&mut graph);
    graph.save_snapshot(&snapshot_path).with_context(|| {
        format!(
            "failed to save cleaned snapshot to {}",
            snapshot_path.display()
        )
    })?;

    println!("spec 015 cleanup complete:");
    println!("  snapshot             : {}", snapshot_path.display());
    println!("  backup               : {}", backup_path.display());
    println!("  nodes before         : {}", report.nodes_before);
    println!("  nodes after          : {}", report.nodes_after);
    println!(
        "  graph_user_creation  : {} incident node(s) removed",
        report.graph_user_creation_incidents_removed
    );
    println!(
        "  brute-force users    : {} User node(s) removed",
        report.brute_force_user_nodes_removed
    );
    if !report.removed_user_names.is_empty() {
        println!("  removed users        : (names redacted)");
    }
    Ok(())
}

pub(crate) fn run_backfill_015_research_only(data_dir: &std::path::Path) -> Result<()> {
    use chrono::Local;
    use std::fs;

    cloud_safelist::init();

    let snapshot_path = knowledge_graph::KnowledgeGraph::dated_snapshot_path(data_dir);
    if !snapshot_path.exists() {
        anyhow::bail!(
            "No dated snapshot found at {} — run the agent at least once first",
            snapshot_path.display()
        );
    }

    let stamp = Local::now().format("%Y%m%dT%H%M%S");
    let backup_path = backfill_015_research_only_backup_path(&snapshot_path, &stamp.to_string());
    fs::copy(&snapshot_path, &backup_path)
        .with_context(|| format!("failed to back up snapshot to {}", backup_path.display()))?;
    println!(
        "spec 015 research-only backfill: backed up snapshot to {}",
        backup_path.display()
    );

    let mut graph = knowledge_graph::KnowledgeGraph::load_snapshot(&snapshot_path);
    let report = knowledge_graph::migrations::backfill_research_only_flag(&mut graph);
    graph.save_snapshot(&snapshot_path).with_context(|| {
        format!(
            "failed to save cleaned snapshot to {}",
            snapshot_path.display()
        )
    })?;

    println!("spec 015 research-only backfill complete:");
    println!("  snapshot       : {}", snapshot_path.display());
    println!("  backup         : {}", backup_path.display());
    println!("  scanned        : {}", report.incidents_scanned);
    println!("  flagged        : {}", report.incidents_flagged);
    if !report.by_detector.is_empty() {
        println!("  by detector    :");
        let mut top: Vec<(&String, &usize)> = report.by_detector.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        for (det, n) in top.iter().take(15) {
            println!("    {det:<28} {n}");
        }
    }
    Ok(())
}
pub(crate) fn cleanup_015_backup_path(snapshot_path: &Path, stamp: &str) -> PathBuf {
    snapshot_path.with_extension(format!("json.bak-015-{stamp}"))
}

pub(crate) fn backfill_015_research_only_backup_path(snapshot_path: &Path, stamp: &str) -> PathBuf {
    snapshot_path.with_extension(format!("json.bak-015-researchonly-{stamp}"))
}

pub(crate) async fn run_agent(cli: crate::Cli) -> Result<()> {
    if cli.dashboard_generate_password_hash {
        dashboard::generate_password_hash_interactive()?;
        return Ok(());
    }

    if cli.honeypot_sandbox_runner {
        let spec = cli
            .honeypot_sandbox_spec
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing --honeypot-sandbox-spec"))?;
        let result = cli
            .honeypot_sandbox_result
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing --honeypot-sandbox-result"))?;
        skills::builtin::run_honeypot_sandbox_worker(spec, result).await?;
        return Ok(());
    }

    if cli.cleanup_015_graph_signal_quality {
        return run_cleanup_015(&cli.data_dir);
    }

    if cli.backfill_015_research_only {
        return run_backfill_015_research_only(&cli.data_dir);
    }

    if cli.report {
        let out_dir = cli.report_dir.as_deref().unwrap_or(&cli.data_dir);
        if let Some(d) = cli.report_dir.as_deref() {
            std::fs::create_dir_all(d)
                .with_context(|| format!("failed to create report-dir {}", d.display()))?;
        }
        let out = report::generate(&cli.data_dir, out_dir)?;
        info!(
            analyzed_date = %out.report.analyzed_date,
            markdown = %out.markdown_path.display(),
            json = %out.json_path.display(),
            "trial report generated"
        );
        println!(
            "Trial report generated:\n  {}\n  {}",
            out.markdown_path.display(),
            out.json_path.display()
        );
        return Ok(());
    }

    // Load config (optional - all fields have sensible defaults).
    // Done before dashboard check so action config can be wired in.
    let cfg = match &cli.config {
        Some(path) => config::load(path)?,
        None => config::AgentConfig::default(),
    };

    // Validate Telegram config early to fail fast on misconfiguration
    cfg.telegram.validate()?;

    // Initialize cloud provider IP safelist (Google, AWS, Azure, Cloudflare, etc.)
    cloud_safelist::init();

    // Deep security snapshot: shared between agent (updates) and dashboard (reads).
    let deep_security_snapshot = std::sync::Arc::new(std::sync::RwLock::new(
        dashboard::DeepSecuritySnapshot::default(),
    ));

    // Open SQLite store early so the graph can try loading from it.
    // Wrapped in Arc so it can be shared with the dashboard task.
    let sqlite_store: Option<Arc<innerwarden_store::Store>> =
        match innerwarden_store::Store::open(&cli.data_dir) {
            Ok(s) => {
                info!(path = %cli.data_dir.join("innerwarden.db").display(), "sqlite store opened");
                Some(Arc::new(s))
            }
            Err(e) => {
                warn!("sqlite store unavailable: {e:#}");
                None
            }
        };

    // One-time migration from legacy files (JSONL + JSON → SQLite)
    if let Some(ref sq) = sqlite_store {
        if innerwarden_store::Store::has_legacy_files(&cli.data_dir) {
            match sq.migrate_from_legacy(&cli.data_dir) {
                Ok(report) => info!("legacy migration done: {report}"),
                Err(e) => warn!("legacy migration failed: {e:#}"),
            }
        }
    }

    // Shared knowledge graph: try SQLite store first, fall back to file-based dated snapshot.
    let shared_graph = std::sync::Arc::new(std::sync::RwLock::new({
        let from_store = sqlite_store
            .as_deref()
            .and_then(knowledge_graph::KnowledgeGraph::load_from_store);
        if let Some(g) = from_store {
            g
        } else {
            knowledge_graph::KnowledgeGraph::load_today_snapshot(&cli.data_dir)
        }
    }));

    // Advisory cache: shared between dashboard (writes advisory denials) and
    // the incident processing loop (checks for advisory violations).
    let advisory_cache: Arc<RwLock<VecDeque<AdvisoryEntry>>> =
        Arc::new(RwLock::new(VecDeque::new()));

    // Agent-guard snitch alert channel. Created before the dashboard block
    // so the receiver can be used in the dispatch task spawned later.
    let (agent_alert_tx, mut agent_alert_rx) =
        tokio::sync::mpsc::channel::<dashboard::AgentGuardAlert>(64);

    if cli.dashboard {
        let auth = dashboard::DashboardAuth::try_from_env()?;
        let action_cfg = dashboard::DashboardActionConfig {
            enabled: cfg.responder.enabled,
            dry_run: cfg.responder.dry_run,
            block_backend: cfg.responder.block_backend.clone(),
            allowed_skills: cfg.responder.allowed_skills.clone(),
            ai_enabled: cfg.ai.enabled,
            ai_provider: cfg.ai.provider.clone(),
            ai_model: cfg.ai.model.clone(),
            fail2ban_enabled: cfg.fail2ban.enabled,
            geoip_enabled: cfg.geoip.enabled,
            abuseipdb_enabled: cfg.abuseipdb.enabled,
            abuseipdb_auto_block_threshold: cfg.abuseipdb.auto_block_threshold,
            honeypot_mode: cfg.honeypot.mode.clone(),
            telegram_enabled: cfg.telegram.enabled,
            slack_enabled: cfg.slack.enabled,
            cloudflare_enabled: cfg.cloudflare.enabled,
            crowdsec_enabled: cfg.crowdsec.enabled,
            webhook_format: cfg.webhook.format.clone(),
            sudo_protection_enabled: cfg
                .responder
                .allowed_skills
                .iter()
                .any(|s| s.contains("suspend-user")),
            execution_guard_enabled: cfg
                .responder
                .allowed_skills
                .iter()
                .any(|s| s.contains("execution")),
            mesh_enabled: cfg.mesh.enabled,
            web_push_enabled: !cfg.web_push.vapid_public_key.is_empty(),
            shield_enabled: cfg.cloudflare.enabled,
            dna_enabled: true, // DNA fingerprinting is always active
            retention_events_days: cfg.data.events_keep_days,
            retention_incidents_days: cfg.data.incidents_keep_days,
            retention_decisions_days: cfg.data.decisions_keep_days,
            retention_telemetry_days: cfg.data.telemetry_keep_days,
            retention_reports_days: cfg.data.reports_keep_days,
            trusted_ips: cfg.allowlist.trusted_ips.clone(),
            trusted_users: cfg.allowlist.trusted_users.clone(),
        };
        let dashboard_data_dir = cli.data_dir.clone();
        let dashboard_bind = cli.dashboard_bind.clone();
        let web_push_pub_key = cfg.web_push.vapid_public_key.clone();
        let trusted_proxies = cfg.dashboard.trusted_proxies.clone();
        let session_timeout_minutes = cfg.dashboard.session_timeout_minutes;
        let max_sessions = cfg.dashboard.max_sessions;
        let dashboard_advisory_cache = advisory_cache.clone();

        // Load ATR rule engine from rules directory.
        let rules_dir = std::path::Path::new("/etc/innerwarden/rules");
        let rule_engine = std::sync::Arc::new(
            innerwarden_agent_guard::rules::RuleEngine::load(rules_dir).unwrap_or_else(|e| {
                warn!(error = %e, "failed to load ATR rules, starting with empty engine");
                innerwarden_agent_guard::rules::RuleEngine::empty()
            }),
        );

        let agent_alert_tx = agent_alert_tx.clone();
        let deep_security = deep_security_snapshot.clone();
        let dashboard_graph = shared_graph.clone();
        let dashboard_ai: Option<Arc<dyn ai::AiProvider>> = if cfg.ai.enabled {
            match ai::build_provider(&cfg.ai) {
                Ok(p) => Some(Arc::from(p)),
                Err(e) => {
                    warn!("briefing AI provider failed: {e:#}");
                    None
                }
            }
        } else {
            None
        };
        let dashboard_briefing = Arc::new(tokio::sync::Mutex::new(None::<briefing::Briefing>));
        let briefing_hour = cfg.briefing.hour;
        let briefing_minute = cfg.briefing.minute;
        let dashboard_store = sqlite_store.clone();
        let tls_cert = cli.tls_cert.clone();
        let tls_key = cli.tls_key.clone();
        let insecure_no_tls = cli.insecure_no_tls;
        tokio::spawn(async move {
            if let Err(e) = dashboard::serve(
                dashboard_data_dir,
                dashboard_bind,
                auth,
                action_cfg,
                web_push_pub_key,
                trusted_proxies,
                session_timeout_minutes,
                max_sessions,
                dashboard_advisory_cache,
                rule_engine,
                agent_alert_tx,
                deep_security,
                dashboard_graph,
                dashboard_ai,
                dashboard_briefing,
                briefing_hour,
                briefing_minute,
                dashboard_store,
                tls_cert,
                tls_key,
                insecure_no_tls,
            )
            .await
            {
                warn!(error = %e, "dashboard exited with error");
            }
        });
    }

    info!(
        data_dir = %cli.data_dir.display(),
        mode = if cli.once { "once" } else { "continuous" },
        narrative = cfg.narrative.enabled,
        webhook = cfg.webhook.enabled,
        ai = cfg.ai.enabled,
        correlation = cfg.correlation.enabled,
        correlation_window_secs = cfg.correlation.window_seconds,
        telemetry = cfg.telemetry.enabled,
        honeypot_mode = %cfg.honeypot.mode,
        honeypot_bind_addr = %cfg.honeypot.bind_addr,
        honeypot_services = ?cfg.honeypot.services,
        honeypot_ssh_port = cfg.honeypot.port,
        honeypot_http_port = cfg.honeypot.http_port,
        honeypot_isolation_profile = %cfg.honeypot.isolation_profile,
        honeypot_forensics_keep_days = cfg.honeypot.forensics_keep_days,
        honeypot_forensics_max_total_mb = cfg.honeypot.forensics_max_total_mb,
        honeypot_sandbox = cfg.honeypot.sandbox.enabled,
        honeypot_containment_mode = %cfg.honeypot.containment.mode,
        honeypot_containment_jail_runner = %cfg.honeypot.containment.jail_runner,
        honeypot_containment_jail_profile = %cfg.honeypot.containment.jail_profile,
        honeypot_external_handoff = cfg.honeypot.external_handoff.enabled,
        honeypot_external_handoff_allowlist = cfg.honeypot.external_handoff.enforce_allowlist,
        honeypot_external_handoff_signature = cfg.honeypot.external_handoff.signature_enabled,
        honeypot_external_handoff_attestation = cfg.honeypot.external_handoff.attestation_enabled,
        honeypot_pcap_handoff = cfg.honeypot.pcap_handoff.enabled,
        honeypot_redirect = cfg.honeypot.redirect.enabled,
        responder = cfg.responder.enabled,
        dry_run = cfg.responder.dry_run,
        "innerwarden-agent v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Clean up old summaries on startup
    if cfg.narrative.enabled {
        if let Err(e) = narrative::cleanup_old(&cli.data_dir, cfg.narrative.keep_days) {
            warn!("failed to clean up old summaries: {e:#}");
        }
    }

    // Clean up old data files on startup
    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
    if removed > 0 {
        info!(removed, "data_retention: cleaned up old files on startup");
    }

    // Build shared agent state
    // Pre-populate blocklist + decision cooldowns from recent (today + yesterday)
    // decision files so that IPs we already decided to block are skipped after a
    // restart, even in dry-run mode.
    let (decisions_bl, startup_cooldowns) = load_startup_decision_state(&cli.data_dir, false);

    let startup_blocklist = {
        let mut bl = if cfg.responder.enabled && !cfg.responder.dry_run {
            skills::Blocklist::load_from_ufw().await
        } else {
            skills::Blocklist::default()
        };
        // Merge IPs from recent decision files
        for ip in decisions_bl.as_vec() {
            bl.insert(ip);
        }
        bl
    };

    // Build Telegram client (None when disabled or misconfigured)
    let telegram_client: Option<Arc<telegram::TelegramClient>> = if cfg.telegram.enabled {
        let token = cfg.telegram.resolved_bot_token();
        let chat_id = cfg.telegram.resolved_chat_id();
        if token.is_empty() || chat_id.is_empty() {
            warn!("telegram.enabled = true but bot_token/chat_id not configured - disabling");
            None
        } else {
            let dashboard_url = if cfg.telegram.dashboard_url.is_empty() {
                None
            } else {
                Some(cfg.telegram.dashboard_url.clone())
            };
            match telegram::TelegramClient::new(token, chat_id, dashboard_url) {
                Ok(mut c) => {
                    if cfg.telegram.dev_mode {
                        c.dev_mode = true;
                        info!("Telegram dev mode ON — FP review button on every notification");
                    }
                    info!("Telegram client initialised (T.1 notifications enabled)");
                    Some(Arc::new(c))
                }
                Err(e) => {
                    warn!("failed to create Telegram client: {e:#}");
                    None
                }
            }
        }
    } else {
        None
    };

    // Build Slack client (None when disabled or unconfigured)
    let slack_client: Option<slack::SlackClient> = if cfg.slack.enabled {
        let url = cfg.slack.resolved_webhook_url();
        if url.is_empty() {
            warn!("slack.enabled = true but webhook_url not configured - disabling");
            None
        } else {
            match slack::SlackClient::new(&url) {
                Ok(c) => {
                    info!("Slack notifications enabled");
                    Some(c)
                }
                Err(e) => {
                    warn!("failed to create Slack client: {e:#}");
                    None
                }
            }
        }
    } else {
        None
    };

    // Create approval channel - polling task is spawned after state is built (continuous mode only)
    let (approval_tx, approval_rx_for_state) =
        tokio::sync::mpsc::channel::<telegram::ApprovalResult>(64);

    let store = state_store::StateStore::open(&cli.data_dir).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "state store open failed - using fresh store");
        state_store::StateStore::open(&std::env::temp_dir()).expect("fallback store")
    });

    // Seed the persistent store with decision cooldowns loaded from recent JSONL files.
    // This ensures restart continuity: IPs already decided on won't be re-evaluated.
    for (key, ts) in &startup_cooldowns {
        store.set_cooldown(state_store::CooldownTable::Decision, key, *ts);
    }

    // Spawn snitch alert dispatch task (uses cloned notification clients).
    {
        let tg = telegram_client.clone();
        let sc_url = if cfg.slack.enabled {
            cfg.slack.resolved_webhook_url()
        } else {
            String::new()
        };
        let wh_url = cfg.webhook.url.clone();
        let wh_enabled = cfg.webhook.enabled;
        let wh_timeout = cfg.webhook.timeout_secs;
        let wh_format = cfg.webhook.format.clone();
        let alert_data_dir = cli.data_dir.clone();
        tokio::spawn(async move {
            let sc = if !sc_url.is_empty() {
                slack::SlackClient::new(&sc_url).ok()
            } else {
                None
            };
            let mut cooldowns: std::collections::HashMap<String, tokio::time::Instant> =
                std::collections::HashMap::new();
            while let Some(alert) = agent_alert_rx.recv().await {
                // 60s cooldown per agent+command hash.
                let key = format!(
                    "{}:{}",
                    alert.agent_name,
                    innerwarden_core::audit::sha256_hex(&alert.command)
                );
                let now = tokio::time::Instant::now();
                if let Some(last) = cooldowns.get(&key) {
                    if now.duration_since(*last) < std::time::Duration::from_secs(60) {
                        continue;
                    }
                }
                cooldowns.insert(key, now);
                cooldowns
                    .retain(|_, v| now.duration_since(*v) < std::time::Duration::from_secs(300));

                info!(
                    agent = %alert.agent_name,
                    command = %alert.command,
                    severity = %alert.severity,
                    recommendation = %alert.recommendation,
                    "agent-guard snitch alert"
                );

                // JSONL audit trail (write first, before network calls that may block).
                {
                    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
                    let path = alert_data_dir.join(format!("agent-guard-events-{today}.jsonl"));
                    match serde_json::to_string(&alert) {
                        Ok(line) => {
                            use std::io::Write;
                            match std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&path)
                            {
                                Ok(mut f) => {
                                    if let Err(e) = writeln!(f, "{line}") {
                                        warn!(error = %e, path = %path.display(), "failed to write agent-guard event");
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, path = %path.display(), "failed to open agent-guard events file")
                                }
                            }
                        }
                        Err(e) => warn!(error = %e, "failed to serialize agent-guard alert"),
                    }
                }

                // Telegram notification.
                if let Some(ref tg) = tg {
                    if let Err(e) = tg.send_agent_guard_alert(&alert).await {
                        warn!(error = %e, "agent-guard Telegram alert failed");
                    }
                }

                // Slack notification.
                if let Some(ref sc) = sc {
                    if let Err(e) = sc.send_agent_guard_alert(&alert).await {
                        warn!(error = %e, "agent-guard Slack alert failed");
                    }
                }

                // Webhook notification.
                if wh_enabled {
                    if let Err(e) =
                        webhook::send_agent_guard_alert(&wh_url, wh_timeout, &alert, &wh_format)
                            .await
                    {
                        warn!(error = %e, "agent-guard webhook alert failed");
                    }
                }
            }
        });
    }

    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: startup_blocklist,
        correlator: correlation::TemporalCorrelator::new(cfg.correlation.window_seconds, 4096),
        telemetry: telemetry::TelemetryState::default(),
        telemetry_writer: if cfg.telemetry.enabled {
            match telemetry::TelemetryWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create telemetry writer: {e:#}");
                    None
                }
            }
        } else {
            None
        },
        ai_provider: if cfg.ai.enabled {
            match ai::build_provider(&cfg.ai) {
                Ok(p) => Some(Arc::from(p)),
                Err(e) => {
                    warn!("failed to create AI provider: {e:#}");
                    None
                }
            }
        } else {
            None
        },
        // Decision writer is always created — Layer 1/2 decisions are written
        // even without AI. Previously gated on cfg.ai.enabled which caused
        // zero audit trail when AI was disabled or during agent restarts.
        decision_writer: match decisions::DecisionWriter::new(&cli.data_dir) {
            Ok(w) => Some(w),
            Err(e) => {
                warn!("failed to create decision writer: {e:#}");
                None
            }
        },
        last_narrative_at: load_last_narrative_instant(&cli.data_dir),
        last_daily_summary_telegram: None,
        telegram_daily_sent: 0,
        telegram_budget_date: None,
        telegram_deferred: HashMap::new(),
        telegram_client,
        pending_confirmations: HashMap::new(),
        approval_rx: None, // set below in continuous mode
        grouping_engine: notification_pipeline::GroupingEngine::new(&cfg.notifications),
        environment_profile: environment_profile::load_or_bootstrap(
            &cli.data_dir,
            &cfg.environment,
        ),
        anomaly_engine: neural_lifecycle::AnomalyEngine::new(neural_lifecycle::AnomalyConfig {
            data_dir: cli.data_dir.clone(),
            ..Default::default()
        }),
        neural_incidents: Vec::new(),
        trust_rules: load_trust_rules(&cli.data_dir),
        crowdsec: if cfg.crowdsec.enabled {
            info!(url = %cfg.crowdsec.url, "CrowdSec integration enabled");
            Some(crowdsec::CrowdSecState::new(&cfg.crowdsec))
        } else {
            None
        },
        abuseipdb: if cfg.abuseipdb.enabled {
            let key = abuseipdb::resolve_api_key(&cfg.abuseipdb.api_key);
            if key.is_empty() {
                warn!("abuseipdb.enabled=true but no API key found - disabling enrichment");
                None
            } else {
                info!(
                    "AbuseIPDB enrichment enabled (max_age_days={})",
                    cfg.abuseipdb.max_age_days
                );
                Some(abuseipdb::AbuseIpDbClient::new(
                    key,
                    cfg.abuseipdb.max_age_days,
                ))
            }
        } else {
            None
        },
        fail2ban: if cfg.fail2ban.enabled {
            info!("Fail2ban integration enabled");
            Some(fail2ban::Fail2BanState::new(&cfg.fail2ban))
        } else {
            None
        },
        geoip_client: if cfg.geoip.enabled {
            info!("GeoIP enrichment enabled (ip-api.com, free tier)");
            Some(geoip::GeoIpClient::new())
        } else {
            None
        },
        slack_client,
        cloudflare_client: if cfg.cloudflare.enabled {
            let token = cloudflare::resolve_api_token(&cfg.cloudflare.api_token);
            if token.is_empty() || cfg.cloudflare.zone_id.is_empty() {
                warn!(
                    "cloudflare.enabled=true but api_token or zone_id not configured - disabling"
                );
                None
            } else {
                info!(zone_id = %cfg.cloudflare.zone_id, "Cloudflare IP block push enabled");
                Some(cloudflare::CloudflareClient::with_prefix(
                    cfg.cloudflare.zone_id.clone(),
                    token,
                    cfg.cloudflare.block_notes_prefix.clone(),
                ))
            }
        } else {
            None
        },
        circuit_breaker_until: None,
        pending_honeypot_choices: HashMap::new(),
        ip_reputations: load_ip_reputations(&cli.data_dir),
        lsm_enabled: false,
        mesh: if cfg.mesh.enabled {
            match mesh::MeshIntegration::new(&cfg.mesh, &cli.data_dir) {
                Ok(m) => {
                    info!(node_id = %m.node_id(), peers = m.peer_count(), "Mesh network enabled");
                    Some(m)
                }
                Err(e) => {
                    warn!(error = %e, "Mesh network init failed");
                    None
                }
            }
        } else {
            None
        },
        recent_blocks: std::collections::VecDeque::new(),
        xdp_block_times: HashMap::new(),
        response_lifecycle: response_lifecycle::ResponseLifecycle::load_snapshot(
            &cli.data_dir,
            sqlite_store.as_deref(),
        ),
        abuseipdb_report_queue: Vec::new(),
        narrative_acc: NarrativeAccumulator::default(),
        narrative_incidents_offset: 0,
        forensics: forensics::ForensicsCapture::new(&cli.data_dir),
        store,
        baseline: baseline::BaselineStore::load(&cli.data_dir, sqlite_store.as_deref()),
        sqlite_store: sqlite_store.clone(),
        maintenance_scheduler: if sqlite_store.is_some() {
            Some(innerwarden_store::maintenance::MaintenanceScheduler::new())
        } else {
            None
        },
        attacker_profiles: HashMap::new(), // loaded from redb below
        last_intel_consolidation_at: None,
        correlation_engine: correlation_engine::CorrelationEngine::new(),
        playbook_engine: playbook::PlaybookEngine::new(&cli.data_dir),
        defender_brain: defender_brain::DefenderBrain::load(
            &cli.data_dir.join("defender-brain.json").to_string_lossy(),
        ),
        brain_history: defender_brain::BrainHistory::new(500),
        brain_stats: defender_brain::BrainStats::load(&cli.data_dir),
        pcap_capture: pcap_capture::PcapCapture::new(&cli.data_dir),
        scoring_engine: scoring::ScoringEngine::new(0.95),
        last_firmware_incident_at: None,
        last_hypervisor_incident_at: None,
        hypervisor_environment: None,
        killchain_tracker: innerwarden_killchain::tracker::PidTracker::new()
            .with_timeout(cfg.killchain.session_timeout_secs)
            .with_pre_chain_threshold(cfg.killchain.pre_chain_threshold)
            .with_excluded_comms(
                killchain_inline::KILLCHAIN_SELF_EXCLUDED_COMMS
                    .iter()
                    .copied(),
            ),
        last_killchain_cleanup: std::time::Instant::now(),
        dna_state: dna_inline::DnaState::new(
            &cli.data_dir.join("dna"),
            cfg.dna.min_sequence,
            cfg.dna.anomaly_threshold,
            cfg.dna.session_timeout_secs,
        ),
        shield_state: if cfg.shield.enabled {
            Some(shield_inline::ShieldState::new(
                &cli.data_dir.join("shield"),
                &cfg.shield.bpf_path,
                cfg.shield.dry_run,
            ))
        } else {
            None
        },
        last_dna_save: std::time::Instant::now(),
        deep_security_snapshot: Some(deep_security_snapshot.clone()),
        dynamic_trusted_ips: Vec::new(),
        dynamic_trusted_users: Vec::new(),
        dynamic_trusted_processes: Vec::new(),
        operator_ips: std::collections::HashMap::new(),
        last_operator_refresh: std::time::Instant::now(),
        suppressed_incident_ids: firmware_tick::load_suppressed_ids(&cli.data_dir),
        threat_feed: None, // initialized below if configured
        last_baseline_anomaly_ts: None,
        last_autoencoder_anomaly_ts: None,
        latest_anomaly_score: None,
        two_factor_state: two_factor::TwoFactorState::new(),
        knowledge_graph: shared_graph.clone(),
        graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
        last_graph_snapshot: std::time::Instant::now(),
        #[cfg(feature = "redis-reader")]
        redis_reader: None,
        notification_burst_tracker: notification_gate::BurstTracker::new(),
    };

    // Seed operator IPs from active SSH sessions (who -i).
    // Only publickey SSH sessions from trusted_users are considered operators.
    // IPs are dynamic — they expire when the session ends (refreshed every 30s).
    crate::loops::slow_loop::refresh_operator_ips(&mut state, &cfg.allowlist);
    state.last_operator_refresh = std::time::Instant::now();

    // Load attacker intelligence profiles from persistent store
    state.attacker_profiles = attacker_intel::load_from_store(&state.store);
    if !state.attacker_profiles.is_empty() {
        info!(
            profiles = state.attacker_profiles.len(),
            "loaded attacker profiles from state store"
        );
    }

    // Initialize threat feed client if VT API key or IOC feed URLs are configured
    {
        let vt_key = if cfg.threat_feeds.virustotal_api_key.is_empty() {
            threat_feeds::resolve_vt_api_key("")
        } else {
            cfg.threat_feeds.virustotal_api_key.clone()
        };
        let feed_urls = cfg.threat_feeds.effective_urls();
        if !feed_urls.is_empty() {
            info!(
                feeds = feed_urls.len(),
                "threat feeds: {} URLs configured",
                feed_urls.len()
            );
        }
        let client = threat_feeds::ThreatFeedClient::new(
            vt_key,
            feed_urls,
            &cli.data_dir,
            sqlite_store.as_deref(),
        );
        let feed_state = client.state();
        if feed_state.total_iocs > 0 {
            info!(
                ips = feed_state.malicious_ips.len(),
                domains = feed_state.malicious_domains.len(),
                hashes = feed_state.malicious_hashes.len(),
                "threat feeds: loaded cached IOCs"
            );
        }
        state.threat_feed = Some(client);
    }

    // Connect Redis reader if configured
    #[cfg(feature = "redis-reader")]
    if let Some(ref url) = cfg.redis_url {
        let redis_cfg = redis_reader::agent_config(url, cfg.redis_stream.as_deref());
        match redis_reader::RedisStreamReader::connect(redis_cfg).await {
            Ok(r) => {
                info!("Redis stream reader connected - events from Redis");
                state.redis_reader = Some(r);
            }
            Err(e) => {
                warn!("Redis reader connection failed ({e:#}), using JSONL fallback");
            }
        }
    }

    if !state.ip_reputations.is_empty() {
        info!(
            count = state.ip_reputations.len(),
            "loaded local IP reputations from disk"
        );
    }

    if let Some(ref mesh_node) = state.mesh {
        match mesh_node.start_listener().await {
            Ok((addr, _handle)) => info!(addr = %addr, "mesh listener started"),
            Err(e) => warn!(error = %e, "mesh listener failed to start"),
        }
    }

    // Discover mesh peer identities (ping each, learn their public keys).
    // Must happen after listener starts so peers can ping us back.
    if let Some(ref mut mesh_node) = state.mesh {
        mesh_node.discover_peers().await;
        info!(
            peers = mesh_node.peer_count(),
            "mesh peer discovery complete"
        );
    }

    // Legacy cursor kept for test compatibility (tests still pass AgentCursor)
    let mut cursor = reader::AgentCursor::default();

    if cli.once {
        let handled = crate::process::incidents::process_incidents(
            &cli.data_dir,
            &mut cursor,
            &cfg,
            &mut state,
            &advisory_cache,
        )
        .await;
        let new_events = crate::loops::slow_loop::process_narrative_tick(
            &cli.data_dir,
            &mut cursor,
            &cfg,
            &mut state,
        )
        .await?;
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        if let Some(w) = &mut state.telemetry_writer {
            w.flush();
        }
        info!(new_events, incidents_handled = handled, "run complete");
    } else {
        // Activate approval channel and start Telegram polling task
        state.approval_rx = Some(approval_rx_for_state);
        if let Some(ref tg) = state.telegram_client {
            // Register persistent command menu (fire-and-forget)
            tg.set_commands().await;
            let tg_clone = tg.clone();
            tokio::spawn(async move { tg_clone.run_polling(approval_tx).await });
            info!("Telegram polling task started (T.2 approvals enabled)");
        }

        // Proactive startup suggestions (fail2ban detected but not integrated, etc.)
        crate::bot_commands::probe_and_suggest(&cfg, state.telegram_client.as_deref()).await;

        // Boot self-test: verify self-awareness is working.
        crate::loops::slow_loop::boot_self_test();

        // One-time backfill: reconcile JSONL decisions with the knowledge graph.
        // Fixes historical incidents where auto-block gates wrote to JSONL but
        // not to the graph (incident_obvious + incident_crowdsec before the fix).
        crate::loops::slow_loop::backfill_graph_decisions(&cli.data_dir, &mut state);

        // Always-on honeypot: permanent SSH listener from startup.
        // A watch channel is used to signal shutdown on SIGTERM/SIGINT.
        let always_on_shutdown_tx = if cfg.honeypot.mode == "always_on" {
            let (tx, rx) = tokio::sync::watch::channel(false);

            // Build a filter blocklist pre-populated from today's + yesterday's decisions.
            let initial_blocked: std::collections::HashSet<String> = {
                let (bl, _) = load_startup_decision_state(&cli.data_dir, false);
                bl.as_vec().into_iter().collect()
            };
            let filter_bl = std::sync::Arc::new(std::sync::Mutex::new(initial_blocked));

            let port = cfg.honeypot.port;
            let bind_addr = cfg.honeypot.bind_addr.clone();
            let max_auth = cfg.honeypot.ssh_max_auth_attempts;
            let abuseipdb_client = if cfg.abuseipdb.enabled {
                let key = abuseipdb::resolve_api_key(&cfg.abuseipdb.api_key);
                if key.is_empty() {
                    None
                } else {
                    Some(std::sync::Arc::new(abuseipdb::AbuseIpDbClient::new(
                        key,
                        cfg.abuseipdb.max_age_days,
                    )))
                }
            } else {
                None
            };
            let abuseipdb_threshold = cfg.abuseipdb.auto_block_threshold;
            let ai_clone = state.ai_provider.clone();
            let tg_clone = state.telegram_client.clone();
            let data_dir_clone = cli.data_dir.clone();
            let responder_enabled = cfg.responder.enabled;
            let dry_run = cfg.responder.dry_run;
            let block_backend = cfg.responder.block_backend.clone();
            let allowed_skills = cfg.responder.allowed_skills.clone();
            let interaction = cfg.honeypot.interaction.clone();

            tokio::spawn(async move {
                honeypot_always_on::run_always_on_honeypot(
                    port,
                    bind_addr,
                    max_auth,
                    filter_bl,
                    ai_clone,
                    tg_clone,
                    abuseipdb_client,
                    abuseipdb_threshold,
                    data_dir_clone,
                    responder_enabled,
                    dry_run,
                    block_backend,
                    allowed_skills,
                    interaction,
                    rx,
                )
                .await;
            });

            Some(tx)
        } else {
            None
        };

        let ai_poll = cfg.ai.incident_poll_secs;
        info!(
            narrative_interval_secs = cli.interval,
            incident_interval_secs = ai_poll,
            "entering continuous mode"
        );

        let mut narrative_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cli.interval));
        let mut incident_ticker = tokio::time::interval(tokio::time::Duration::from_secs(ai_poll));
        let mut crowdsec_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.crowdsec.poll_secs.max(10),
        ));
        let mut fail2ban_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.fail2ban.poll_secs.max(10),
        ));
        let mut mesh_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cfg.mesh.poll_secs.max(10)));
        let mut firmware_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.firmware.poll_secs.max(60),
        ));
        let mut hypervisor_ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            cfg.hypervisor.poll_secs.max(60),
        ));

        // SIGTERM / SIGINT
        #[cfg(unix)]
        let mut sigterm = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::terminate())?
        };

        loop {
            #[cfg(unix)]
            let shutdown = tokio::select! {
                _ = incident_ticker.tick() => {
                    crate::loops::fast_loop::run_incident_tick(
                        &cli.data_dir,
                        &mut cursor,
                        &cfg,
                        &mut state,
                        &advisory_cache,
                    ).await;
                    false
                }
                _ = narrative_ticker.tick() => {
                    match crate::loops::slow_loop::process_narrative_tick(
                        &cli.data_dir,
                        &mut cursor,
                        &cfg,
                        &mut state,
                    ).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => {
                            state.telemetry.observe_error("narrative_tick");
                            warn!("narrative tick error: {e:#}");
                        }
                    }
                    // Tick notification pipeline — emit group summaries for
                    // groups that hit count threshold or expired windows.
                    {
                        let summaries = state.grouping_engine.tick();
                        if !summaries.is_empty() {
                            let tg_level = cfg.telegram.channel_notifications.notification_level;
                            let tg_summaries: Vec<String> = summaries
                                .iter()
                                .filter(|s| notification_pipeline::should_notify_summary(s, tg_level))
                                .filter(|s| notification_pipeline::is_immediate_threat_summary(s))
                                .map(|s| s.format_html())
                                .collect();
                            if !tg_summaries.is_empty() {
                                if let Some(ref tg) = state.telegram_client {
                                    let digest = tg_summaries.join("\n");
                                    if let Err(e) = tg.send_raw_html(&digest).await {
                                        warn!("Telegram group summary failed: {e:#}");
                                    }
                                }
                            }
                        }
                    }

                    // Refresh operator IPs from active SSH sessions (every 30s).
                    // Expired sessions are removed so dynamic IPs don't stay protected forever.
                    if state.last_operator_refresh.elapsed() >= std::time::Duration::from_secs(30) {
                        crate::loops::slow_loop::refresh_operator_ips(
                            &mut state,
                            &cfg.allowlist,
                        );
                        state.last_operator_refresh = std::time::Instant::now();
                    }

                    // Hot-reload dynamic allowlist from /etc/innerwarden/allowlist.toml.
                    // Operators can add IPs/users/processes via Telegram or by editing the file.
                    {
                        let allowlist_path = std::path::Path::new("/etc/innerwarden/allowlist.toml");
                        if allowlist_path.exists() {
                            if let Ok(content) = std::fs::read_to_string(allowlist_path) {
                                if let Ok(table) = content.parse::<toml::Table>() {
                                    let extract = |key: &str| -> Vec<String> {
                                        table.get(key)
                                            .and_then(|v| v.as_table())
                                            .map(|t| t.keys().cloned().collect())
                                            .unwrap_or_default()
                                    };
                                    state.dynamic_trusted_ips = extract("ips");
                                    state.dynamic_trusted_users = extract("users");
                                    state.dynamic_trusted_processes = extract("processes");
                                }
                            }
                        }
                    }

                    // Autoencoder nightly training — at 3 AM UTC.
                    {
                        let hour = chrono::Utc::now().hour();
                        if hour == 3 {
                            let today_key = format!("anomaly_train:{}", chrono::Utc::now().format("%Y-%m-%d"));
                            if !state.store.has_cooldown(state_store::CooldownTable::Decision, &today_key) {
                                info!("autoencoder: triggering nightly training");
                                match state.anomaly_engine.train_nightly() {
                                    Ok(()) => {
                                        info!(
                                            maturity = format!("{:.2}", state.anomaly_engine.maturity),
                                            cycles = state.anomaly_engine.training_cycles,
                                            "autoencoder: training complete"
                                        );
                                        state.store.set_cooldown(
                                            state_store::CooldownTable::Decision,
                                            &today_key,
                                            chrono::Utc::now(),
                                        );
                                    }
                                    Err(e) => warn!("autoencoder training failed: {e}"),
                                }
                            }
                        }
                    }

                    // Defender brain daily retrain — at 3:30 AM UTC (after autoencoder at 3 AM).
                    // Reads brain-log.json (features + AI decisions), fine-tunes policy head.
                    {
                        let now_utc = chrono::Utc::now();
                        if now_utc.hour() == 3 && now_utc.minute() >= 30 {
                            let today_key = format!("brain_retrain:{}", now_utc.format("%Y-%m-%d"));
                            if !state.store.has_cooldown(state_store::CooldownTable::Decision, &today_key) {
                                info!("defender brain: triggering daily retrain");
                                match state.defender_brain.retrain_from_log(&cli.data_dir) {
                                    Some((entries, accuracy)) => {
                                        info!(
                                            entries,
                                            accuracy = format!("{:.1}%", accuracy * 100.0),
                                            "defender brain: retrain complete"
                                        );
                                        state.brain_stats.last_retrain =
                                            Some(now_utc.to_rfc3339());
                                        state.brain_stats.last_retrain_accuracy = Some(accuracy);
                                        state.brain_stats.last_retrain_entries = Some(entries);
                                        state.brain_stats.total_since_retrain = 0;
                                        state.brain_stats.agreed_since_retrain = 0;
                                        state.brain_stats.save(&cli.data_dir);
                                    }
                                    None => info!("defender brain: retrain skipped (not enough data)"),
                                }
                                state.store.set_cooldown(
                                    state_store::CooldownTable::Decision,
                                    &today_key,
                                    now_utc,
                                );
                            }
                        }
                    }

                    // Trim in-memory structures to prevent unbounded memory growth
                    state.blocklist.trim_if_needed(10_000);
                    let cutoff_2h = chrono::Utc::now() - chrono::Duration::hours(2);
                    state.store.retain_cooldowns(state_store::CooldownTable::Decision, cutoff_2h);
                    state.store.retain_cooldowns(state_store::CooldownTable::Notification, cutoff_2h);
                    // Cap block_counts to 5000 entries
                    if state.store.block_counts_len() > 5000 {
                        state.store.clear_block_counts();
                    }
                    // Cap ip_reputations and persist to disk for dashboard
                    if state.ip_reputations.len() > 10000 {
                        // Keep only the top 5000 by reputation_score
                        let mut entries: Vec<_> = state.ip_reputations.drain().collect();
                        entries.sort_by(|a, b| b.1.reputation_score.partial_cmp(&a.1.reputation_score).unwrap_or(std::cmp::Ordering::Equal));
                        entries.truncate(5000);
                        state.ip_reputations = entries.into_iter().collect();
                    }
                    persist_ip_reputations(&cli.data_dir, &state.ip_reputations);

                    // ── Safeguard: XDP TTL - expire old blocklist entries ──
                    //
                    // Only removes the local bookkeeping entry after the kernel
                    // command succeeds (or confirms the entry was already gone).
                    // Transient failures keep the local state so a subsequent
                    // tick retries — preventing drift between `xdp_block_times`
                    // and the actual blocklist BPF map.
                    {
                        let now_utc = chrono::Utc::now();
                        let expired_ips: Vec<String> = state.xdp_block_times
                            .iter()
                            .filter(|(_, (ts, ttl))| {
                                let cutoff = *ts + chrono::Duration::seconds(*ttl);
                                now_utc > cutoff
                            })
                            .map(|(ip, _)| ip.clone())
                            .collect();
                        for ip in &expired_ips {
                            let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
                                // Not parseable — drop from state to avoid a
                                // poison entry; can't act on kernel anyway.
                                warn!(ip, "XDP cleanup: unparseable IP in xdp_block_times, dropping local entry");
                                state.xdp_block_times.remove(ip);
                                continue;
                            };
                            let b = addr.octets();
                            let ttl_secs = state.xdp_block_times.get(ip).map(|(_, t)| *t).unwrap_or(0);
                            let output = tokio::process::Command::new("sudo")
                                .args(["bpftool", "map", "delete", "pinned",
                                    "/sys/fs/bpf/innerwarden/blocklist",
                                    "key", &b[0].to_string(), &b[1].to_string(),
                                    &b[2].to_string(), &b[3].to_string()])
                                .output().await;
                            match output {
                                Ok(out) if out.status.success() => {
                                    state.xdp_block_times.remove(ip);
                                    info!(ip, ttl_secs, "XDP adaptive TTL expired - removed from blocklist");
                                }
                                Ok(out) => {
                                    let stderr = String::from_utf8_lossy(&out.stderr);
                                    let lower = stderr.to_lowercase();
                                    // Same classifier as response_lifecycle: if the
                                    // entry is already gone, call it a success.
                                    let already_absent = lower.contains("no such")
                                        || lower.contains("not found")
                                        || lower.contains("does not exist");
                                    if already_absent {
                                        state.xdp_block_times.remove(ip);
                                        info!(ip, ttl_secs, "XDP cleanup: entry already absent in kernel map, local state cleared");
                                    } else {
                                        warn!(
                                            ip,
                                            ttl_secs,
                                            status = ?out.status,
                                            stderr = %stderr.trim(),
                                            "XDP cleanup FAILED - keeping local state to retry next tick (kernel/local drift protection)"
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        ip,
                                        error = %e,
                                        "XDP cleanup: bpftool spawn failed - keeping local state to retry next tick"
                                    );
                                }
                            }
                        }
                    }

                    // ── Response Lifecycle: unified TTL cleanup ──
                    // Handles auto-revert for ufw, iptables, nftables (backends that
                    // didn't have TTL before). XDP/container/nginx/sudo still use
                    // their existing cleanup above; the lifecycle tracks them for
                    // dashboard visibility.
                    //
                    // State machine: stage_pending_reverts transitions Active→RevertPending
                    // (or restages RevertFailed with retry budget); we then execute each
                    // revert and report back via mark_reverted / mark_revert_failed.
                    // Entries are NEVER declared complete until the backend command has
                    // confirmed success (or been classified as already_absent). Orphaned
                    // entries — retries exhausted — are logged at WARN level; dashboards
                    // and Prometheus surface the drift.
                    {
                        let reverts = state.response_lifecycle.stage_pending_reverts();
                        let mut n_ok = 0usize;
                        let mut n_orphaned = 0usize;
                        for revert in &reverts {
                            match response_lifecycle::execute_revert(revert, cfg.responder.dry_run).await {
                                Ok(()) => {
                                    state.response_lifecycle.mark_reverted(&revert.id, "expired");
                                    n_ok += 1;
                                }
                                Err(err) => {
                                    let outcome = state
                                        .response_lifecycle
                                        .mark_revert_failed(&revert.id, err.clone());
                                    if let response_lifecycle::FailureOutcome::Orphaned {
                                        backend,
                                        target,
                                        last_error,
                                        ..
                                    } = outcome
                                    {
                                        n_orphaned += 1;
                                        // Surface is deliberately WARN log +
                                        // Prometheus counter + dashboard state,
                                        // not push notification. Orphaned means
                                        // "local/kernel state drift" — that's an
                                        // observability concern for a technical
                                        // operator watching logs/metrics, not an
                                        // interrupt-worthy pager event. Telegram
                                        // and Slack pushes are reserved for
                                        // incident-level signals.
                                        warn!(
                                            id = %revert.id,
                                            ?backend,
                                            %target,
                                            %last_error,
                                            "response ORPHANED — rule may still be active; check responses dashboard"
                                        );
                                    }
                                }
                            }
                        }
                        if n_ok > 0 || n_orphaned > 0 {
                            info!(
                                reverted = n_ok,
                                orphaned = n_orphaned,
                                "response lifecycle tick"
                            );
                        }
                        // Persist snapshot for dashboard /api/responses endpoint.
                        let json = state.response_lifecycle.to_json();
                        let path = cli.data_dir.join("responses.json");
                        if let Ok(data) = serde_json::to_string(&json) {
                            // Dual-write: SQLite blob + JSON file
                            if let Some(ref sq) = state.sqlite_store {
                                if let Err(e) = sq.set_blob("responses", &data) {
                                    warn!("failed to write responses blob: {e}");
                                }
                            }
                            let _ = tokio::fs::write(&path, data).await;
                        }
                    }

                    // ── Neural score → BPF map (Active Defence) ──
                    // Write the latest anomaly score to the kernel's NEURAL_SCORE map
                    // so the LSM hook can enforce ML-based decisions at wire speed.
                    #[cfg(target_os = "linux")]
                    {
                        let score = state.anomaly_engine.latest_score();
                        if score > 0.0 {
                            let score_fixed = (score * 65536.0) as i32; // Q16.16
                            let threshold_fixed = (0.75_f32 * 65536.0) as i32; // default 0.75
                            const NEURAL_SCORE_PIN: &str = "/sys/fs/bpf/innerwarden/neural_score";
                            if std::path::Path::new(NEURAL_SCORE_PIN).exists() {
                                // Write score (key 0)
                                let _ = tokio::process::Command::new("sudo")
                                    .args([
                                        "bpftool", "map", "update", "pinned", NEURAL_SCORE_PIN,
                                        "key", "0", "0", "0", "0",
                                        "value",
                                        &(score_fixed as u32 & 0xff).to_string(),
                                        &((score_fixed as u32 >> 8) & 0xff).to_string(),
                                        &((score_fixed as u32 >> 16) & 0xff).to_string(),
                                        &((score_fixed as u32 >> 24) & 0xff).to_string(),
                                        "any",
                                    ])
                                    .output()
                                    .await;
                                // Write threshold (key 1)
                                let _ = tokio::process::Command::new("sudo")
                                    .args([
                                        "bpftool", "map", "update", "pinned", NEURAL_SCORE_PIN,
                                        "key", "1", "0", "0", "0",
                                        "value",
                                        &(threshold_fixed as u32 & 0xff).to_string(),
                                        &((threshold_fixed as u32 >> 8) & 0xff).to_string(),
                                        &((threshold_fixed as u32 >> 16) & 0xff).to_string(),
                                        &((threshold_fixed as u32 >> 24) & 0xff).to_string(),
                                        "any",
                                    ])
                                    .output()
                                    .await;
                            }
                        }
                    }

                    // ── Safeguard: flush AbuseIPDB delayed report queue ──
                    {
                        let report_cutoff = chrono::Utc::now() - chrono::Duration::seconds(ABUSEIPDB_REPORT_DELAY_SECS);
                        let ready: Vec<_> = state.abuseipdb_report_queue
                            .iter()
                            .filter(|(_, _, _, ts)| *ts < report_cutoff)
                            .cloned()
                            .collect();
                        if let Some(ref client) = state.abuseipdb {
                            for (ip, comment, categories, _) in &ready {
                                client.report(ip, categories, comment).await;
                                info!(ip, "AbuseIPDB report sent (after 5min delay)");
                            }
                        }
                        state.abuseipdb_report_queue.retain(|(_, _, _, ts)| *ts >= report_cutoff);
                    }

                    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
                    if removed > 0 {
                        info!(removed, "data_retention: cleaned up old files");
                    }

                    // ── SQLite maintenance (time-gated inside tick) ──
                    if let (Some(ref mut sched), Some(ref sq)) =
                        (&mut state.maintenance_scheduler, &state.sqlite_store)
                    {
                        let integrity_alerts = sched.tick(sq);
                        if !integrity_alerts.is_empty() {
                            for alert in &integrity_alerts {
                                warn!(alert = %alert, "DATABASE SECURITY ALERT");
                            }
                            if let Some(tg) = &state.telegram_client {
                                let msg = format!(
                                    "\u{1f6a8} <b>Database Security Alert</b>\n\n{}\n\n\
                                     <i>Possible tampering or corruption detected. \
                                     Investigate immediately.</i>",
                                    integrity_alerts
                                        .iter()
                                        .map(|a| format!("\u{2022} {a}"))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                );
                                if let Err(e) = tg.send_text_message(&msg).await {
                                    warn!("failed to send integrity alert: {e:#}");
                                }
                            }
                        }
                    }

                    // ── Memory housekeeping: cap unbounded HashMaps ──
                    {
                        const MAX_IP_REPUTATIONS: usize = 2000;
                        if state.ip_reputations.len() > MAX_IP_REPUTATIONS {
                            let mut entries: Vec<_> = state.ip_reputations.drain().collect();
                            entries.sort_by(|a, b| {
                                b.1.reputation_score
                                    .partial_cmp(&a.1.reputation_score)
                                    .unwrap_or(std::cmp::Ordering::Equal)
                            });
                            entries.truncate(MAX_IP_REPUTATIONS);
                            state.ip_reputations = entries.into_iter().collect();
                        }

                        // Expire pending Telegram confirmations older than 30 minutes
                        let confirm_cutoff =
                            chrono::Utc::now() - chrono::Duration::minutes(30);
                        state
                            .pending_confirmations
                            .retain(|_, (pc, _, _)| pc.created_at > confirm_cutoff);

                        // Expire pending honeypot choices past their deadline
                        let now_utc = chrono::Utc::now();
                        state
                            .pending_honeypot_choices
                            .retain(|_, choice| choice.expires_at > now_utc);

                        // ── Threat feed poll + save ──
                        if let Some(ref mut tf) = state.threat_feed {
                            tf.poll_feeds().await;
                            tf.save(&cli.data_dir, state.sqlite_store.as_deref());
                        }

                        // ── Pcap capture cooldown cleanup ──
                        state.pcap_capture.cleanup();

                        // ── 2FA pending action expiry cleanup ──
                        state.two_factor_state.cleanup_expired();

                        // ── Baseline rate anomaly check + save ──
                        {
                            let rate_anomalies = state.baseline.check_rate_anomalies();
                            for anomaly in &rate_anomalies {
                                info!(
                                    anomaly_type = ?anomaly.anomaly_type,
                                    severity = ?anomaly.severity,
                                    "baseline rate anomaly: {}",
                                    anomaly.description
                                );
                            }
                            state.baseline.save(&cli.data_dir, state.sqlite_store.as_deref());
                        }

                        // ── Attacker intelligence consolidation (every 5 min) ──
                        const INTEL_INTERVAL_SECS: u64 = 300;
                        let should_consolidate = state
                            .last_intel_consolidation_at
                            .map(|t| t.elapsed().as_secs() >= INTEL_INTERVAL_SECS)
                            .unwrap_or(true);
                        if should_consolidate && !state.attacker_profiles.is_empty() {
                            // Backfill enrichment for profiles missing GeoIP/AbuseIPDB
                            incident_enrichment::backfill_enrichment(&mut state).await;
                            // Scan honeypot sessions for known attacker IPs
                            scan_honeypot_for_profiles(
                                &cli.data_dir,
                                &mut state.attacker_profiles,
                            );

                            attacker_intel::consolidation_tick(
                                &mut state.attacker_profiles,
                                &state.store,
                                &cli.data_dir,
                                state.sqlite_store.as_deref(),
                            );
                            state.last_intel_consolidation_at = Some(Instant::now());
                        }

                        // Cap attacker profiles to 10,000 by risk score
                        const MAX_ATTACKER_PROFILES: usize = 10_000;
                        if state.attacker_profiles.len() > MAX_ATTACKER_PROFILES {
                            let mut entries: Vec<_> =
                                state.attacker_profiles.drain().collect();
                            entries.sort_by(|a, b| b.1.risk_score.cmp(&a.1.risk_score));
                            entries.truncate(MAX_ATTACKER_PROFILES);
                            state.attacker_profiles = entries.into_iter().collect();
                        }

                        // ── Monthly threat report auto-generation (1st of month) ──
                        {
                            let today = chrono::Local::now().date_naive();
                            if today.day() == 1 {
                                let prev_month = (today - chrono::Duration::days(1))
                                    .format("%Y-%m")
                                    .to_string();
                                if !threat_report::report_exists(&cli.data_dir, &prev_month) {
                                    let profiles = state.attacker_profiles.clone();
                                    let data_dir = cli.data_dir.clone();
                                    tokio::spawn(async move {
                                        match threat_report::generate_monthly(
                                            &data_dir,
                                            &prev_month,
                                            &profiles,
                                        ) {
                                            Ok(report) => {
                                                if let Err(e) =
                                                    threat_report::write_report(&report, &data_dir)
                                                {
                                                    warn!(
                                                        "monthly report write failed: {e:#}"
                                                    );
                                                } else {
                                                    info!(
                                                        month = %prev_month,
                                                        "monthly threat report generated"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "monthly report generation failed: {e:#}"
                                                );
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }

                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received - shutting down");
                    true
                }
                _ = crowdsec_ticker.tick() => {
                    if let Some(ref mut cs) = state.crowdsec {
                        crowdsec::sync_threat_list(cs).await;
                    }
                    false
                }
                _ = fail2ban_ticker.tick() => {
                    if let Some(ref mut fb) = state.fail2ban {
                        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                        fail2ban::sync_tick(
                            fb,
                            &mut state.blocklist,
                            &state.skill_registry,
                            &cfg,
                            &mut state.decision_writer,
                            &host,
                            state.telegram_client.as_ref(),
                        ).await;
                    }
                    false
                }
                _ = mesh_ticker.tick() => {
                    info!("mesh ticker fired");
                    if let Some(ref mut m) = state.mesh {
                        m.rediscover_if_needed().await;
                        let result = m.tick();
                        if !result.block_ips.is_empty() || m.staged_count() > 0 {
                            info!(staged = m.staged_count(), new_blocks = result.block_ips.len(), "mesh tick");
                        }
                        // Notify Telegram about new mesh blocks (gated).
                        for (ip, ttl) in &result.block_ips {
                            info!(ip, ttl, "mesh: new block from peer network");
                            state.blocklist.insert(ip.clone());
                            // Mesh blocks are always contained -> daily briefing only.
                            let ctx = notification_gate::NotificationContext::for_mesh_block();
                            let verdict = notification_gate::should_notify(&ctx);
                            match verdict {
                                notification_gate::NotificationVerdict::SendNow => {
                                    if let Some(ref tg) = state.telegram_client {
                                        let msg = format!(
                                            "\u{1f310} <b>MESH NETWORK</b>\n\n\
                                             Peer node detected threat from <code>{ip}</code>\n\
                                             Action: blocked for {}h (auto-revert)",
                                            ttl / 3600
                                        );
                                        let tg = tg.clone();
                                        tokio::spawn(async move {
                                            let _ = tg.send_alert_html(&msg).await;
                                        });
                                    }
                                }
                                notification_gate::NotificationVerdict::DailyBriefingOnly => {
                                    *state.telegram_deferred.entry("mesh".to_string()).or_insert(0) += 1;
                                    if let Some(count) = state.notification_burst_tracker.record_contained() {
                                        if let Some(ref tg) = state.telegram_client {
                                            let msg = notification_gate::format_burst_summary(count);
                                            let tg = tg.clone();
                                            tokio::spawn(async move {
                                                let _ = tg.send_alert_html(&msg).await;
                                            });
                                        }
                                    }
                                }
                                notification_gate::NotificationVerdict::Drop => {}
                            }
                        }
                        if !result.unblock_ips.is_empty() {
                            info!(
                                expired = result.unblock_ips.len(),
                                "mesh: TTL expired blocks removed"
                            );
                        }
                        m.persist().ok();
                    }
                    false
                }
                _ = firmware_ticker.tick() => {
                    if cfg.firmware.enabled {
                        firmware_tick::process_firmware_tick(&cli.data_dir, &cfg, &mut state)
                            .await;
                    }
                    false
                }
                _ = hypervisor_ticker.tick() => {
                    if cfg.hypervisor.enabled {
                        hypervisor_tick::process_hypervisor_tick(&cli.data_dir, &cfg, &mut state)
                            .await;
                    }
                    false
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received - shutting down");
                    true
                }
            };

            #[cfg(not(unix))]
            let shutdown = tokio::select! {
                _ = incident_ticker.tick() => {
                    crate::loops::fast_loop::run_incident_tick(
                        &cli.data_dir,
                        &mut cursor,
                        &cfg,
                        &mut state,
                        &advisory_cache,
                    ).await;
                    false
                }
                _ = narrative_ticker.tick() => {
                    match crate::loops::slow_loop::process_narrative_tick(
                        &cli.data_dir,
                        &mut cursor,
                        &cfg,
                        &mut state,
                    ).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => {
                            state.telemetry.observe_error("narrative_tick");
                            warn!("narrative tick error: {e:#}");
                        }
                    }
                    // Tick notification pipeline — emit group summaries.
                    {
                        let summaries = state.grouping_engine.tick();
                        if !summaries.is_empty() {
                            let tg_level = cfg.telegram.channel_notifications.notification_level;
                            let tg_summaries: Vec<String> = summaries
                                .iter()
                                .filter(|s| notification_pipeline::should_notify_summary(s, tg_level))
                                .filter(|s| notification_pipeline::is_immediate_threat_summary(s))
                                .map(|s| s.format_html())
                                .collect();
                            if !tg_summaries.is_empty() {
                                if let Some(ref tg) = state.telegram_client {
                                    let digest = tg_summaries.join("\n");
                                    if let Err(e) = tg.send_raw_html(&digest).await {
                                        warn!("Telegram group summary failed: {e:#}");
                                    }
                                }
                            }
                        }
                    }

                    // Trim in-memory structures to prevent unbounded memory growth
                    state.blocklist.trim_if_needed(10_000);
                    let cutoff_2h = chrono::Utc::now() - chrono::Duration::hours(2);
                    state.store.retain_cooldowns(state_store::CooldownTable::Decision, cutoff_2h);
                    state.store.retain_cooldowns(state_store::CooldownTable::Notification, cutoff_2h);
                    // Cap block_counts to 5000 entries
                    if state.store.block_counts_len() > 5000 {
                        state.store.clear_block_counts();
                    }
                    // Cap ip_reputations and persist to disk for dashboard
                    if state.ip_reputations.len() > 10000 {
                        let mut entries: Vec<_> = state.ip_reputations.drain().collect();
                        entries.sort_by(|a, b| b.1.reputation_score.partial_cmp(&a.1.reputation_score).unwrap_or(std::cmp::Ordering::Equal));
                        entries.truncate(5000);
                        state.ip_reputations = entries.into_iter().collect();
                    }
                    persist_ip_reputations(&cli.data_dir, &state.ip_reputations);
                    let removed = data_retention::cleanup(&cli.data_dir, &cfg.data);
                    if removed > 0 {
                        info!(removed, "data_retention: cleaned up old files");
                    }
                    false
                }
                _ = crowdsec_ticker.tick() => {
                    if let Some(ref mut cs) = state.crowdsec {
                        crowdsec::sync_threat_list(cs).await;
                    }
                    false
                }
                _ = fail2ban_ticker.tick() => {
                    if let Some(ref mut fb) = state.fail2ban {
                        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                        fail2ban::sync_tick(
                            fb,
                            &mut state.blocklist,
                            &state.skill_registry,
                            &cfg,
                            &mut state.decision_writer,
                            &host,
                            state.telegram_client.as_ref(),
                        ).await;
                    }
                    false
                }
                _ = mesh_ticker.tick() => {
                    if let Some(ref mut m) = state.mesh {
                        m.rediscover_if_needed().await;
                        let result = m.tick();
                        for (ip, ttl) in &result.block_ips {
                            info!(ip, ttl, "mesh: new block from peer network");
                            state.blocklist.insert(ip.clone());
                            // Mesh blocks are contained -> daily briefing via gate.
                            *state.telegram_deferred.entry("mesh".to_string()).or_insert(0) += 1;
                            let _ = state.notification_burst_tracker.record_contained();
                        }
                        m.persist().ok();
                    }
                    false
                }
                _ = firmware_ticker.tick() => {
                    if cfg.firmware.enabled {
                        firmware_tick::process_firmware_tick(&cli.data_dir, &cfg, &mut state)
                            .await;
                    }
                    false
                }
                _ = hypervisor_ticker.tick() => {
                    if cfg.hypervisor.enabled {
                        hypervisor_tick::process_hypervisor_tick(&cli.data_dir, &cfg, &mut state)
                            .await;
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received - shutting down");
                    true
                }
            };

            if shutdown {
                // Signal always-on honeypot listener to stop (if running).
                if let Some(ref tx) = always_on_shutdown_tx {
                    let _ = tx.send(true);
                }
                if let Some(w) = &mut state.decision_writer {
                    w.flush();
                }
                if let Some(w) = &mut state.telemetry_writer {
                    w.flush();
                }
                break;
            }
        }
    }

    Ok(())
}
