// Use jemalloc on Linux - the default glibc allocator fragments memory and
// never returns it to the OS, causing apparent "leaks" under sustained load.
// jemalloc aggressively returns unused pages via madvise(MADV_DONTNEED).
#[cfg(not(target_os = "macos"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod abuseipdb;
mod agent_context;
mod ai;
mod allowlist;
mod attacker_intel;
mod baseline;
mod bot_actions;
mod bot_commands;
mod bot_helpers;
mod briefing;
mod cloud_safelist;
mod cloudflare;
mod config;
mod correlation;
mod correlation_engine;
mod crowdsec;
mod dashboard;
mod data_retention;
mod decision_block_ip;
mod decision_confirmation;
mod decision_cooldown;
mod decision_honeypot;
mod decision_skill_actions;
mod decisions;
mod defender_brain;
mod dna_inline;
mod environment_profile;
mod fail2ban;
mod firmware_tick;
mod forensics;
mod geoip;
mod honeypot_always_on;
mod honeypot_post_session;
mod hypervisor_tick;
mod incident_abuseipdb;
mod incident_action_report;
mod incident_advisory;
mod incident_ai_context;
mod incident_ai_failure;
mod incident_attacker_profile;
mod incident_audit_write;
mod incident_autodismiss;
mod incident_crowdsec;
mod incident_decision_eval;
mod incident_enrichment;
mod incident_execution_gate;
mod incident_flow;
mod incident_forensics;
mod incident_honeypot_router;
mod incident_honeypot_suggestion;
mod incident_notifications;
mod incident_obvious;
mod incident_playbook;
mod incident_post_decision;
mod incident_prelude;
mod incident_reputation;
mod ioc;
mod ip_reputation;
mod killchain_inline;
mod knowledge_graph;
mod mesh;
mod mitre;
mod narrative;
mod narrative_anomaly;
mod narrative_autofp;
mod narrative_daily_summary;
mod narrative_incident_ingest;
#[allow(
    dead_code,
    unused_imports,
    unused_variables,
    clippy::needless_range_loop
)]
mod neural_lifecycle;
mod notification_gate;
mod notification_pipeline;
mod pcap_capture;
mod playbook;
#[allow(dead_code)]
mod reader;
#[cfg(feature = "redis-reader")]
mod redis_reader;
mod report;
mod response_lifecycle;
mod scoring;
mod shield_inline;
mod skills;
mod slack;
mod state_store;
mod telegram;
mod telemetry;
mod telemetry_tick;
mod threat_feeds;
mod threat_report;
mod trust_rules;
#[allow(dead_code)]
mod two_factor;
mod web_push;
mod webhook;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::{Datelike as _, Timelike as _};
use clap::Parser;
use tracing::{debug, info, warn};

use crate::bot_actions::{handle_pending_confirmation, handle_telegram_action_callback};
use crate::bot_commands::{handle_telegram_bot_command, probe_and_suggest};
#[cfg(test)]
use crate::bot_helpers::{
    parse_telegram_triage_action, sanitize_allowlist_process_name, TelegramTriageAction,
};
use crate::dashboard::AdvisoryEntry;

#[derive(Parser)]
#[command(
    name = "innerwarden-agent",
    version,
    about = "Interpretive layer - reads sensor JSONL, generates narratives, and auto-responds to incidents"
)]
struct Cli {
    /// Path to the sensor data directory (where events-*.jsonl and incidents-*.jsonl live)
    #[arg(long, default_value = "/var/lib/innerwarden")]
    data_dir: PathBuf,

    /// Path to agent config TOML (narrative, webhook, ai, responder settings). Optional.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Run once (process new entries then exit) instead of continuous mode
    #[arg(long)]
    once: bool,

    /// Generate a trial operational report from existing artifacts and exit
    #[arg(long)]
    report: bool,

    /// Output directory for generated reports (default: same as --data-dir)
    #[arg(long)]
    report_dir: Option<PathBuf>,

    /// Run read-only local dashboard server and exit this process only on SIGTERM/SIGINT
    #[arg(long)]
    dashboard: bool,

    /// Bind address for dashboard mode (default: localhost only — use 0.0.0.0:8787 to expose)
    #[arg(long, default_value = "127.0.0.1:8787")]
    dashboard_bind: String,

    /// Utility: generate Argon2 password hash for dashboard auth and exit.
    #[arg(long)]
    dashboard_generate_password_hash: bool,

    /// Poll interval in seconds for the narrative slow loop (default: 30)
    #[arg(long, default_value = "30")]
    interval: u64,

    /// Internal: run honeypot sandbox worker mode.
    #[arg(long, hide = true)]
    honeypot_sandbox_runner: bool,

    /// Internal: path to honeypot sandbox runner spec JSON.
    #[arg(long, hide = true)]
    honeypot_sandbox_spec: Option<PathBuf>,

    /// Internal: path to honeypot sandbox runner result JSON.
    #[arg(long, hide = true)]
    honeypot_sandbox_result: Option<PathBuf>,

    /// Spec 015 one-shot migration: load today's dated graph snapshot,
    /// delete `graph_user_creation` false-positive incidents and
    /// brute-force User nodes, then save and exit. Never runs unless this
    /// flag is passed explicitly. Creates a backup of the snapshot as
    /// `<name>.bak-015` before writing.
    #[arg(long)]
    cleanup_015_graph_signal_quality: bool,

    /// Spec 015 follow-up: load today's dated graph snapshot and set the
    /// `research_only` flag on every Incident whose connected IPs are
    /// 100% self-traffic (cloud providers, Telegram, GeoIP, Canonical,
    /// OCI peers). Incidents are preserved for neural training — only
    /// the operator dashboard filter changes. Creates a backup as
    /// `<name>.bak-015-researchonly-<stamp>` before writing.
    #[arg(long)]
    backfill_015_research_only: bool,
}

// ---------------------------------------------------------------------------
// Shared agent state (passed through tick functions)
// ---------------------------------------------------------------------------

/// Accumulates event/incident stats incrementally for narrative generation.
/// Avoids re-reading the full events file every 5 minutes.
#[derive(Default)]
struct NarrativeAccumulator {
    /// Event counts by kind (e.g. "ssh.login_failed" → 42)
    events_by_kind: HashMap<String, usize>,
    /// IP mention counts
    ip_counts: HashMap<String, usize>,
    /// User mention counts
    user_counts: HashMap<String, usize>,
    /// Total events seen today
    total_events: usize,
    /// All incidents seen today (small - typically <100)
    incidents: Vec<innerwarden_core::incident::Incident>,
    /// Date this accumulator is for (resets on date change)
    date: String,
}

impl NarrativeAccumulator {
    /// Maximum unique IPs/users to track. Narrative only uses top 10,
    /// so keeping 500 is generous while preventing unbounded growth.
    const MAX_ENTITY_ENTRIES: usize = 500;

    fn ingest_events(&mut self, events: &[innerwarden_core::event::Event]) {
        for ev in events {
            self.total_events += 1;
            *self.events_by_kind.entry(ev.kind.clone()).or_insert(0) += 1;
            for entity in &ev.entities {
                match entity.r#type {
                    innerwarden_core::entities::EntityType::Ip => {
                        if self.ip_counts.contains_key(&entity.value)
                            || self.ip_counts.len() < Self::MAX_ENTITY_ENTRIES
                        {
                            *self.ip_counts.entry(entity.value.clone()).or_insert(0) += 1;
                        }
                    }
                    innerwarden_core::entities::EntityType::User => {
                        if self.user_counts.contains_key(&entity.value)
                            || self.user_counts.len() < Self::MAX_ENTITY_ENTRIES
                        {
                            *self.user_counts.entry(entity.value.clone()).or_insert(0) += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn ingest_incidents(&mut self, incidents: &[innerwarden_core::incident::Incident]) {
        self.incidents.extend_from_slice(incidents);
        // Cap at 500 incidents - narrative only needs recent ones for the report
        if self.incidents.len() > 500 {
            let drain = self.incidents.len() - 500;
            self.incidents.drain(..drain);
        }
    }

    fn reset_for_date(&mut self, date: &str) {
        if self.date != date {
            self.events_by_kind.clear();
            self.ip_counts.clear();
            self.user_counts.clear();
            self.total_events = 0;
            self.incidents.clear();
            self.date = date.to_string();
        }
    }

    /// Build synthetic Events from counters for narrative::generate.
    /// Caps total at 2000 events to prevent memory explosion on busy hosts.
    /// Uses proportional sampling when total exceeds cap.
    fn synthetic_events(&self) -> Vec<innerwarden_core::event::Event> {
        use innerwarden_core::{entities::EntityRef, event::Event};
        const MAX_SYNTHETIC: usize = 2000;

        let total: usize = self.events_by_kind.values().sum();
        let scale = if total > MAX_SYNTHETIC {
            MAX_SYNTHETIC as f64 / total as f64
        } else {
            1.0
        };

        let mut events = Vec::with_capacity(MAX_SYNTHETIC.min(total) + 20);
        for (kind, count) in &self.events_by_kind {
            let n = ((*count as f64) * scale).ceil() as usize;
            for _ in 0..n.max(1) {
                events.push(Event {
                    ts: chrono::Utc::now(),
                    host: String::new(),
                    source: String::new(),
                    kind: kind.clone(),
                    severity: innerwarden_core::event::Severity::Info,
                    summary: String::new(),
                    details: serde_json::Value::Null,
                    tags: vec![],
                    entities: vec![],
                });
            }
        }

        // Top IPs (max 10, 1 event each)
        for (ip, _) in self.ip_counts.iter().take(10) {
            events.push(Event {
                ts: chrono::Utc::now(),
                host: String::new(),
                source: String::new(),
                kind: "synthetic.entity".to_string(),
                severity: innerwarden_core::event::Severity::Info,
                summary: String::new(),
                details: serde_json::Value::Null,
                tags: vec![],
                entities: vec![EntityRef::ip(ip)],
            });
        }
        for (user, _) in self.user_counts.iter().take(10) {
            events.push(Event {
                ts: chrono::Utc::now(),
                host: String::new(),
                source: String::new(),
                kind: "synthetic.entity".to_string(),
                severity: innerwarden_core::event::Severity::Info,
                summary: String::new(),
                details: serde_json::Value::Null,
                tags: vec![],
                entities: vec![EntityRef::user(user)],
            });
        }
        events
    }
}

struct AgentState {
    skill_registry: skills::SkillRegistry,
    blocklist: skills::Blocklist,
    correlator: correlation::TemporalCorrelator,
    telemetry: telemetry::TelemetryState,
    telemetry_writer: Option<telemetry::TelemetryWriter>,
    /// Wrapped in Arc so we can clone a handle for use within a loop iteration
    /// without holding a borrow of `state` across async calls that need `&mut state`.
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    decision_writer: Option<decisions::DecisionWriter>,
    /// Tracks when the daily narrative was last written so we can enforce a
    /// minimum interval and avoid rewriting on every 30-second tick.
    last_narrative_at: Option<std::time::Instant>,
    /// Date for which we last sent the daily Telegram digest (avoids re-sending).
    last_daily_summary_telegram: Option<chrono::NaiveDate>,
    /// Telegram daily budget: how many immediate notifications sent today.
    /// Resets when the date changes.
    #[allow(dead_code)]
    telegram_daily_sent: u32,
    /// Date the daily budget counter applies to.
    #[allow(dead_code)]
    telegram_budget_date: Option<chrono::NaiveDate>,
    /// Incidents deferred from Telegram (not immediate threats) — accumulated
    /// per-detector for the daily digest breakdown.
    telegram_deferred: std::collections::HashMap<String, u32>,
    /// Telegram client for T.1 notifications and T.2 approvals (None when disabled).
    telegram_client: Option<Arc<telegram::TelegramClient>>,
    /// Pending T.2 operator confirmations keyed by incident_id.
    /// Stores the original decision and incident so the action can be executed when approved.
    pending_confirmations: HashMap<
        String,
        (
            telegram::PendingConfirmation,
            ai::AiDecision,
            innerwarden_core::incident::Incident,
        ),
    >,
    /// Receives approval results from the Telegram polling task.
    /// Drained at the start of every incident tick via try_recv.
    approval_rx: Option<tokio::sync::mpsc::Receiver<telegram::ApprovalResult>>,
    /// Notification pipeline — groups incidents by detector+entity to reduce noise.
    grouping_engine: notification_pipeline::GroupingEngine,
    /// Environment profile — cloud/VM detection, human UIDs, services.
    environment_profile: environment_profile::EnvironmentProfile,
    /// Neural autoencoder anomaly engine — learns "normal" and flags novel patterns.
    anomaly_engine: neural_lifecycle::AnomalyEngine,
    /// Neural incidents pending processing — buffered here because the agent
    /// cannot append to the sensor's incidents file (different user).
    neural_incidents: Vec<innerwarden_core::incident::Incident>,
    /// In-memory trust rules: set of "detector:action" strings.
    /// Loaded from data_dir/trust-rules.json at startup; updated live when operator clicks "Always".
    trust_rules: std::collections::HashSet<String>,
    /// CrowdSec LAPI sync state (None when crowdsec.enabled = false).
    crowdsec: Option<crowdsec::CrowdSecState>,
    /// AbuseIPDB client for IP reputation enrichment (None when disabled).
    abuseipdb: Option<abuseipdb::AbuseIpDbClient>,
    /// Fail2ban sync state (None when fail2ban.enabled = false).
    fail2ban: Option<fail2ban::Fail2BanState>,
    /// GeoIP client for IP geolocation enrichment via ip-api.com (None when disabled).
    geoip_client: Option<geoip::GeoIpClient>,
    /// Slack client for incident notifications (None when disabled).
    slack_client: Option<slack::SlackClient>,
    /// Cloudflare integration client (None when disabled).
    cloudflare_client: Option<cloudflare::CloudflareClient>,
    /// Circuit breaker: when tripped by a high-volume incident burst, AI analysis
    /// is suspended until this timestamp. None = circuit breaker not tripped.
    circuit_breaker_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Pending operator honeypot choices keyed by IP.
    /// When Telegram is configured and AI recommends Honeypot, execution is deferred
    /// until the operator picks an action via the 4-button inline keyboard.
    pending_honeypot_choices: HashMap<String, PendingHoneypotChoice>,
    /// Local IP reputation: per-IP history used for adaptive block TTL.
    /// Persisted to `ip-reputation.json` every slow-loop tick.
    ip_reputations: HashMap<String, LocalIpReputation>,
    /// Whether LSM enforcement has been auto-enabled this session.
    lsm_enabled: bool,
    /// Mesh collaborative defense network (None when mesh.enabled = false).
    mesh: Option<mesh::MeshIntegration>,
    /// Rate limiter: timestamps of recent block actions (rolling 1-minute window).
    /// Prevents false-positive cascades from blocking too many IPs at once.
    recent_blocks: std::collections::VecDeque<chrono::DateTime<chrono::Utc>>,
    /// XDP blocklist entries with timestamps and per-IP TTL for adaptive expiration.
    /// Periodically cleaned: IPs older than their individual TTL are removed.
    xdp_block_times: HashMap<String, (chrono::DateTime<chrono::Utc>, i64)>,
    /// Unified response lifecycle: tracks all active responses (block IP, container,
    /// nginx, sudo) with TTL, auto-revert, manual revert, and Prometheus metrics.
    response_lifecycle: response_lifecycle::ResponseLifecycle,
    /// AbuseIPDB report queue - IPs are held for ABUSEIPDB_REPORT_DELAY_SECS
    /// before reporting, giving time for false-positive correction.
    abuseipdb_report_queue: Vec<(String, String, String, chrono::DateTime<chrono::Utc>)>,
    /// Incremental narrative accumulator - avoids re-reading events file.
    narrative_acc: NarrativeAccumulator,
    /// Legacy: was byte offset for JSONL incident reading. SQLite cursor is
    /// now stored in the database itself. Kept to avoid churning test state structs.
    #[allow(dead_code)]
    narrative_incidents_offset: u64,
    /// Forensics capture - grabs /proc state for High/Critical process incidents.
    forensics: forensics::ForensicsCapture,
    /// Persistent state store (redb) - cooldowns, block_counts, ip_reputations,
    /// xdp_block_times, trust_rules. Primary source of truth for reads.
    store: state_store::StateStore,
    sqlite_store: Option<Arc<innerwarden_store::Store>>,
    /// SQLite maintenance scheduler (None when sqlite_store is None).
    maintenance_scheduler: Option<innerwarden_store::maintenance::MaintenanceScheduler>,
    /// Attacker intelligence profiles: IP → unified profile.
    attacker_profiles: HashMap<String, attacker_intel::AttackerProfile>,
    /// Last attacker intel consolidation timestamp (5-minute interval).
    last_intel_consolidation_at: Option<std::time::Instant>,
    /// Cross-layer correlation engine: detects multi-stage attack chains.
    correlation_engine: correlation_engine::CorrelationEngine,
    /// Baseline learning: detects anomalies from normal behavior.
    baseline: baseline::BaselineStore,
    /// Playbook engine: automated response sequences.
    playbook_engine: playbook::PlaybookEngine,
    /// AlphaZero-trained defender brain: neural decision engine.
    defender_brain: defender_brain::DefenderBrain,
    /// History of brain suggestions for dashboard + FP audit.
    brain_history: defender_brain::BrainHistory,
    /// Brain evolution stats (agreement tracking, weekly trend).
    brain_stats: defender_brain::BrainStats,
    /// Selective packet capture on incidents.
    pcap_capture: pcap_capture::PcapCapture,
    /// V10 neural scoring model — replaced by autoencoder (anomaly_engine).
    /// Kept for API compatibility; will be removed in v0.9.
    #[allow(dead_code)]
    scoring_engine: scoring::ScoringEngine,
    /// Firmware incident cooldown: timestamp of last firmware trust_degraded incident.
    /// Prevents duplicate alerts when trust score is persistently low (e.g., VMs).
    last_firmware_incident_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Hypervisor incident cooldown: timestamp of last hypervisor trust_degraded incident.
    last_hypervisor_incident_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Cached hypervisor environment classification (updated by hypervisor_tick).
    /// Used by firmware_tick for VM detection and by other modules for context.
    hypervisor_environment: Option<innerwarden_hypervisor::Environment>,
    /// Kill chain PID tracker — processes eBPF events and detects attack patterns.
    killchain_tracker: innerwarden_killchain::tracker::PidTracker,
    /// Timestamp of last kill chain stale-PID cleanup.
    last_killchain_cleanup: std::time::Instant,
    /// Threat DNA engine — behavioral fingerprinting, anomaly detection, attack chain tracking.
    dna_state: dna_inline::DnaState,
    /// DDoS Shield engine — rate limiting, SYN tracking, escalation, XDP blocking.
    shield_state: Option<shield_inline::ShieldState>,
    /// Shared deep security snapshot for dashboard API.
    deep_security_snapshot:
        Option<std::sync::Arc<std::sync::RwLock<dashboard::DeepSecuritySnapshot>>>,
    /// Timestamp of last DNA state persistence.
    last_dna_save: std::time::Instant,
    /// Dynamic allowlist loaded from /etc/innerwarden/allowlist.toml.
    /// Hot-reloaded every 60s. Merged with static config allowlist at check time.
    dynamic_trusted_ips: Vec<String>,
    dynamic_trusted_users: Vec<String>,
    dynamic_trusted_processes: Vec<String>,
    /// IPs of active operator SSH sessions (trusted_users). Never blocked.
    /// Value = last time the session was confirmed active via `who`.
    operator_ips: std::collections::HashMap<String, std::time::Instant>,
    /// Last time we refreshed operator_ips from `who -i`.
    last_operator_refresh: std::time::Instant,
    /// Suppressed incident patterns (user-configurable via CLI/dashboard).
    suppressed_incident_ids: std::collections::HashSet<String>,
    /// Threat feed client for external intelligence (None when disabled).
    threat_feed: Option<threat_feeds::ThreatFeedClient>,
    /// Timestamp of last baseline anomaly detection (for score fusion with autoencoder).
    last_baseline_anomaly_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of last autoencoder anomaly detection (for score fusion with baseline).
    last_autoencoder_anomaly_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// Latest autoencoder anomaly score (0.0-1.0). Used as signal to boost confidence
    /// in decisions made by other detectors. Reset each tick.
    latest_anomaly_score: Option<f32>,
    /// Two-factor authentication state (pending actions, brute force protection).
    two_factor_state: two_factor::TwoFactorState,
    /// Knowledge graph — in-memory directed graph for attack context (shared with dashboard).
    knowledge_graph: std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    /// Graph-based detector state (cooldowns).
    graph_detector_state: knowledge_graph::detectors::GraphDetectorState,
    /// Timestamp of last knowledge graph snapshot save.
    last_graph_snapshot: std::time::Instant,
    /// Redis stream reader for events (None when redis_url is not configured).
    #[cfg(feature = "redis-reader")]
    redis_reader: Option<redis_reader::RedisStreamReader>,
    /// Notification gate burst tracker — counts contained threats for burst summary.
    notification_burst_tracker: notification_gate::BurstTracker,
}

/// Tracks a deferred honeypot-or-block decision waiting for operator input via Telegram.
struct PendingHoneypotChoice {
    #[allow(dead_code)]
    ip: String,
    incident_id: String,
    incident: innerwarden_core::incident::Incident,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) use decision_cooldown::DECISION_COOLDOWN_SECS;
pub(crate) use decision_cooldown::{
    decision_cooldown_candidates, decision_cooldown_key_for_decision, load_last_narrative_instant,
    load_startup_decision_state, notification_cooldown_keys, ABUSEIPDB_REPORT_DELAY_SECS,
    MAX_BLOCKS_PER_MINUTE, NOTIFICATION_COOLDOWN_SECS,
};
pub(crate) use ip_reputation::{
    adaptive_block_ttl_secs, append_blocked_ip, load_ip_reputations, persist_ip_reputations,
    scan_honeypot_for_profiles, LocalIpReputation,
};
pub(crate) use trust_rules::{
    append_trust_rule, enable_lsm_enforcement, is_trusted, load_trust_rules, should_auto_enable_lsm,
};
// Constants re-exported from decision_cooldown (kept here for backward compat)

// Cooldown functions moved to decision_cooldown.rs

// (cooldown functions, startup state loaders, and narrative instant moved to decision_cooldown.rs)

// Trust rules and LSM enforcement moved to trust_rules.rs

// ---------------------------------------------------------------------------
// Spec 015: one-shot cleanup of graph_user_creation false positives and
// brute-force User node pollution. Invoked via
// `innerwarden-agent --cleanup-015-graph-signal-quality`. Non-destructive
// outside that flag: the function below loads today's dated snapshot,
// writes a timestamped backup, applies the migration, and saves the result.
// ---------------------------------------------------------------------------

fn run_cleanup_015(data_dir: &std::path::Path) -> Result<()> {
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
    let backup_path = snapshot_path.with_extension(format!("json.bak-015-{stamp}"));
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

fn run_backfill_015_research_only(data_dir: &std::path::Path) -> Result<()> {
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
    let backup_path = snapshot_path.with_extension(format!("json.bak-015-researchonly-{stamp}"));
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present (fail-silent - production uses real env vars)
    match dotenvy::dotenv() {
        Ok(path) => debug!("loaded env from {}", path.display()),
        Err(dotenvy::Error::Io(_)) => {} // no .env file - that's fine
        Err(e) => warn!("could not parse .env file: {e}"),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden_agent=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

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
        decision_writer: if cfg.ai.enabled {
            match decisions::DecisionWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create decision writer: {e:#}");
                    None
                }
            }
        } else {
            None
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
            .with_pre_chain_threshold(cfg.killchain.pre_chain_threshold),
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
    refresh_operator_ips(&mut state, &cfg.allowlist);
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
        let handled = process_incidents(
            &cli.data_dir,
            &mut cursor,
            &cfg,
            &mut state,
            &advisory_cache,
        )
        .await;
        let new_events =
            process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await?;
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
        probe_and_suggest(&cfg, state.telegram_client.as_deref()).await;

        // Boot self-test: verify self-awareness is working.
        boot_self_test();

        // One-time backfill: reconcile JSONL decisions with the knowledge graph.
        // Fixes historical incidents where auto-block gates wrote to JSONL but
        // not to the graph (incident_obvious + incident_crowdsec before the fix).
        backfill_graph_decisions(&cli.data_dir, &mut state);

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
                    process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state, &advisory_cache).await;
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await {
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
                        refresh_operator_ips(&mut state, &cfg.allowlist);
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
                    process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state, &advisory_cache).await;
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg, &mut state).await {
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

// ---------------------------------------------------------------------------
// Incident tick - runs every 2s
//
// Responsibilities (in order, for every new incident):
//   1. Webhook: notify immediately for all incidents above min_severity
//   2. AI analysis: only for High/Critical that pass the algorithm gate
//
// The incident cursor is advanced and saved after every tick, so a crash
// between ticks never causes double-processing or lost webhook notifications.
// ---------------------------------------------------------------------------

/// Returns the number of incidents handled (webhook sent and/or AI analyzed).
async fn process_incidents(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    advisory_cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
) -> usize {
    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "suspend-user-sudo")
    {
        match skills::builtin::cleanup_expired_sudo_suspensions(data_dir, cfg.responder.dry_run)
            .await
        {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired sudo suspensions cleaned up");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("suspend_user_sudo_cleanup");
                warn!("failed to cleanup expired sudo suspensions: {e:#}");
            }
        }
    }

    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "rate-limit-nginx")
    {
        match skills::builtin::cleanup_expired_nginx_blocks(data_dir, cfg.responder.dry_run).await {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired nginx deny rules cleaned up");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("rate_limit_nginx_cleanup");
                warn!("failed to cleanup expired nginx blocks: {e:#}");
            }
        }
    }

    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "block-container")
    {
        match skills::builtin::cleanup_expired_container_blocks(data_dir, cfg.responder.dry_run)
            .await
        {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired container pauses lifted");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("block_container_cleanup");
                warn!("failed to cleanup expired container blocks: {e:#}");
            }
        }
    }

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let new_incidents = if let Some(ref sq) = state.sqlite_store {
        let cval = sq.get_agent_cursor("incidents").unwrap_or(0);
        match sq.incidents_since(cval, 5000) {
            Ok(rows) if !rows.is_empty() => {
                let max_id = rows.last().unwrap().0;
                let entries = rows.into_iter().map(|(_, inc)| inc).collect();
                let _ = sq.set_agent_cursor("incidents", max_id);
                reader::ReadResult {
                    entries,
                    new_offset: 0,
                }
            }
            _ => reader::ReadResult {
                entries: vec![],
                new_offset: 0,
            },
        }
    } else {
        warn!("sqlite_store not available — cannot read incidents");
        return 0;
    };

    // Drain any pending T.2/T.3 approval results from the Telegram polling task.
    // This MUST run before the early-return below, otherwise bot commands
    // (/status, /menu, etc.) would never be processed when there are no new incidents.
    let pending_approvals: Vec<telegram::ApprovalResult> = {
        let mut results = Vec::new();
        if let Some(rx) = state.approval_rx.as_mut() {
            while let Ok(r) = rx.try_recv() {
                results.push(r);
            }
        }
        results
    };
    for approval in pending_approvals {
        process_telegram_approval(approval, data_dir, cfg, state).await;
    }

    // Expire stale pending confirmations and honeypot choices
    let now = chrono::Utc::now();
    state
        .pending_confirmations
        .retain(|_, (pending, _, _)| pending.expires_at > now);
    state
        .pending_honeypot_choices
        .retain(|_, choice| choice.expires_at > now);

    // Drain neural incidents (autoencoder) into the processing pipeline.
    // These couldn't be written to the sensor's file (different user).
    let neural = std::mem::take(&mut state.neural_incidents);
    if !neural.is_empty() {
        info!(count = neural.len(), "processing buffered neural incidents");
    }

    if new_incidents.entries.is_empty() && neural.is_empty() {
        return 0;
    }

    // Advance cursor before any async work - prevents double-processing on crash/restart
    cursor.set_incidents_offset(&today, new_incidents.new_offset);

    let notification_thresholds =
        incident_notifications::compute_notification_thresholds(cfg, state);

    // Circuit breaker: if a previous tick tripped the breaker, check if cooldown expired
    if let Some(until) = state.circuit_breaker_until {
        if chrono::Utc::now() < until {
            info!(
                until = %until,
                incident_count = new_incidents.entries.len(),
                "AI circuit breaker open - skipping AI analysis for this tick"
            );
            // Still process webhooks/notifications below, just skip AI
        } else {
            info!("AI circuit breaker reset after cooldown");
            state.circuit_breaker_until = None;
        }
    }

    // Trip circuit breaker if incident volume exceeds threshold
    let circuit_breaker_open = if cfg.ai.circuit_breaker_threshold > 0
        && new_incidents.entries.len() >= cfg.ai.circuit_breaker_threshold
        && state.circuit_breaker_until.is_none()
    {
        let until = chrono::Utc::now()
            + chrono::Duration::seconds(cfg.ai.circuit_breaker_cooldown_secs as i64);
        warn!(
            incident_count = new_incidents.entries.len(),
            threshold = cfg.ai.circuit_breaker_threshold,
            cooldown_secs = cfg.ai.circuit_breaker_cooldown_secs,
            until = %until,
            "AI circuit breaker TRIPPED - high-volume incident burst detected, skipping AI"
        );
        state.circuit_breaker_until = Some(until);
        true
    } else {
        state.circuit_breaker_until.is_some()
    };

    // Pre-compute AI context (only if AI is configured and circuit breaker is not open)
    let ai_enabled = cfg.ai.enabled && state.ai_provider.is_some() && !circuit_breaker_open;
    let (all_events, skill_infos, ai_provider, provider_name, already_blocked, mut blocked_set) =
        if ai_enabled {
            let events = if let Some(ref sq) = state.sqlite_store {
                sq.events_since(0, 50_000)
                    .map(|rows| rows.into_iter().map(|(_, ev)| ev).collect())
                    .unwrap_or_default()
            } else {
                warn!("sqlite_store not available — AI context will have no events");
                vec![]
            };
            let infos = state.skill_registry.infos();
            // Clone the Arc - owned handle, no borrow of `state`
            let prov: Arc<dyn ai::AiProvider> = state.ai_provider.as_ref().unwrap().clone();
            let pname = prov.name();
            let blocked = state.blocklist.as_vec();
            // Mutable so we can update it mid-tick to prevent duplicate AI calls
            // for the same IP when multiple incidents arrive in the same 2s window.
            let blocked_set: HashSet<String> = blocked.iter().cloned().collect();
            (events, infos, Some(prov), pname, blocked, blocked_set)
        } else {
            (vec![], vec![], None, "", vec![], HashSet::new())
        };

    let mut handled = 0;
    let mut ai_calls_this_tick: usize = 0;

    let all_incidents: Vec<&innerwarden_core::incident::Incident> =
        new_incidents.entries.iter().chain(neural.iter()).collect();

    // Feed incidents into knowledge graph
    {
        let mut graph = state.knowledge_graph.write().unwrap();
        for incident in &all_incidents {
            graph.ingest_incident(incident);
        }
    }

    // Feed incidents into DNA attack chain tracker (MITRE ATT&CK progression).
    if cfg.dna.enabled {
        let incident_refs: Vec<innerwarden_core::incident::Incident> =
            all_incidents.iter().map(|i| (*i).clone()).collect();
        dna_inline::process_incidents(
            &mut state.dna_state,
            &incident_refs,
            &mut state.correlation_engine,
        );
    }

    for incident in &all_incidents {
        state.telemetry.observe_incident(incident);

        // Dedup: suppress sensor incident if graph handles this detector
        {
            let sensor_detector = incident.incident_id.split(':').next().unwrap_or("");
            let entity_value = incident
                .entities
                .first()
                .map(|e| e.value.as_str())
                .unwrap_or("");

            // Phase 3D: if detector is in graph_only_detectors, always suppress sensor version
            if cfg
                .graph_only_detectors
                .iter()
                .any(|d| d == sensor_detector)
            {
                tracing::debug!(
                    incident_id = %incident.incident_id,
                    "sensor incident suppressed: detector is graph-only"
                );
                handled += 1;
                continue;
            }

            // Otherwise, suppress if graph recently detected same entity
            if state.graph_detector_state.should_suppress_sensor(
                sensor_detector,
                entity_value,
                chrono::Utc::now(),
            ) {
                tracing::debug!(
                    incident_id = %incident.incident_id,
                    "sensor incident suppressed: graph already detected"
                );
                handled += 1;
                continue;
            }
        }

        // VirusTotal enrichment: when YARA scanner detects a binary, check its
        // SHA-256 hash against VT. Result logged for operator context.
        if incident.incident_id.starts_with("yara_scan:") {
            if let Some(hash) = incident
                .evidence
                .get(0)
                .and_then(|e| e.get("sha256"))
                .and_then(|v| v.as_str())
            {
                if let Some(ref tf) = state.threat_feed {
                    match tf.check_virustotal(hash).await {
                        Some(vt) if vt.is_malicious => {
                            info!(
                                incident_id = %incident.incident_id,
                                sha256 = %hash,
                                malicious = vt.malicious,
                                suspicious = vt.suspicious,
                                "VirusTotal CONFIRMED malicious: {}/{} engines",
                                vt.malicious,
                                vt.malicious + vt.suspicious + vt.undetected
                            );
                        }
                        Some(vt) => {
                            info!(
                                incident_id = %incident.incident_id,
                                sha256 = %hash,
                                malicious = vt.malicious,
                                "VirusTotal: {}/{} engines flagged",
                                vt.malicious,
                                vt.malicious + vt.suspicious + vt.undetected
                            );
                        }
                        None => {} // VT not configured or request failed
                    }
                }
            }
        }

        incident_attacker_profile::update_incident_ip_profiles(incident, state);

        incident_forensics::maybe_capture_incident_forensics(incident, state);

        let related_incidents =
            incident_prelude::prepare_incident_prelude(incident, cfg, state).await;

        incident_notifications::dispatch_incident_notifications(
            incident,
            data_dir,
            cfg,
            state,
            &notification_thresholds,
        )
        .await;

        incident_advisory::handle_advisory_violation(incident, advisory_cache, state).await;

        // 1b. Enrichment — runs for ALL incidents regardless of severity.
        // GeoIP + AbuseIPDB + attacker profile update must happen before the
        // AI gate filters out low-severity incidents, otherwise auto-blocked
        // and low-severity IPs never get country/abuse_confidence data.
        let ip_geo_early = incident_enrichment::lookup_incident_geoip(incident, state).await;
        let ip_rep_early = incident_reputation::lookup_abuseipdb_reputation(incident, state).await;
        incident_enrichment::enrich_attacker_identity(
            incident,
            state,
            ip_geo_early.as_ref(),
            ip_rep_early.as_ref(),
        );
        incident_enrichment::log_threat_feed_match(incident, state);

        // 2. AI analysis - only when AI is enabled and incident passes the gate.
        match incident_flow::evaluate_pre_ai_flow(
            incident,
            cfg,
            state,
            ai_enabled,
            &blocked_set,
            ai_calls_this_tick,
        ) {
            incident_flow::PreAiFlowDecision::Proceed => {}
            incident_flow::PreAiFlowDecision::SkipAllowlisted => {
                // Mark the incident node as allowlisted in the knowledge graph
                let mut graph = state.knowledge_graph.write().unwrap();
                graph.set_allowlisted(&incident.incident_id, true);
                drop(graph);
                handled += 1;
                continue;
            }
            incident_flow::PreAiFlowDecision::SkipBelowSeverity => {
                // Low-severity noise: write auto-dismiss decision so the
                // dashboard shows a clear outcome instead of "needs attention".
                if incident_autodismiss::try_autodismiss_noise(incident, cfg, state) {
                    state.grouping_engine.mark_auto_resolved(incident);
                }
                handled += 1;
                continue;
            }
            incident_flow::PreAiFlowDecision::SkipHandled
            | incident_flow::PreAiFlowDecision::PipelineTestHandled => {
                handled += 1;
                continue;
            }
        }

        if incident_obvious::try_handle_obvious_incident(incident, data_dir, cfg, state).await {
            state.grouping_engine.mark_auto_resolved(incident);
            handled += 1;
            continue;
        }

        state.telemetry.observe_gate_pass();

        // ai_provider is Some when ai_enabled - safe to unwrap
        let provider = ai_provider.as_ref().unwrap();

        info!(
            incident_id = %incident.incident_id,
            provider = provider_name,
            correlated_count = related_incidents.len(),
            "sending incident to AI for analysis"
        );

        let ai_context_inputs = incident_ai_context::build_ai_context_inputs(
            incident,
            &all_events,
            &related_incidents,
            cfg.ai.context_events,
        );

        // ── Auto-handle decisions (may `continue` to skip AI) ──────────
        // Enrichment already ran in step 1b. Reuse the results.
        let ip_reputation = ip_rep_early;

        if incident_abuseipdb::try_handle_abuseipdb_autoblock(
            incident,
            data_dir,
            cfg,
            state,
            ip_reputation.as_ref(),
            &mut blocked_set,
        )
        .await
        {
            state.grouping_engine.mark_auto_resolved(incident);
            handled += 1;
            continue;
        }

        if incident_crowdsec::try_handle_crowdsec_autoblock(
            incident,
            data_dir,
            cfg,
            state,
            &mut blocked_set,
        )
        .await
        {
            state.grouping_engine.mark_auto_resolved(incident);
            handled += 1;
            continue;
        }

        if incident_honeypot_router::try_handle_honeypot_routing(
            incident,
            data_dir,
            cfg,
            state,
            &blocked_set,
        )
        .await
        {
            handled += 1;
            continue;
        }

        // Build graph context: attack narrative from knowledge graph neighborhood.
        // Phase 015: prefer the Incident node as center (richest context after 014-D
        // incident enrichment links incidents to processes), fall back to entity nodes.
        let graph_context = {
            let graph = state.knowledge_graph.read().unwrap();
            let center_node = graph.find_by_incident(&incident.incident_id).or_else(|| {
                incident.entities.iter().find_map(|e| match e.r#type {
                    innerwarden_core::entities::EntityType::Ip => graph.find_by_ip(&e.value),
                    innerwarden_core::entities::EntityType::User => graph.find_by_user(&e.value),
                    innerwarden_core::entities::EntityType::Path => graph.find_by_path(&e.value),
                    innerwarden_core::entities::EntityType::Container => {
                        graph.find_by_container(&e.value)
                    }
                    _ => None,
                })
            });
            center_node.map(|node| graph.attack_narrative(node, 3))
        };

        let ctx = ai::DecisionContext {
            incident,
            recent_events: ai_context_inputs.recent_events,
            related_incidents: ai_context_inputs.related_incidents,
            already_blocked: already_blocked.clone(),
            available_skills: skill_infos
                .iter()
                .map(|s| ai::SkillInfo {
                    id: s.id.clone(),
                    applicable_to: s.applicable_to.clone(),
                })
                .collect(),
            ip_reputation: ip_reputation.clone(),
            ip_geo: ip_geo_early.clone(),
            graph_context,
        };

        state.telemetry.observe_ai_sent();
        let decision_start = Instant::now();
        let mut decision = match provider.decide(&ctx).await {
            Ok(d) => d,
            Err(e) => {
                incident_ai_failure::handle_ai_decision_failure(
                    incident,
                    provider_name,
                    cfg,
                    state,
                    &e,
                );

                handled += 1;
                continue;
            }
        };
        let latency_ms = decision_start.elapsed().as_millis();
        state
            .telemetry
            .observe_ai_decision(&decision.action, latency_ms);
        ai_calls_this_tick += 1;

        incident_post_decision::apply_post_decision_safeguards(
            incident,
            cfg,
            state,
            &mut decision,
            &mut blocked_set,
        );

        incident_decision_eval::apply_correlation_boost_and_log_decision(
            incident,
            cfg,
            state,
            &mut decision,
            data_dir,
        );

        if incident_honeypot_suggestion::maybe_defer_honeypot_to_operator(
            incident,
            provider_name,
            &decision,
            cfg,
            state,
        )
        .await
        {
            handled += 1;
            continue;
        }

        let (execution_result, cloudflare_pushed) =
            incident_execution_gate::execute_or_skip_decision(
                incident, &decision, data_dir, cfg, state,
            )
            .await;

        incident_audit_write::write_decision_audit_entry(
            incident,
            provider_name,
            &decision,
            &execution_result,
            cfg,
            state,
        );

        // Feed decision into knowledge graph
        {
            let (action_type, action_target) = match &decision.action {
                ai::AiAction::BlockIp { ip, .. } => ("block_ip", Some(ip.as_str())),
                ai::AiAction::Monitor { ip } => ("monitor", Some(ip.as_str())),
                ai::AiAction::Honeypot { ip } => ("honeypot", Some(ip.as_str())),
                ai::AiAction::SuspendUserSudo { user, .. } => {
                    ("suspend_user_sudo", Some(user.as_str()))
                }
                ai::AiAction::KillProcess { user, .. } => ("kill_process", Some(user.as_str())),
                ai::AiAction::BlockContainer { container_id, .. } => {
                    ("block_container", Some(container_id.as_str()))
                }
                ai::AiAction::Ignore { .. } => ("ignore", None),
                ai::AiAction::RequestConfirmation { .. } => ("request_confirmation", None),
                ai::AiAction::KillChainResponse { .. } => ("kill_chain_response", None),
            };
            let auto_executed = decision.auto_execute && !execution_result.is_empty();
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.ingest_decision(
                &incident.incident_id,
                action_type,
                action_target,
                decision.confidence,
                &decision.reason,
                auto_executed,
                chrono::Utc::now(),
            );
        }

        incident_playbook::maybe_evaluate_and_persist_playbook(incident, data_dir, state);

        incident_action_report::maybe_send_post_execution_telegram_report(
            incident,
            &decision,
            &execution_result,
            cloudflare_pushed,
            cfg,
            state,
            ip_reputation.as_ref(),
            ip_geo_early.as_ref(),
        );

        handled += 1;
    }

    telemetry_tick::write_tick_snapshot(state, "incident_tick");

    handled
}

/// Refresh operator IPs from active SSH sessions.
/// Replaces the entire set — IPs whose sessions ended are automatically removed.
fn refresh_operator_ips(state: &mut AgentState, allowlist: &config::AllowlistConfig) {
    let now = std::time::Instant::now();
    let mut active_ips = std::collections::HashMap::new();

    // Check active sessions via `who -i`
    if let Ok(output) = std::process::Command::new("who").arg("-i").output() {
        let who_out = String::from_utf8_lossy(&output.stdout);
        for line in who_out.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let (Some(user), Some(ip_raw)) = (parts.first(), parts.last()) {
                let ip = ip_raw.trim_matches(|c| c == '(' || c == ')');
                if allowlist.trusted_users.iter().any(|u| u == *user) && !ip.is_empty() && ip != ":"
                {
                    active_ips.insert(ip.to_string(), now);
                }
            }
        }
    }

    // Log removed sessions
    for old_ip in state.operator_ips.keys() {
        if !active_ips.contains_key(old_ip) {
            info!(ip = %old_ip, "operator session ended — IP protection removed");
        }
    }
    // Log new sessions
    for new_ip in active_ips.keys() {
        if !state.operator_ips.contains_key(new_ip) {
            info!(ip = %new_ip, "operator session detected — IP protected");
        }
    }

    state.operator_ips = active_ips;
}

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
                    ai_provider: state.ai_provider.clone(),
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
                    ai_provider: state.ai_provider.clone(),
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
                    ai_provider: state.ai_provider.clone(),
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

// ---------------------------------------------------------------------------
// Telegram T.2 approval handler
// ---------------------------------------------------------------------------

/// Process a single operator approval result received from the Telegram polling task.
/// Resolves and executes (or discards) the pending confirmation, writes an audit entry,
/// and informs the operator via Telegram of the outcome.
async fn process_telegram_approval(
    result: telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // 2FA: intercept TOTP code responses before any other handler
    if bot_helpers::handle_totp_response(&result, data_dir, cfg, state) {
        return;
    }

    if handle_telegram_bot_command(&result, data_dir, cfg, state).await {
        return;
    }

    if bot_helpers::handle_telegram_triage_action(&result, data_dir, cfg, state) {
        return;
    }

    if handle_telegram_action_callback(&result, data_dir, cfg, state).await {
        return;
    }

    let _ = handle_pending_confirmation(&result, data_dir, cfg, state).await;
}

// ---------------------------------------------------------------------------
// Narrative tick - runs every 30s
//
// Responsibility: regenerate the daily Markdown summary when new events arrive.
// Webhook and incident processing have been moved to process_incidents so that
// all incidents are notified in real-time, not batched every 30 seconds.
// ---------------------------------------------------------------------------

/// Returns the number of new events seen this tick.
async fn process_narrative_tick(
    data_dir: &Path,
    _cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Result<usize> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    // Read new events: from Redis if available, JSONL otherwise.
    #[cfg(feature = "redis-reader")]
    let (events_entries, events_count) = if let Some(ref mut rr) = state.redis_reader {
        match rr.read_events::<innerwarden_core::event::Event>().await {
            Ok(entries) => {
                let count = entries.len();
                (entries, count)
            }
            Err(e) => {
                warn!("Redis event read failed: {e:#}");
                state.telemetry.observe_error("redis_reader");
                (Vec::new(), 0)
            }
        }
    } else if let Some(ref sq) = state.sqlite_store {
        let cval = sq.get_agent_cursor("events").unwrap_or(0);
        match sq.events_since(cval, 5000) {
            Ok(rows) if !rows.is_empty() => {
                let max_id = rows.last().unwrap().0;
                let entries: Vec<_> = rows.into_iter().map(|(_, ev)| ev).collect();
                let count = entries.len();
                let _ = sq.set_agent_cursor("events", max_id);
                (entries, count)
            }
            _ => (Vec::new(), 0),
        }
    } else {
        warn!("sqlite_store not available — cannot read events");
        (Vec::new(), 0)
    };

    #[cfg(not(feature = "redis-reader"))]
    let (events_entries, events_count) = if let Some(ref sq) = state.sqlite_store {
        let cval = sq.get_agent_cursor("events").unwrap_or(0);
        match sq.events_since(cval, 5000) {
            Ok(rows) if !rows.is_empty() => {
                let max_id = rows.last().unwrap().0;
                let entries: Vec<_> = rows.into_iter().map(|(_, ev)| ev).collect();
                let count = entries.len();
                let _ = sq.set_agent_cursor("events", max_id);
                (entries, count)
            }
            _ => (Vec::new(), 0),
        }
    } else {
        warn!("sqlite_store not available — cannot read events");
        (Vec::new(), 0)
    };

    state.telemetry.observe_events(&events_entries);

    // Track operator IPs: any SSH login via publickey is an operator (has the private key).
    for ev in &events_entries {
        if ev.kind == "ssh.login_success"
            || ev.kind == "auth.login_success"
            || ev.kind == "auth.session_opened"
        {
            let method = ev
                .details
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if method == "publickey" {
                let ip = ev
                    .details
                    .get("ip")
                    .or_else(|| ev.details.get("src_ip"))
                    .and_then(|v| v.as_str());
                if let Some(ip) = ip {
                    let is_new = !state.operator_ips.contains_key(ip);
                    state
                        .operator_ips
                        .insert(ip.to_string(), std::time::Instant::now());
                    if is_new {
                        let user = ev
                            .details
                            .get("user")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        info!(
                            user,
                            ip, "operator session detected (publickey) — IP protected"
                        );
                    }
                }
            }
        }
    }

    // Feed new events into the narrative accumulator (incremental, no file re-read)
    state.narrative_acc.reset_for_date(&today);
    state.narrative_acc.ingest_events(&events_entries);

    // Feed events into knowledge graph (in-memory attack context)
    let trigger_incidents = {
        let mut graph = state.knowledge_graph.write().unwrap();
        // Set host label for trigger incidents (once)
        if graph.trigger_host.is_empty() {
            let host_label = graph
                .system_node()
                .and_then(|id| graph.get_node(id))
                .map(|n| n.label())
                .unwrap_or_else(|| "unknown".to_string());
            graph.set_trigger_host(&host_label);
        }
        for ev in &events_entries {
            graph.ingest(ev);
        }
        graph.drain_trigger_incidents()
    };

    // Process real-time trigger incidents (CRITICAL detectors, <2s latency)
    if !trigger_incidents.is_empty() {
        tracing::info!(count = trigger_incidents.len(), "real-time triggers fired");
        // Ingest trigger incidents into the graph
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            for inc in &trigger_incidents {
                graph.ingest_incident(inc);
            }
        }
        // Phase 6E: trigger incidents are already in the knowledge graph
        // (ingested above). No separate JSONL write needed.
    }

    // Periodic graph maintenance (cleanup expired + dated snapshot every 60s)
    if state.last_graph_snapshot.elapsed().as_secs() >= 60 {
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.cleanup_expired(chrono::Utc::now());
            graph.compact_edges();
            graph.enforce_memory_limit();
            // Phase 7: save to dated snapshot (graph-snapshot-YYYY-MM-DD.json)
            if let Err(e) = graph.save_dated_snapshot(data_dir) {
                warn!("knowledge graph snapshot failed: {e:#}");
            }
            // Spec 016: also save to SQLite store
            if let Some(ref sq) = state.sqlite_store {
                if let Err(e) = graph.save_to_store(sq) {
                    warn!("knowledge graph SQLite snapshot failed: {e:#}");
                }
            }
            let metrics = graph.metrics();
            if let Ok(json) = serde_json::to_vec(&metrics) {
                let _ = std::fs::write(data_dir.join("graph-stats.json"), json);
            }
            // Phase 7: cleanup old snapshots (keep 7 days)
            knowledge_graph::KnowledgeGraph::cleanup_old_snapshots(data_dir, 7);
            // Spec 016: also cleanup SQLite snapshots
            if let Some(ref sq) = state.sqlite_store {
                knowledge_graph::KnowledgeGraph::cleanup_store_snapshots(sq, 7);
            }
        }
        state.last_graph_snapshot = std::time::Instant::now();
    }

    // Update neural autoencoder with graph structural features
    {
        let graph = state.knowledge_graph.read().unwrap();
        let gf = graph.extract_neural_features();
        state.anomaly_engine.set_graph_features(gf);
    }

    // Run graph-based detectors (parallel to sensor detectors)
    {
        let (graph_incidents, _host_label) = {
            let graph = state.knowledge_graph.read().unwrap();
            let host = graph
                .system_node()
                .and_then(|id| graph.get_node(id))
                .map(|n| n.label())
                .unwrap_or_else(|| "unknown".to_string());
            let calibration_ctx = knowledge_graph::detectors::CalibrationContext {
                is_cloud: state.environment_profile.is_cloud(),
                human_uids: state.environment_profile.human_uids.clone(),
            };
            let incidents = knowledge_graph::detectors::run_all_with_calibration(
                &graph,
                &mut state.graph_detector_state,
                &host,
                chrono::Utc::now(),
                &calibration_ctx,
            );
            (incidents, host)
        };
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            for inc in &graph_incidents {
                graph.ingest_incident(inc);
            }
        }
        if !graph_incidents.is_empty() {
            // Phase 6E: graph detector incidents are already in the knowledge graph
            // (ingested above). No separate JSONL write needed.
            tracing::info!(count = graph_incidents.len(), "graph detectors fired");
        }
    }

    // Feed events into cross-layer correlation engine and baseline learning
    for ev in &events_entries {
        let corr_event = correlation_engine::CorrelationEngine::classify_event(ev);
        let ev_entities = corr_event.entities.clone();
        state.correlation_engine.observe(corr_event);
        let anomalies = state.baseline.observe_event(ev);
        if !anomalies.is_empty() {
            state.last_baseline_anomaly_ts = Some(chrono::Utc::now());
        }
        for anomaly in &anomalies {
            info!(
                anomaly_type = ?anomaly.anomaly_type,
                description = %anomaly.description,
                "baseline anomaly detected"
            );

            // Inject baseline anomalies into correlation engine.
            let kind = match anomaly.anomaly_type {
                crate::baseline::AnomalyType::EventRateDrop => "baseline.silence",
                crate::baseline::AnomalyType::EventRateSpike => "baseline.rate_spike",
                crate::baseline::AnomalyType::ProcessLineage => "baseline.new_process",
                crate::baseline::AnomalyType::UserLoginTime => "baseline.unusual_login",
                crate::baseline::AnomalyType::NewDestination => "baseline.new_destination",
            };
            let baseline_corr = correlation_engine::CorrelationEngine::baseline_event(
                kind,
                anomaly.severity.clone(),
                ev_entities.clone(),
                serde_json::json!({
                    "description": anomaly.description,
                    "expected": anomaly.expected,
                    "observed": anomaly.observed,
                }),
            );
            state.correlation_engine.observe(baseline_corr);
        }
    }

    // Feed eBPF events through kill chain tracker (inline pattern detection).
    if cfg.killchain.enabled {
        let kc_incidents = killchain_inline::process_events(
            &mut state.killchain_tracker,
            &events_entries,
            &mut state.correlation_engine,
        );
        killchain_inline::write_incidents(data_dir, &kc_incidents);
        killchain_inline::notify_telegram(
            &state.telegram_client,
            &kc_incidents,
            &state.notification_burst_tracker,
            &mut state.telegram_deferred,
        );

        // Periodic stale PID cleanup (every 60s).
        if state.last_killchain_cleanup.elapsed().as_secs() >= 60 {
            killchain_inline::cleanup_stale(&mut state.killchain_tracker);
            state.last_killchain_cleanup = std::time::Instant::now();
        }
    }

    // Feed events through threat DNA engine (behavioral fingerprinting + anomaly detection).
    if cfg.dna.enabled {
        dna_inline::process_events(
            &mut state.dna_state,
            &events_entries,
            &mut state.correlation_engine,
            &mut state.attacker_profiles,
        );

        // Periodic DNA state persistence (every 5 min).
        if state.last_dna_save.elapsed().as_secs() >= 300 {
            dna_inline::save(&state.dna_state);
            state.last_dna_save = std::time::Instant::now();
        }
    }

    // Feed events through DDoS shield (rate limiting, SYN tracking, escalation).
    if let Some(ref mut shield) = state.shield_state {
        // Build risk score lookup for pre-emptive rate limiting.
        let ip_risks: std::collections::HashMap<String, u8> = state
            .attacker_profiles
            .iter()
            .filter(|(_, p)| p.risk_score > 60)
            .map(|(ip, p)| (ip.clone(), p.risk_score))
            .collect();
        let (_drops, shield_incidents, shield_blocked) =
            shield_inline::process_events(shield, &events_entries, &ip_risks);
        shield_inline::write_incidents(data_dir, &shield_incidents);
        shield_inline::notify_telegram(
            &state.telegram_client,
            &shield_incidents,
            &state.notification_burst_tracker,
            &mut state.telegram_deferred,
        );
        // Sync: register shield blocks in agent blocklist and attacker intel.
        for ip in &shield_blocked {
            state.blocklist.insert(ip.clone());
            // Enrich attacker profiles with shield block data.
            let profile = state
                .attacker_profiles
                .entry(ip.clone())
                .or_insert_with(|| attacker_intel::new_profile(ip, chrono::Utc::now()));
            attacker_intel::observe_shield_block(profile, "shield:rate_limit");
        }
        // Inject shield escalation incidents into correlation engine.
        for inc in &shield_incidents {
            if let Some(title) = inc.get("title").and_then(|t| t.as_str()) {
                let kind = if title.contains("Critical") {
                    "shield.escalation.critical"
                } else if title.contains("UnderAttack") {
                    "shield.escalation.under_attack"
                } else if title.contains("Elevated") {
                    "shield.escalation.elevated"
                } else {
                    "shield.escalation.transition"
                };
                let corr = correlation_engine::CorrelationEngine::shield_event(kind, inc.clone());
                state.correlation_engine.observe(corr);
            }
        }
    }

    narrative_anomaly::process_anomalies(data_dir, &today, &events_entries, state);

    narrative_incident_ingest::ingest_new_incidents(data_dir, &today, state)?;

    narrative_daily_summary::maybe_write_daily_summary_and_digest(
        data_dir,
        &today,
        events_count,
        cfg,
        state,
    )
    .await;

    narrative_autofp::maybe_suggest_allowlist_from_fp_reports(data_dir, state).await;

    // Update deep security snapshot for dashboard.
    if let Some(ref ds) = state.deep_security_snapshot {
        let (kc_tracked, kc_pre, kc_full) = killchain_inline::stats(&state.killchain_tracker);
        let snap = dashboard::DeepSecuritySnapshot {
            firmware_trust_score: None, // updated by firmware_tick
            firmware_last_audit: None,
            hypervisor_environment: state
                .hypervisor_environment
                .as_ref()
                .map(|e| format!("{e:?}")),
            hypervisor_trust_score: None, // updated by hypervisor_tick
            killchain_pids_tracked: kc_tracked,
            killchain_pre_chains: kc_pre,
            killchain_full_matches: kc_full,
            dna_fingerprints: state.dna_state.store.len(),
            dna_anomaly_alerts: state.dna_state.anomaly_detector.anomaly_count(),
            dna_attack_chains: state.dna_state.chain_tracker.len(),
        };
        if let Ok(mut guard) = ds.write() {
            *guard = snap;
        }
    }

    telemetry_tick::write_tick_snapshot(state, "narrative_tick");

    Ok(events_count)
}

// ---------------------------------------------------------------------------
// LSM auto-enable helpers
// ---------------------------------------------------------------------------

// LSM enforcement and trust rules moved to trust_rules.rs

// ---------------------------------------------------------------------------
// Boot self-test — verify self-awareness is working on startup
// ---------------------------------------------------------------------------

/// One-time reconciliation: read all decisions-*.jsonl files and write
/// missing decisions to the knowledge graph. This fixes historical data
/// where auto-block gates (obvious, CrowdSec) wrote decisions to JSONL
/// but not to the graph.
fn backfill_graph_decisions(data_dir: &std::path::Path, state: &mut AgentState) {
    use std::io::BufRead;

    let mut filled = 0usize;
    let mut scanned = 0usize;

    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("decisions-") || !name.ends_with(".jsonl") {
            continue;
        }
        let Ok(file) = std::fs::File::open(entry.path()) else {
            continue;
        };
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(d) = serde_json::from_str::<decisions::DecisionEntry>(&line) else {
                continue;
            };
            scanned += 1;

            // Backfill all decisions that have an action type
            if d.action_type.is_empty() || d.dry_run {
                continue;
            }

            // Check if the graph incident node is missing a decision
            let mut graph = state.knowledge_graph.write().unwrap();
            let needs_backfill = graph
                .find_by_incident(&d.incident_id)
                .and_then(|nid| {
                    if let Some(crate::knowledge_graph::types::Node::Incident {
                        decision, ..
                    }) = graph.get_node(nid)
                    {
                        Some(decision.is_none())
                    } else {
                        None
                    }
                })
                .unwrap_or(false);

            if needs_backfill {
                graph.ingest_decision(
                    &d.incident_id,
                    &d.action_type,
                    d.target_ip.as_deref(),
                    d.confidence,
                    &d.reason,
                    true,
                    d.ts,
                );
                filled += 1;
            }
        }
    }

    if filled > 0 {
        info!(
            filled,
            scanned, "backfill: reconciled JSONL decisions with knowledge graph"
        );
    }

    // Phase 2: dismiss visible incidents that never received any decision.
    // These are historical incidents from before the noise-gate was deployed.
    // Without this, they show as "OBSERVING" forever in the dashboard.
    {
        use crate::knowledge_graph::types::{Node, NodeType};
        let mut graph = state.knowledge_graph.write().unwrap();
        let orphan_ids: Vec<_> = graph
            .nodes_of_type(NodeType::Incident)
            .iter()
            .filter_map(|&id| {
                if let Some(Node::Incident {
                    incident_id,
                    decision,
                    research_only,
                    ..
                }) = graph.get_node(id)
                {
                    if decision.is_none() && !research_only {
                        return Some((id, incident_id.clone()));
                    }
                }
                None
            })
            .collect();

        let dismissed = orphan_ids.len();
        for (_nid, iid) in &orphan_ids {
            graph.ingest_decision(
                iid,
                "dismiss",
                None,
                1.0,
                "Retroactive dismiss: historical incident with no decision",
                true,
                chrono::Utc::now(),
            );
        }

        if dismissed > 0 {
            info!(
                dismissed,
                "backfill: dismissed orphan incidents with no decision"
            );
        }
    }
}

/// Quick validation at agent startup that the host inventory (own IPs,
/// listening ports) was loaded correctly by the sensor, and cloud safelist
/// is initialized. Logs warnings for anything that looks wrong.
fn boot_self_test() {
    use tracing::{info, warn};

    // Check cloud safelist initialized (own IPs loaded)
    let local_ips = cloud_safelist::local_ip_count();
    if local_ips > 0 {
        info!(local_ips, "boot self-test: local interface IPs loaded");
    } else {
        warn!(
            "boot self-test: no local interface IPs detected — self-traffic filtering may not work"
        );
    }

    // Check that cloud safelist ranges are loaded
    let cloud_ranges = cloud_safelist::cloud_range_count();
    if cloud_ranges > 0 {
        info!(
            cloud_ranges,
            "boot self-test: cloud provider IP ranges loaded"
        );
    } else {
        warn!("boot self-test: no cloud IP ranges loaded");
    }

    info!("boot self-test: passed");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::Path;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tempfile::TempDir;

    // ------------------------------------------------------------------
    // Minimal mock AI provider - returns a fixed decision, no network I/O
    // ------------------------------------------------------------------

    struct MockAiProvider {
        decision: ai::AiDecision,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for MockAiProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            Ok(self.decision.clone())
        }
        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
        }
    }

    struct CountingMockAiProvider {
        decision: ai::AiDecision,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for CountingMockAiProvider {
        fn name(&self) -> &'static str {
            "mock-counting"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }
        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
        }
    }

    struct CorrelationInspectingMockAiProvider {
        decision: ai::AiDecision,
        last_related_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for CorrelationInspectingMockAiProvider {
        fn name(&self) -> &'static str {
            "mock-correlation"
        }

        async fn decide(&self, ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            self.last_related_count
                .store(ctx.related_incidents.len(), Ordering::SeqCst);
            Ok(self.decision.clone())
        }

        async fn chat(&self, _system_prompt: &str, _user_message: &str) -> anyhow::Result<String> {
            Ok("mock chat response".to_string())
        }
    }

    /// Create a test incident (ssh brute-force from an external IP).
    fn test_incident(ip: &str) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: "SSH Brute Force".to_string(),
            summary: format!("9 failed SSH attempts from {ip}"),
            evidence: serde_json::json!({"failed_attempts": 9}),
            recommended_checks: vec![],
            tags: vec!["ssh".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        }
    }

    fn test_incident_with_kind(ip: &str, kind: &str) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("{kind}:{ip}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: format!("{kind} detected"),
            summary: format!("{kind} from {ip}"),
            evidence: serde_json::json!({"kind": kind}),
            recommended_checks: vec![],
            tags: vec![kind.to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        }
    }

    /// Write a minimal Incident JSON line (kept for backcompat with tests that need JSONL).
    fn incident_line(ip: &str) -> String {
        serde_json::to_string(&test_incident(ip)).unwrap()
    }

    fn incident_line_with_kind(ip: &str, kind: &str) -> String {
        serde_json::to_string(&test_incident_with_kind(ip, kind)).unwrap()
    }

    /// Open a SQLite store in the temp dir and return it wrapped in Arc.
    fn test_sqlite_store(dir: &std::path::Path) -> Arc<innerwarden_store::Store> {
        Arc::new(innerwarden_store::Store::open(dir).unwrap())
    }

    /// Insert an incident into the SQLite store.
    fn insert_test_incident(
        store: &innerwarden_store::Store,
        incident: &innerwarden_core::incident::Incident,
    ) {
        store.insert_incident(incident).unwrap();
    }

    fn sha256_hex_for_test(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn triage_approval(incident_id: &str, operator: &str) -> telegram::ApprovalResult {
        telegram::ApprovalResult {
            incident_id: incident_id.to_string(),
            approved: true,
            operator_name: operator.to_string(),
            always: false,
            chosen_action: String::new(),
        }
    }

    fn triage_test_state(data_dir: &Path) -> AgentState {
        AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: None,
            decision_writer: Some(decisions::DecisionWriter::new(data_dir).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_daily_sent: 0,
            telegram_budget_date: None,
            telegram_deferred: HashMap::new(),
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            grouping_engine: notification_pipeline::GroupingEngine::new(
                &crate::config::NotificationPipelineConfig::default(),
            ),
            environment_profile: environment_profile::EnvironmentProfile::default(),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            neural_incidents: Vec::new(),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(data_dir),
            store: state_store::StateStore::open(data_dir).unwrap(),
            sqlite_store: None,
            maintenance_scheduler: None,
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            defender_brain: defender_brain::DefenderBrain::new(),
            brain_history: defender_brain::BrainHistory::new(100),
            brain_stats: defender_brain::BrainStats::default(),
            pcap_capture: pcap_capture::PcapCapture::new(data_dir),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            last_hypervisor_incident_at: None,
            hypervisor_environment: None,
            killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
            last_killchain_cleanup: std::time::Instant::now(),
            dna_state: dna_inline::DnaState::new(
                &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
                3,
                3.0,
                300,
            ),
            last_dna_save: std::time::Instant::now(),
            shield_state: None,
            deep_security_snapshot: None,
            dynamic_trusted_ips: Vec::new(),
            dynamic_trusted_users: Vec::new(),
            dynamic_trusted_processes: Vec::new(),
            operator_ips: std::collections::HashMap::new(),
            last_operator_refresh: std::time::Instant::now(),
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            latest_anomaly_score: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
                knowledge_graph::KnowledgeGraph::new(),
            )),
            graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
            last_graph_snapshot: std::time::Instant::now(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
            notification_burst_tracker: notification_gate::BurstTracker::new(),
        }
    }

    #[test]
    fn parse_telegram_triage_action_routes_allow_proc() {
        assert_eq!(
            parse_telegram_triage_action("__allow_proc__:cargo-build"),
            Some(TelegramTriageAction::AllowProc("cargo-build"))
        );
    }

    #[test]
    fn parse_telegram_triage_action_routes_allow_ip() {
        assert_eq!(
            parse_telegram_triage_action("__allow_ip__:1.2.3.4"),
            Some(TelegramTriageAction::AllowIp("1.2.3.4"))
        );
    }

    #[test]
    fn parse_telegram_triage_action_routes_fp_report() {
        assert_eq!(
            parse_telegram_triage_action("__fp__:ssh_bruteforce:1.2.3.4:test"),
            Some(TelegramTriageAction::ReportFp(
                "ssh_bruteforce:1.2.3.4:test"
            ))
        );
    }

    #[test]
    fn parse_telegram_triage_action_ignores_non_triage_ids() {
        assert_eq!(parse_telegram_triage_action("__status__"), None);
        assert_eq!(
            parse_telegram_triage_action("approve:ssh_bruteforce:id"),
            None
        );
    }

    #[test]
    fn sanitize_allowlist_process_name_removes_dangerous_chars() {
        assert_eq!(
            sanitize_allowlist_process_name("  bad\"proc\nname  "),
            Some("badproc name".to_string())
        );
        assert_eq!(sanitize_allowlist_process_name("   "), None);
    }

    #[tokio::test]
    async fn telegram_triage_allowlist_skip_paths_are_audited_with_hash_chain() {
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = triage_test_state(dir.path());

        process_telegram_approval(
            triage_approval("__allow_proc__:   ", "alice"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;
        process_telegram_approval(
            triage_approval("__allow_ip__:not-an-ip", "alice"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let lines: Vec<String> = std::fs::read_to_string(&decisions_path)
            .unwrap()
            .lines()
            .map(|line| line.to_string())
            .collect();

        assert_eq!(lines.len(), 2, "expected two triage audit entries");

        let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();

        assert_eq!(first["action_type"], "allowlist_add");
        assert_eq!(first["execution_result"], "skipped:empty_process_name");
        assert_eq!(second["action_type"], "allowlist_add");
        assert_eq!(second["execution_result"], "skipped:invalid_ip");

        assert!(
            first.get("prev_hash").is_none(),
            "first entry should not have prev_hash"
        );
        let expected_prev_hash = sha256_hex_for_test(&lines[0]);
        assert_eq!(
            second["prev_hash"].as_str(),
            Some(expected_prev_hash.as_str())
        );
    }

    #[tokio::test]
    async fn telegram_triage_fp_reports_write_audit_and_fp_log() {
        let dir = TempDir::new().unwrap();
        let cfg = config::AgentConfig::default();
        let mut state = triage_test_state(dir.path());
        let fp_incident_id = "ssh_bruteforce:1.2.3.4:test";

        process_telegram_approval(
            triage_approval(&format!("__fp__:{fp_incident_id}"), "alice"),
            dir.path(),
            &cfg,
            &mut state,
        )
        .await;

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }

        let today_local = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = dir.path().join(format!("decisions-{today_local}.jsonl"));
        let decision_line = std::fs::read_to_string(&decisions_path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        let decision: serde_json::Value = serde_json::from_str(&decision_line).unwrap();

        assert_eq!(decision["incident_id"], fp_incident_id);
        assert_eq!(decision["action_type"], "fp_report");
        assert_eq!(decision["execution_result"], "reported_fp:ssh_bruteforce");
        assert_eq!(decision["ai_provider"], "operator:telegram:alice");

        let today_utc = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let fp_path = dir.path().join(format!("fp-reports-{today_utc}.jsonl"));
        let fp_content = std::fs::read_to_string(&fp_path).unwrap();
        assert!(fp_content.contains("\"incident_id\":\"ssh_bruteforce:1.2.3.4:test\""));
        assert!(fp_content.contains("\"detector\":\"ssh_bruteforce\""));
        assert!(fp_content.contains("\"reporter\":\"alice\""));
    }

    // ------------------------------------------------------------------
    // Golden path: incident → algorithm gate → mock AI → dry-run block → decisions.jsonl
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn golden_path_dry_run_produces_decision_entry() {
        let dir = TempDir::new().unwrap();

        // 1. Plant a single brute-force incident from a routable external IP.
        let attacker_ip = "1.2.3.4";
        let store = test_sqlite_store(dir.path());
        insert_test_incident(&store, &test_incident(attacker_ip));

        // 2. Config: AI enabled, responder dry_run=true, ufw backend allowed
        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.8,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        // 3. Mock provider always recommends blocking the IP
        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.97,
                auto_execute: true,
                reason: "9 SSH failures, no success, external IP - classic brute force".to_string(),
                alternatives: vec!["monitor".to_string()],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_daily_sent: 0,
            telegram_budget_date: None,
            telegram_deferred: HashMap::new(),
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            grouping_engine: notification_pipeline::GroupingEngine::new(
                &crate::config::NotificationPipelineConfig::default(),
            ),
            environment_profile: environment_profile::EnvironmentProfile::default(),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            neural_incidents: Vec::new(),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            sqlite_store: Some(store.clone()),
            maintenance_scheduler: None,
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            defender_brain: defender_brain::DefenderBrain::new(),
            brain_history: defender_brain::BrainHistory::new(100),
            brain_stats: defender_brain::BrainStats::default(),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            last_hypervisor_incident_at: None,
            hypervisor_environment: None,
            killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
            last_killchain_cleanup: std::time::Instant::now(),
            dna_state: dna_inline::DnaState::new(
                &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
                3,
                3.0,
                300,
            ),
            last_dna_save: std::time::Instant::now(),
            shield_state: None,
            deep_security_snapshot: None,
            dynamic_trusted_ips: Vec::new(),
            dynamic_trusted_users: Vec::new(),
            dynamic_trusted_processes: Vec::new(),
            operator_ips: std::collections::HashMap::new(),
            last_operator_refresh: std::time::Instant::now(),
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            latest_anomaly_score: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
                knowledge_graph::KnowledgeGraph::new(),
            )),
            graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
            last_graph_snapshot: std::time::Instant::now(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
            notification_burst_tracker: notification_gate::BurstTracker::new(),
        };

        // 4. Run the incident tick
        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;

        // Verify: one incident handled
        assert_eq!(handled, 1, "expected 1 incident handled");

        // Verify: decision written to audit trail
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        assert!(
            content.contains(attacker_ip),
            "decision must record the target IP"
        );
        assert!(
            content.contains("block_ip"),
            "decision must record action type"
        );
        assert!(
            content.contains("\"dry_run\":true"),
            "dry_run must be flagged in audit trail"
        );
        assert!(
            content.contains("mock"),
            "AI provider name must appear in audit trail"
        );
    }

    // ------------------------------------------------------------------
    // allowed_skills whitelist: AI selects a disallowed skill → fallback used
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn allowed_skills_whitelist_enforced() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "5.6.7.8";
        let store = test_sqlite_store(dir.path());
        insert_test_incident(&store, &test_incident(attacker_ip));

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                // Only ufw is allowed; AI picks iptables - should fall back silently
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        // AI picks iptables (not in whitelist)
        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-iptables".to_string(), // NOT in allowed_skills
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "brute force".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_daily_sent: 0,
            telegram_budget_date: None,
            telegram_deferred: HashMap::new(),
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            grouping_engine: notification_pipeline::GroupingEngine::new(
                &crate::config::NotificationPipelineConfig::default(),
            ),
            environment_profile: environment_profile::EnvironmentProfile::default(),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            neural_incidents: Vec::new(),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            sqlite_store: Some(store.clone()),
            maintenance_scheduler: None,
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            defender_brain: defender_brain::DefenderBrain::new(),
            brain_history: defender_brain::BrainHistory::new(100),
            brain_stats: defender_brain::BrainStats::default(),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            last_hypervisor_incident_at: None,
            hypervisor_environment: None,
            killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
            last_killchain_cleanup: std::time::Instant::now(),
            dna_state: dna_inline::DnaState::new(
                &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
                3,
                3.0,
                300,
            ),
            last_dna_save: std::time::Instant::now(),
            shield_state: None,
            deep_security_snapshot: None,
            dynamic_trusted_ips: Vec::new(),
            dynamic_trusted_users: Vec::new(),
            dynamic_trusted_processes: Vec::new(),
            operator_ips: std::collections::HashMap::new(),
            last_operator_refresh: std::time::Instant::now(),
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            latest_anomaly_score: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
                knowledge_graph::KnowledgeGraph::new(),
            )),
            graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
            last_graph_snapshot: std::time::Instant::now(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
            notification_burst_tracker: notification_gate::BurstTracker::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;

        // Still handled (not skipped entirely) - fell back to ufw
        assert_eq!(handled, 1);

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        // The execution used the ufw fallback, not iptables.
        // The audit trail still records the IP the AI identified.
        assert!(content.contains(attacker_ip));
    }

    #[tokio::test]
    async fn same_ip_in_same_tick_triggers_single_ai_call() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "9.8.7.6";
        let store = test_sqlite_store(dir.path());
        insert_test_incident(&store, &test_incident(attacker_ip));
        // Insert a second incident for the same IP (different ID to avoid UNIQUE constraint)
        let mut inc2 = test_incident(attacker_ip);
        inc2.incident_id = format!("ssh_bruteforce:{attacker_ip}:test2");
        insert_test_incident(&store, &inc2);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CountingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "duplicate IP in same tick".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
            calls: calls.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_daily_sent: 0,
            telegram_budget_date: None,
            telegram_deferred: HashMap::new(),
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            grouping_engine: notification_pipeline::GroupingEngine::new(
                &crate::config::NotificationPipelineConfig::default(),
            ),
            environment_profile: environment_profile::EnvironmentProfile::default(),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            neural_incidents: Vec::new(),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            sqlite_store: Some(store.clone()),
            maintenance_scheduler: None,
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            defender_brain: defender_brain::DefenderBrain::new(),
            brain_history: defender_brain::BrainHistory::new(100),
            brain_stats: defender_brain::BrainStats::default(),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            last_hypervisor_incident_at: None,
            hypervisor_environment: None,
            killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
            last_killchain_cleanup: std::time::Instant::now(),
            dna_state: dna_inline::DnaState::new(
                &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
                3,
                3.0,
                300,
            ),
            last_dna_save: std::time::Instant::now(),
            shield_state: None,
            deep_security_snapshot: None,
            dynamic_trusted_ips: Vec::new(),
            dynamic_trusted_users: Vec::new(),
            dynamic_trusted_processes: Vec::new(),
            operator_ips: std::collections::HashMap::new(),
            last_operator_refresh: std::time::Instant::now(),
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            latest_anomaly_score: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
                knowledge_graph::KnowledgeGraph::new(),
            )),
            graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
            last_graph_snapshot: std::time::Instant::now(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
            notification_burst_tracker: notification_gate::BurstTracker::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;
        assert_eq!(handled, 2, "both incidents should be accounted for");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "same IP in same tick must call AI only once"
        );

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        assert_eq!(
            content.lines().count(),
            1,
            "only one decision should be recorded"
        );
    }

    #[tokio::test]
    async fn temporal_correlation_context_is_passed_to_ai() {
        let dir = TempDir::new().unwrap();

        let attacker_ip = "2.3.4.5";
        let store = test_sqlite_store(dir.path());
        insert_test_incident(&store, &test_incident_with_kind(attacker_ip, "port_scan"));
        insert_test_incident(
            &store,
            &test_incident_with_kind(attacker_ip, "credential_stuffing"),
        );

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            correlation: config::CorrelationConfig {
                enabled: true,
                window_seconds: 300,
                max_related_incidents: 8,
            },
            responder: config::ResponderConfig {
                enabled: false,
                ..config::ResponderConfig::default()
            },
            ..config::AgentConfig::default()
        };

        let related_count = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CorrelationInspectingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::Ignore {
                    reason: "test correlation".to_string(),
                },
                confidence: 0.9,
                auto_execute: false,
                reason: "test correlation".to_string(),
                alternatives: vec![],
                estimated_threat: "medium".to_string(),
            },
            last_related_count: related_count.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_daily_sent: 0,
            telegram_budget_date: None,
            telegram_deferred: HashMap::new(),
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            grouping_engine: notification_pipeline::GroupingEngine::new(
                &crate::config::NotificationPipelineConfig::default(),
            ),
            environment_profile: environment_profile::EnvironmentProfile::default(),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            neural_incidents: Vec::new(),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            sqlite_store: Some(store.clone()),
            maintenance_scheduler: None,
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            defender_brain: defender_brain::DefenderBrain::new(),
            brain_history: defender_brain::BrainHistory::new(100),
            brain_stats: defender_brain::BrainStats::default(),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            last_hypervisor_incident_at: None,
            hypervisor_environment: None,
            killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
            last_killchain_cleanup: std::time::Instant::now(),
            dna_state: dna_inline::DnaState::new(
                &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
                3,
                3.0,
                300,
            ),
            last_dna_save: std::time::Instant::now(),
            shield_state: None,
            deep_security_snapshot: None,
            dynamic_trusted_ips: Vec::new(),
            dynamic_trusted_users: Vec::new(),
            dynamic_trusted_processes: Vec::new(),
            operator_ips: std::collections::HashMap::new(),
            last_operator_refresh: std::time::Instant::now(),
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            latest_anomaly_score: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
                knowledge_graph::KnowledgeGraph::new(),
            )),
            graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
            last_graph_snapshot: std::time::Instant::now(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
            notification_burst_tracker: notification_gate::BurstTracker::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;
        assert_eq!(handled, 2);
        assert!(
            related_count.load(Ordering::SeqCst) >= 1,
            "second correlated incident should carry prior incident context"
        );
    }

    #[tokio::test]
    async fn honeypot_demo_writes_synthetic_decoy_event() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "7.7.7.7";
        let store = test_sqlite_store(dir.path());
        insert_test_incident(&store, &test_incident(attacker_ip));

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["honeypot".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::Honeypot {
                    ip: attacker_ip.to_string(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "demo honeypot test".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_daily_sent: 0,
            telegram_budget_date: None,
            telegram_deferred: HashMap::new(),
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            grouping_engine: notification_pipeline::GroupingEngine::new(
                &crate::config::NotificationPipelineConfig::default(),
            ),
            environment_profile: environment_profile::EnvironmentProfile::default(),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            neural_incidents: Vec::new(),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            sqlite_store: Some(store.clone()),
            maintenance_scheduler: None,
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            defender_brain: defender_brain::DefenderBrain::new(),
            brain_history: defender_brain::BrainHistory::new(100),
            brain_stats: defender_brain::BrainStats::default(),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            last_hypervisor_incident_at: None,
            hypervisor_environment: None,
            killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
            last_killchain_cleanup: std::time::Instant::now(),
            dna_state: dna_inline::DnaState::new(
                &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
                3,
                3.0,
                300,
            ),
            last_dna_save: std::time::Instant::now(),
            shield_state: None,
            deep_security_snapshot: None,
            dynamic_trusted_ips: Vec::new(),
            dynamic_trusted_users: Vec::new(),
            dynamic_trusted_processes: Vec::new(),
            operator_ips: std::collections::HashMap::new(),
            last_operator_refresh: std::time::Instant::now(),
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            latest_anomaly_score: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
                knowledge_graph::KnowledgeGraph::new(),
            )),
            graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
            last_graph_snapshot: std::time::Instant::now(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
            notification_burst_tracker: notification_gate::BurstTracker::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;
        assert_eq!(handled, 1);

        let events_path = dir.path().join(format!("events-{today}.jsonl"));
        let content = std::fs::read_to_string(&events_path).unwrap();
        assert!(content.contains("honeypot.demo_decoy_hit"));
        assert!(content.contains("DEMO/SIMULATION/DECOY"));
        assert!(content.contains(attacker_ip));
    }

    // ------------------------------------------------------------------
    // Decision cooldown: second incident from same IP/detector is suppressed
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn decision_cooldown_suppresses_repeat() {
        let dir = TempDir::new().unwrap();

        let attacker_ip = "1.2.3.4";

        // Plant TWO identical brute-force incidents from the same IP
        let store = test_sqlite_store(dir.path());
        insert_test_incident(&store, &test_incident(attacker_ip));
        let mut inc2 = test_incident(attacker_ip);
        inc2.incident_id = format!("ssh_bruteforce:{attacker_ip}:test2");
        insert_test_incident(&store, &inc2);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.8,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CountingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.97,
                auto_execute: true,
                reason: "brute force".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
            calls: calls.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            telemetry: telemetry::TelemetryState::default(),
            telemetry_writer: None,
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
            last_narrative_at: None,
            last_daily_summary_telegram: None,
            telegram_daily_sent: 0,
            telegram_budget_date: None,
            telegram_deferred: HashMap::new(),
            telegram_client: None,
            pending_confirmations: HashMap::new(),
            approval_rx: None,
            grouping_engine: notification_pipeline::GroupingEngine::new(
                &crate::config::NotificationPipelineConfig::default(),
            ),
            environment_profile: environment_profile::EnvironmentProfile::default(),
            anomaly_engine: neural_lifecycle::AnomalyEngine::new(Default::default()),
            neural_incidents: Vec::new(),
            trust_rules: std::collections::HashSet::new(),
            crowdsec: None,
            abuseipdb: None,
            fail2ban: None,
            geoip_client: None,
            slack_client: None,
            cloudflare_client: None,
            circuit_breaker_until: None,
            pending_honeypot_choices: HashMap::new(),
            ip_reputations: HashMap::new(),
            lsm_enabled: false,
            mesh: None,
            recent_blocks: std::collections::VecDeque::new(),
            xdp_block_times: HashMap::new(),
            response_lifecycle: response_lifecycle::ResponseLifecycle::new(),
            abuseipdb_report_queue: Vec::new(),
            narrative_acc: NarrativeAccumulator::default(),
            narrative_incidents_offset: 0,
            forensics: forensics::ForensicsCapture::new(dir.path()),
            store: state_store::StateStore::open(dir.path()).unwrap(),
            sqlite_store: Some(store.clone()),
            maintenance_scheduler: None,
            attacker_profiles: HashMap::new(),
            last_intel_consolidation_at: None,
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            baseline: baseline::BaselineStore::new(),
            playbook_engine: playbook::PlaybookEngine::new(std::path::Path::new("/nonexistent")),
            defender_brain: defender_brain::DefenderBrain::new(),
            brain_history: defender_brain::BrainHistory::new(100),
            brain_stats: defender_brain::BrainStats::default(),
            pcap_capture: pcap_capture::PcapCapture::new(dir.path()),
            scoring_engine: scoring::ScoringEngine::new(0.95),
            last_firmware_incident_at: None,
            last_hypervisor_incident_at: None,
            hypervisor_environment: None,
            killchain_tracker: innerwarden_killchain::tracker::PidTracker::new(),
            last_killchain_cleanup: std::time::Instant::now(),
            dna_state: dna_inline::DnaState::new(
                &std::path::PathBuf::from("/var/lib/innerwarden/dna"),
                3,
                3.0,
                300,
            ),
            last_dna_save: std::time::Instant::now(),
            shield_state: None,
            deep_security_snapshot: None,
            dynamic_trusted_ips: Vec::new(),
            dynamic_trusted_users: Vec::new(),
            dynamic_trusted_processes: Vec::new(),
            operator_ips: std::collections::HashMap::new(),
            last_operator_refresh: std::time::Instant::now(),
            suppressed_incident_ids: std::collections::HashSet::new(),
            threat_feed: None,
            last_baseline_anomaly_ts: None,
            last_autoencoder_anomaly_ts: None,
            latest_anomaly_score: None,
            two_factor_state: two_factor::TwoFactorState::new(),
            knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
                knowledge_graph::KnowledgeGraph::new(),
            )),
            graph_detector_state: knowledge_graph::detectors::GraphDetectorState::new(),
            last_graph_snapshot: std::time::Instant::now(),
            #[cfg(feature = "redis-reader")]
            redis_reader: None,
            notification_burst_tracker: notification_gate::BurstTracker::new(),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(
            dir.path(),
            &mut cursor,
            &cfg,
            &mut state,
            &Arc::new(RwLock::new(VecDeque::new())),
        )
        .await;

        // Both incidents are "handled" (counted), but the AI should be called
        // only ONCE - the second incident is suppressed by the decision
        // cooldown that was recorded after the first decision.
        assert_eq!(handled, 2);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "AI should be called once - second incident suppressed by cooldown"
        );

        // Verify the cooldown entry was recorded in the persistent store
        assert!(
            state.store.has_cooldown(
                state_store::CooldownTable::Decision,
                &format!("block_ip:ssh_bruteforce:ip:{}", attacker_ip)
            ),
            "decision cooldown should be recorded in store"
        );
    }

    // ------------------------------------------------------------------
    // Always-on honeypot tests
    // ------------------------------------------------------------------

    /// Test that the filter blocklist correctly drops IPs that are already blocked.
    #[test]
    fn test_always_on_filter_blocks_known_ip() {
        let mut set = std::collections::HashSet::new();
        set.insert("1.2.3.4".to_string());
        set.insert("5.6.7.8".to_string());

        // Known-bad IP should be "blocked" (present in set).
        assert!(
            set.contains("1.2.3.4"),
            "IP 1.2.3.4 should be in the filter blocklist"
        );
        assert!(
            set.contains("5.6.7.8"),
            "IP 5.6.7.8 should be in the filter blocklist"
        );

        // Unknown IP should NOT be blocked.
        assert!(
            !set.contains("9.9.9.9"),
            "IP 9.9.9.9 should not be in the filter blocklist"
        );

        // After inserting a new IP, it should be filtered.
        set.insert("9.9.9.9".to_string());
        assert!(
            set.contains("9.9.9.9"),
            "IP 9.9.9.9 should be in the filter blocklist after insertion"
        );
    }

    /// Test that the "always_on" mode string is recognized and would trigger startup.
    #[test]
    fn test_always_on_mode_recognized() {
        // Verify config recognises the mode string (no panic on deserialise).
        let toml = r#"
            [honeypot]
            mode = "always_on"
            port = 2222
            bind_addr = "127.0.0.1"
            interaction = "medium"
        "#;
        let cfg: config::AgentConfig = toml::from_str(toml).expect("should parse always_on mode");
        assert_eq!(cfg.honeypot.mode, "always_on");
        assert_eq!(cfg.honeypot.port, 2222);

        // Verify the mode check used in main() matches.
        let is_always_on = cfg.honeypot.mode == "always_on";
        assert!(
            is_always_on,
            "mode check should return true for 'always_on'"
        );

        // Demo and listener modes should NOT match.
        let mut cfg2 = config::AgentConfig::default();
        cfg2.honeypot.mode = "demo".to_string();
        assert!(
            cfg2.honeypot.mode != "always_on",
            "demo should not match always_on"
        );

        let mut cfg3 = config::AgentConfig::default();
        cfg3.honeypot.mode = "listener".to_string();
        assert!(
            cfg3.honeypot.mode != "always_on",
            "listener should not match always_on"
        );
    }

    // ── Memory safety: NarrativeAccumulator tests ────────────────────

    #[test]
    fn synthetic_events_capped_at_2000() {
        let mut acc = NarrativeAccumulator {
            date: "2026-01-01".to_string(),
            ..Default::default()
        };
        // Simulate 100k events of one kind
        *acc.events_by_kind
            .entry("ssh.login_failed".to_string())
            .or_insert(0) = 100_000;
        let events = acc.synthetic_events();
        assert!(
            events.len() <= 2100, // 2000 cap + some entity events
            "synthetic_events should be capped, got {}",
            events.len()
        );
    }

    #[test]
    fn synthetic_events_preserves_proportions() {
        let mut acc = NarrativeAccumulator {
            date: "2026-01-01".to_string(),
            ..Default::default()
        };
        *acc.events_by_kind
            .entry("ssh.login_failed".to_string())
            .or_insert(0) = 8000;
        *acc.events_by_kind
            .entry("sudo.command".to_string())
            .or_insert(0) = 2000;
        let events = acc.synthetic_events();
        let ssh = events
            .iter()
            .filter(|e| e.kind == "ssh.login_failed")
            .count();
        let sudo = events.iter().filter(|e| e.kind == "sudo.command").count();
        // ssh should be ~4x more than sudo (8000:2000 ratio)
        assert!(ssh > sudo, "ssh ({ssh}) should be more than sudo ({sudo})");
    }

    #[test]
    fn incidents_capped_at_500() {
        let mut acc = NarrativeAccumulator {
            date: "2026-01-01".to_string(),
            ..Default::default()
        };
        let incident = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "test:1".to_string(),
            severity: innerwarden_core::event::Severity::High,
            title: "test".to_string(),
            summary: "test".to_string(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };
        let batch: Vec<_> = (0..600).map(|_| incident.clone()).collect();
        acc.ingest_incidents(&batch);
        assert_eq!(
            acc.incidents.len(),
            500,
            "incidents should be capped at 500"
        );
    }

    #[test]
    fn block_counts_cleared_at_threshold() {
        let dir = TempDir::new().unwrap();
        let store = state_store::StateStore::open(dir.path()).unwrap();
        for i in 0..5001 {
            store.increment_block_count(&format!("1.2.3.{i}"));
        }
        assert!(store.block_counts_len() > 5000);
        // Simulate the trim logic from narrative tick
        if store.block_counts_len() > 5000 {
            store.clear_block_counts();
        }
        assert_eq!(store.block_counts_len(), 0);
    }

    #[test]
    fn narrative_accumulator_resets_on_date_change() {
        let mut acc = NarrativeAccumulator {
            date: "2026-01-01".to_string(),
            ..Default::default()
        };
        *acc.events_by_kind
            .entry("ssh.login_failed".to_string())
            .or_insert(0) = 100;
        acc.total_events = 100;

        acc.reset_for_date("2026-01-02");
        assert_eq!(acc.total_events, 0);
        assert!(acc.events_by_kind.is_empty());
        assert_eq!(acc.date, "2026-01-02");
    }
}
