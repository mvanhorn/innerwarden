// Clippy 1.95 promotes `unnecessary_sort_by` to a default-deny lint, but
// `sort_by_key(|x| Reverse(...))` is less readable than the explicit
// `sort_by(|a, b| b.x.cmp(&a.x))` pattern used throughout the agent for
// reverse-sort leaderboards (threat report, attacker intel, MITRE heatmap).
// Keep the existing style workspace-wide for this crate.
#![allow(clippy::unnecessary_sort_by)]

// Use jemalloc on Linux - the default glibc allocator fragments memory and
// never returns it to the OS, causing apparent "leaks" under sustained load.
// jemalloc aggressively returns unused pages via madvise(MADV_DONTNEED).
//
// Spec 035 PR-A2 phase 1: this allocator is disabled when the
// `dhat-heap` feature is active so DHAT's allocator can take its
// place for heap-budget tests. The two `#[global_allocator]` statics
// below are mutually exclusive by cfg construction:
//   - jemalloc:  cfg(all(not(target_os = "macos"), not(feature = "dhat-heap")))
//   - dhat:      cfg(feature = "dhat-heap")
// These cfg gates cannot both match simultaneously, so only one
// `#[global_allocator]` ever exists in a given build. If a future
// refactor breaks this invariant Rust emits "duplicate lang item"
// and the build fails — that diagnostic IS the compile-time guarantee
// (an explicit `compile_error!` macro cannot observe the state of
// another cfg-gated item without producing the same duplicate-lang
// error first).
#[cfg(all(not(target_os = "macos"), not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Spec 035 PR-A2 phase 1: DHAT global allocator. Replaces jemalloc
// (Linux) or the system allocator (macOS) when the `dhat-heap`
// feature is active. DHAT records every allocation, so this binary
// runs noticeably slower and MUST NOT ship to production. The feature
// exists to drive heap-budget regression tests under
// `cargo test -p innerwarden-agent --features dhat-heap ...`.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static DHAT_ALLOC: dhat::Alloc = dhat::Alloc;

// Spec 030: embed jemalloc runtime configuration in the binary so
// operators do not need to set a MALLOC_CONF env var to get
// production-ready memory behaviour.
//
// - `background_thread:true` runs purging off the hot path.
// - `dirty_decay_ms:1000` returns dirty pages to the OS after 1 s of
//   idleness (default is 10 s). A security agent has spiky
//   allocation patterns (JSON parsing, graph rebuilds, tokenizer
//   batches) and the lower decay keeps RSS close to the working set
//   instead of the recent peak.
// - `muzzy_decay_ms:1000` does the same for muzzy pages (the state
//   between "dirty" and "returned to the OS"). Matching the dirty
//   interval gives a single predictable decay window.
//
// Linux-only; the macOS build uses the system allocator so this
// symbol is not needed there.
#[cfg(all(not(target_os = "macos"), not(test)))]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static MALLOC_CONF: &[u8] = b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000\0";

mod abuseipdb;
mod abuseipdb_report_budget;
mod agent_context;
mod ai;
mod allowlist;
mod attacker_intel;
mod baseline;
mod bot_actions;
mod bot_commands;
mod bot_helpers;
mod briefing;
mod capped_log;
mod circuit_breaker;
mod cloud_safelist;
mod cloudflare;
mod config;
mod correlation;
mod correlation_engine;
mod correlation_response;
mod crowdsec;
mod dashboard;
mod data_retention;
mod decision_block_ip;
mod decision_confirmation;
mod decision_cooldown;
mod decision_honeypot;
mod decision_skill_actions;
mod decisions;
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
mod incident_auto_rules;
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
mod loops;
mod mesh;
mod mitre;
mod narrative;
mod narrative_anomaly;
mod narrative_autofp;
mod narrative_daily_summary;
mod narrative_incident_ingest;
mod narrative_observation_verify;
#[allow(
    dead_code,
    unused_imports,
    unused_variables,
    clippy::needless_range_loop
)]
mod neural_lifecycle;
mod notification_gate;
mod notification_pipeline;
mod observation_verify;
mod pcap_capture;
mod playbook;
mod process;
mod process_health;
#[allow(dead_code)]
mod reader;
mod report;
mod response_lifecycle;
mod scoring;
mod shield_inline;
mod skills;
mod slack;
#[allow(dead_code)]
mod soc_checks;
mod state_store;
// Spec 036 (audit I-04) PR-1: TaskGroup primitive. All items are
// `pub(crate)` and unused during this PR; the `dead_code` allowance
// goes away with the first migration (decision_writer / telegram
// batcher / pcap_capture) in the follow-up PR.
#[allow(dead_code)]
mod task_group;
mod telegram;
mod telemetry;
mod telemetry_tick;
mod threat_feeds;
mod threat_report;
mod trust_rules;
#[allow(dead_code)]
mod trust_scoring;
#[allow(dead_code)]
mod two_factor;
mod web_push;
mod webhook;
#[allow(dead_code)]
mod zero_trust;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(test)]
use crate::bot_helpers::{
    parse_telegram_triage_action, sanitize_allowlist_process_name, TelegramTriageAction,
};
use anyhow::Result;
use clap::Parser;
use tracing::{debug, warn};

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

    /// Path to TLS certificate file (PEM). If not set, dashboard auto-generates
    /// a self-signed cert and serves on HTTPS.
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to TLS private key file (PEM). Required if --tls-cert is set.
    #[arg(long)]
    tls_key: Option<String>,

    /// Disable TLS and serve dashboard over plain HTTP (NOT recommended for
    /// production). Default: HTTPS with auto-generated self-signed cert.
    #[arg(long)]
    insecure_no_tls: bool,

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

    /// One-shot: force the autoencoder's nightly training routine to run
    /// immediately (instead of waiting for 03:00 UTC). Reads events from
    /// `innerwarden.db`, trains `anomaly-model.bin` in place, then exits.
    /// Used after a feature-layout bump (or after a stale / saturated model
    /// is detected in production) so the operator doesn't have to wait a
    /// whole day for the baseline to recalibrate.
    #[arg(long)]
    retrain_anomaly: bool,
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
                    innerwarden_core::entities::EntityType::Ip
                        if (self.ip_counts.contains_key(&entity.value)
                            || self.ip_counts.len() < Self::MAX_ENTITY_ENTRIES) =>
                    {
                        *self.ip_counts.entry(entity.value.clone()).or_insert(0) += 1;
                    }
                    innerwarden_core::entities::EntityType::User
                        if (self.user_counts.contains_key(&entity.value)
                            || self.user_counts.len() < Self::MAX_ENTITY_ENTRIES) =>
                    {
                        *self.user_counts.entry(entity.value.clone()).or_insert(0) += 1;
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
    /// Spec 029: capability router. Call sites resolve providers by
    /// role (classifier vs llm) via `provider_for(Capability::X)`.
    /// Back-compat test in `ai::router::back_compat_tests` guarantees
    /// that a router built from a single legacy provider resolves
    /// every capability identically to pre-029 code.
    ai_router: ai::AiRouter,
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
    /// Last time the periodic env census ran. Spec 005 Phase 6.
    last_env_census_at: Option<std::time::Instant>,
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
    /// Path used to (re-)open `sqlite_store`. Persisted on the state so
    /// `try_recover_sqlite_store` can lazily retry the open after a
    /// boot-time `database is locked` race; pre-2026-04-23 a failed
    /// initial open left the store as `None` for the entire process
    /// lifetime, silently dropping every SQLite-mediated write
    /// (graph snapshots, blob writes, cursor updates).
    sqlite_store_path: std::path::PathBuf,
    /// Last attempted reopen instant — guards against tight retry loops
    /// when the underlying error is permanent (e.g. disk full).
    sqlite_reopen_last_attempt: Option<std::time::Instant>,
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
    /// Notification gate burst tracker — counts contained threats for burst summary.
    notification_burst_tracker: notification_gate::BurstTracker,
    /// Spec 005 Phase 7 — implicit operator feedback (ignore-driven demotion).
    feedback_tracker: notification_pipeline::FeedbackTracker,
    /// Last time the feedback tracker ticked 24h-old pendings into ignores.
    last_feedback_tick_at: Option<std::time::Instant>,
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

pub(crate) use process::post_decision::{
    append_honeypot_marker_event, execute_decision, honeypot_runtime,
};

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
    loops::boot::run_agent(cli).await
}

#[cfg(test)]
mod tests;
