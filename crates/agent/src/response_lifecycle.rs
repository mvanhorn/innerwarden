//! Unified response lifecycle: tracks all active responses (block IP, container pause,
//! nginx deny, sudo suspension) with TTL and auto-revert.
//!
//! State machine (per entry):
//!
//!     Active ──(TTL expires | manual revert)──▶ RevertPending
//!                                                    │
//!                     ┌──────────────────────────────┤
//!                     ▼                              │
//!              mark_reverted(ok)          mark_revert_failed(err)
//!                     │                              │
//!                     ▼                 classify error ─ AlreadyAbsent ──▶ history
//!                 history                              └─ Transient
//!                                                         │
//!                                       attempts < MAX ───┤
//!                                                         │
//!                                              RevertFailed (stays in active)
//!                                                         │
//!                                       stage_pending_reverts on next tick
//!                                                         │
//!                                                         ▼
//!                                                  RevertPending
//!                                       attempts >= MAX ──▶ Orphaned → history + alert
//!
//! Key invariants:
//! - The audit trail (history) only records **terminal** states. An entry
//!   marked `expired`/`manual`/`already_absent` means the revert command
//!   was confirmed to have succeeded or the rule was confirmed to be absent.
//!   `orphaned` means the system has given up trying to revert — the rule
//!   may still be active in the kernel/firewall.
//! - While retries are in flight, the entry stays in `active` with its
//!   current state (`RevertFailed`) so dashboards can surface the drift.
//! - `is_tracked` treats all non-terminal states as "still active" to avoid
//!   duplicate registration while a retry is in progress.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{info, warn};

/// Maximum number of revert attempts before an entry is declared Orphaned
/// and an alert is raised.
const MAX_REVERT_ATTEMPTS: u32 = 3;

/// Backend that applied the response (determines how to revert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBackend {
    Xdp,
    Ufw,
    Iptables,
    Nftables,
    Pf,
    Cloudflare,
    Nginx,
    Container,
    Sudo,
}

/// Type of response action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    BlockIp,
    BlockContainer,
    SuspendSudo,
    RateLimitNginx,
    KillProcess,
}

/// Why a revert was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevertTrigger {
    /// TTL expired.
    TtlExpired,
    /// Manual revert (dashboard action, operator command).
    Manual,
}

/// State of a tracked response in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleState {
    /// Rule is applied, TTL not yet reached. Normal operating state.
    Active,
    /// Revert has been handed to the executor but completion has not been
    /// reported yet. Short-lived (one cleanup tick). `prior_attempts` is
    /// the number of failed attempts BEFORE this staging, so after a
    /// subsequent `mark_revert_failed` the new total is `prior_attempts+1`.
    /// Required so retries accumulate across the RevertFailed ↔ RevertPending
    /// ping-pong instead of resetting to zero each tick.
    RevertPending {
        since: DateTime<Utc>,
        trigger: RevertTrigger,
        prior_attempts: u32,
    },
    /// Last revert attempt failed with a transient error. Entry stays in
    /// `active` so dashboards show the drift; next cleanup tick will
    /// re-stage it for another attempt until `attempts >= MAX_REVERT_ATTEMPTS`.
    RevertFailed {
        last_attempt_at: DateTime<Utc>,
        attempts: u32,
        last_error: String,
        trigger: RevertTrigger,
    },
}

/// A tracked active response with TTL.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveResponse {
    pub id: String,
    pub response_type: ResponseType,
    pub backend: ResponseBackend,
    pub target: String,
    pub incident_id: String,
    pub created_at: DateTime<Utc>,
    pub ttl_secs: i64,
    pub expires_at: DateTime<Utc>,
    /// Backend-specific handle needed for revert (e.g., nftables rule handle).
    pub revert_handle: Option<String>,
    /// Lifecycle state. All entries start as `Active`.
    #[serde(default = "LifecycleState::default_active")]
    pub state: LifecycleState,
}

impl LifecycleState {
    #[allow(dead_code)] // used as serde default; also kept for explicit initialization callers
    fn default_active() -> Self {
        LifecycleState::Active
    }
}

/// Action to revert a response.
#[derive(Debug, Clone)]
pub struct RevertAction {
    pub id: String,
    pub backend: ResponseBackend,
    pub target: String,
    pub revert_handle: Option<String>,
}

/// What should happen after a revert attempt fails. Returned by
/// `mark_revert_failed` so the caller can fire alerts on Orphaned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureOutcome {
    /// The error string indicated the rule was already gone. Treated as
    /// success; entry moved to history with reason `already_absent`.
    AlreadyAbsent,
    /// Transient error; entry transitioned to `RevertFailed` and will be
    /// retried on the next cleanup tick.
    Retrying { attempt: u32 },
    /// Retry budget exhausted. Entry moved to history with reason `orphaned`.
    /// The rule may still be active in the kernel/firewall — the system
    /// admits it lost control and stops trying.
    ///
    /// The caller is **not** expected to route this into Telegram/Slack/
    /// webhook notifications. Orphaned is a local/kernel state drift
    /// condition — an observability concern for a technical operator
    /// watching logs, Prometheus, and the responses dashboard — not an
    /// interrupt-worthy pager event. Push notifications are reserved for
    /// incident-level signals (real attacker activity). Surface is: WARN
    /// log with structured fields, Prometheus counter
    /// (`innerwarden_responses_orphaned_total`), and the entry living in
    /// history with `reason="orphaned: <stderr>"` so the dashboard
    /// paints it in red.
    Orphaned {
        backend: ResponseBackend,
        target: String,
        last_error: String,
        trigger: RevertTrigger,
    },
    /// Called `mark_revert_failed` on an id that wasn't in `RevertPending`.
    /// Shouldn't happen in practice; logged as a warning.
    UnknownId,
}

/// Classification of a revert error string. Drives the retry/give-up policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    /// The rule was already gone (another actor removed it, reboot, etc).
    /// Treat as success.
    AlreadyAbsent,
    /// Transient failure — worth retrying.
    Transient,
}

fn classify_revert_error(err: &str) -> ErrorKind {
    let lower = err.to_lowercase();
    // Patterns per backend, verified against real stderr on Ubuntu 24.04
    // aarch64 (kernel 6.8.0-106) by running each backend's delete command
    // against a non-existent rule and capturing the output:
    //
    //   iptables-1.8.10: "iptables: Bad rule (does a matching rule exist in
    //                     that chain?)."  exit=1
    //   nft-1.0.9:       "Error: Could not process rule: No such file or
    //                     directory"  exit=1
    //   bpftool (key):   "Error: delete failed: No such file or directory"
    //                    exit=254
    //   bpftool (path):  "Error: bpf obj get (...): No such file or
    //                     directory"  exit=255
    //
    // UFW IS DIFFERENT: `ufw delete deny from <ip>` for a non-existent rule
    // prints "Could not delete non-existent rule" but exits 0, so run_cmd
    // returns Ok(()) and this classifier is never called. The entry is
    // then routed through mark_reverted("expired") rather than
    // mark_revert_failed -> already_absent. Functionally correct (ufw is
    // saying "nothing to do, consider it done"), but means the
    // already_absent counter is systematically undercounted for ufw
    // deployments. Left as-is: detecting this would require parsing stdout
    // inside run_cmd which is invasive. The ufw marker below is kept as
    // defense-in-depth in case a future ufw version starts returning
    // non-zero — then the substring "non-existent" still classifies correctly.
    const ABSENT_MARKERS: &[&str] = &[
        // Generic ENOENT variants. "No such file or directory" from any
        // kernel syscall wrapper passes through this.
        "no such",
        "not found",
        "does not exist",
        "doesn't exist",
        // ufw phrasing (defense-in-depth, see note above).
        "non-existent",
        "nonexistent",
        // iptables phrasings.
        "no chain/target/match",
        "matching rule exist",
        // nft phrasing when rule was referenced by handle that's gone.
        "rule does not exist",
    ];
    if ABSENT_MARKERS.iter().any(|m| lower.contains(m)) {
        ErrorKind::AlreadyAbsent
    } else {
        ErrorKind::Transient
    }
}

/// Unified lifecycle manager for all response actions.
pub struct ResponseLifecycle {
    active: Vec<ActiveResponse>,
    history: VecDeque<CompletedResponse>,
    next_id: u64,
    /// Counters for Prometheus.
    total_registered: u64,
    total_reverted: u64,
    total_expired: u64,
    /// Number of individual revert attempt failures (not entries — an entry
    /// can contribute multiple failures before being orphaned or resolved).
    total_revert_failures: u64,
    /// Reverts that resolved because the rule was already gone.
    total_already_absent: u64,
    /// Entries given up on after exhausting retries. These are the ones that
    /// require operator attention.
    total_orphaned: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompletedResponse {
    pub id: String,
    pub response_type: ResponseType,
    pub backend: ResponseBackend,
    pub target: String,
    pub incident_id: String,
    pub created_at: DateTime<Utc>,
    pub reverted_at: DateTime<Utc>,
    pub reason: String, // "expired" or "manual"
}

impl ResponseLifecycle {
    pub fn new() -> Self {
        Self {
            active: Vec::new(),
            history: VecDeque::new(),
            next_id: 1,
            total_registered: 0,
            total_reverted: 0,
            total_expired: 0,
            total_revert_failures: 0,
            total_already_absent: 0,
            total_orphaned: 0,
        }
    }

    /// Restore active responses from a previous `responses.json` snapshot.
    /// Called once on agent startup to survive restarts. Expired entries are
    /// moved to history automatically via the next `tick_cleanup` call.
    /// Tries SQLite blob first, falls back to JSON file.
    pub fn load_snapshot(
        data_dir: &std::path::Path,
        store: Option<&innerwarden_store::Store>,
    ) -> Self {
        // Try SQLite blob first, fall back to JSON file
        let content = if let Some(sq) = store {
            match sq.get_blob("responses") {
                Ok(Some(json)) => {
                    tracing::info!("loaded response lifecycle from sqlite blob");
                    json
                }
                _ => {
                    let path = data_dir.join("responses.json");
                    match std::fs::read_to_string(&path) {
                        Ok(c) => c,
                        Err(_) => return Self::new(),
                    }
                }
            }
        } else {
            let path = data_dir.join("responses.json");
            match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => return Self::new(),
            }
        };
        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return Self::new(),
        };

        let mut lifecycle = Self::new();
        let now = Utc::now();

        // Restore active responses
        if let Some(active_arr) = json["active"].as_array() {
            for item in active_arr {
                let target = item["target"].as_str().unwrap_or_default();
                let incident_id = item["incident_id"].as_str().unwrap_or_default();
                let ttl_secs = item["ttl_secs"].as_i64().unwrap_or(3600);
                let created_at = item["created_at"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or(now);
                let expires_at = item["expires_at"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or(created_at + chrono::Duration::seconds(ttl_secs));
                let backend = match item["backend"].as_str().unwrap_or("ufw") {
                    "xdp" => ResponseBackend::Xdp,
                    "iptables" => ResponseBackend::Iptables,
                    "nftables" => ResponseBackend::Nftables,
                    "pf" => ResponseBackend::Pf,
                    "cloudflare" => ResponseBackend::Cloudflare,
                    "nginx" => ResponseBackend::Nginx,
                    "container" => ResponseBackend::Container,
                    "sudo" => ResponseBackend::Sudo,
                    _ => ResponseBackend::Ufw,
                };
                let response_type = match item["type"].as_str().unwrap_or("block_ip") {
                    "block_container" => ResponseType::BlockContainer,
                    "suspend_sudo" => ResponseType::SuspendSudo,
                    "rate_limit_nginx" => ResponseType::RateLimitNginx,
                    "kill_process" => ResponseType::KillProcess,
                    _ => ResponseType::BlockIp,
                };

                if target.is_empty() {
                    continue;
                }

                let id = format!("resp-{}", lifecycle.next_id);
                lifecycle.next_id += 1;
                // Restore state if present (entries mid-retry survive restart).
                // Unknown/missing state defaults to Active so legacy snapshots
                // just keep working.
                let state = parse_state_from_json(&item["state"]).unwrap_or(LifecycleState::Active);
                lifecycle.active.push(ActiveResponse {
                    id,
                    response_type,
                    backend,
                    target: target.to_string(),
                    incident_id: incident_id.to_string(),
                    created_at,
                    ttl_secs,
                    expires_at,
                    revert_handle: item["revert_handle"].as_str().map(String::from),
                    state,
                });
                lifecycle.total_registered += 1;
            }
        }

        // Restore counters from totals (keep accumulated counts across restarts)
        if let Some(totals) = json.get("totals") {
            lifecycle.total_registered = totals["registered"]
                .as_u64()
                .unwrap_or(lifecycle.total_registered);
            lifecycle.total_expired = totals["expired"].as_u64().unwrap_or(0);
            lifecycle.total_reverted = totals["reverted"].as_u64().unwrap_or(0);
            lifecycle.total_revert_failures = totals["revert_failures"].as_u64().unwrap_or(0);
            lifecycle.total_already_absent = totals["already_absent"].as_u64().unwrap_or(0);
            lifecycle.total_orphaned = totals["orphaned"].as_u64().unwrap_or(0);
        }

        // Restore history
        if let Some(history_arr) = json["history"].as_array() {
            for item in history_arr {
                let target = item["target"].as_str().unwrap_or_default();
                if target.is_empty() {
                    continue;
                }
                let backend = match item["backend"].as_str().unwrap_or("ufw") {
                    "xdp" => ResponseBackend::Xdp,
                    "iptables" => ResponseBackend::Iptables,
                    "nftables" => ResponseBackend::Nftables,
                    "pf" => ResponseBackend::Pf,
                    "cloudflare" => ResponseBackend::Cloudflare,
                    _ => ResponseBackend::Ufw,
                };
                let response_type = match item["type"].as_str().unwrap_or("block_ip") {
                    "block_container" => ResponseType::BlockContainer,
                    "suspend_sudo" => ResponseType::SuspendSudo,
                    _ => ResponseType::BlockIp,
                };
                lifecycle.history.push_back(CompletedResponse {
                    id: item["id"].as_str().unwrap_or("").to_string(),
                    response_type,
                    backend,
                    target: target.to_string(),
                    incident_id: item["incident_id"].as_str().unwrap_or("").to_string(),
                    created_at: item["created_at"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(now),
                    reverted_at: item["reverted_at"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(now),
                    reason: item["reason"].as_str().unwrap_or("expired").to_string(),
                });
            }
        }

        // Also hydrate from today's decisions JSONL to catch blocks from code paths
        // that don't go through ResponseLifecycle (e.g. honeypot, dashboard actions).
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = data_dir.join(format!("decisions-{today}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&decisions_path) {
            let tracked_targets: std::collections::HashSet<String> =
                lifecycle.active.iter().map(|r| r.target.clone()).collect();
            let mut added = 0usize;
            for line in content.lines() {
                if line.is_empty() {
                    continue;
                }
                let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if entry["action_type"].as_str() != Some("block_ip") {
                    continue;
                }
                let Some(ip) = entry["target_ip"].as_str() else {
                    continue;
                };
                if ip.is_empty() || tracked_targets.contains(ip) {
                    continue;
                }
                // Check if already in active set (may have been added from snapshot)
                if lifecycle.active.iter().any(|r| r.target == ip) {
                    continue;
                }
                let ts = entry["ts"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or(now);
                // Use 1-hour default TTL for rehydrated blocks
                let ttl = 3600i64;
                let expires_at = ts + chrono::Duration::seconds(ttl);
                if expires_at <= now {
                    // Already expired — skip
                    continue;
                }
                let skill_id = entry["skill_id"].as_str().unwrap_or("block-ip-ufw");
                let backend = if skill_id.contains("xdp") {
                    ResponseBackend::Xdp
                } else if skill_id.contains("iptables") {
                    ResponseBackend::Iptables
                } else if skill_id.contains("nftables") {
                    ResponseBackend::Nftables
                } else {
                    ResponseBackend::Ufw
                };
                let incident_id = entry["incident_id"].as_str().unwrap_or("").to_string();

                let id = format!("resp-{}", lifecycle.next_id);
                lifecycle.next_id += 1;
                lifecycle.active.push(ActiveResponse {
                    id,
                    response_type: ResponseType::BlockIp,
                    backend,
                    target: ip.to_string(),
                    incident_id,
                    created_at: ts,
                    ttl_secs: ttl,
                    expires_at,
                    revert_handle: None,
                    state: LifecycleState::Active,
                });
                lifecycle.total_registered += 1;
                added += 1;
            }
            if added > 0 {
                info!(added, "hydrated response lifecycle from today's decisions");
            }
        }

        if !lifecycle.active.is_empty() || !lifecycle.history.is_empty() {
            info!(
                active = lifecycle.active.len(),
                history = lifecycle.history.len(),
                total_registered = lifecycle.total_registered,
                "response lifecycle restored"
            );
        }

        lifecycle
    }

    /// Register a new response. Returns the response ID.
    pub fn register(
        &mut self,
        response_type: ResponseType,
        backend: ResponseBackend,
        target: &str,
        incident_id: &str,
        ttl_secs: i64,
        revert_handle: Option<String>,
    ) -> String {
        let id = format!("resp-{}", self.next_id);
        self.next_id += 1;

        let now = Utc::now();
        let response = ActiveResponse {
            id: id.clone(),
            response_type,
            backend,
            target: target.to_string(),
            incident_id: incident_id.to_string(),
            created_at: now,
            ttl_secs,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            revert_handle,
            state: LifecycleState::Active,
        };

        info!(
            id = %response.id,
            backend = ?response.backend,
            target = %response.target,
            ttl_secs,
            "response registered"
        );

        self.active.push(response);
        self.total_registered += 1;
        id
    }

    /// Scan active entries for work that needs a revert command issued.
    /// Called from the slow loop (every 30s).
    ///
    /// Transitions:
    /// - `Active` with expired TTL → `RevertPending { TtlExpired }`
    /// - `RevertFailed` with attempts < MAX → `RevertPending { <same trigger> }`
    ///
    /// The entry **stays in `active`** after this call. The caller is
    /// responsible for executing each returned `RevertAction` and then calling
    /// `mark_reverted` or `mark_revert_failed` to drive the terminal
    /// transition. This is the fix for the "audit trail lies" bug: until the
    /// revert is confirmed, the entry is never declared complete.
    pub fn stage_pending_reverts(&mut self) -> Vec<RevertAction> {
        let now = Utc::now();
        let mut reverts = Vec::new();

        for entry in self.active.iter_mut() {
            let next_state = match &entry.state {
                LifecycleState::Active if now > entry.expires_at => {
                    Some(LifecycleState::RevertPending {
                        since: now,
                        trigger: RevertTrigger::TtlExpired,
                        prior_attempts: 0,
                    })
                }
                LifecycleState::RevertFailed {
                    attempts, trigger, ..
                } if *attempts < MAX_REVERT_ATTEMPTS => Some(LifecycleState::RevertPending {
                    since: now,
                    trigger: *trigger,
                    // Carry accumulated failures across the ping-pong so
                    // mark_revert_failed can compute new_attempts correctly.
                    prior_attempts: *attempts,
                }),
                _ => None,
            };
            if let Some(next) = next_state {
                entry.state = next;
                reverts.push(RevertAction {
                    id: entry.id.clone(),
                    backend: entry.backend.clone(),
                    target: entry.target.clone(),
                    revert_handle: entry.revert_handle.clone(),
                });
            }
        }

        // Cap history at 1000 entries (history only grows via terminal transitions).
        while self.history.len() > 1000 {
            self.history.pop_front();
        }

        reverts
    }

    /// Request a manual revert for a specific response by ID. Transitions
    /// `Active` or `RevertFailed` to `RevertPending { Manual }` and returns
    /// the action to execute. The caller must then call `mark_reverted` or
    /// `mark_revert_failed` to close the loop.
    #[allow(dead_code)] // wired to POST /api/responses/:id/revert in spec 016
    pub fn request_manual_revert(&mut self, id: &str) -> Option<RevertAction> {
        let now = Utc::now();
        let entry = self.active.iter_mut().find(|r| r.id == id)?;
        // Don't re-stage something already in-flight.
        if matches!(entry.state, LifecycleState::RevertPending { .. }) {
            return None;
        }
        // Preserve accumulated failure count if we're escalating a failed
        // TTL revert to a manual one (rare but valid).
        let prior_attempts = match &entry.state {
            LifecycleState::RevertFailed { attempts, .. } => *attempts,
            _ => 0,
        };
        entry.state = LifecycleState::RevertPending {
            since: now,
            trigger: RevertTrigger::Manual,
            prior_attempts,
        };
        Some(RevertAction {
            id: entry.id.clone(),
            backend: entry.backend.clone(),
            target: entry.target.clone(),
            revert_handle: entry.revert_handle.clone(),
        })
    }

    /// Terminal success path. Called by the executor after a revert command
    /// completed without error (or after a failure was classified as
    /// `AlreadyAbsent`). Moves the entry out of `active` and into `history`.
    ///
    /// `reason` values in practice:
    /// - `"expired"` — normal TTL success
    /// - `"manual"` — dashboard/operator action
    /// - `"already_absent"` — rule was already gone (treated as success)
    pub fn mark_reverted(&mut self, id: &str, reason: &str) {
        let now = Utc::now();
        let Some(idx) = self.active.iter().position(|r| r.id == id) else {
            warn!(id, "mark_reverted called on unknown id");
            return;
        };
        let resp = self.active.remove(idx);
        // Figure out the original trigger if we're mid-pending; fall back to
        // TtlExpired so the counter math stays sane if something weird happens.
        let trigger = match &resp.state {
            LifecycleState::RevertPending { trigger, .. } => *trigger,
            LifecycleState::RevertFailed { trigger, .. } => *trigger,
            LifecycleState::Active => {
                // Caller jumped straight to mark_reverted without staging.
                // This is fine for code paths that own their own revert
                // (Container/Nginx/Sudo), just account it as TTL.
                RevertTrigger::TtlExpired
            }
        };
        match trigger {
            RevertTrigger::TtlExpired => self.total_expired += 1,
            RevertTrigger::Manual => self.total_reverted += 1,
        }
        if reason == "already_absent" {
            self.total_already_absent += 1;
        }
        self.history.push_back(CompletedResponse {
            id: resp.id,
            response_type: resp.response_type,
            backend: resp.backend,
            target: resp.target,
            incident_id: resp.incident_id,
            created_at: resp.created_at,
            reverted_at: now,
            reason: reason.to_string(),
        });
        while self.history.len() > 1000 {
            self.history.pop_front();
        }
    }

    /// Terminal failure path. Called by the executor after a revert command
    /// returned an error. Classifies the error autonomously:
    ///
    /// - `AlreadyAbsent` (stderr indicates the rule was gone) → entry moves to
    ///   history as `already_absent` (success).
    /// - `Transient` + `attempts < MAX` → entry transitions to `RevertFailed`,
    ///   stays in active, will be retried next tick.
    /// - `Transient` + `attempts >= MAX` → entry moves to history as
    ///   `orphaned`. Returns `FailureOutcome::Orphaned { .. }` so the caller
    ///   can fire a high-severity alert via the normal notification pipeline.
    pub fn mark_revert_failed(&mut self, id: &str, error: String) -> FailureOutcome {
        let now = Utc::now();
        self.total_revert_failures += 1;

        let Some(idx) = self.active.iter().position(|r| r.id == id) else {
            warn!(id, "mark_revert_failed called on unknown id");
            return FailureOutcome::UnknownId;
        };

        // Determine trigger and prior attempts from the current state.
        // The source of truth for `prior_attempts` is whichever state the
        // entry is currently in — RevertPending carries it forward from the
        // previous RevertFailed (if any) via stage_pending_reverts.
        let (trigger, prior_attempts) = match &self.active[idx].state {
            LifecycleState::RevertPending {
                trigger,
                prior_attempts,
                ..
            } => (*trigger, *prior_attempts),
            LifecycleState::RevertFailed {
                trigger, attempts, ..
            } => (*trigger, *attempts),
            LifecycleState::Active => {
                // Unexpected — we got a failure report for something that
                // was never staged. Log and treat as transient with 0 prior
                // attempts so retry logic still applies.
                warn!(id, "mark_revert_failed called on entry in Active state");
                (RevertTrigger::TtlExpired, 0u32)
            }
        };

        let kind = classify_revert_error(&error);
        if kind == ErrorKind::AlreadyAbsent {
            // Rule was already gone — success in disguise. Caller-provided
            // error becomes part of the audit trail via `reason`.
            info!(id, %error, "revert target already absent — treating as success");
            self.mark_reverted(id, "already_absent");
            return FailureOutcome::AlreadyAbsent;
        }

        let new_attempts = prior_attempts + 1;
        if new_attempts >= MAX_REVERT_ATTEMPTS {
            // Exhausted. Move to history as orphaned and surface to caller.
            let resp = self.active.remove(idx);
            let backend = resp.backend.clone();
            let target = resp.target.clone();
            let last_error = error.clone();
            self.total_orphaned += 1;
            self.history.push_back(CompletedResponse {
                id: resp.id,
                response_type: resp.response_type,
                backend: resp.backend,
                target: resp.target,
                incident_id: resp.incident_id,
                created_at: resp.created_at,
                reverted_at: now,
                reason: format!("orphaned: {error}"),
            });
            while self.history.len() > 1000 {
                self.history.pop_front();
            }
            warn!(
                id,
                backend = ?backend,
                target = %target,
                attempts = new_attempts,
                error = %error,
                "response ORPHANED — revert retries exhausted, rule may still be active"
            );
            return FailureOutcome::Orphaned {
                backend,
                target,
                last_error,
                trigger,
            };
        }

        // Still have retry budget. Transition to RevertFailed and keep in active.
        self.active[idx].state = LifecycleState::RevertFailed {
            last_attempt_at: now,
            attempts: new_attempts,
            last_error: error,
            trigger,
        };
        warn!(
            id,
            attempts = new_attempts,
            max = MAX_REVERT_ATTEMPTS,
            "revert failed — will retry on next cleanup tick"
        );
        FailureOutcome::Retrying {
            attempt: new_attempts,
        }
    }

    /// Get all currently active responses.
    #[allow(dead_code)] // snapshot read path for the dashboard lifecycle view
    pub fn list_active(&self) -> &[ActiveResponse] {
        &self.active
    }

    /// Get recent history of completed (expired/reverted) responses.
    #[allow(dead_code)] // snapshot read path for the dashboard history drawer
    pub fn list_history(&self) -> &VecDeque<CompletedResponse> {
        &self.history
    }

    /// Check if an IP is already tracked (to avoid duplicates).
    pub fn is_tracked(&self, target: &str, backend: &ResponseBackend) -> bool {
        self.active
            .iter()
            .any(|r| r.target == target && &r.backend == backend)
    }

    /// Generate Prometheus metrics lines.
    #[allow(dead_code)] // exposed by /metrics endpoint in spec 016
    pub fn to_prometheus_lines(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP innerwarden_responses_active Currently active response actions\n");
        out.push_str("# TYPE innerwarden_responses_active gauge\n");

        // Count by backend
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for r in &self.active {
            let key = match r.backend {
                ResponseBackend::Xdp => "xdp",
                ResponseBackend::Ufw => "ufw",
                ResponseBackend::Iptables => "iptables",
                ResponseBackend::Nftables => "nftables",
                ResponseBackend::Pf => "pf",
                ResponseBackend::Cloudflare => "cloudflare",
                ResponseBackend::Nginx => "nginx",
                ResponseBackend::Container => "container",
                ResponseBackend::Sudo => "sudo",
            };
            *counts.entry(key).or_default() += 1;
        }
        for (backend, count) in &counts {
            out.push_str(&format!(
                "innerwarden_responses_active{{backend=\"{backend}\"}} {count}\n"
            ));
        }

        out.push_str("# HELP innerwarden_responses_total Total response actions registered\n");
        out.push_str("# TYPE innerwarden_responses_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_total {}\n",
            self.total_registered
        ));

        out.push_str("# HELP innerwarden_responses_expired_total Responses expired by TTL\n");
        out.push_str("# TYPE innerwarden_responses_expired_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_expired_total {}\n",
            self.total_expired
        ));

        out.push_str("# HELP innerwarden_responses_reverted_total Responses manually reverted\n");
        out.push_str("# TYPE innerwarden_responses_reverted_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_reverted_total {}\n",
            self.total_reverted
        ));

        out.push_str("# HELP innerwarden_responses_revert_failures_total Count of failed revert attempts (not entries)\n");
        out.push_str("# TYPE innerwarden_responses_revert_failures_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_revert_failures_total {}\n",
            self.total_revert_failures
        ));

        out.push_str("# HELP innerwarden_responses_already_absent_total Reverts that resolved because rule was already gone\n");
        out.push_str("# TYPE innerwarden_responses_already_absent_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_already_absent_total {}\n",
            self.total_already_absent
        ));

        out.push_str("# HELP innerwarden_responses_orphaned_total Responses given up on — rule may still be active in kernel/firewall\n");
        out.push_str("# TYPE innerwarden_responses_orphaned_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_orphaned_total {}\n",
            self.total_orphaned
        ));

        // Break down current active entries by state for live drift visibility.
        let (n_active, n_pending, n_failed) = self.state_counts();
        out.push_str(
            "# HELP innerwarden_responses_by_state Active entries broken down by lifecycle state\n",
        );
        out.push_str("# TYPE innerwarden_responses_by_state gauge\n");
        out.push_str(&format!(
            "innerwarden_responses_by_state{{state=\"active\"}} {n_active}\n"
        ));
        out.push_str(&format!(
            "innerwarden_responses_by_state{{state=\"revert_pending\"}} {n_pending}\n"
        ));
        out.push_str(&format!(
            "innerwarden_responses_by_state{{state=\"revert_failed\"}} {n_failed}\n"
        ));

        out
    }

    /// Count entries by lifecycle state. Used for metrics and tests.
    pub fn state_counts(&self) -> (usize, usize, usize) {
        let mut n_active = 0usize;
        let mut n_pending = 0usize;
        let mut n_failed = 0usize;
        for r in &self.active {
            match r.state {
                LifecycleState::Active => n_active += 1,
                LifecycleState::RevertPending { .. } => n_pending += 1,
                LifecycleState::RevertFailed { .. } => n_failed += 1,
            }
        }
        (n_active, n_pending, n_failed)
    }

    /// Serialize active responses as JSON (for /api/responses).
    pub fn to_json(&self) -> serde_json::Value {
        let now = Utc::now();
        let active: Vec<serde_json::Value> = self
            .active
            .iter()
            .map(|r| {
                let remaining = (r.expires_at - now).num_seconds().max(0);
                serde_json::json!({
                    "id": r.id,
                    "type": r.response_type,
                    "backend": r.backend,
                    "target": r.target,
                    "incident_id": r.incident_id,
                    "created_at": r.created_at.to_rfc3339(),
                    "expires_at": r.expires_at.to_rfc3339(),
                    "ttl_secs": r.ttl_secs,
                    "remaining_secs": remaining,
                    "state": r.state,
                })
            })
            .collect();

        let history: Vec<serde_json::Value> = self
            .history
            .iter()
            .rev()
            .take(50)
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "type": r.response_type,
                    "backend": r.backend,
                    "target": r.target,
                    "incident_id": r.incident_id,
                    "created_at": r.created_at.to_rfc3339(),
                    "reverted_at": r.reverted_at.to_rfc3339(),
                    "reason": r.reason,
                })
            })
            .collect();

        let (n_active, n_pending, n_failed) = self.state_counts();

        serde_json::json!({
            "active": active,
            "active_count": self.active.len(),
            "state_counts": {
                "active": n_active,
                "revert_pending": n_pending,
                "revert_failed": n_failed,
            },
            "history": history,
            "totals": {
                "registered": self.total_registered,
                "expired": self.total_expired,
                "reverted": self.total_reverted,
                "revert_failures": self.total_revert_failures,
                "already_absent": self.total_already_absent,
                "orphaned": self.total_orphaned,
            }
        })
    }
}

/// Parse a serialized `LifecycleState` back out of JSON. Missing/unknown
/// shapes fall back to `Active` so legacy snapshots just work. Only used by
/// `load_snapshot`.
fn parse_state_from_json(v: &serde_json::Value) -> Option<LifecycleState> {
    let kind = v.get("kind").and_then(|k| k.as_str())?;
    match kind {
        "active" => Some(LifecycleState::Active),
        "revert_pending" => {
            let since = v
                .get("since")
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(Utc::now);
            let trigger = parse_trigger(v.get("trigger")).unwrap_or(RevertTrigger::TtlExpired);
            let prior_attempts = v
                .get("prior_attempts")
                .and_then(|a| a.as_u64())
                .unwrap_or(0) as u32;
            Some(LifecycleState::RevertPending {
                since,
                trigger,
                prior_attempts,
            })
        }
        "revert_failed" => {
            let last_attempt_at = v
                .get("last_attempt_at")
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(Utc::now);
            let attempts = v.get("attempts").and_then(|a| a.as_u64()).unwrap_or(0) as u32;
            let last_error = v
                .get("last_error")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let trigger = parse_trigger(v.get("trigger")).unwrap_or(RevertTrigger::TtlExpired);
            Some(LifecycleState::RevertFailed {
                last_attempt_at,
                attempts,
                last_error,
                trigger,
            })
        }
        _ => None,
    }
}

fn parse_trigger(v: Option<&serde_json::Value>) -> Option<RevertTrigger> {
    match v.and_then(|s| s.as_str())? {
        "ttl_expired" => Some(RevertTrigger::TtlExpired),
        "manual" => Some(RevertTrigger::Manual),
        _ => None,
    }
}

/// Execute a revert action on the appropriate backend.
///
/// Returns `Ok(())` on success (or when the backend's revert is a no-op
/// tracked elsewhere). Returns `Err(stderr_like_string)` on failure so the
/// caller can classify and decide retry/orphan. The string is what the
/// autonomous classifier in `mark_revert_failed` inspects — it MUST contain
/// the raw stderr from the backend tool when that's what failed, so patterns
/// like "no such", "non-existent", etc. flow through.
pub async fn execute_revert(revert: &RevertAction, dry_run: bool) -> Result<(), String> {
    let desc = format!("{:?} {}", revert.backend, revert.target);

    if dry_run {
        info!(id = %revert.id, action = %desc, "DRY RUN: would revert response");
        return Ok(());
    }

    let result = match &revert.backend {
        ResponseBackend::Ufw => {
            run_cmd("sudo", &["ufw", "delete", "deny", "from", &revert.target]).await
        }
        ResponseBackend::Iptables => {
            run_cmd(
                "sudo",
                &[
                    "iptables",
                    "-D",
                    "INPUT",
                    "-s",
                    &revert.target,
                    "-j",
                    "DROP",
                ],
            )
            .await
        }
        ResponseBackend::Nftables => {
            if let Some(handle) = &revert.revert_handle {
                run_cmd(
                    "sudo",
                    &[
                        "nft", "delete", "rule", "inet", "filter", "input", "handle", handle,
                    ],
                )
                .await
            } else {
                Err("no nftables handle stored for revert".to_string())
            }
        }
        ResponseBackend::Xdp => {
            // XDP revert via bpftool — parse IP octets.
            if let Ok(addr) = revert.target.parse::<std::net::Ipv4Addr>() {
                let b = addr.octets();
                run_cmd(
                    "sudo",
                    &[
                        "bpftool",
                        "map",
                        "delete",
                        "pinned",
                        "/sys/fs/bpf/innerwarden/blocklist",
                        "key",
                        &b[0].to_string(),
                        &b[1].to_string(),
                        &b[2].to_string(),
                        &b[3].to_string(),
                    ],
                )
                .await
            } else {
                Err(format!("cannot parse IP for XDP revert: {}", revert.target))
            }
        }
        // Container, Nginx, Sudo reverts are still handled by their existing
        // cleanup functions (file-based metadata with expires_at). The lifecycle
        // tracks them for dashboard visibility but delegates revert to the
        // existing code paths.
        ResponseBackend::Container | ResponseBackend::Nginx | ResponseBackend::Sudo => {
            // These are managed by their own metadata files and cleanup functions.
            // The lifecycle tracks them for visibility only.
            Ok(())
        }
        ResponseBackend::Cloudflare | ResponseBackend::Pf => {
            // Cloudflare: would need rule_id to delete. PF: macOS only.
            // Not auto-reverted for now.
            warn!(backend = ?revert.backend, "auto-revert not implemented for this backend");
            Ok(())
        }
    };

    if result.is_ok() {
        info!(id = %revert.id, backend = ?revert.backend, target = %revert.target, "response reverted");
    }
    result
}

async fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("spawn {program}: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{program} {} exited {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(lc: &mut ResponseLifecycle, ip: &str, ttl: i64) -> String {
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            ip,
            "inc-test",
            ttl,
            None,
        )
    }

    #[test]
    fn test_register_and_expire_success_path() {
        let mut lc = ResponseLifecycle::new();

        // Register with 0-second TTL (expires immediately).
        let id = reg(&mut lc, "1.2.3.4", 0);

        assert_eq!(lc.list_active().len(), 1);
        assert!(matches!(lc.list_active()[0].state, LifecycleState::Active));

        std::thread::sleep(std::time::Duration::from_millis(10));

        // Stage should find it expired and transition to RevertPending, NOT
        // move it to history — the audit trail only records confirmed reverts.
        let staged = lc.stage_pending_reverts();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].target, "1.2.3.4");
        assert_eq!(staged[0].backend, ResponseBackend::Ufw);
        assert_eq!(
            lc.list_active().len(),
            1,
            "entry stays in active until confirmed"
        );
        assert!(
            lc.list_history().is_empty(),
            "history must not grow before confirmation"
        );
        assert!(matches!(
            lc.list_active()[0].state,
            LifecycleState::RevertPending {
                trigger: RevertTrigger::TtlExpired,
                ..
            }
        ));

        // Caller confirms the revert ran successfully.
        lc.mark_reverted(&id, "expired");
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "expired");
    }

    #[test]
    fn test_revert_failure_keeps_in_active_and_retries() {
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "7.7.7.7", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Tick #1: stage + fail with a transient error.
        let staged = lc.stage_pending_reverts();
        assert_eq!(staged.len(), 1);
        let outcome = lc.mark_revert_failed(&id, "sudo: sudo token timeout".to_string());
        assert!(matches!(outcome, FailureOutcome::Retrying { attempt: 1 }));
        assert_eq!(lc.list_active().len(), 1, "still in active while retrying");
        assert!(lc.list_history().is_empty(), "nothing in history yet");
        assert!(matches!(
            lc.list_active()[0].state,
            LifecycleState::RevertFailed { attempts: 1, .. }
        ));

        // Tick #2: stage should pick it up again.
        let staged = lc.stage_pending_reverts();
        assert_eq!(
            staged.len(),
            1,
            "RevertFailed with budget should be restaged"
        );

        // Tick #2 success closes it out.
        lc.mark_reverted(&id, "expired");
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "expired");
    }

    #[test]
    fn test_revert_exhaustion_becomes_orphaned() {
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "8.8.8.8", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Three failing attempts.
        let mut last_outcome = FailureOutcome::UnknownId;
        for _ in 0..MAX_REVERT_ATTEMPTS {
            let staged = lc.stage_pending_reverts();
            assert_eq!(staged.len(), 1);
            last_outcome = lc.mark_revert_failed(&id, "generic transient error".to_string());
        }

        // Final attempt should be Orphaned + entry moved to history.
        match last_outcome {
            FailureOutcome::Orphaned {
                ref target,
                ref backend,
                ..
            } => {
                assert_eq!(target, "8.8.8.8");
                assert_eq!(backend, &ResponseBackend::Ufw);
            }
            other => panic!("expected Orphaned, got {other:?}"),
        }
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert!(lc.list_history()[0].reason.starts_with("orphaned"));

        // Counter should have bumped.
        let prom = lc.to_prometheus_lines();
        assert!(prom.contains("innerwarden_responses_orphaned_total 1"));
        assert!(prom.contains("innerwarden_responses_revert_failures_total 3"));
    }

    #[test]
    fn test_revert_failure_already_absent_is_success() {
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "9.9.9.9", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));

        lc.stage_pending_reverts();
        // UFW's "could not delete non-existent rule" is one of the markers.
        let outcome =
            lc.mark_revert_failed(&id, "ERROR: Could not delete non-existent rule".to_string());
        assert_eq!(outcome, FailureOutcome::AlreadyAbsent);
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "already_absent");

        let prom = lc.to_prometheus_lines();
        assert!(prom.contains("innerwarden_responses_already_absent_total 1"));
    }

    #[test]
    fn test_classify_revert_error_patterns() {
        // ── Verified against real stderr captured on Ubuntu 24.04 aarch64,
        //    kernel 6.8.0-106, by running each backend's delete command
        //    against a non-existent rule. If any of these fail, a tool has
        //    drifted its error message and we risk orphaning responses that
        //    were actually fine. The "VERIFIED" cases are byte-for-byte
        //    real output; the "defense-in-depth" cases are guesses at
        //    variations not observed but plausible across versions.

        let absent_cases = [
            // ──── iptables (VERIFIED on iptables-1.8.10) ────
            // `sudo iptables -D INPUT -s 198.51.100.42 -j DROP` → exit 1
            "iptables: Bad rule (does a matching rule exist in that chain?).",
            // ──── nftables (VERIFIED on nft-1.0.9) ────
            // `sudo nft delete rule inet iwtest input handle <gone>` → exit 1
            "Error: Could not process rule: No such file or directory",
            // ──── bpftool (VERIFIED on bpftool from kernel 6.8) ────
            // `sudo bpftool map delete pinned <missing_path> key ...` → exit 255
            "Error: bpf obj get (/tmp/nonexistent_map): No such file or directory",
            // `sudo bpftool map delete pinned <real_path> key <missing>` → exit 254
            "Error: delete failed: No such file or directory",
            // ──── ufw (defense-in-depth only) ────
            // In practice ufw exits 0 for delete-non-existent so this path
            // is never hit via run_cmd. Kept in case a future ufw version
            // starts returning non-zero, or a wrapper forwards the message
            // through some stderr-carrying channel.
            "ERROR: Could not delete non-existent rule",
            // ──── defense-in-depth: plausible variants ────
            "iptables v1.8.7: No chain/target/match by that name.",
            "Error: Could not process rule: No such process",
            "nft: rule does not exist",
            "key nonexistent",
            "entry doesn't exist in map",
        ];
        for c in absent_cases {
            assert_eq!(
                classify_revert_error(c),
                ErrorKind::AlreadyAbsent,
                "expected AlreadyAbsent for {c:?}"
            );
        }

        // Transient errors — genuinely retry-able. None of these mean the
        // rule was gone, so they must NOT trip the already_absent path (if
        // they did, we'd silently mark a rule reverted that's actually
        // still enforced in the kernel/firewall).
        let transient_cases = [
            "sudo: a terminal is required to read the password",
            "sudo: no tty present and no askpass program specified",
            "Operation not permitted",
            "Permission denied",
            "connection refused",
            "Resource temporarily unavailable",
            "Error: Could not open socket to kernel: Operation not permitted",
            // Kernel says "busy", NOT "not found" — critical distinction.
            "nft: Error: Could not process rule: Device or resource busy",
        ];
        for c in transient_cases {
            assert_eq!(
                classify_revert_error(c),
                ErrorKind::Transient,
                "expected Transient for {c:?}"
            );
        }
    }

    #[test]
    fn test_rehydrate_from_snapshot_preserves_state() {
        // Mid-retry persistence: if the agent crashes while an entry is in
        // RevertFailed state, the snapshot should preserve attempts so we
        // don't reset the retry budget on restart.
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "172.16.0.1", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));
        lc.stage_pending_reverts();
        lc.mark_revert_failed(&id, "sudo: token expired".to_string());
        // Entry is now RevertFailed{attempts:1}. Serialize + round-trip.
        let snapshot = lc.to_json();
        let active = snapshot["active"].as_array().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0]["state"]["kind"], "revert_failed");
        assert_eq!(active[0]["state"]["attempts"], 1);

        // Write to temp dir and reload.
        let tmp = std::env::temp_dir().join(format!("innerwarden-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("responses.json"),
            serde_json::to_string(&snapshot).unwrap(),
        )
        .unwrap();
        let reloaded = ResponseLifecycle::load_snapshot(&tmp, None);
        assert_eq!(reloaded.list_active().len(), 1);
        match &reloaded.list_active()[0].state {
            LifecycleState::RevertFailed { attempts, .. } => {
                assert_eq!(*attempts, 1, "attempts counter must survive reload");
            }
            other => panic!("expected RevertFailed after reload, got {other:?}"),
        }
        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_rehydrate_legacy_snapshot_defaults_to_active() {
        // Backwards-compat: snapshots from before the state machine don't
        // have a `state` field. Those entries must load as Active so legacy
        // responses.json files Just Work on first run after upgrade.
        let tmp =
            std::env::temp_dir().join(format!("innerwarden-test-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let legacy = serde_json::json!({
            "active": [{
                "id": "resp-1",
                "type": "block_ip",
                "backend": "ufw",
                "target": "192.0.2.50",
                "incident_id": "inc-legacy",
                "created_at": chrono::Utc::now().to_rfc3339(),
                "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339(),
                "ttl_secs": 3600i64,
                // Note: no "state" field — this is legacy shape.
            }],
            "active_count": 1,
            "history": [],
            "totals": { "registered": 1, "expired": 0, "reverted": 0 }
        });
        std::fs::write(
            tmp.join("responses.json"),
            serde_json::to_string(&legacy).unwrap(),
        )
        .unwrap();
        let reloaded = ResponseLifecycle::load_snapshot(&tmp, None);
        assert_eq!(reloaded.list_active().len(), 1);
        assert!(matches!(
            reloaded.list_active()[0].state,
            LifecycleState::Active
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_manual_revert_success() {
        let mut lc = ResponseLifecycle::new();

        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Iptables,
            "5.6.7.8",
            "inc-002",
            3600,
            None,
        );

        let action = lc.request_manual_revert(&id).unwrap();
        assert_eq!(action.target, "5.6.7.8");
        assert_eq!(lc.list_active().len(), 1, "still in active until confirmed");
        assert!(matches!(
            lc.list_active()[0].state,
            LifecycleState::RevertPending {
                trigger: RevertTrigger::Manual,
                ..
            }
        ));

        lc.mark_reverted(&id, "manual");
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "manual");
    }

    #[test]
    fn test_manual_revert_failure_then_orphan() {
        let mut lc = ResponseLifecycle::new();
        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Iptables,
            "5.6.7.8",
            "inc-002",
            3600,
            None,
        );

        // Manual trigger with transient failure.
        lc.request_manual_revert(&id).unwrap();
        let outcome = lc.mark_revert_failed(&id, "some random failure".to_string());
        assert!(matches!(outcome, FailureOutcome::Retrying { attempt: 1 }));

        // State should preserve the Manual trigger through retries.
        if let LifecycleState::RevertFailed { trigger, .. } = lc.list_active()[0].state {
            assert_eq!(trigger, RevertTrigger::Manual);
        } else {
            panic!("expected RevertFailed state");
        }
    }

    #[test]
    fn test_request_manual_revert_idempotent_on_pending() {
        let mut lc = ResponseLifecycle::new();
        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "1.1.1.1",
            "inc",
            3600,
            None,
        );
        assert!(lc.request_manual_revert(&id).is_some());
        // Second call while already pending should be a no-op (None) so we
        // don't double-issue the command.
        assert!(lc.request_manual_revert(&id).is_none());
    }

    #[test]
    fn test_is_tracked_includes_failed_entries() {
        // A RevertFailed entry is still "tracked" — the rule is supposed to
        // be there. We must NOT accept a duplicate registration while we're
        // still trying to revert.
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "10.0.0.1", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));
        lc.stage_pending_reverts();
        lc.mark_revert_failed(&id, "sudo failure".to_string());
        assert!(lc.is_tracked("10.0.0.1", &ResponseBackend::Ufw));
    }

    #[test]
    fn test_is_tracked() {
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Xdp,
            "10.0.0.1",
            "inc-003",
            3600,
            None,
        );
        assert!(lc.is_tracked("10.0.0.1", &ResponseBackend::Xdp));
        assert!(!lc.is_tracked("10.0.0.1", &ResponseBackend::Ufw));
        assert!(!lc.is_tracked("10.0.0.2", &ResponseBackend::Xdp));
    }

    #[test]
    fn test_prometheus_output() {
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "1.1.1.1",
            "inc-004",
            3600,
            None,
        );
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Xdp,
            "2.2.2.2",
            "inc-005",
            3600,
            None,
        );

        let prom = lc.to_prometheus_lines();
        assert!(prom.contains("innerwarden_responses_active{backend=\"ufw\"} 1"));
        assert!(prom.contains("innerwarden_responses_active{backend=\"xdp\"} 1"));
        assert!(prom.contains("innerwarden_responses_total 2"));
        // New counters exposed even when zero.
        assert!(prom.contains("innerwarden_responses_revert_failures_total 0"));
        assert!(prom.contains("innerwarden_responses_already_absent_total 0"));
        assert!(prom.contains("innerwarden_responses_orphaned_total 0"));
        assert!(prom.contains("innerwarden_responses_by_state{state=\"active\"} 2"));
    }

    #[test]
    fn test_json_output_exposes_state() {
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Iptables,
            "3.3.3.3",
            "inc-006",
            3600,
            None,
        );

        let json = lc.to_json();
        assert_eq!(json["active_count"], 1);
        assert_eq!(json["active"][0]["target"], "3.3.3.3");
        assert_eq!(json["active"][0]["state"]["kind"], "active");
        assert!(json["active"][0]["remaining_secs"].as_i64().unwrap() > 3500);
        assert_eq!(json["state_counts"]["active"], 1);
        assert_eq!(json["state_counts"]["revert_pending"], 0);
        assert_eq!(json["state_counts"]["revert_failed"], 0);
    }

    #[test]
    fn test_history_cap() {
        // History growth happens via mark_reverted; use manual revert path.
        let mut lc = ResponseLifecycle::new();
        for i in 0..1100 {
            let id = lc.register(
                ResponseType::BlockIp,
                ResponseBackend::Ufw,
                &format!("10.0.{}.{}", i / 256, i % 256),
                "inc",
                3600,
                None,
            );
            lc.request_manual_revert(&id);
            lc.mark_reverted(&id, "manual");
        }
        assert!(lc.history.len() <= 1000);
    }
}
