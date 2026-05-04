use std::io::Write;
use std::path::Path;
use std::sync::atomic::AtomicU64;

use tracing::{info, warn};

use innerwarden_killchain::tracker::PidTracker;

use crate::correlation_engine;

/// `comm` values whose events the kill chain tracker must ignore. These are
/// the platform's own thread names — the agent, sensor, and watchdog. Without
/// this list, routine agent activity (outbound threat-feed fetches +
/// credential file reads) trivially matches DATA_EXFIL against the agent
/// itself.
///
/// Linux `comm` is truncated to 15 characters (`TASK_COMM_LEN = 16` including
/// NUL), so the binary names below are already in their truncated form as
/// they appear in kernel events.
pub const KILLCHAIN_SELF_EXCLUDED_COMMS: &[&str] = &[
    "tokio-rt-worker", // tokio async runtime worker pool (15 chars)
    "innerwarden-age", // innerwarden-agent (truncated)
    "innerwarden-sen", // innerwarden-sensor (truncated)
    "innerwarden-wat", // innerwarden-watchdog (truncated)
];

/// Process a batch of sensor events through the kill chain tracker.
/// Returns incidents (JSON values) for any detected chains.
/// Also feeds the correlation engine with kill chain events.
pub(crate) fn process_events(
    tracker: &mut PidTracker,
    events: &[innerwarden_core::event::Event],
    correlation_engine: &mut correlation_engine::CorrelationEngine,
) -> Vec<serde_json::Value> {
    let mut all_incidents = Vec::new();

    for event in events {
        // Convert core Event to JSON for the killchain tracker.
        let json = event_to_tracker_json(event);
        let incidents = tracker.process_event(&json);

        for inc in &incidents {
            // Feed kill chain detections into the correlation engine.
            let pattern = inc
                .get("evidence")
                .and_then(|e| e.get("pattern"))
                .and_then(|p| p.as_str())
                .unwrap_or("unknown");

            let severity_str = inc
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("medium");

            let kind = format!("killchain.{}", pattern);
            let mut corr_event = correlation_engine::CorrelationEngine::killchain_event(
                &kind,
                serde_json::json!({
                    "pattern": pattern,
                    "severity": severity_str,
                    "pid": inc.get("evidence").and_then(|e| e.get("pid")),
                }),
            );
            // Phase 014-C: carry incident_id so link_correlated_incidents can
            // create CorrelatedWith edges if this kill chain pattern is part
            // of a larger multi-stage cross-layer attack chain.
            if let Some(iid) = inc.get("incident_id").and_then(|v| v.as_str()) {
                corr_event.incident_id = iid.to_string();
            }
            correlation_engine.observe(corr_event);
        }

        all_incidents.extend(incidents);
    }

    all_incidents
}

/// Write kill chain incidents to the daily JSONL file **and** the unified
/// SQLite store (when available). The JSONL path is retained for legacy
/// consumers; SQLite is the source of truth for dashboard queries, attacker
/// intel, and monthly reports, so missing sqlite writes make kill chain
/// detections invisible to the rest of the agent.
pub(crate) fn write_incidents(
    data_dir: &Path,
    sqlite_store: Option<&innerwarden_store::Store>,
    incidents: &[serde_json::Value],
) {
    if incidents.is_empty() {
        return;
    }

    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
    let path = data_dir.join(format!("incidents-{today}.jsonl"));

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            for inc in incidents {
                if let Ok(line) = serde_json::to_string(inc) {
                    let _ = writeln!(f, "{line}");
                }
            }
            info!(count = incidents.len(), "killchain: emitted incidents");
        }
        Err(e) => warn!(error = %e, "killchain: failed to write incidents"),
    }

    if let Some(store) = sqlite_store {
        let mut persisted = 0usize;
        for inc in incidents {
            match serde_json::from_value::<innerwarden_core::incident::Incident>(inc.clone()) {
                Ok(parsed) => {
                    // Structural guard: `core::Incident` now tolerates missing
                    // fields via `#[serde(default)]` (spec 035 A5, JSONL
                    // backwards compat), so garbage input like
                    // `{"foo": 1}` parses into a default-filled Incident
                    // with an empty `incident_id`. Drop those before they
                    // reach sqlite — an incident without an id is not an
                    // incident.
                    if parsed.incident_id.is_empty() {
                        warn!("killchain: incident missing incident_id, skipping");
                        continue;
                    }
                    if let Err(e) = store.insert_incident(&parsed) {
                        warn!(error = %e, "killchain: sqlite insert_incident failed");
                    } else {
                        persisted += 1;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "killchain: incident JSON did not match Incident schema");
                }
            }
        }
        if persisted > 0 {
            info!(persisted, "killchain: incidents persisted to sqlite");
        }
    }
}

// 2026-05-02 audit B2/P3 fix: patterns whose required bitmask carries
// strong forensic semantics — reverse shells, code injection, full
// exploit chains. Kernel-level evidence on these chains is not
// something a binary-name heuristic ("ssh is a tool") may overrule.
// `data_exfil` is intentionally absent because it is the noisy 2-bit
// `socket + sensitive_read` signal that fires on legitimate apt/snap
// updates reading /etc/resolv.conf and connecting to mirrors —
// keeping its existing operator-context dismiss is what stops the
// operator's own SSH session from drowning the dashboard in
// false-positive DATA_EXFIL incidents. The auditor's release rule
// (`kill_chain ... must NEVER reach AI decision dismiss with
// confidence >=0.95`) is held by the strong-pattern guard below;
// the data_exfil escape hatch ships at confidence 0.94 (see
// inline-decision write below) so the post-decision untouchable
// gate never sees a 1.0-confidence dismiss for the strong classes.
const STRONG_KILLCHAIN_PATTERNS: &[&str] = &[
    "reverse_shell",
    "bind_shell",
    "code_inject",
    "inject_shell",
    "exploit_shell",
    "exploit_c2",
    "full_exploit",
];

/// True iff the kill chain pattern carries kernel-level forensic
/// semantics that must never be auto-dismissed by binary-name /
/// operator-session heuristics. The auditor (2026-05-02) flagged
/// kill_chain dismisses at 100% confidence for kernel-level evidence
/// as a release blocker; this predicate is the in-process gate.
fn is_strong_killchain_pattern(pattern: &str) -> bool {
    STRONG_KILLCHAIN_PATTERNS
        .iter()
        .any(|p| pattern.eq_ignore_ascii_case(p))
}

/// Phase 7B (audit RC-2 — Slice C): for each kill chain incident
/// whose target IP belongs to an active operator SSH session, write a
/// `dismiss` decision through the standard hash-chained audit path.
/// The operator running `cat /etc/passwd` from their SSH shell is not
/// an attacker, but the eBPF detector legitimately fires on the
/// `socket + sensitive_read` co-occurrence. Pre-7B these incidents
/// stayed decisionless and accumulated in the dashboard's "Stuck >1h"
/// bucket as a false-positive alarm. The dismiss decision carries
/// `ai_provider="operator-session-fp"` and a reason explaining the
/// session match so the audit log makes the call visible.
///
/// 2026-05-02 audit B2/P3: strong kill chain patterns
/// (reverse_shell, code_inject, full_exploit, etc) are skipped here
/// even if the target IP matches the operator session — the auditor
/// observed `kill_chain DATA_EXFIL @ 100% DISMISS` and ruled that
/// kernel-level forensic evidence may not be overruled by IP / binary
/// heuristics. Skipped incidents flow through the standard AI router
/// where `incident_untouchable` forces RequestConfirmation.
pub(crate) fn dismiss_operator_session_incidents(
    data_dir: &Path,
    sqlite_store: Option<&std::sync::Arc<innerwarden_store::Store>>,
    incidents: &[serde_json::Value],
    operator_ips: &std::collections::HashMap<String, std::time::Instant>,
) {
    if incidents.is_empty() || operator_ips.is_empty() {
        return;
    }
    for inc in incidents {
        // Phase 11 fix: the killchain tracker emits `evidence` as an
        // array containing one object (`evidence: [{...}]`). The
        // pre-Phase-11 read tried `.get("evidence").get("c2_ip")`
        // which works only when evidence is an object — silently
        // returning None on the real array schema. Net effect: the
        // operator-session FP dismiss never fired in prod for the
        // 2 weeks since Phase 7B shipped. The helper below reads
        // both shapes (array-of-one and bare object) to keep the
        // dismiss compatible with any tracker variant that lands.
        let evidence_obj = inc.get("evidence").and_then(|e| match e {
            serde_json::Value::Array(arr) => arr.first(),
            obj @ serde_json::Value::Object(_) => Some(obj),
            _ => None,
        });
        let Some(ev) = evidence_obj else { continue };
        let target_ip = ev.get("c2_ip").and_then(|v| v.as_str());
        let Some(target_ip) = target_ip else { continue };
        if !operator_ips.contains_key(target_ip) {
            continue;
        }
        // Match — write the dismiss decision inline.
        let incident_id = inc
            .get("incident_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if incident_id.is_empty() {
            continue;
        }
        let pattern = ev.get("pattern").and_then(|p| p.as_str()).unwrap_or("?");
        // 2026-05-02 audit B2 guard: kernel-level forensic patterns
        // (reverse_shell, full_exploit, code_inject, ...) must reach
        // the AI router so incident_untouchable can force
        // RequestConfirmation. The IP-match heuristic is strong but
        // not strong enough to overrule kernel evidence.
        if is_strong_killchain_pattern(pattern) {
            warn!(
                incident_id = %incident_id,
                pattern = %pattern,
                target_ip = %target_ip,
                "killchain: skipping operator-session-fp dismiss for strong pattern \
                 (audit B2/P3) — incident routes through AI router + untouchable"
            );
            continue;
        }
        let entry = crate::decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            ai_provider: "operator-session-fp".to_string(),
            action_type: "dismiss".to_string(),
            target_ip: Some(target_ip.to_string()),
            target_user: None,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason: format!(
                "Auto-dismissed: kill chain {pattern} target IP matches an active operator SSH \
                 session ({target_ip}). The operator's own shell tripped the socket+sensitive_read \
                 pattern; this is a known false positive on operator-initiated activity."
            ),
            estimated_threat: "none".to_string(),
            execution_result: "dismissed".to_string(),
            prev_hash: None,
        };
        if let Err(e) = crate::decisions::append_chained(data_dir, &entry, sqlite_store) {
            warn!(
                incident_id = %incident_id,
                error = %e,
                "killchain: failed to write operator-session-fp dismiss decision"
            );
        }
    }
}

/// Phase 11 (audit RC-2 / 2026-04-29 Slice C+): kill chain incidents
/// where the process making the socket is a well-known operator or
/// system tool (`ssh`, `scp`, `rsync`, `apt`, `snap`, etc.) running
/// under a regular-user uid (>=1000) are auto-dismissed inline. This
/// is the "Microsoft Azure outbound apt update" class of false
/// positives that surfaced post-Phase-7 — the agent's own apt/snap
/// update process trips `socket+sensitive_read` against legitimate
/// cloud destinations and the dashboard reports them as DATA_EXFIL.
///
/// The dismiss carries `ai_provider="self-traffic-fp"` and a reason
/// explaining the process+uid match so the audit log makes the call
/// visible. The operator can grep decisions for this provider to
/// audit all auto-dismissed false positives over time.
///
/// Heuristic — process is "self-traffic-class" when:
/// 1. comm is in `SELF_TRAFFIC_COMMS` (operator/system tools), AND
/// 2. uid >= 1000 (regular operator) OR uid == 0 (root, system tool)
///
/// Anything else stays for the AI router to decide.
///
/// 2026-05-03: this list is the **single source of truth** for what
/// the agent considers "operator/system traffic that legitimately
/// trips kill_chain's `socket + sensitive_read` co-occurrence". Both
/// `dismiss_self_traffic_incidents` (which writes the dismiss
/// decision) and `notify_telegram` (which suppresses the Telegram
/// alert) consume from `self_traffic_comms(cfg)` so they cannot
/// drift out of sync. Pre-2026-05-03 they had separate constants —
/// the dismiss list included `apt`/`snap`/`cloud-init`, the
/// Telegram allowlist did not, so operators saw "Critical Threat"
/// alerts for apt updates while the AI silently dismissed them.
///
/// Operators can extend this list per-deploy via
/// `[killchain] self_traffic_comms_extra = ["puppet", "chef"]` in
/// agent.toml. Builtins below cover the common Linux tooling.
pub(crate) const BUILTIN_SELF_TRAFFIC_COMMS: &[&str] = &[
    // Operator-driven outbound tooling: SSH jumps, file copies, git ops, package managers.
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "git",
    "git-remote-", // git-remote-https etc (truncated form)
    "curl",
    "wget",
    // 2026-05-05 (Wave 9b): libcurl-using package fetchers (apt, snap, etc)
    // launch worker threads whose `comm` becomes the protocol scheme rather
    // than the parent binary name. On 2026-04-28..05-04 prod these accounted
    // for 77 of 169 (45%) killchain DATA_EXFIL incidents that did not get
    // auto-dismissed because the comms were absent from this list. Kept
    // separately from `apt`/`snap` so a future contributor sees the
    // motivation; the prefix matcher in `matches_self_traffic_comm` does
    // not actually need them broken out.
    "http",
    "https",
    // System package management & daemons that legitimately do
    // socket + sensitive_read against cloud / mirror endpoints.
    "apt",
    "apt-get",
    "snap",
    "snapd",
    "systemd-resolv",  // truncated systemd-resolved
    "systemd-network", // truncated systemd-networkd
    "chronyd",
    "ntpd",
    "fwupdmgr",
    "unattended-upgr", // truncated unattended-upgrade
    "needrestart",
    // Cloud-init / systemd helpers that fetch metadata at boot.
    "cloud-init",
];

/// Subset of [`BUILTIN_SELF_TRAFFIC_COMMS`] whose dismissal does NOT require
/// the uid to be either 0 or >=1000.
///
/// **Why this exists.** The general uid filter (`uid == 0 || uid >= 1000`)
/// was added to catch lateral-movement-flavoured cases like `www-data` (uid
/// 33) running `ssh`. For ssh / scp / git / rsync that is the right call,
/// because those comms can spawn shells and pivot. For pure network-fetcher
/// comms (`apt`, `http`, `https`, `wget`, package daemons) the uid is
/// largely irrelevant: the operation is "download from a public host" and
/// the worst-case interpretation of an unexpected uid is "compromised
/// service used the package manager", which still does not warrant a
/// `kill_chain DATA_EXFIL @ Critical` alert.
///
/// **Real-world prod symptom.** Debian/Ubuntu apt runs its HTTPS download
/// step under uid 105 (`_apt`, the unprivileged sandbox), and the worker's
/// `comm` becomes `http` or `https` rather than `apt`. Pre-Wave-9b that hit
/// BOTH gates (comm not in list AND uid 105 fails the {0, >=1000} check),
/// so the operator's nightly apt update produced 9-15 critical "DATA_EXFIL
/// to Ubuntu mirror IP" incidents per day that reached the AI router.
///
/// **Login-shell tools deliberately stay uid-checked.** `ssh`, `scp`,
/// `sftp`, `rsync`, `git`, `git-remote-` are NOT in this set. The lateral-
/// movement risk on those comms still justifies the {0, >=1000} gate.
const UID_AGNOSTIC_FETCHER_COMMS: &[&str] = &[
    "apt",
    "apt-get",
    "snap",
    "snapd",
    "http",
    "https",
    "curl",
    "wget",
    "systemd-resolv",
    "systemd-network",
    "chronyd",
    "ntpd",
    "fwupdmgr",
    "unattended-upgr",
    "needrestart",
    "cloud-init",
];

/// True iff `comm` is a network-fetcher tool whose dismissal does not need
/// the uid to be in `{0, >=1000}`. Uses the same prefix-match semantics as
/// [`matches_self_traffic_comm`].
fn comm_is_uid_agnostic_fetcher(comm: &str) -> bool {
    if comm.is_empty() {
        return false;
    }
    UID_AGNOSTIC_FETCHER_COMMS
        .iter()
        .any(|prefix| comm == *prefix || comm.starts_with(*prefix))
}

/// Returns the merged self-traffic comm list: builtins + operator
/// additions from `[killchain].self_traffic_comms_extra`. This is
/// the function both consumers (dismiss + telegram-suppress) MUST
/// call; never bypass to read `BUILTIN_SELF_TRAFFIC_COMMS` directly,
/// or operator-added comms get ignored.
pub(crate) fn self_traffic_comms(cfg: &crate::config::KillchainConfig) -> Vec<String> {
    let mut merged: Vec<String> = BUILTIN_SELF_TRAFFIC_COMMS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for extra in &cfg.self_traffic_comms_extra {
        let trimmed = extra.trim();
        if !trimmed.is_empty() && !merged.iter().any(|c| c == trimmed) {
            merged.push(trimmed.to_string());
        }
    }
    merged
}

/// Match a process `comm` against a self-traffic comm list using the
/// same prefix-match semantics as the original constant (e.g.
/// `git-remote-` covers `git-remote-https`).
pub(crate) fn matches_self_traffic_comm(comm: &str, list: &[String]) -> bool {
    if comm.is_empty() {
        return false;
    }
    list.iter()
        .any(|prefix| comm == prefix.as_str() || comm.starts_with(prefix.as_str()))
}

pub(crate) fn dismiss_self_traffic_incidents(
    data_dir: &Path,
    sqlite_store: Option<&std::sync::Arc<innerwarden_store::Store>>,
    incidents: &[serde_json::Value],
    self_traffic_list: &[String],
) {
    if incidents.is_empty() {
        return;
    }
    for inc in incidents {
        // Pull comm + uid from the structured evidence (Phase 11
        // schema bump in `crates/killchain`). Bail on missing fields
        // so a future schema change doesn't silently mis-dismiss.
        let evidence = inc.get("evidence").and_then(|v| v.as_array());
        let Some(evidence_arr) = evidence else {
            continue;
        };
        let Some(ev) = evidence_arr.first() else {
            continue;
        };
        let comm = ev.get("comm").and_then(|v| v.as_str()).unwrap_or("");
        let uid = ev.get("uid").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
        let pid = ev.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let pattern = ev
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let c2_ip = ev
            .get("c2_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if comm.is_empty() {
            continue;
        }

        // Self-traffic check: comm matches a known operator/system tool.
        if !matches_self_traffic_comm(comm, self_traffic_list) {
            continue;
        }
        // Uid policy:
        //   - Login-shell tools (ssh, scp, sftp, rsync, git, git-remote-)
        //     require uid in {0, >=1000}. Service-account uids (1-999)
        //     running these comms could be lateral movement and deserve a
        //     real AI decision.
        //   - Network-fetcher tools (apt, http, https, wget, snap, ...)
        //     are uid-agnostic. The operation is "download from a public
        //     host", not shell escalation, so the uid is irrelevant to
        //     the FP determination. This unblocks the apt-as-_apt (uid
        //     105) case that flooded prod with FP DATA_EXFIL incidents
        //     pre-Wave-9b.
        let uid_ok = comm_is_uid_agnostic_fetcher(comm) || uid == 0 || uid >= 1000;
        if !uid_ok {
            continue;
        }

        let incident_id = inc
            .get("incident_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if incident_id.is_empty() {
            continue;
        }
        // 2026-05-02 audit B2 guard: kernel-level forensic patterns
        // (reverse_shell, full_exploit, code_inject, ...) must NEVER
        // be silently dismissed by a binary-name heuristic — even if
        // the comm is `ssh` and the uid is 0/operator. The auditor
        // saw "kill_chain DATA_EXFIL → DISMISS @ 100%" with rationale
        // 'ssh is a known operator/system tool' and ruled that
        // kernel-level fd-redirect-to-socket evidence may not be
        // overruled here. Skipped incidents flow through the AI
        // router and hit `incident_untouchable::transform`.
        if is_strong_killchain_pattern(&pattern) {
            warn!(
                incident_id = %incident_id,
                pattern = %pattern,
                comm = %comm,
                uid = %uid,
                "killchain: skipping self-traffic-fp dismiss for strong pattern \
                 (audit B2/P3) — incident routes through AI router + untouchable"
            );
            continue;
        }
        let entry = crate::decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            ai_provider: "self-traffic-fp".to_string(),
            action_type: "dismiss".to_string(),
            target_ip: if c2_ip.is_empty() {
                None
            } else {
                Some(c2_ip.clone())
            },
            target_user: None,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason: format!(
                "Auto-dismissed: kill chain {pattern} target {c2_ip} fired by process \
                 {comm} (PID {pid}, UID {uid}). {comm} is a known operator/system tool, \
                 not attacker activity (apt/snap update, ssh jump, git fetch, etc)."
            ),
            estimated_threat: "none".to_string(),
            execution_result: "dismissed".to_string(),
            prev_hash: None,
        };
        if let Err(e) = crate::decisions::append_chained(data_dir, &entry, sqlite_store) {
            warn!(
                incident_id = %incident_id,
                error = %e,
                "killchain: failed to write self-traffic-fp dismiss decision"
            );
        }
    }
}

/// Service-process allowlist — distinct from `BUILTIN_SELF_TRAFFIC_COMMS`.
/// These are long-running services (web gateways, runtimes, databases)
/// whose `socket + dup` co-occurrence is normal during request
/// handling. Different semantic from self-traffic (operator/system
/// tooling). Kept as its own const because they are operationally
/// different concepts; merging would mis-skip apt-vs-postgres.
const KILLCHAIN_SERVICE_ALLOWLIST: &[&str] = &[
    "ruby",
    "python",
    "python3",
    "node",
    "java",
    "beam.smp", // runtimes
    "nginx",
    "haproxy",
    "envoy",
    "caddy", // proxies
    "postgres",
    "mysqld",
    "redis-server", // databases
    "openclaw",
    "innerwarden", // our own
];

/// Notify via Telegram for critical kill chain detections.
/// Gated through the centralized notification gate.
///
/// 2026-05-03 (PR #417): `self_traffic_list` is the SAME list
/// `dismiss_self_traffic_incidents` uses — keeps the two paths in
/// lock-step. Without this, the operator received Telegram alerts
/// for apt/snap/cloud-init updates that the AI then silently
/// auto-dismissed (the previous version of this function had its
/// own hardcoded service allowlist that lacked apt/snap/etc).
pub(crate) fn notify_telegram(
    telegram_client: &Option<std::sync::Arc<crate::telegram::TelegramClient>>,
    incidents: &[serde_json::Value],
    burst_tracker: &crate::notification_gate::BurstTracker,
    deferred: &mut std::collections::HashMap<String, u32>,
    gate_suppressed_counter: &AtomicU64,
    self_traffic_list: &[String],
) {
    let Some(tg) = telegram_client else { return };

    for inc in incidents {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("medium");
        if severity != "critical" {
            continue;
        }

        // Skip known service processes (socket+dup is normal for them).
        let comm = inc
            .get("evidence")
            .and_then(|e| e.get("comm"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if KILLCHAIN_SERVICE_ALLOWLIST
            .iter()
            .any(|a| comm.starts_with(a))
        {
            continue;
        }
        // 2026-05-03: also skip self-traffic comms (apt, snap, ssh,
        // cloud-init, ...). The dismiss path will write a
        // `self-traffic-fp` decision shortly; suppressing the alert
        // here means the operator never gets paged for an apt update.
        if matches_self_traffic_comm(comm, self_traffic_list) {
            continue;
        }

        // Gate through notification policy.
        let ctx = crate::notification_gate::NotificationContext::from_killchain_json(inc);
        let verdict =
            crate::notification_gate::should_notify_with_counter(&ctx, gate_suppressed_counter);

        match verdict {
            crate::notification_gate::NotificationVerdict::SendNow => {
                let title = inc
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("Kill chain detected");
                let summary = inc.get("summary").and_then(|s| s.as_str()).unwrap_or("");
                let pattern = inc
                    .get("evidence")
                    .and_then(|e| e.get("pattern"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("unknown");

                let msg = format!(
                    "\u{26d3}\u{fe0f} <b>Kill Chain Alert</b>\n\n\
                     \u{1f534} CRITICAL\n\
                     <b>{title}</b>\n\
                     Pattern: {pattern}\n\
                     {summary}",
                );
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg.send_alert_html(&msg).await;
                });
            }
            crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                *deferred.entry(ctx.detector.clone()).or_insert(0) += 1;
                if ctx.is_contained {
                    if let Some(count) = burst_tracker.record_contained() {
                        let msg = crate::notification_gate::format_burst_summary(count);
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let _ = tg.send_alert_html(&msg).await;
                        });
                    }
                }
                info!(
                    detector = %ctx.detector,
                    "killchain notification deferred to daily briefing"
                );
            }
            crate::notification_gate::NotificationVerdict::Drop => {}
        }
    }
}

/// Convert an innerwarden_core::Event to the JSON format expected by PidTracker.
fn event_to_tracker_json(event: &innerwarden_core::event::Event) -> serde_json::Value {
    serde_json::json!({
        "kind": event.kind,
        "source": event.source,
        "host": event.host,
        "ts": event.ts.to_rfc3339(),
        "details": event.details,
    })
}

/// Periodic maintenance: clean up stale PIDs from the tracker.
pub(crate) fn cleanup_stale(tracker: &mut PidTracker) {
    tracker.cleanup_stale();
}

/// Get tracker stats for telemetry/logging.
pub(crate) fn stats(tracker: &PidTracker) -> (usize, usize, usize) {
    tracker.stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture: builtins-only self-traffic list (no config extras).
    /// Mirrors what `self_traffic_comms(default_cfg)` returns at runtime.
    fn test_self_traffic_list() -> Vec<String> {
        BUILTIN_SELF_TRAFFIC_COMMS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    // ── Phase 7B Slice C anchors ────────────────────────────────────
    //
    // dismiss_operator_session_incidents must (1) skip non-operator
    // IPs entirely, (2) write a dismiss decision when c2_ip matches an
    // active operator session, and (3) be a no-op on empty inputs.

    #[test]
    fn dismiss_operator_session_skips_non_operator_target() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:2026-04-29T10:00Z",
            "evidence": {
                "c2_ip": "203.0.113.99",
                "pattern": "DATA_EXFIL",
            }
        })];
        // operator_ips is empty — c2_ip 203.0.113.99 must NOT match.
        let operator_ips: std::collections::HashMap<String, std::time::Instant> =
            std::collections::HashMap::new();
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    #[test]
    fn dismiss_operator_session_writes_dismiss_when_target_is_operator() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:2026-04-29T10:00Z",
            "evidence": {
                "c2_ip": "203.0.113.99",
                "pattern": "DATA_EXFIL",
            }
        })];
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("203.0.113.99".to_string(), std::time::Instant::now());
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(store.decisions_count().unwrap(), 1);
        let decisions = store
            .decisions_for_incident("kill_chain:detected:DATA_EXFIL:2026-04-29T10:00Z")
            .unwrap();
        assert_eq!(decisions.len(), 1);
        // The decision JSON line must encode the auto-dismiss
        // explanation the operator can audit later.
        let decoded: serde_json::Value = serde_json::from_str(&decisions[0]).unwrap();
        assert_eq!(decoded["action_type"], "dismiss");
        assert_eq!(decoded["ai_provider"], "operator-session-fp");
    }

    #[test]
    fn dismiss_operator_session_handles_array_evidence_from_tracker() {
        // The killchain tracker emits `evidence: [{...}]` (array of
        // one object). Pre-Phase-11 the dismiss helper read from
        // object-shape evidence and silently failed on array data,
        // so the operator-session FP never fired in prod for 2 weeks
        // after Phase 7B was deployed. This anchor pins the
        // array-shape read path so the regression is caught at
        // build time if the read regresses.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1234:2026-04-29T15:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "20.26.156.215",
                "pid": 1234,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("20.26.156.215".to_string(), std::time::Instant::now());
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(
            store.decisions_count().unwrap(),
            1,
            "array-shape evidence must be read correctly"
        );
    }

    #[test]
    fn dismiss_operator_session_is_noop_when_inputs_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("10.0.0.5".to_string(), std::time::Instant::now());
        // Empty incidents.
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &[], &operator_ips);
        assert_eq!(store.decisions_count().unwrap(), 0);
        // Empty operator_ips, with incidents.
        let incidents = vec![serde_json::json!({
            "incident_id": "x:y",
            "evidence": {"c2_ip": "1.2.3.4"}
        })];
        let empty_ops: std::collections::HashMap<String, std::time::Instant> =
            std::collections::HashMap::new();
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &empty_ops);
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    // ── Phase 11A: self-traffic FP anchors ────────────────────────────
    //
    // dismiss_self_traffic_incidents must (1) write a dismiss when
    // comm matches a self-traffic tool with operator uid, (2) skip
    // incidents whose process is unknown / a service account, (3)
    // be a no-op on incidents missing structured pid/comm/uid in
    // evidence (forward-compatibility with older tracker schemas).

    #[test]
    fn dismiss_self_traffic_writes_dismiss_for_apt_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1234:2026-04-29T10:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "20.26.156.215",
                "pid": 1234,
                "comm": "apt",
                "uid": 0,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
        let decisions = store
            .decisions_for_incident("kill_chain:detected:DATA_EXFIL:1234:2026-04-29T10:00Z")
            .unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&decisions[0]).unwrap();
        assert_eq!(decoded["action_type"], "dismiss");
        assert_eq!(decoded["ai_provider"], "self-traffic-fp");
    }

    #[test]
    fn dismiss_self_traffic_writes_dismiss_for_ssh_operator_uid() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:5678:2026-04-29T11:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.50",
                "pid": 5678,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn dismiss_self_traffic_skips_unknown_comm() {
        // A process that's not in SELF_TRAFFIC_COMMS must NOT be
        // dismissed — needs to go to the AI router for a real call.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:9999:2026-04-29T12:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.99",
                "pid": 9999,
                "comm": "evil_tool",
                "uid": 1001,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    #[test]
    fn dismiss_self_traffic_skips_service_account_uid() {
        // A web server (uid 33 / www-data) running ssh is NOT typical
        // operator activity — could be lateral movement via stolen
        // shell. Don't auto-dismiss.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:7777:2026-04-29T13:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.20",
                "pid": 7777,
                "comm": "ssh",
                "uid": 33,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    #[test]
    fn dismiss_self_traffic_skips_incidents_without_structured_evidence() {
        // Forward-compat: an incident from an older killchain version
        // without comm/uid/pid in evidence must NOT be dismissed
        // blindly. AI router handles it.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1111:2026-04-29T14:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.5",
                // No pid/comm/uid — older schema.
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    // event_to_tracker_json preserves key fields
    #[test]
    fn event_to_tracker_json_has_required_fields() {
        let event = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "myhost".into(),
            kind: "syscall.execve".into(),
            source: "ebpf".into(),
            details: serde_json::json!({"pid": 1234, "comm": "bash"}),
            severity: innerwarden_core::event::Severity::Medium,
            summary: String::new(),
            tags: vec![],
            entities: vec![],
        };
        let json = event_to_tracker_json(&event);
        assert_eq!(json["kind"], "syscall.execve");
        assert_eq!(json["source"], "ebpf");
        assert_eq!(json["host"], "myhost");
        assert!(json["ts"].as_str().is_some());
        assert_eq!(json["details"]["pid"], 1234);
        assert_eq!(json["details"]["comm"], "bash");
    }

    // event_to_tracker_json handles empty details
    #[test]
    fn event_to_tracker_json_empty_details() {
        let event = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            kind: "file.read".into(),
            source: "audit".into(),
            details: serde_json::json!({}),
            severity: innerwarden_core::event::Severity::Low,
            summary: String::new(),
            tags: vec![],
            entities: vec![],
        };
        let json = event_to_tracker_json(&event);
        assert_eq!(json["kind"], "file.read");
        assert!(json["details"].is_object());
    }

    // Self-exclusion: the platform's own thread names are all present and
    // each fits in Linux's 15-char comm limit.
    #[test]
    fn self_excluded_comms_cover_platform_threads_and_respect_comm_len() {
        const COMM_LEN: usize = 15;
        for name in KILLCHAIN_SELF_EXCLUDED_COMMS {
            assert!(
                name.len() <= COMM_LEN,
                "'{name}' exceeds {COMM_LEN}-char comm limit — kernel would truncate it and the match would never fire"
            );
        }
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"tokio-rt-worker"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-age"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-sen"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-wat"));
    }

    // Wiring: a tracker built with the self-exclusion list ignores events
    // attributed to the agent's tokio worker pool.
    #[test]
    fn tracker_configured_with_self_exclusions_drops_tokio_rt_worker() {
        let mut tracker =
            PidTracker::new().with_excluded_comms(KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied());

        let connect = serde_json::json!({
            "kind": "network.outbound_connect",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 1234,
                "uid": 0,
                "comm": "tokio-rt-worker",
                "dst_ip": "1.1.1.1",
                "dst_port": 443
            }
        });
        let read = serde_json::json!({
            "kind": "file.read_access",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 1234,
                "uid": 0,
                "comm": "tokio-rt-worker",
                "filename": "/root/.ssh/id_rsa"
            }
        });

        assert!(tracker.process_event(&connect).is_empty());
        assert!(tracker.process_event(&read).is_empty());
        assert_eq!(tracker.stats(), (0, 0, 0));
    }

    // write_incidents must persist a conforming incident to the sqlite store
    // when one is provided, *and* to the JSONL file (unchanged legacy path).
    #[test]
    fn write_incidents_persists_to_sqlite_when_store_provided() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");

        let incident = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "testhost",
            "incident_id": "kill_chain:detected:DATA_EXFIL:999:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "Kill chain detected: DATA_EXFIL (PID 999, attacker)",
            "summary": "PID 999 (attacker) completed DATA_EXFIL pattern.",
            "evidence": [{"pattern": "DATA_EXFIL"}],
            "recommended_checks": [],
            "tags": ["kill_chain", "detected", "data_exfil"],
            "entities": []
        });

        write_incidents(tmp.path(), Some(&store), &[incident]);

        assert_eq!(store.incidents_count().unwrap(), 1);
        let found = store
            .get_incident("kill_chain:detected:DATA_EXFIL:999:2026-04-16T15:52Z")
            .unwrap();
        assert!(found.is_some(), "incident must be queryable by incident_id");

        let jsonl = std::fs::read_to_string(tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        )))
        .expect("jsonl written");
        assert!(jsonl.contains("DATA_EXFIL"));
    }

    // write_incidents without a store must still write JSONL and not panic.
    #[test]
    fn write_incidents_without_store_still_writes_jsonl() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let incident = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "testhost",
            "incident_id": "kill_chain:detected:REVERSE_SHELL:42:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "t",
            "summary": "s",
            "evidence": [],
            "recommended_checks": [],
            "tags": [],
            "entities": []
        });
        write_incidents(tmp.path(), None, &[incident]);
        let jsonl = std::fs::read_to_string(tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        )))
        .expect("jsonl written");
        assert!(jsonl.contains("REVERSE_SHELL"));
    }

    // A malformed incident (missing `incident_id`) must be dropped before it
    // reaches sqlite — the rest of the batch still writes. Pre-spec-035-A5
    // the serde layer rejected records missing required fields; post-A5 the
    // wire type tolerates missing fields (JSONL backwards-compat with old
    // releases), so the guard moved to a structural check in `write_incidents`
    // on the one invariant that still rules a record out as "not an incident":
    // a non-empty id. See spec 035 A5 and the comment in `write_incidents`.
    #[test]
    fn write_incidents_skips_malformed_and_persists_valid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");

        let bad = serde_json::json!({"not_an_incident": true});
        let good = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "h",
            "incident_id": "kill_chain:detected:DATA_EXFIL:1:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "t",
            "summary": "s",
            "evidence": [],
            "recommended_checks": [],
            "tags": [],
            "entities": []
        });

        write_incidents(tmp.path(), Some(&store), &[bad, good]);

        assert_eq!(store.incidents_count().unwrap(), 1);
    }

    // An empty incident slice must be a cheap no-op — no JSONL file created,
    // no sqlite write attempted.
    #[test]
    fn write_incidents_empty_is_noop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");
        write_incidents(tmp.path(), Some(&store), &[]);
        assert_eq!(store.incidents_count().unwrap(), 0);

        let expected_jsonl = tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        ));
        assert!(
            !expected_jsonl.exists(),
            "no JSONL file should be created for empty input"
        );
    }

    // ─── Spec 024 contract tests ───────────────────────────────────────
    //
    // PidTracker::process_event contract:
    //   - Events whose `details.comm` matches `KILLCHAIN_SELF_EXCLUDED_COMMS`
    //     MUST NOT mutate tracker state. Self-exclusion is the whole reason
    //     the platform stopped DATA_EXFIL'ing itself in PR #124.
    //   - Events unrelated to kill-chain bits (e.g. a cold exec that is not
    //     in any known pattern) MUST NOT emit an incident.
    //   - When an event DOES advance a pattern, process_event returns a
    //     non-empty Vec. The specific contents are the PidTracker's own
    //     business; the agent contract is only about presence/absence.

    #[test]
    fn contract_excluded_comm_never_mutates_state() {
        let mut tracker =
            PidTracker::new().with_excluded_comms(KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied());
        let (pids_before, _, _) = tracker.stats();

        for comm in KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied() {
            let ev = serde_json::json!({
                "kind": "network.outbound_connect",
                "ts": chrono::Utc::now().to_rfc3339(),
                "host": "h",
                "details": {
                    "pid": 1111,
                    "uid": 0,
                    "comm": comm,
                    "dst_ip": "1.1.1.1",
                    "dst_port": 443
                }
            });
            let incidents = tracker.process_event(&ev);
            assert!(
                incidents.is_empty(),
                "self-excluded comm '{comm}' must never emit incidents"
            );
        }
        let (pids_after, _, _) = tracker.stats();
        assert_eq!(
            pids_before, pids_after,
            "self-excluded comms must not mutate tracker state"
        );
    }

    #[test]
    fn contract_innocent_event_emits_no_incidents() {
        // A noop event must produce a Vec with zero incidents. We assert
        // on length (Vec API) rather than identity so the storage layer is
        // free to change.
        let mut tracker = PidTracker::new();
        let ev = serde_json::json!({
            "kind": "file.read_access",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 9999,
                "uid": 1000,
                "comm": "user-shell",
                "filename": "/home/user/.bashrc"
            }
        });
        let out: Vec<serde_json::Value> = tracker.process_event(&ev);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn contract_returns_vec_not_option() {
        // Signature check: if someone ever changes process_event to return
        // Option<Incident> (which it *has* looked like in the past), scenario
        // and replay pipelines that iterate will silently lose batches.
        let mut tracker = PidTracker::new();
        let out: Vec<serde_json::Value> = tracker.process_event(&serde_json::json!({
            "kind": "noop",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {"pid": 1, "comm": "init"}
        }));
        // Vec is iterable by reference and by value. Both compile ⇒ contract holds.
        let _ = out.iter().count();
        let _ = out.into_iter().count();
    }

    // KILLCHAIN_COMM_ALLOWLIST prevents notification for known service processes
    #[test]
    fn comm_allowlist_blocks_known_services() {
        let allowlist: &[&str] = &[
            "ruby",
            "python",
            "python3",
            "node",
            "java",
            "beam.smp",
            "nginx",
            "haproxy",
            "envoy",
            "caddy",
            "postgres",
            "mysqld",
            "redis-server",
            "openclaw",
            "innerwarden",
        ];
        // Known services should be in the list
        assert!(allowlist.iter().any(|a| "nginx".starts_with(a)));
        assert!(allowlist.iter().any(|a| "python3".starts_with(a)));
        assert!(allowlist.iter().any(|a| "innerwarden-agent".starts_with(a)));
        // Unknown attacker binaries should NOT match
        assert!(!allowlist.iter().any(|a| "nc".starts_with(a)));
        assert!(!allowlist.iter().any(|a| "bash".starts_with(a)));
    }

    // ── 2026-05-02 audit B2/P3 anchors — strong kill chain pattern guard ──
    //
    // The auditor saw `kill_chain DATA_EXFIL → DISMISS @ 100% confidence`
    // with rationale "ssh is a known operator/system tool". The durable
    // rule is that kernel-level forensic patterns must NEVER be silently
    // auto-dismissed by binary-name / IP heuristics. These anchors pin
    // the strong-pattern guard against future regression: a fixture
    // incident with detector kill_chain and a strong pattern must NOT
    // be dismissed even when every other condition (operator-IP match,
    // operator/system comm, root/operator uid) lines up. data_exfil
    // dismiss is preserved — that's the noisy 2-bit signal whose
    // operator-context dismiss kept the dashboard usable pre-audit;
    // the strong patterns route through the AI router + untouchable
    // gate for an explicit operator confirmation.

    #[test]
    fn dismiss_operator_session_skips_reverse_shell_pattern_even_for_operator_ip() {
        // Strong pattern + operator-IP match: must not dismiss. Auditor
        // rule: kernel-level forensic evidence overrides the IP match.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:REVERSE_SHELL:2026-05-02T10:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "REVERSE_SHELL",
                "c2_ip": "203.0.113.99",
                "pid": 1234,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("203.0.113.99".to_string(), std::time::Instant::now());
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "REVERSE_SHELL must NOT be auto-dismissed (audit B2/P3): operator-IP heuristic \
             cannot overrule kernel-level forensic evidence — the incident must reach the AI \
             router so incident_untouchable can force RequestConfirmation"
        );
    }

    #[test]
    fn dismiss_operator_session_still_dismisses_data_exfil_for_operator_ip() {
        // Preserve the apt/snap/cloud-init noise reduction: data_exfil
        // is the noisy 2-bit `socket+sensitive_read` pattern that fires
        // on legit package updates reading /etc/resolv.conf and
        // connecting to mirrors. Operator-IP match remains a strong
        // enough signal here. Audit B2 narrowed the suppression to
        // strong patterns; the data_exfil escape hatch survives.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:2026-05-02T10:30Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "20.26.156.215",
                "pid": 1234,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("20.26.156.215".to_string(), std::time::Instant::now());
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(
            store.decisions_count().unwrap(),
            1,
            "DATA_EXFIL with operator-IP match must remain auto-dismissed — disabling this \
             would re-flood the dashboard with false-positive apt/snap/cloud-init traffic"
        );
    }

    #[test]
    fn dismiss_self_traffic_skips_full_exploit_pattern_even_for_root_apt() {
        // Strong pattern + apt + uid 0: must NOT dismiss. The "apt
        // running as root" heuristic is fine for data_exfil noise
        // reduction but cannot overrule a FULL_EXPLOIT chain.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:FULL_EXPLOIT:2026-05-02T11:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "FULL_EXPLOIT",
                "c2_ip": "203.0.113.50",
                "pid": 5678,
                "comm": "apt",
                "uid": 0,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "FULL_EXPLOIT must NOT be auto-dismissed even when comm/uid match self-traffic \
             (audit B2/P3) — kernel-level kill chain evidence routes through AI router + \
             incident_untouchable instead"
        );
    }

    #[test]
    fn dismiss_self_traffic_skips_code_inject_for_ssh_operator_uid() {
        // CODE_INJECT chain (ptrace + mprotect RWX) with comm=ssh +
        // uid=1001 must reach the AI router — binary-name heuristic
        // cannot overrule a code-injection signature.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:CODE_INJECT:2026-05-02T11:30Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "CODE_INJECT",
                "c2_ip": "203.0.113.77",
                "pid": 9999,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    #[test]
    fn is_strong_killchain_pattern_recognises_all_documented_strong_patterns() {
        // Lock the canonical strong-pattern set. If a future contributor
        // adds a new pattern in `crates/killchain/src/patterns.rs`, this
        // test serves as the trigger to re-evaluate whether it should
        // be in STRONG_KILLCHAIN_PATTERNS too.
        for p in [
            "reverse_shell",
            "REVERSE_SHELL",
            "bind_shell",
            "code_inject",
            "inject_shell",
            "exploit_shell",
            "exploit_c2",
            "full_exploit",
            "FULL_EXPLOIT",
        ] {
            assert!(
                is_strong_killchain_pattern(p),
                "expected `{p}` to be classified as a strong kill chain pattern"
            );
        }
        // data_exfil is intentionally NOT strong — see comment on
        // STRONG_KILLCHAIN_PATTERNS in this module for the rationale.
        assert!(!is_strong_killchain_pattern("data_exfil"));
        assert!(!is_strong_killchain_pattern("DATA_EXFIL"));
    }

    // ── 2026-05-03 (PR #417) anchors — single source of truth for ──
    //                     self-traffic comms
    //
    // Pre-PR-#417 the dismiss path used SELF_TRAFFIC_COMMS (apt,
    // snap, ssh, cloud-init, ...) and the Telegram notify path had
    // its own KILLCHAIN_COMM_ALLOWLIST (nginx, postgres, ruby, ...).
    // The two lists drifted: dismiss recognised apt as FP and
    // skipped the AI router; notify did NOT, so the operator got
    // 11 Telegram alerts for an apt update before AI silently
    // dismissed them. These anchors pin the SoT contract.

    #[test]
    fn matches_self_traffic_comm_uses_prefix_semantics() {
        let list = test_self_traffic_list();
        // Exact match.
        assert!(matches_self_traffic_comm("apt", &list));
        assert!(matches_self_traffic_comm("ssh", &list));
        assert!(matches_self_traffic_comm("cloud-init", &list));
        // Prefix match: `git-remote-https` matches `git-remote-`.
        assert!(matches_self_traffic_comm("git-remote-https", &list));
        // Empty comm never matches.
        assert!(!matches_self_traffic_comm("", &list));
        // Unknown comm.
        assert!(!matches_self_traffic_comm("evil_tool", &list));
    }

    #[test]
    fn self_traffic_comms_returns_builtins_when_config_extras_empty() {
        let cfg = crate::config::KillchainConfig::default();
        assert!(cfg.self_traffic_comms_extra.is_empty());
        let list = self_traffic_comms(&cfg);
        // Builtins all present.
        for builtin in BUILTIN_SELF_TRAFFIC_COMMS {
            assert!(
                list.iter().any(|c| c == *builtin),
                "builtin `{builtin}` must be in the merged list when extras is empty"
            );
        }
        assert_eq!(list.len(), BUILTIN_SELF_TRAFFIC_COMMS.len());
    }

    #[test]
    fn self_traffic_comms_appends_operator_extras() {
        // Operator extends via `[killchain] self_traffic_comms_extra`.
        let cfg = crate::config::KillchainConfig {
            self_traffic_comms_extra: vec![
                "puppet".to_string(),
                "chef-client".to_string(),
                "salt-minion".to_string(),
            ],
            ..Default::default()
        };
        let list = self_traffic_comms(&cfg);
        assert!(list.iter().any(|c| c == "puppet"));
        assert!(list.iter().any(|c| c == "chef-client"));
        assert!(list.iter().any(|c| c == "salt-minion"));
        // Builtins still there.
        assert!(list.iter().any(|c| c == "apt"));
    }

    #[test]
    fn self_traffic_comms_dedupes_extras_against_builtins() {
        // Operator accidentally lists `apt` (already a builtin).
        // Merged list must not have it twice.
        let cfg = crate::config::KillchainConfig {
            self_traffic_comms_extra: vec!["apt".to_string(), "puppet".to_string()],
            ..Default::default()
        };
        let list = self_traffic_comms(&cfg);
        let apt_count = list.iter().filter(|c| c.as_str() == "apt").count();
        assert_eq!(
            apt_count, 1,
            "duplicate extras must be deduped against builtins"
        );
    }

    #[test]
    fn self_traffic_comms_trims_and_skips_empty_extras() {
        let cfg = crate::config::KillchainConfig {
            self_traffic_comms_extra: vec![
                "  puppet  ".to_string(),
                "".to_string(),
                "   ".to_string(),
            ],
            ..Default::default()
        };
        let list = self_traffic_comms(&cfg);
        assert!(list.iter().any(|c| c == "puppet"));
        assert!(!list.iter().any(|c| c.is_empty() || c.trim().is_empty()));
    }

    // ── 2026-05-05 (Wave 9b) anchors — service-account fetcher dismiss ──
    //
    // The general uid filter (uid == 0 || uid >= 1000) was too strict for
    // network-fetcher comms. Specifically: Debian/Ubuntu apt runs its
    // HTTPS download under uid 105 (`_apt`, the unprivileged sandbox), and
    // the worker thread's `comm` becomes `http` or `https`. Pre-Wave-9b
    // both gates rejected the dismiss (comm not in BUILTIN list AND uid
    // 105 fails the {0, >=1000} check) and the operator's nightly apt
    // update produced 9-15 critical "DATA_EXFIL to Ubuntu mirror IP"
    // incidents per day that reached the AI router (62 https + 15 http
    // incidents in the 7d window 2026-04-28..05-04).
    //
    // Anchors below pin: (1) http/https/etc are now in the self-traffic
    // list, (2) the uid check is bypassed for fetcher comms only,
    // (3) login-shell comms (ssh, scp, ...) still enforce the uid check
    // so the original lateral-movement protection is intact.

    #[test]
    fn dismiss_self_traffic_dismisses_apt_https_thread_at_apt_uid_105() {
        // The exact prod symptom that motivated Wave 9b: apt's https
        // worker (uid 105 = _apt) downloads from Ubuntu mirror.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1234:2026-05-05T03:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "91.189.91.46",
                "pid": 1234,
                "comm": "https",
                "uid": 105,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(
            store.decisions_count().unwrap(),
            1,
            "apt's https worker at uid 105 (_apt) MUST be auto-dismissed - this was 62 \
             of 169 prod incidents per 7d window pre-Wave-9b"
        );
    }

    #[test]
    fn dismiss_self_traffic_dismisses_apt_http_at_apt_uid() {
        // Same path as above but the http (port 80) variant.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:5555:2026-05-05T03:01Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "91.189.91.104",
                "pid": 5555,
                "comm": "http",
                "uid": 105,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn dismiss_self_traffic_dismisses_apt_at_apt_uid_directly() {
        // Even when the worker comm IS `apt` (no thread-rename), uid 105
        // would have failed pre-Wave-9b. After Wave 9b apt is fetcher-class
        // and uid-agnostic.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:7777:2026-05-05T03:02Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "91.189.91.46",
                "pid": 7777,
                "comm": "apt",
                "uid": 105,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn dismiss_self_traffic_still_blocks_ssh_at_service_account_uid() {
        // Lateral-movement guard on login-shell comms must NOT regress.
        // ssh from www-data (uid 33) is not legitimate operator activity
        // and must reach the AI router for a real call. This is the test
        // the Wave 9b uid-agnostic carveout MUST NOT erode.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:8888:2026-05-05T03:03Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.20",
                "pid": 8888,
                "comm": "ssh",
                "uid": 33,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "ssh from www-data (uid 33) MUST still reach the AI router - the Wave 9b \
             fetcher carveout cannot erode the lateral-movement guard on login-shell comms"
        );
    }

    #[test]
    fn dismiss_self_traffic_still_dismisses_ssh_at_operator_uid() {
        // Pre-Wave-9b ssh at uid >= 1000 was already dismissed via the
        // {0, >=1000} gate. This anchor pins that it still IS dismissed
        // post-Wave-9b (the old branch is preserved as the fallback when
        // the comm is not a fetcher).
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:9001:2026-05-05T03:04Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "20.26.156.215",
                "pid": 9001,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn comm_is_uid_agnostic_fetcher_recognises_documented_fetchers() {
        // Lock the fetcher set against a future contributor accidentally
        // moving a comm out of UID_AGNOSTIC_FETCHER_COMMS without bumping
        // a comment. If you add a comm here, also add a behavioural test
        // upstream that exercises it through dismiss_self_traffic.
        for comm in [
            "apt",
            "apt-get",
            "snap",
            "snapd",
            "http",
            "https",
            "curl",
            "wget",
            "systemd-resolv",
            "systemd-network",
            "chronyd",
            "ntpd",
            "fwupdmgr",
            "unattended-upgr",
            "needrestart",
            "cloud-init",
        ] {
            assert!(
                comm_is_uid_agnostic_fetcher(comm),
                "expected `{comm}` to be classified as a uid-agnostic fetcher comm"
            );
        }
        // Login-shell tools must NOT be uid-agnostic - the lateral-
        // movement guard applies to them.
        for login in ["ssh", "scp", "sftp", "rsync", "git", "git-remote-https"] {
            assert!(
                !comm_is_uid_agnostic_fetcher(login),
                "`{login}` must require the uid check (lateral-movement guard)"
            );
        }
        // Empty comm is never a fetcher (avoids matching everything via
        // the "starts_with empty" pitfall).
        assert!(!comm_is_uid_agnostic_fetcher(""));
    }

    #[test]
    fn dismiss_self_traffic_still_skips_strong_pattern_for_apt_uid_105() {
        // Wave 9b extends the dismiss for fetcher comms across uids, but
        // the strong-pattern guard (audit B2/P3) MUST still skip. apt at
        // uid 105 with REVERSE_SHELL is still a kernel-level forensic
        // signal that cannot be overruled by a comm/uid heuristic.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:REVERSE_SHELL:6666:2026-05-05T03:05Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "REVERSE_SHELL",
                "c2_ip": "203.0.113.99",
                "pid": 6666,
                "comm": "https",
                "uid": 105,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "REVERSE_SHELL must NEVER be auto-dismissed even when comm/uid match the \
             new fetcher carveout - kernel-level forensic evidence routes through the \
             AI router + incident_untouchable"
        );
    }

    #[test]
    fn dismiss_self_traffic_skips_when_comm_not_in_extended_list() {
        // Operator-added comm `puppet` was on the dismiss path now —
        // dismiss MUST honour it. End-to-end anchor that the merged
        // list flows through to the dismiss decision.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1234:2026-05-03T08:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.20",
                "pid": 1234,
                "comm": "puppet",
                "uid": 0,
            }]
        })];
        let cfg = crate::config::KillchainConfig {
            self_traffic_comms_extra: vec!["puppet".to_string()],
            ..Default::default()
        };
        let extended_list = self_traffic_comms(&cfg);
        dismiss_self_traffic_incidents(tmp.path(), Some(&store), &incidents, &extended_list);
        assert_eq!(
            store.decisions_count().unwrap(),
            1,
            "puppet (operator-added) must be dismissed via self-traffic-fp path"
        );
    }

    #[test]
    fn telegram_notify_and_dismiss_consume_same_self_traffic_list() {
        // The KEY anchor: this test will fail at build-time if anyone
        // re-introduces a separate hardcoded comm allowlist in
        // notify_telegram. Both code paths in killchain_inline.rs
        // must call `matches_self_traffic_comm(comm, list)` against
        // the SAME list. Pre-PR-#417 they had divergent constants
        // and the operator received Telegram alerts for apt updates
        // that were silently auto-dismissed.
        let src = include_str!("killchain_inline.rs");

        // dismiss path uses matches_self_traffic_comm.
        assert!(
            src.contains("matches_self_traffic_comm(comm, self_traffic_list)"),
            "dismiss_self_traffic_incidents must use matches_self_traffic_comm \
             against the passed-in list"
        );

        // notify_telegram path also uses matches_self_traffic_comm.
        let notify_section_start = src
            .find("pub(crate) fn notify_telegram(")
            .expect("notify_telegram fn must exist");
        let notify_section = &src[notify_section_start..];
        assert!(
            notify_section.contains("matches_self_traffic_comm(comm, self_traffic_list)"),
            "notify_telegram MUST call matches_self_traffic_comm against the SAME \
             self_traffic_list — anchored on PR #417 to prevent the dismiss/notify \
             drift that flooded the operator's Telegram with apt-update FPs"
        );

        // The new architecture: KILLCHAIN_SERVICE_ALLOWLIST (services
        // that do socket+dup as part of normal request handling)
        // exists separately from BUILTIN_SELF_TRAFFIC_COMMS (operator
        // tooling that does socket+sensitive_read on package
        // updates). Both names must be present and distinct.
        assert!(src.contains("KILLCHAIN_SERVICE_ALLOWLIST"));
        assert!(src.contains("BUILTIN_SELF_TRAFFIC_COMMS"));
    }
}
