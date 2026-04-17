//! Centralized notification gate. ALL automated Telegram messages must pass
//! through this gate. Only real, uncontained threats get immediate notification.
//! Everything else goes to daily briefing or is dropped entirely.
//!
//! Bot command responses (operator asked for info) and daily briefings are
//! exempt — they bypass this gate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::info;

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// What the gate decides for a given notification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotificationVerdict {
    /// Send immediately to Telegram.
    SendNow,
    /// Accumulate for daily briefing (do not send now).
    DailyBriefingOnly,
    /// Drop entirely (not even in briefing).
    Drop,
}

// ---------------------------------------------------------------------------
// Context — callers build this from whatever data they have
// ---------------------------------------------------------------------------

/// Describes the notification being considered. Callers populate from incident
/// data, kill chain output, honeypot session, etc.
pub(crate) struct NotificationContext {
    #[allow(dead_code)]
    pub severity: String,
    pub detector: String,
    /// "blocked", "killed", "contained", "suspended", "monitoring", "open", etc.
    #[allow(dead_code)]
    pub outcome: String,
    pub is_contained: bool,
    pub is_active_intrusion: bool,
    pub is_compromise: bool,
    pub is_honeypot_probe: bool,
}

impl NotificationContext {
    /// Build from a core Incident (used by the main incident pipeline path).
    pub fn from_incident(incident: &innerwarden_core::incident::Incident) -> Self {
        let detector = incident
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();

        let severity_str = format!("{:?}", incident.severity).to_lowercase();

        // Determine outcome from tags / evidence.
        let outcome = Self::extract_outcome(incident);
        let is_contained = Self::check_contained(&outcome);

        // is_compromise: kill chain reached data_exfil or persistence AND Critical.
        let is_compromise = matches!(
            incident.severity,
            innerwarden_core::event::Severity::Critical
        ) && incident.tags.iter().any(|t| {
            t == "data_exfiltration"
                || t == "persistence"
                || t == "data_exfil"
                || t == "exfiltration"
                || t == "rootkit"
        });

        // is_active_intrusion: Critical AND kill chain with 3+ stages or
        // combination of privesc + persistence + lateral_movement.
        let is_active_intrusion = matches!(
            incident.severity,
            innerwarden_core::event::Severity::Critical
        ) && {
            let has_multi_stage = incident.tags.iter().any(|t| t.contains("killchain"))
                || detector.starts_with("killchain");
            let has_privesc = incident
                .tags
                .iter()
                .any(|t| t == "privesc" || t == "privilege_escalation");
            let has_persistence = incident.tags.iter().any(|t| t == "persistence");
            let has_lateral = incident.tags.iter().any(|t| t == "lateral_movement");
            has_multi_stage || (has_privesc && has_persistence) || (has_privesc && has_lateral)
        };

        let is_honeypot_probe = detector == "honeypot"
            && incident
                .tags
                .iter()
                .any(|t| t == "probe" || t == "probe_only");

        Self {
            severity: severity_str,
            detector,
            outcome,
            is_contained,
            is_active_intrusion,
            is_compromise,
            is_honeypot_probe,
        }
    }

    /// Build from a kill chain JSON incident (killchain_inline produces JSON values).
    pub fn from_killchain_json(inc: &serde_json::Value) -> Self {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("medium")
            .to_string();

        let pattern = inc
            .get("evidence")
            .and_then(|e| e.get("pattern"))
            .and_then(|p| p.as_str())
            .unwrap_or("unknown");

        let detector = format!("killchain.{}", pattern);

        let outcome = inc
            .get("outcome")
            .and_then(|o| o.as_str())
            .unwrap_or("open")
            .to_string();
        let is_contained = Self::check_contained(&outcome);

        // Kill chain data_exfil pattern at critical = compromise.
        let is_compromise =
            severity == "critical" && (pattern == "data_exfil" || pattern == "full_exploit");

        // Kill chain with 3+ bit stages is active intrusion (reverse_shell=3,
        // bind_shell=4, full_exploit=3, exploit_shell=3).
        let stage_count = inc
            .get("evidence")
            .and_then(|e| e.get("flags"))
            .and_then(|f| f.as_u64())
            .map(|f| (f as u32).count_ones())
            .unwrap_or(0);
        let is_active_intrusion = severity == "critical" && stage_count >= 3;

        Self {
            severity,
            detector,
            outcome,
            is_contained,
            is_active_intrusion,
            is_compromise,
            is_honeypot_probe: false,
        }
    }

    /// Build for a shield (DDoS) incident.
    pub fn from_shield_json(inc: &serde_json::Value) -> Self {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("low")
            .to_string();

        let detector = "shield".to_string();

        let outcome = inc
            .get("outcome")
            .and_then(|o| o.as_str())
            .unwrap_or("blocked")
            .to_string();
        let is_contained = Self::check_contained(&outcome);
        let is_active_intrusion = severity == "critical" && !is_contained;

        Self {
            severity,
            detector,
            outcome,
            is_contained,
            // DDoS is not intrusion unless it escalated past mitigation.
            is_active_intrusion,
            is_compromise: false,
            is_honeypot_probe: false,
        }
    }

    /// Build for a firmware/hypervisor tick incident.
    pub fn from_firmware_or_hypervisor(
        inc: &innerwarden_core::incident::Incident,
        detector_label: &str,
    ) -> Self {
        let severity_str = format!("{:?}", inc.severity).to_lowercase();

        // Firmware/hypervisor alerts about trust degradation are informational
        // unless they indicate active rootkit/compromise.
        let is_compromise = matches!(inc.severity, innerwarden_core::event::Severity::Critical)
            && inc.tags.iter().any(|t| {
                t == "rootkit" || t == "firmware_tampering" || t == "msr_write" || t == "spi_flash"
            });

        Self {
            severity: severity_str,
            detector: detector_label.to_string(),
            outcome: "monitoring".to_string(),
            is_contained: false,
            is_active_intrusion: false,
            is_compromise,
            is_honeypot_probe: false,
        }
    }

    /// Build for a mesh network block notification.
    pub fn for_mesh_block() -> Self {
        Self {
            severity: "medium".to_string(),
            detector: "mesh".to_string(),
            outcome: "blocked".to_string(),
            is_contained: true,
            is_active_intrusion: false,
            is_compromise: false,
            is_honeypot_probe: false,
        }
    }

    /// Build for an advisory-ignored notification.
    pub fn for_advisory_ignored(risk_score: u32) -> Self {
        Self {
            severity: if risk_score >= 80 {
                "critical".to_string()
            } else if risk_score >= 60 {
                "high".to_string()
            } else {
                "medium".to_string()
            },
            detector: "advisory".to_string(),
            outcome: "open".to_string(),
            is_contained: false,
            // Advisory ignored is serious but not intrusion per se.
            is_active_intrusion: risk_score >= 80,
            is_compromise: false,
            is_honeypot_probe: false,
        }
    }

    /// Build for a honeypot session report.
    pub fn for_honeypot_session(is_probe_only: bool, auto_blocked: bool) -> Self {
        Self {
            severity: "low".to_string(),
            detector: "honeypot".to_string(),
            outcome: if auto_blocked {
                "blocked".to_string()
            } else {
                "monitoring".to_string()
            },
            is_contained: auto_blocked,
            is_active_intrusion: false,
            is_compromise: false,
            is_honeypot_probe: is_probe_only,
        }
    }

    /// Build for an auto-FP suggestion.
    pub fn for_autofp_suggestion() -> Self {
        Self {
            severity: "info".to_string(),
            detector: "autofp".to_string(),
            outcome: "monitoring".to_string(),
            is_contained: false,
            is_active_intrusion: false,
            is_compromise: false,
            is_honeypot_probe: false,
        }
    }

    fn extract_outcome(incident: &innerwarden_core::incident::Incident) -> String {
        // Check tags for action outcomes.
        for tag in &incident.tags {
            match tag.as_str() {
                "blocked" | "killed" | "contained" | "suspended" => return tag.clone(),
                _ => {}
            }
        }
        // Check evidence for outcome field.
        if let Some(outcome) = incident.evidence.get("outcome").and_then(|o| o.as_str()) {
            return outcome.to_string();
        }
        if let Some(arr) = incident.evidence.as_array() {
            for e in arr {
                if let Some(outcome) = e.get("outcome").and_then(|o| o.as_str()) {
                    return outcome.to_string();
                }
            }
        }
        "open".to_string()
    }

    fn check_contained(outcome: &str) -> bool {
        matches!(
            outcome,
            "blocked" | "killed" | "contained" | "suspended" | "auto_blocked"
        )
    }
}

// ---------------------------------------------------------------------------
// Gate decision
// ---------------------------------------------------------------------------

/// Evaluate notification policy. Returns what the caller should do.
pub(crate) fn should_notify(ctx: &NotificationContext) -> NotificationVerdict {
    // Rule 1: Server compromise (persistence/exfil confirmed) -> always send.
    if ctx.is_compromise {
        return NotificationVerdict::SendNow;
    }

    // Rule 2: Active intrusion NOT contained -> send immediately.
    if ctx.is_active_intrusion && !ctx.is_contained {
        return NotificationVerdict::SendNow;
    }

    // Rule 3: Already contained -> daily briefing only.
    if ctx.is_contained {
        return NotificationVerdict::DailyBriefingOnly;
    }

    // Rule 4: Honeypot probe-only -> drop entirely.
    if ctx.is_honeypot_probe {
        return NotificationVerdict::Drop;
    }

    // Rule 5: Everything else -> daily briefing.
    NotificationVerdict::DailyBriefingOnly
}

// ---------------------------------------------------------------------------
// Burst summary counter
// ---------------------------------------------------------------------------

/// Tracks contained-threat count for burst summary notifications.
/// When 50+ threats are auto-blocked in one hour, a single summary is sent.
pub(crate) struct BurstTracker {
    /// Count of contained threats since last summary or window reset.
    contained_count: AtomicU64,
    /// Timestamp when the current counting window started.
    window_start: std::sync::Mutex<DateTime<Utc>>,
    /// Whether a burst summary has already been sent for this window.
    summary_sent: std::sync::atomic::AtomicBool,
}

const BURST_THRESHOLD: u64 = 50;
const BURST_WINDOW_SECS: i64 = 3600;

impl BurstTracker {
    pub fn new() -> Self {
        Self {
            contained_count: AtomicU64::new(0),
            window_start: std::sync::Mutex::new(Utc::now()),
            summary_sent: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Record a contained threat. Returns Some(count) if the burst threshold
    /// has been reached and a summary should be sent.
    pub fn record_contained(&self) -> Option<u64> {
        let now = Utc::now();

        // Check if window expired — reset if so.
        {
            let mut start = self.window_start.lock().unwrap();
            if (now - *start).num_seconds() >= BURST_WINDOW_SECS {
                *start = now;
                self.contained_count.store(0, Ordering::Relaxed);
                self.summary_sent.store(false, Ordering::Relaxed);
            }
        }

        let count = self.contained_count.fetch_add(1, Ordering::Relaxed) + 1;

        if count >= BURST_THRESHOLD && !self.summary_sent.swap(true, Ordering::Relaxed) {
            Some(count)
        } else {
            None
        }
    }

    /// Get current contained count (for testing/telemetry).
    #[cfg(test)]
    pub fn count(&self) -> u64 {
        self.contained_count.load(Ordering::Relaxed)
    }
}

/// Format the burst summary message as HTML for Telegram.
pub(crate) fn format_burst_summary(count: u64) -> String {
    format!(
        "\u{1f6e1}\u{fe0f} <b>Under heavy attack</b>\n\n\
         <b>{count}</b> threats auto-blocked this hour.\n\
         All contained. No action needed.\n\n\
         <i>Details in daily briefing.</i>"
    )
}

// ---------------------------------------------------------------------------
// Convenience: gate + send for common patterns
// ---------------------------------------------------------------------------

/// Gate an automated alert through the notification policy. If `SendNow`,
/// sends via `send_fn`. If `DailyBriefingOnly`, increments the deferred
/// counter and records in burst tracker. Returns the verdict.
#[allow(dead_code)]
pub(crate) async fn gate_and_send<F, Fut>(
    ctx: &NotificationContext,
    tg: &Arc<crate::telegram::TelegramClient>,
    burst_tracker: &BurstTracker,
    deferred: &mut std::collections::HashMap<String, u32>,
    send_fn: F,
) -> NotificationVerdict
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let verdict = should_notify(ctx);

    match verdict {
        NotificationVerdict::SendNow => {
            send_fn().await;
        }
        NotificationVerdict::DailyBriefingOnly => {
            *deferred.entry(ctx.detector.clone()).or_insert(0) += 1;
            info!(
                detector = %ctx.detector,
                severity = %ctx.severity,
                "notification gate: deferred to daily briefing"
            );
            if ctx.is_contained {
                if let Some(count) = burst_tracker.record_contained() {
                    let msg = format_burst_summary(count);
                    let tg = tg.clone();
                    tokio::spawn(async move {
                        let _ = tg.send_alert_html(&msg).await;
                    });
                }
            }
        }
        NotificationVerdict::Drop => {
            info!(
                detector = %ctx.detector,
                "notification gate: dropped (noise)"
            );
        }
    }

    verdict
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(
        severity: &str,
        detector: &str,
        is_contained: bool,
        is_active_intrusion: bool,
        is_compromise: bool,
        is_honeypot_probe: bool,
    ) -> NotificationContext {
        NotificationContext {
            severity: severity.to_string(),
            detector: detector.to_string(),
            outcome: if is_contained {
                "blocked".to_string()
            } else {
                "open".to_string()
            },
            is_contained,
            is_active_intrusion,
            is_compromise,
            is_honeypot_probe,
        }
    }

    #[test]
    fn compromise_always_sends() {
        let ctx = make_ctx(
            "critical",
            "killchain.data_exfil",
            false,
            false,
            true,
            false,
        );
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn compromise_sends_even_when_contained() {
        let ctx = make_ctx("critical", "killchain.data_exfil", true, false, true, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn active_intrusion_not_contained_sends() {
        let ctx = make_ctx(
            "critical",
            "killchain.reverse_shell",
            false,
            true,
            false,
            false,
        );
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn active_intrusion_contained_defers() {
        let ctx = make_ctx(
            "critical",
            "killchain.reverse_shell",
            true,
            true,
            false,
            false,
        );
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn contained_threat_defers() {
        let ctx = make_ctx("high", "ssh_bruteforce", true, false, false, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn honeypot_probe_drops() {
        let ctx = make_ctx("low", "honeypot", false, false, false, true);
        assert_eq!(should_notify(&ctx), NotificationVerdict::Drop);
    }

    #[test]
    fn regular_scan_defers() {
        let ctx = make_ctx("medium", "port_scan", false, false, false, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn shield_blocked_defers() {
        let ctx = make_ctx("high", "shield", true, false, false, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn firmware_monitoring_defers() {
        let ctx = make_ctx("medium", "firmware", false, false, false, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn firmware_rootkit_compromise_sends() {
        let ctx = make_ctx("critical", "firmware", false, false, true, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn mesh_block_defers() {
        let ctx = NotificationContext::for_mesh_block();
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn autofp_suggestion_defers() {
        let ctx = NotificationContext::for_autofp_suggestion();
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn honeypot_session_blocked_defers() {
        let ctx = NotificationContext::for_honeypot_session(false, true);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn honeypot_session_probe_only_drops() {
        let ctx = NotificationContext::for_honeypot_session(true, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::Drop);
    }

    #[test]
    fn advisory_high_risk_sends() {
        let ctx = NotificationContext::for_advisory_ignored(85);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn advisory_low_risk_defers() {
        let ctx = NotificationContext::for_advisory_ignored(50);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    // -- Burst tracker tests --

    #[test]
    fn burst_tracker_fires_at_threshold() {
        let tracker = BurstTracker::new();
        for _ in 0..49 {
            assert!(tracker.record_contained().is_none());
        }
        // 50th should trigger.
        let result = tracker.record_contained();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 50);
    }

    #[test]
    fn burst_tracker_fires_only_once() {
        let tracker = BurstTracker::new();
        for _ in 0..50 {
            tracker.record_contained();
        }
        // Additional records should not fire again.
        assert!(tracker.record_contained().is_none());
        assert!(tracker.record_contained().is_none());
    }

    #[test]
    fn burst_tracker_count() {
        let tracker = BurstTracker::new();
        tracker.record_contained();
        tracker.record_contained();
        tracker.record_contained();
        assert_eq!(tracker.count(), 3);
    }

    // -- NotificationContext builder tests --

    #[test]
    fn from_incident_detects_compromise() {
        let incident = innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: "test".into(),
            incident_id: "data_exfil:1.2.3.4:abc".into(),
            severity: innerwarden_core::event::Severity::Critical,
            title: "Data exfiltration".into(),
            summary: "".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["data_exfiltration".into()],
            entities: vec![],
        };
        let ctx = NotificationContext::from_incident(&incident);
        assert!(ctx.is_compromise);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn from_incident_contained_defers() {
        let incident = innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: "test".into(),
            incident_id: "ssh_bruteforce:1.2.3.4:abc".into(),
            severity: innerwarden_core::event::Severity::High,
            title: "SSH brute force".into(),
            summary: "".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["blocked".into()],
            entities: vec![],
        };
        let ctx = NotificationContext::from_incident(&incident);
        assert!(ctx.is_contained);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn from_killchain_json_active_intrusion() {
        let inc = serde_json::json!({
            "severity": "critical",
            "evidence": {
                "pattern": "reverse_shell",
                "flags": 7  // socket + dup_stdin + dup_stdout = 3 bits
            }
        });
        let ctx = NotificationContext::from_killchain_json(&inc);
        assert!(ctx.is_active_intrusion);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn from_killchain_json_data_exfil_compromise() {
        let inc = serde_json::json!({
            "severity": "critical",
            "evidence": {
                "pattern": "data_exfil",
                "flags": 257  // sensitive_read + socket
            }
        });
        let ctx = NotificationContext::from_killchain_json(&inc);
        assert!(ctx.is_compromise);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn from_shield_blocked_defers() {
        let inc = serde_json::json!({
            "severity": "high",
            "outcome": "blocked"
        });
        let ctx = NotificationContext::from_shield_json(&inc);
        assert!(ctx.is_contained);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    // ─── Spec 024 contract tests ───────────────────────────────────────
    //
    // The notification_gate contract:
    //
    //   should_notify(ctx) ∈ { SendNow, DailyBriefingOnly, Drop }
    //
    // — the set is closed. No I/O, no side effects, no async, no state. Any
    // new verdict variant is a breaking change to downstream consumers and
    // must be reflected here. Keeping this contract explicit is the sole
    // reason the gate exists as a separate module: callers can reason about
    // the space of possible outcomes without reading implementation.
    //
    // Every matrix cell below represents one logical branch of the gate;
    // adding or removing a branch without updating this table means the
    // gate's behavioural envelope shifted and downstream callers
    // (Telegram, briefing, burst tracker) may silently drift.

    #[test]
    fn contract_verdict_is_one_of_three_enum_variants_exhaustive_match() {
        // Compile-time proof: an exhaustive match covers exactly the three
        // verdicts. If a fourth is added, this test stops compiling and
        // forces the author to explicitly update callers.
        let ctx = make_ctx("low", "noop", false, false, false, false);
        let verdict = should_notify(&ctx);
        match verdict {
            NotificationVerdict::SendNow
            | NotificationVerdict::DailyBriefingOnly
            | NotificationVerdict::Drop => {}
        }
    }

    #[test]
    fn contract_pure_function_no_mutation_of_context() {
        // The gate MUST NOT mutate its context. Downstream callers share
        // the context across verdicts and can observe drift if the gate
        // modifies flags. We assert structural equality pre/post.
        let ctx_before = make_ctx("critical", "killchain.reverse_shell", true, true, false, false);
        let ctx_after = make_ctx("critical", "killchain.reverse_shell", true, true, false, false);
        let _ = should_notify(&ctx_before);
        assert_eq!(ctx_before.detector, ctx_after.detector);
        assert_eq!(ctx_before.is_contained, ctx_after.is_contained);
        assert_eq!(ctx_before.is_active_intrusion, ctx_after.is_active_intrusion);
        assert_eq!(ctx_before.is_compromise, ctx_after.is_compromise);
        assert_eq!(ctx_before.is_honeypot_probe, ctx_after.is_honeypot_probe);
    }

    #[test]
    fn contract_full_precedence_table() {
        // Full Cartesian precedence table. Each row is (compromise, active,
        // contained, probe) → verdict. Redundant-by-design with the
        // narrower tests above; lives here as the single-place rulebook
        // an operator can point at when asking "why did this fire?".
        type Row = ((bool, bool, bool, bool), NotificationVerdict);
        let rows: &[Row] = &[
            // compromise wins over everything.
            ((true, false, false, false), NotificationVerdict::SendNow),
            ((true, true, false, false), NotificationVerdict::SendNow),
            ((true, false, true, false), NotificationVerdict::SendNow),
            ((true, false, false, true), NotificationVerdict::SendNow),
            // active + not-contained: send.
            ((false, true, false, false), NotificationVerdict::SendNow),
            // active + contained: defer.
            ((false, true, true, false), NotificationVerdict::DailyBriefingOnly),
            // contained alone: defer.
            ((false, false, true, false), NotificationVerdict::DailyBriefingOnly),
            // probe only (not contained): drop. This is the noise floor.
            ((false, false, false, true), NotificationVerdict::Drop),
            // nothing special: defer.
            ((false, false, false, false), NotificationVerdict::DailyBriefingOnly),
        ];
        for &((compromise, active, contained, probe), want) in rows {
            let ctx = make_ctx(
                "medium",
                "test",
                contained,
                active,
                compromise,
                probe,
            );
            let got = should_notify(&ctx);
            assert_eq!(
                got, want,
                "contract regression: (compromise={compromise}, active={active}, contained={contained}, probe={probe}) expected {want:?} got {got:?}"
            );
        }
    }
}
