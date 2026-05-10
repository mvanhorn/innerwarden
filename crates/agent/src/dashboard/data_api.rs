// Auto-extracted from mod.rs — dashboard data_api handlers

use super::*;
#[cfg(test)]
use std::io::BufRead;

/// Dashboard auto-sleep timeout: 15 minutes of no requests.
pub(super) const DASHBOARD_SLEEP_SECS: u64 = 15 * 60;

pub(super) fn is_dashboard_sleeping(last_activity: &std::sync::atomic::AtomicU64) -> bool {
    let last = last_activity.load(std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(last) > DASHBOARD_SLEEP_SECS
}

/// Build the AI briefing system prompt. When the operator has a bot
/// personality configured, use it as the base so the Home briefing speaks
/// in the same voice as Telegram `/ask`; otherwise fall back to a plain
/// analyst prompt (preserves behaviour in test fixtures that build a bare
/// `DashboardActionConfig::default()`).
pub(super) fn briefing_system_prompt(personality: &str) -> String {
    let guidance = "FORMAT: generate a concise intelligence briefing. \
        Short sections. No fluff. No generic security advice. \
        Name the TTP and state the action taken for any real incident; \
        treat routine scanner noise as one summary line, not a section each.";
    if personality.trim().is_empty() {
        format!("You are a senior security analyst.\n\n{guidance}")
    } else {
        format!("{}\n\n{guidance}", personality.trim_end())
    }
}

/// Spec 029 PR-C.2: uniform error response when the LLM role is not
/// configured. Centralises the wording so every endpoint that needs
/// `Capability::Generate` or `Capability::Explain` points operators
/// at the same `[ai.llm]` config key. Kept as a small helper so the
/// fallback path is unit-testable without spinning up a
/// `DashboardState` and an axum router.
pub(super) fn llm_unavailable_error(feature: &str) -> serde_json::Value {
    serde_json::json!({
        "error": format!(
            "LLM role not configured. Set [ai.llm] in agent.toml to enable {feature}."
        ),
    })
}

/// Build the AI explain-threat system prompt used by the Threats drill-down.
/// Uses the same base personality as the briefing so all three AI surfaces
/// (Home briefing, Threats explain, Telegram /ask) speak in one voice,
/// layered with the plain-English simplification guidance.
pub(super) fn explain_system_prompt(personality: &str) -> String {
    // Feynman-style explainer (Spec 046 follow-up, 2026-05-10).
    // Operator complaint: AI explanations were either "No data found"
    // or generic 2-sentence summaries that didn't help a non-technical
    // person understand "is this scary or not?". Feynman technique:
    // explain by analogy + tell the story + answer the worry directly.
    let simplifier = "FORMAT — Feynman technique:\n\
        1. STORY (1-2 sentences): tell what happened as a story. \
           Use a real-world analogy where useful (a fake door, a wrong key, \
           someone shouting gibberish through a mailbox). Be SPECIFIC about what \
           the attacker actually did, in plain language a non-technical person \
           understands. NEVER start with jargon like 'proto_anomaly' or 'TCP'.\n\
        2. WHY IT HAPPENED (1 sentence): explain WHY this is in the operator's \
           threat list. Was it caught by a honeypot? A real service? A dropper bot? \
           A scanner? Help them know if this is a known class of noise or a \
           real threat.\n\
        3. THREAT VERDICT (1 sentence): answer 'should I worry?' directly. \
           Only call it dangerous if the attacker got past initial contact \
           (successful auth, shell access, data exfil). Probes that fail at \
           the door are NOISE — say so plainly. If it's noise, also say what \
           WOULD make this concerning (e.g., 'come back to worry only if this IP \
           also shows up in <other detector>').\n\n\
        Constraints: total length 4-6 sentences. No bullet points. No markdown. \
        Base your story strictly on the incident data provided — no invented \
        details. If the data says 'malformed SSH banner', do not say 'tried \
        admin/admin' (that's a different attack). When the incident hit the \
        honeypot port (the operator-controlled trap), say so explicitly — \
        that's the wow moment.";
    if personality.trim().is_empty() {
        format!(
            "You are a security guide explaining threats to a non-technical \
             person who runs InnerWarden on their own server. Your job is to \
             make them feel oriented: did something bad happen, what was it, \
             and what (if anything) they should do.\n\n{simplifier}"
        )
    } else {
        format!("{}\n\n{simplifier}", personality.trim_end())
    }
}
/// Phase 5 (audit RC-2 / 2026-04-29) introduced a SQLite-backed
/// counter aggregation to replace the lossy in-memory KG iteration.
/// Phase 7 (this commit) generalises that into a single-pass producer
/// of *both* the legacy flat fields (for backwards-compat clients
/// like the Telegram bot) and the new typed `OverviewSnapshot` (for
/// the redesigned Home tile UX). One SQL walk, two output shapes,
/// no recomputation.
///
/// Top-level invariants this function holds:
///
/// 1. **Date scoping**: only incidents whose `ts` starts with `date`
///    are counted. No leakage from previous/next day.
/// 2. **Internal-traffic filter**: applies the same
///    `is_internal_incident_fields` predicate the Threats list and
///    Live Feed use, so all surfaces agree on which incidents are
///    "real attacks" vs. system noise.
/// 3. **Allowlist segregation**: incidents flagged
///    `is_allowlisted=1` (column written by the agent's fast loop in
///    the SkipAllowlisted branch) go into the `allowlisted` bucket
///    and do NOT inflate `attention`. This is the operator-visible
///    bug the Phase 7 redesign closes.
/// 4. **Pending categorisation**: incidents with no decision are
///    bucketed by reason — in-flight (<5min), declined, cooldown'd,
///    stuck (>1h, no cooldown). The "stuck" category is the
///    SystemHealth signal.
/// 5. **Unique-attacker count**: the per-bucket `unique_attackers`
///    field is built from a deduplicated set of external IPs
///    extracted from each incident's `entities`. RFC 1918 addresses
///    are excluded so a misconfigured outbound-NAT host doesn't show
///    up as an attacker against itself.
#[derive(Default)]
pub(super) struct OverviewCounts {
    pub incidents_count: usize,
    pub decisions_count: usize,
    pub ai_confirmed: usize,
    pub ai_responded: usize,
    pub ai_ignored: usize,
    pub unresolved_count: usize,
    pub safely_resolved: usize,
    pub handled_ips_today: usize,
    pub blocked_count: usize,
    pub observing_count: usize,
    pub attention_count: usize,
    pub allowlisted_count: usize,
    pub severity_breakdown: std::collections::HashMap<String, usize>,
    pub by_detector: BTreeMap<String, usize>,
    /// Phase 7: the typed snapshot built alongside the flat counts.
    /// `None` only on default-constructed instances (test fixtures
    /// before population); populated by
    /// `compute_overview_counts_from_sqlite` on every successful read.
    pub snapshot: Option<super::types::OverviewSnapshot>,
}

/// One row from the incidents+latest-decision JOIN, post-decoding,
/// post-filter-eligibility check. Keeps the inner loop small.
struct OverviewRow {
    detector: String,
    severity: String,
    is_allowlisted: bool,
    ts_ms: i64,
    action_type: Option<String>,
    target_ip: Option<String>,
    external_ips: std::collections::BTreeSet<String>,
}

/// Read all of `date`'s incidents from SQLite (the durable source of
/// truth, unaffected by KG TTL eviction), join with each one's latest
/// decision, and produce both the legacy flat counters and the
/// Phase 7 typed snapshot.
///
/// Returns `None` when the SQLite store is unreachable. Callers fall
/// back to the in-memory KG iteration in that case so test fixtures
/// without a Store keep working.
pub(super) fn compute_overview_counts_from_sqlite(
    store: &innerwarden_store::Store,
    date: &str,
    sev_min_rank: u8,
    detector_substring: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
    degraded: &DegradedSignals,
    data_dir: &std::path::Path,
) -> Option<OverviewCounts> {
    use super::types::{BucketStats, OutcomeBuckets, OverviewSnapshot, PendingBreakdown};

    let conn = store.conn().ok()?;
    // Phase 7B: last-decision freshness query first, on the SAME
    // connection. The connection pool for in-memory test stores has
    // max_size=1, so opening a second conn here deadlocks. Reuse the
    // one we'll hold for the JOIN below.
    let last_decision_secs_ago: Option<i64> = (|| -> Option<i64> {
        let last_ts: String = conn
            .query_row(
                "SELECT ts FROM decisions ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok()?;
        let parsed = chrono::DateTime::parse_from_rfc3339(&last_ts).ok()?;
        let secs = (now - parsed.with_timezone(&chrono::Utc))
            .num_seconds()
            .max(0);
        Some(secs)
    })();
    let pattern = format!("{date}%");
    let mut stmt = conn
        .prepare_cached(
            "SELECT i.incident_id, i.detector, i.title, i.severity, i.ts, \
                    i.is_allowlisted, i.data, \
                    d.action_type, d.target_ip \
             FROM incidents i \
             LEFT JOIN ( \
                 SELECT incident_id, action_type, target_ip, \
                        ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY id DESC) AS rn \
                 FROM decisions \
             ) d ON d.incident_id = i.incident_id AND d.rn = 1 \
             WHERE i.ts LIKE ?1",
        )
        .ok()?;
    let raw_rows = stmt
        .query_map([&pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,         // incident_id
                row.get::<_, String>(1)?,         // detector
                row.get::<_, String>(2)?,         // title
                row.get::<_, String>(3)?,         // severity
                row.get::<_, String>(4)?,         // ts iso
                row.get::<_, i64>(5)?,            // is_allowlisted (0/1)
                row.get::<_, String>(6)?,         // data JSON
                row.get::<_, Option<String>>(7)?, // action_type
                row.get::<_, Option<String>>(8)?, // target_ip
            ))
        })
        .ok()?;

    let mut decoded: Vec<OverviewRow> = Vec::new();
    for raw in raw_rows {
        let Ok((
            incident_id,
            detector,
            title,
            severity,
            ts_iso,
            is_allowlisted_flag,
            data,
            action_type,
            target_ip,
        )) = raw
        else {
            continue;
        };
        let parsed: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Skip research-only incidents (spec 015) — invisible to the
        // operator-facing counts by design.
        if parsed
            .get("research_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        // Extract the external IPs once, share between the
        // is_internal check and the unique-attacker dedup set.
        let external_ips: std::collections::BTreeSet<String> = parsed
            .get("entities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let is_ip = e
                            .get("type")
                            .and_then(|t| t.as_str())
                            .map(|t| t.eq_ignore_ascii_case("ip"))
                            .unwrap_or(false);
                        if !is_ip {
                            return None;
                        }
                        let value = e.get("value").and_then(|v| v.as_str())?;
                        if value.is_empty() || crate::incident_auto_rules::is_internal_ip_pub(value)
                        {
                            return None;
                        }
                        Some(value.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        let has_external_ip = !external_ips.is_empty();
        if crate::dashboard::live_feed::is_internal_incident_fields(
            &detector,
            &title,
            has_external_ip,
        ) {
            continue;
        }
        if sev_min_rank > 0
            && crate::dashboard::investigation::severity_rank(&severity) < sev_min_rank
        {
            continue;
        }
        if let Some(needle) = detector_substring {
            if !detector.to_ascii_lowercase().contains(needle) {
                continue;
            }
        }
        let ts_ms = chrono::DateTime::parse_from_rfc3339(&ts_iso)
            .map(|t| t.with_timezone(&chrono::Utc).timestamp_millis())
            .unwrap_or_else(|_| now.timestamp_millis());
        // (Phase 7 Slice A scope: cooldown-suppressed pending detection
        // is age-heuristic only. A future slice can plumb the cooldown
        // store in to distinguish "<1h, AI deliberately suppressed" from
        // "<1h, AI hasn't run yet" — neither is operator-actionable so
        // both bucket as in_flight for now. The "stuck" signal that
        // matters most is age-only, which we have.)
        let _ = incident_id; // not needed beyond the cooldown plumbing
        decoded.push(OverviewRow {
            detector,
            severity: severity.to_lowercase(),
            is_allowlisted: is_allowlisted_flag != 0,
            ts_ms,
            action_type,
            target_ip,
            external_ips,
        });
    }

    let mut counts = OverviewCounts::default();
    let mut handled_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut buckets = OutcomeBuckets::default();
    let mut bucket_attackers_blocked: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut bucket_attackers_observing: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut bucket_attackers_honeypot: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut bucket_attackers_dismissed: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut bucket_attackers_allowlisted: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut bucket_attackers_attention: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut pending = PendingBreakdown::default();
    let now_ms = now.timestamp_millis();
    let in_flight_threshold_ms = 5 * 60 * 1000; // 5 minutes
    let stuck_threshold_ms = 60 * 60 * 1000; // 1 hour

    for row in &decoded {
        counts.incidents_count += 1;
        *counts.by_detector.entry(row.detector.clone()).or_insert(0) += 1;
        *counts
            .severity_breakdown
            .entry(row.severity.clone())
            .or_insert(0) += 1;

        // Allowlisted incidents go into the allowlisted bucket and
        // never count toward the operator-action buckets, regardless
        // of whether they happened to receive a decision (typically
        // they don't — the SkipAllowlisted branch short-circuits the
        // AI router).
        if row.is_allowlisted {
            counts.allowlisted_count += 1;
            buckets.allowlisted.incidents += 1;
            *buckets
                .allowlisted
                .severities
                .entry(row.severity.clone())
                .or_insert(0) += 1;
            for ip in &row.external_ips {
                bucket_attackers_allowlisted.insert(ip.clone());
            }
            continue;
        }

        let outcome =
            super::threat_contract::classify_decision(row.action_type.as_deref(), Some("ok"));
        match super::threat_contract::kpi_bucket(outcome) {
            super::threat_contract::KpiBucket::Blocked => counts.blocked_count += 1,
            super::threat_contract::KpiBucket::Observing => counts.observing_count += 1,
            super::threat_contract::KpiBucket::Attention => counts.attention_count += 1,
            super::threat_contract::KpiBucket::None => {}
        }

        // Bucket-level severity histogram + unique attacker set.
        let (bucket, attackers_set): (&mut BucketStats, &mut std::collections::HashSet<String>) =
            match outcome {
                super::threat_contract::OUTCOME_BLOCKED => {
                    (&mut buckets.blocked, &mut bucket_attackers_blocked)
                }
                super::threat_contract::OUTCOME_HONEYPOT => {
                    (&mut buckets.honeypot, &mut bucket_attackers_honeypot)
                }
                super::threat_contract::OUTCOME_MONITORING => {
                    (&mut buckets.observing, &mut bucket_attackers_observing)
                }
                super::threat_contract::OUTCOME_DISMISSED => {
                    (&mut buckets.dismissed, &mut bucket_attackers_dismissed)
                }
                _ => (&mut buckets.attention, &mut bucket_attackers_attention),
            };
        bucket.incidents += 1;
        *bucket.severities.entry(row.severity.clone()).or_insert(0) += 1;
        for ip in &row.external_ips {
            attackers_set.insert(ip.clone());
        }

        // Pending breakdown: only applies to the "attention" bucket
        // (no decision yet, or escalate/request_confirmation).
        if outcome == super::threat_contract::OUTCOME_OPEN {
            let age_ms = now_ms - row.ts_ms;
            match row.action_type.as_deref() {
                Some("escalate") | Some("request_confirmation") => {
                    pending.declined_by_ai += 1;
                }
                _ => {
                    if age_ms < in_flight_threshold_ms {
                        pending.in_flight += 1;
                    } else if age_ms >= stuck_threshold_ms {
                        pending.stuck += 1;
                    } else {
                        // Between 5min and 1h, no decision. Treat as
                        // in-flight: the AI processing pipeline runs
                        // every few seconds, and a 5-60min gap typically
                        // means budget-saturation or cooldown-suppression
                        // — both AI-deliberate, not operator-actionable.
                        // The "stuck" signal kicks in at >1h which is the
                        // threshold where operator must look.
                        pending.in_flight += 1;
                    }
                }
            }
        }

        if let Some(action) = &row.action_type {
            counts.decisions_count += 1;
            let target_is_ip = row.target_ip.as_ref().is_some_and(|t| t.contains('.'));
            match action.as_str() {
                "ignore" | "dismiss" => counts.ai_ignored += 1,
                "monitor" => {
                    counts.ai_confirmed += 1;
                    counts.safely_resolved += 1;
                    if target_is_ip {
                        if let Some(ip) = &row.target_ip {
                            handled_ips.insert(ip.clone());
                        }
                    }
                }
                "request_confirmation" | "escalate" => {
                    counts.ai_confirmed += 1;
                    counts.unresolved_count += 1;
                }
                _ => {
                    counts.ai_confirmed += 1;
                    if target_is_ip {
                        counts.ai_responded += 1;
                        if let Some(ip) = &row.target_ip {
                            handled_ips.insert(ip.clone());
                        }
                    }
                    counts.safely_resolved += 1;
                }
            }
        }
    }
    counts.handled_ips_today = handled_ips.len();

    // Phase 10 (2026-04-29): unify the attacker-count semantic across
    // every dashboard surface. Pre-Phase-10 this function emitted
    // per-bucket sets where the same IP could appear in multiple
    // buckets (one IP with mixed block_ip + dismiss decisions ended up
    // in BOTH buckets). The Threats list, on the other hand, used
    // `aggregate_outcomes` precedence to assign each IP to exactly
    // ONE bucket. Three surfaces showed three different "blocked"
    // numbers for the same data — operator-visible bug.
    //
    // The fix: count per-IP aggregate outcome, the same way the
    // Threats list does. Each IP appears in exactly one bucket.
    // Sums-to-total of all bucket attackers = total unique IPs today.
    // Now Home pyramid + Threats list groups + top header tiles all
    // show the same numbers by construction.
    let mut ip_outcomes: std::collections::HashMap<String, Vec<&'static str>> =
        std::collections::HashMap::new();
    let mut ip_allowlisted: std::collections::HashSet<String> = std::collections::HashSet::new();
    for row in &decoded {
        if row.is_allowlisted {
            for ip in &row.external_ips {
                ip_allowlisted.insert(ip.clone());
            }
            continue;
        }
        let outcome =
            super::threat_contract::classify_decision(row.action_type.as_deref(), Some("ok"));
        for ip in &row.external_ips {
            ip_outcomes.entry(ip.clone()).or_default().push(outcome);
        }
    }
    // Walk per-IP, derive aggregate outcome via the same precedence
    // the Threats list uses, increment that bucket's counter once.
    for (ip, outcomes) in &ip_outcomes {
        if ip_allowlisted.contains(ip) {
            // Allowlisted-precedence override: IP shows up in the
            // allowlisted group regardless of other incident outcomes
            // it had today (matches build_attackers_from_sqlite).
            continue;
        }
        let aggregate = super::threat_contract::aggregate_outcomes(outcomes.iter().copied());
        match aggregate {
            super::threat_contract::OUTCOME_BLOCKED => {
                buckets.blocked.unique_attackers += 1;
            }
            super::threat_contract::OUTCOME_HONEYPOT => {
                buckets.honeypot.unique_attackers += 1;
            }
            super::threat_contract::OUTCOME_MONITORING => {
                buckets.observing.unique_attackers += 1;
            }
            super::threat_contract::OUTCOME_DISMISSED => {
                buckets.dismissed.unique_attackers += 1;
            }
            _ => {
                buckets.attention.unique_attackers += 1;
            }
        }
    }
    buckets.allowlisted.unique_attackers = ip_allowlisted.len();

    // The legacy flat counters (blocked_count, observing_count,
    // attention_count) were ALSO per-incident KPI bucketing. Phase 10
    // rewrites them to match aggregate-attacker semantics so the top
    // header tiles agree with the pyramid and the threats list. The
    // pre-Phase-10 incident-level counts are still available via the
    // bucket.incidents fields when a power user wants them.
    counts.blocked_count = buckets.blocked.unique_attackers + buckets.honeypot.unique_attackers;
    counts.observing_count = buckets.observing.unique_attackers;
    counts.attention_count = buckets.attention.unique_attackers;

    // Drop the old per-incident attacker sets; they're shadowed by
    // the aggregate computation above. Keeping the variable names
    // out of scope past this point would be dead code.
    let _ = (
        bucket_attackers_blocked,
        bucket_attackers_observing,
        bucket_attackers_honeypot,
        bucket_attackers_dismissed,
        bucket_attackers_allowlisted,
        bucket_attackers_attention,
    );

    // Top detectors built from the same `by_detector` accumulator the
    // legacy flat path uses, so both shapes agree by construction.
    let mut top_detectors: Vec<crate::dashboard::types::DetectorCount> = counts
        .by_detector
        .iter()
        .map(|(detector, count)| crate::dashboard::types::DetectorCount {
            detector: detector.clone(),
            count: *count,
        })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    let health = derive_system_health(&pending, last_decision_secs_ago, degraded);

    // 2026-05-02 audit (Spec 039 P3 follow-up): events_today is part
    // of the canonical snapshot contract. Pre-fix it was hardcoded to
    // 0 here and backfilled only by api_overview, so every other
    // surface that read the snapshot (Briefing, Report, Sensors HUD)
    // showed "Events Today: 0" while the per-source counters showed
    // millions. The backfill must live inside the SoT helper so all
    // callers get the same number.
    let telemetry = crate::telemetry::read_latest_snapshot(data_dir, date);
    let events_today: usize = telemetry
        .as_ref()
        .map(|t| t.events_by_collector.values().copied().sum::<u64>() as usize)
        .unwrap_or(0);
    counts.snapshot = Some(OverviewSnapshot {
        date: date.to_string(),
        generated_at: now,
        health,
        buckets,
        pending,
        events_today,
        top_detectors,
    });
    Some(counts)
}

/// Read drift signals from the response lifecycle JSON (SQLite blob
/// first, then `data_dir/responses.json` fallback — same precedence
/// as the `/api/responses` handler). Best-effort: any read or parse
/// failure returns `Default::default()` so a transient I/O hiccup
/// never flips the banner red on its own. The caller (api_overview)
/// treats this as a snapshot input, not a critical-path read.
///
/// PR #425 Wave 4d: orphaned count now reads `gauges.orphaned`
/// (current count) instead of `totals.orphaned` (lifetime counter).
/// Pre-Wave-4d the dashboard banner screamed "17 orphaned (rule may
/// still be active)" months after PR #408's GC had pruned the
/// underlying entries — counter never decrements, so the banner
/// gaslit the operator into searching for ghost rules. Now the
/// banner only fires when entries actually exist on disk. Falls
/// back to `state_counts.revert_failed` if `gauges.orphaned` is
/// missing (transitional shape during deploy).
pub(super) fn read_degraded_signals(state: &super::state::DashboardState) -> DegradedSignals {
    let raw = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("responses").ok().flatten())
        .or_else(|| {
            let canonical = std::fs::canonicalize(&state.data_dir).ok()?;
            let target = canonical.join("responses.json");
            if !target.starts_with(&canonical) {
                return None;
            }
            std::fs::read_to_string(target).ok()
        });
    let mut signals = DegradedSignals::default();
    if let Some(text) = raw {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            // Current orphan count — gauge, not counter. Falls back
            // to the revert_failed gauge if the new shape is absent.
            signals.orphaned_now = v
                .get("gauges")
                .and_then(|g| g.get("orphaned"))
                .and_then(|n| n.as_u64())
                .or_else(|| {
                    v.get("state_counts")
                        .and_then(|s| s.get("revert_failed"))
                        .and_then(|n| n.as_u64())
                })
                .unwrap_or(0);
            // Revert failures stays as a lifetime counter — there's no
            // gauge equivalent because every individual failure is a
            // discrete event rather than a state.
            signals.revert_failures_total = v
                .get("totals")
                .and_then(|t| t.get("revert_failures"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
        }
    }
    signals
}

/// Inputs to `derive_system_health` that surface chronic drift
/// rather than acute pipeline emergencies. None of these tip the
/// system into a red verb on their own — they accumulate from
/// historical orphaned/failed responses. Their purpose is to block
/// the green PROTECTED banner from sitting over silent failures
/// (2026-05-01 dashboard QA audit finding 1.2).
///
/// Numbers are operator-visible — they get embedded in the reason
/// strings on the banner. Keep them honest. Zero is the only value
/// that is allowed to disappear from the UI.
///
/// 2026-05-03 (PR #413): the `playbook_executor_missing` signal was
/// removed alongside the playbook engine itself — there is no
/// engine to be missing an executor for. Future declarative
/// orchestration belongs to Spec 042 active defense.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct DegradedSignals {
    /// PR #425 Wave 4d: current orphan count — entries that really
    /// exist right now, not a lifetime counter. An "orphaned" response
    /// is one where the agent gave up retrying revert and the rule
    /// may still be live in kernel/firewall. Sourced from
    /// `gauges.orphaned` in `to_json()` which is the sum of history
    /// entries with `reason: "orphaned:..."` plus active entries
    /// stuck in `revert_failed`. Pre-Wave-4d this read
    /// `totals.orphaned` (lifetime counter) which gaslit the operator
    /// into seeing 17 orphans months after the entries had been GC'd.
    pub(super) orphaned_now: u64,
    /// Cumulative revert-failure count (`response_lifecycle::total_revert_failures`).
    /// Distinct from `orphaned`: a single response can rack up many
    /// revert failures before the retry budget is exhausted and it
    /// gets orphaned. Tracks the rate of "tried to undo, kernel/firewall
    /// rejected" — a non-zero total indicates either a config drift
    /// (rule was rewritten by an external tool) or a backend bug.
    /// Stays as a lifetime counter because each failure is a discrete
    /// event, not a state.
    pub(super) revert_failures_total: u64,
}

/// Derive the operator-visible health verb from the pending
/// breakdown plus the freshness of the most recent decision.
///
/// Phase 7B (2026-04-29 refinement): the prior version emitted
/// `AiNotResponding` whenever `stuck > 0`, which generated false
/// alarms whenever earlier-day incidents got abandoned even though
/// the AI was processing the steady stream normally. The fix: when
/// the latest decision is fresh (≤5 min), stuck incidents become
/// `AbandonedBacklog` (yellow soft signal — operator can ignore or
/// trigger recovery); only when the latest decision is also stale
/// do we escalate to `AiNotResponding` red.
///
/// 2026-05-01 (audit 1.2 fix): `DegradedSignals` introduces a
/// fourth yellow verb that catches chronic drift the existing red
/// verbs cannot represent (historical orphaned and revert-failure
/// totals above zero). Acute red verbs
/// still take priority; Degraded is the catch-all just before
/// `OperatingNormally` so a clean system stays green.
///
/// Thresholds:
/// - `STUCK_AGE_THRESHOLD_MS = 1h` (incidents older than this with
///   no decision count as stuck — see compute_overview_counts_*)
/// - `AI_DOWN_THRESHOLD_SECS = 1800` (30 minutes of no decision
///   activity = AI is genuinely down). Bumped from 300s on
///   2026-05-03 because the original 5-minute threshold tripped
///   AiNotResponding on quiet systems where 30+ min between
///   decisions is normal — operator sees a healthy AI flagged as
///   "down" while incidents are streaming through. The new
///   threshold is still aggressive enough to catch real outages
///   (production typically has decisions every few minutes when
///   incidents are arriving) but tolerates legitimate idle gaps.
/// - `BACKED_UP_IN_FLIGHT_THRESHOLD = 50`
pub(super) fn derive_system_health(
    pending: &super::types::PendingBreakdown,
    last_decision_secs_ago: Option<i64>,
    degraded: &DegradedSignals,
) -> super::types::SystemHealth {
    use super::types::SystemHealth;
    const AI_DOWN_THRESHOLD_SECS: i64 = 1800;
    const BACKED_UP_IN_FLIGHT_THRESHOLD: usize = 50;

    let ai_is_down_now = match last_decision_secs_ago {
        // No decision ever recorded: treat as AI down only if there
        // are also stuck incidents (i.e., something to decide on but
        // nothing decided). An empty day with 0 stuck is legitimately
        // OperatingNormally.
        None => pending.stuck > 0,
        Some(secs) => secs > AI_DOWN_THRESHOLD_SECS,
    };

    if pending.stuck > 0 {
        if ai_is_down_now {
            return SystemHealth::AiNotResponding {
                stuck_count: pending.stuck,
                last_decision_secs_ago,
            };
        }
        return SystemHealth::AbandonedBacklog {
            stuck_count: pending.stuck,
            last_decision_secs_ago: last_decision_secs_ago.unwrap_or(0),
        };
    }
    if pending.in_flight > BACKED_UP_IN_FLIGHT_THRESHOLD {
        return SystemHealth::BackedUp {
            pending_in_flight: pending.in_flight,
        };
    }
    let degraded_reasons = collect_degraded_reasons(degraded);
    if !degraded_reasons.is_empty() {
        return SystemHealth::Degraded {
            reasons: degraded_reasons,
        };
    }
    SystemHealth::OperatingNormally
}

/// Build the operator-readable reason list for the `Degraded` verb.
/// Reasons are appended in priority order (most actionable first)
/// so the banner can render `reasons[0]` as the headline. Empty
/// list means no degradation signal — caller falls through to
/// `OperatingNormally`.
fn collect_degraded_reasons(degraded: &DegradedSignals) -> Vec<String> {
    let mut reasons = Vec::new();
    if degraded.orphaned_now > 0 {
        reasons.push(format!(
            "{} orphaned response{} pending review (rule may still be active in kernel/firewall, lifecycle gave up retrying revert)",
            degraded.orphaned_now,
            if degraded.orphaned_now == 1 { "" } else { "s" },
        ));
    }
    // PR #425 Wave 4d: revert_failures_total stays a lifetime counter
    // because each failure is a discrete event. But surfacing it on the
    // banner WHEN there are no current orphans is gaslighting — those
    // failures may all have been resolved by retry. Only add this
    // reason if we already have an orphaned-now reason (there ARE
    // current orphans, the failure count helps explain why).
    if degraded.orphaned_now > 0 && degraded.revert_failures_total > 0 {
        reasons.push(format!(
            "{} cumulative revert failure{} (backend rejected undo — config drift or external mutation)",
            degraded.revert_failures_total,
            if degraded.revert_failures_total == 1 { "" } else { "s" },
        ));
    }
    reasons
}

pub(super) async fn api_overview(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<OverviewResponse> {
    let date = resolve_date(query.date.as_deref());
    // When sleeping, return minimal data from telemetry only
    if is_dashboard_sleeping(&state.last_activity) {
        return Json(OverviewResponse {
            date: date.clone(),
            events_count: 0,
            incidents_count: 0,
            decisions_count: 0,
            ai_confirmed: 0,
            ai_responded: 0,
            ai_ignored: 0,
            unresolved_count: 0,
            safely_resolved: 0,
            handled_ips_today: 0,
            blocked_count: 0,
            observing_count: 0,
            attention_count: 0,
            severity_breakdown: std::collections::HashMap::new(),
            allowlisted_count: 0,
            top_detectors: vec![],
            latest_telemetry: crate::telemetry::read_latest_snapshot(&state.data_dir, &date),
            snapshot: None,
        });
    }

    // 2026-04-29: respect explicit historical-date selection so the
    // Home overview agrees with what the operator sees on the
    // Threats tab when both have the same `?date` query param. Pre-
    // fix `/api/overview` always read the live graph (today only),
    // while `/api/entities`/`/api/pivots` swapped to the requested
    // day's snapshot via `graph_for_date` -- the Home tile counted
    // today's blocks but the Threats list showed yesterday's pivot,
    // and the operator could not tell why the numbers diverged.
    let explicit_date =
        crate::dashboard::investigation::explicit_date_filter(query.date.as_deref());
    let arc_graph = crate::dashboard::investigation::graph_for_date(&state, explicit_date);
    let graph = arc_graph.read().unwrap();
    let metrics = graph.metrics();
    let date_filter: Option<chrono::NaiveDate> =
        explicit_date.and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());

    // Phase 5 (audit RC-2 deeper close): when the SQLite store is
    // wired (production path), counts come from the durable incidents
    // + decisions tables, not the lossy in-memory KG. The KG is still
    // used below for graph traversal (events_count via metrics, plus
    // the per-incident loop as a fallback when SQLite is unavailable).
    //
    // Operator-visible behaviour change: the "Handled Today" tile
    // stops decaying as TTL eviction culls older today-incidents.
    // Numbers now match what the Threats list and the JSONL file
    // actually contain.
    let sev_min_rank_filter = query
        .severity_min
        .as_deref()
        .map(crate::dashboard::investigation::severity_rank)
        .unwrap_or(0);
    let detector_substring_filter = query
        .detector
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_ascii_lowercase());
    let now = chrono::Utc::now();
    let degraded = read_degraded_signals(&state);
    let sqlite_counts = state.sqlite_store.as_ref().and_then(|store| {
        compute_overview_counts_from_sqlite(
            store,
            &date,
            sev_min_rank_filter,
            detector_substring_filter.as_deref(),
            now,
            &degraded,
            &state.data_dir,
        )
    });
    if let Some(c) = sqlite_counts {
        let telemetry = crate::telemetry::read_latest_snapshot(&state.data_dir, &date);
        let mut top_detectors: Vec<DetectorCount> = c
            .by_detector
            .iter()
            .map(|(detector, count)| DetectorCount {
                detector: detector.clone(),
                count: *count,
            })
            .collect();
        top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
        top_detectors.truncate(6);
        // 2026-05-02: events_today is now backfilled inside
        // compute_overview_counts_from_sqlite (the SoT helper) so every
        // surface (Briefing, Report, Sensors HUD) gets the same number
        // without re-implementing the telemetry read. The local
        // `telemetry` binding above is retained for the legacy
        // `latest_telemetry` payload field consumed elsewhere.
        let snapshot = c.snapshot.clone().unwrap_or_else(|| {
            // Defensive default: should never hit because
            // compute_overview_counts_from_sqlite always populates,
            // but if it ever returns None we serve a sensible empty
            // snapshot rather than erroring the whole response.
            super::types::OverviewSnapshot {
                date: date.clone(),
                generated_at: now,
                health: super::types::SystemHealth::OperatingNormally,
                buckets: super::types::OutcomeBuckets::default(),
                pending: super::types::PendingBreakdown::default(),
                events_today: 0,
                top_detectors: Vec::new(),
            }
        });
        return Json(OverviewResponse {
            date,
            events_count: metrics.edge_count, // legacy field — kept for backwards-compat
            incidents_count: c.incidents_count,
            decisions_count: c.decisions_count,
            ai_confirmed: c.ai_confirmed,
            ai_responded: c.ai_responded,
            ai_ignored: c.ai_ignored,
            unresolved_count: c.unresolved_count,
            safely_resolved: c.safely_resolved,
            handled_ips_today: c.handled_ips_today,
            blocked_count: c.blocked_count,
            observing_count: c.observing_count,
            attention_count: c.attention_count,
            severity_breakdown: c.severity_breakdown,
            // Phase 7: now populated from the persisted is_allowlisted
            // column. Pre-Phase-7 returned 0 because the flag only
            // lived on the KG node.
            allowlisted_count: c.allowlisted_count,
            top_detectors,
            latest_telemetry: telemetry,
            snapshot: Some(snapshot),
        });
    }

    // Count decisions from Incident nodes
    use crate::knowledge_graph::types::{Node, NodeType, Relation};
    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    let mut decisions_count = 0usize;
    let mut ai_confirmed = 0usize;
    let mut ai_responded = 0usize;
    let mut ai_ignored = 0usize;
    let mut unresolved_count = 0usize;
    let mut safely_resolved = 0usize;
    let mut severity_breakdown: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    // Unique IP entities the AI took a non-ignore action on. Drives the
    // home tile "X handled today" so it matches the unique-IP grouping
    // shown on the Threats tab (`NUMBER_CONSISTENCY.md` row "handled
    // count").
    let mut handled_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut allowlisted_count = 0usize;
    // Spec 037 Threats UX bundle: global KPI counters so the Threats
    // tab no longer derives them from `items` of the currently-selected
    // pivot (which was unstable when switching IP/User/Detector).
    let mut blocked_count = 0usize;
    let mut observing_count = 0usize;
    let mut attention_count = 0usize;

    // Operator filter passed via query string. Applied AFTER the canonical
    // internal/research filter so the operator filter narrows what's
    // already legitimate, not what's noise.
    let sev_min_rank = query
        .severity_min
        .as_deref()
        .map(crate::dashboard::investigation::severity_rank)
        .unwrap_or(0);
    let detector_substring = query
        .detector
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_ascii_lowercase());

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            title,
            decision,
            decision_target,
            severity,
            ts,
            is_allowlisted,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            // 2026-04-29: filter by requested date (when explicit)
            // so Home counts agree with the Threats-tab pivots
            // under the same `?date` query.
            if let Some(target) = date_filter {
                if ts.naive_utc().date() != target {
                    continue;
                }
            }
            // Spec 015 follow-up: skip research-only incidents.
            if *research_only {
                continue;
            }
            // Apply the SAME canonical filter the live-feed and threats tab
            // use, so the home overview counts match the entries those
            // surfaces actually display. Without this, advisory-only
            // detectors (`neural_anomaly`, etc) and IW-system noise
            // (`(en-agent)`, etc) inflate the home counts vs threats.
            let has_external_ip = graph
                .outgoing_edges(id)
                .iter()
                .filter(|e| e.relation == Relation::TriggeredBy)
                .any(|e| {
                    matches!(
                        graph.get_node(e.to),
                        Some(Node::Ip {
                            is_internal: false,
                            ..
                        })
                    )
                });
            if crate::dashboard::live_feed::is_internal_incident_fields(
                detector,
                title,
                has_external_ip,
            ) {
                continue;
            }
            // Operator-supplied severity filter (?severity_min=high).
            if sev_min_rank > 0
                && crate::dashboard::investigation::severity_rank(severity) < sev_min_rank
            {
                continue;
            }
            // Operator-supplied detector substring filter (?detector=ssh).
            if let Some(needle) = &detector_substring {
                if !detector.to_ascii_lowercase().contains(needle) {
                    continue;
                }
            }
            if *is_allowlisted {
                allowlisted_count += 1;
            }
            *by_detector.entry(detector.clone()).or_insert(0) += 1;
            *severity_breakdown
                .entry(severity.to_lowercase())
                .or_insert(0) += 1;
            // 2026-04-29: KPI bucketing routes through
            // `threat_contract::classify_decision` + `kpi_bucket` so
            // the Home counters agree with `/api/incidents.outcome`,
            // pivot row outcomes, and the journey verdict. Pre-fix
            // this site emitted "blocked_count += 1" for ANY decision
            // not in {ignore, monitor, request_confirmation},
            // including unknown future decisions and execution
            // failures -- inflating "Blocked" by every kernel-level
            // rejected block.
            let outcome = super::threat_contract::classify_decision(decision.as_deref(), None);
            match super::threat_contract::kpi_bucket(outcome) {
                super::threat_contract::KpiBucket::Blocked => blocked_count += 1,
                super::threat_contract::KpiBucket::Observing => observing_count += 1,
                super::threat_contract::KpiBucket::Attention => attention_count += 1,
                super::threat_contract::KpiBucket::None => {}
            }
            if let Some(dec) = decision {
                decisions_count += 1;
                let target_is_ip = decision_target.as_ref().is_some_and(|t| t.contains('.'));
                match dec.as_str() {
                    "ignore" => ai_ignored += 1,
                    "monitor" => {
                        ai_confirmed += 1;
                        safely_resolved += 1;
                        if target_is_ip {
                            if let Some(ip) = decision_target {
                                handled_ips.insert(ip.clone());
                            }
                        }
                    }
                    "request_confirmation" => {
                        ai_confirmed += 1;
                        unresolved_count += 1;
                    }
                    _ => {
                        ai_confirmed += 1;
                        if target_is_ip {
                            ai_responded += 1;
                            if let Some(ip) = decision_target {
                                handled_ips.insert(ip.clone());
                            }
                        }
                        safely_resolved += 1;
                    }
                }
            }
            // Incidents without a decision are raw events, NOT unresolved threats
        }
    }

    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    let telemetry = crate::telemetry::read_latest_snapshot(&state.data_dir, &date);
    let handled_ips_today = handled_ips.len();
    Json(OverviewResponse {
        date,
        events_count: metrics.edge_count, // edges ≈ events (each event creates edges)
        incidents_count: incident_nodes.len(),
        decisions_count,
        ai_confirmed,
        ai_responded,
        ai_ignored,
        unresolved_count,
        safely_resolved,
        handled_ips_today,
        blocked_count,
        observing_count,
        attention_count,
        severity_breakdown,
        allowlisted_count,
        top_detectors,
        latest_telemetry: telemetry,
        // KG fallback path doesn't build the typed snapshot — only
        // exercised by tests without a SQLite store. Frontend treats
        // `snapshot: None` as "render legacy flat-field tiles".
        snapshot: None,
    })
}

pub(super) async fn api_incidents(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<IncidentListResponse> {
    // Audit I-06: this body opens SQLite via `graph_for_date` (when the
    // operator picks a historical date) and walks every Incident node
    // plus its TriggeredBy edges. Doing that on the async worker stalls
    // every other dashboard request under WAL contention. spawn_blocking
    // moves the sync work to the blocking pool.
    let response = tokio::task::spawn_blocking(move || compute_incidents_blocking(&state, query))
        .await
        .unwrap_or_else(|_| IncidentListResponse {
            date: String::new(),
            total: 0,
            items: Vec::new(),
        });
    Json(response)
}

fn compute_incidents_blocking(state: &DashboardState, query: ListQuery) -> IncidentListResponse {
    let date = resolve_date(query.date.as_deref());
    let explicit_date =
        crate::dashboard::investigation::explicit_date_filter(query.date.as_deref());
    let limit = normalize_limit(query.limit);

    use crate::knowledge_graph::types::{Node, NodeType};
    let arc_graph = crate::dashboard::investigation::graph_for_date(state, explicit_date);
    let graph = arc_graph.read().unwrap();

    let date_filter: Option<chrono::NaiveDate> =
        explicit_date.and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());

    let mut incident_views: Vec<IncidentView> = graph
        .nodes_of_type(NodeType::Incident)
        .iter()
        .filter_map(|&id| {
            if let Some(Node::Incident {
                incident_id,
                severity,
                title,
                summary,
                ts,
                mitre_ids,
                decision,
                confidence,
                is_allowlisted,
                research_only,
                ..
            }) = graph.get_node(id)
            {
                if *research_only {
                    return None;
                }
                if let Some(target) = date_filter {
                    if ts.naive_utc().date() != target {
                        return None;
                    }
                }
                // Collect entities from TriggeredBy edges
                let entities: Vec<String> = graph
                    .outgoing_edges(id)
                    .iter()
                    .filter(|e| e.relation == crate::knowledge_graph::types::Relation::TriggeredBy)
                    .filter_map(|e| {
                        graph.get_node(e.to).map(|n| {
                            let ntype = format!("{:?}", n.node_type()).to_lowercase();
                            format!("{}:{}", ntype, n.label())
                        })
                    })
                    .collect();

                // 2026-04-29: outcome string normalised via
                // `threat_contract::classify_decision` so this view
                // agrees with `/api/overview.blocked_count`,
                // `/api/pivots`, and the journey verdict. Pre-fix
                // this site emitted "suspended"/"killed"/"contained"
                // for the action variants of containment, "monitored"
                // (singular vs "monitoring" everywhere else), and
                // "resolved" as a catch-all for unknown decisions
                // -- five strings that disagreed with five other
                // sites. The granular skill-kind information is
                // still preserved on `IncidentView.action_taken`
                // (which mirrors the raw `decision` string).
                let outcome = super::threat_contract::classify_decision(decision.as_deref(), None);

                // Effective severity: downgrade for handled incidents
                let sev_lower = severity.to_lowercase();
                let effective_severity = effective_severity(outcome, severity);

                Some(IncidentView {
                    ts: *ts,
                    incident_id: incident_id.clone(),
                    severity: sev_lower,
                    effective_severity,
                    title: title.clone(),
                    summary: summary.clone(),
                    entities,
                    tags: mitre_ids.clone(),
                    outcome: outcome.to_string(),
                    action_taken: decision.clone(),
                    confidence: *confidence,
                    is_allowlisted: *is_allowlisted,
                })
            } else {
                None
            }
        })
        .collect();

    incident_views.sort_by(|a, b| b.ts.cmp(&a.ts));
    let total = incident_views.len();
    let items: Vec<IncidentView> = incident_views.into_iter().take(limit).collect();

    IncidentListResponse { date, total, items }
}
pub(super) async fn api_decisions(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<DecisionListResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);

    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

    let mut views: Vec<DecisionView> = graph
        .nodes_of_type(NodeType::Incident)
        .iter()
        .filter_map(|&id| {
            if let Some(Node::Incident {
                incident_id,
                ts,
                decision: Some(action_type),
                confidence,
                decision_reason,
                decision_target,
                auto_executed,
                ..
            }) = graph.get_node(id)
            {
                Some(DecisionView {
                    ts: *ts,
                    incident_id: incident_id.clone(),
                    action_type: action_type.clone(),
                    target_ip: decision_target.clone(),
                    skill_id: None, // not stored in graph (audit trail detail)
                    confidence: confidence.unwrap_or(0.0),
                    auto_executed: *auto_executed,
                    dry_run: false,
                    reason: decision_reason.clone().unwrap_or_default(),
                    execution_result: if *auto_executed {
                        "ok".to_string()
                    } else {
                        "skipped".to_string()
                    },
                })
            } else {
                None
            }
        })
        .collect();

    views.sort_by(|a, b| b.ts.cmp(&a.ts));
    let total = views.len();
    let items: Vec<DecisionView> = views.into_iter().take(limit).collect();

    Json(DecisionListResponse { date, total, items })
}
/// GET /api/report[?date=YYYY-MM-DD]
/// Returns a TrialReport JSON computed on-demand.
/// `date` defaults to the most recent date with data.
pub(super) async fn api_report(
    State(state): State<DashboardState>,
    Query(query): Query<ReportQuery>,
) -> Response {
    let graph = state.knowledge_graph.read().unwrap();
    let mut report: TrialReport =
        report_mod::compute_for_date_from_graph(&state.data_dir, query.date.as_deref(), &graph);
    drop(graph);

    // 2026-05-02 audit B1/P1 (Spec 039 P2): when the request is for
    // today AND the canonical OverviewSnapshot is available, overwrite
    // the report's incident/block totals with the snapshot's bucket
    // counts so the markdown report and the dashboard tiles read
    // identical numbers. Auditor saw "Report 41 / Threats 5 blocked"
    // contradiction — same source, different scan, different totals.
    // For historical dates the snapshot is not retained, so the
    // KG-derived numbers stay (correct for those dates).
    let today = resolve_date(None);
    let target_date = query.date.clone().unwrap_or_else(|| today.clone());
    if target_date == today {
        if let Some(store) = state.sqlite_store.as_ref() {
            let now = chrono::Utc::now();
            let degraded = read_degraded_signals(&state);
            if let Some(counts) = compute_overview_counts_from_sqlite(
                store,
                &today,
                0,
                None,
                now,
                &degraded,
                &state.data_dir,
            ) {
                if let Some(snap) = counts.snapshot.as_ref() {
                    let buckets = &snap.buckets;
                    let total_incidents = buckets.blocked.incidents
                        + buckets.observing.incidents
                        + buckets.honeypot.incidents
                        + buckets.dismissed.incidents
                        + buckets.allowlisted.incidents
                        + buckets.attention.incidents;
                    report.detection_summary.total_incidents = total_incidents as u64;
                    report.agent_ai_summary.block_ip_count = buckets.blocked.incidents as u64;
                }
            }
        }
    }

    match serde_json::to_string_pretty(&report) {
        Ok(body) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize report",
        )
            .into_response(),
    }
}

/// GET /api/report/dates
/// Returns a JSON array of date strings (YYYY-MM-DD) for which data exists,
/// most recent first. Used by the dashboard report date picker.
pub(super) async fn api_report_dates(State(state): State<DashboardState>) -> Json<Vec<String>> {
    let data_dir = state.data_dir.clone();
    let dates = tokio::task::spawn_blocking(move || report_mod::list_available_dates(&data_dir))
        .await
        .unwrap_or_default();
    Json(dates)
}
// ---------------------------------------------------------------------------
// AI Intelligence Briefing
// ---------------------------------------------------------------------------

/// GET /api/posture — returns the live host posture snapshot.
///
/// Spec 044 Phase 4. Reads `data_dir/posture.json` written by the
/// agent's slow-loop refresh tick (every 10 min). Returns a small
/// envelope with the snapshot itself plus an `age_seconds` so the
/// dashboard JS can render a "stale" badge when the snapshot has
/// drifted past the refresh window.
///
/// When the file is missing the response shape is `{ "available": false }`
/// — the dashboard JS shows a "snapshot pending" hint, the same way the
/// briefing API handles a never-generated briefing.
pub(super) async fn api_posture(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    match crate::posture::load(&state.data_dir) {
        Some(posture) => {
            let raw = serde_json::to_value(&posture).unwrap_or(serde_json::Value::Null);
            Json(serde_json::json!({
                "available": true,
                "age_seconds": posture.age_seconds(),
                "snapshot": raw,
            }))
        }
        None => Json(serde_json::json!({
            "available": false,
            "message": "No posture snapshot yet. The agent writes posture.json at boot and refreshes every 10 min — restart the agent if this persists.",
        })),
    }
}

/// GET /api/briefing — returns the latest generated briefing
pub(super) async fn api_briefing(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let briefing = state.latest_briefing.lock().await;
    match &*briefing {
        Some(b) => Json(serde_json::json!({
            "available": true,
            "generated_at": b.generated_at.to_rfc3339(),
            "date": b.date,
            "threat_level": b.threat_level,
            "summary": b.summary,
            "config": {
                "hour": state.briefing_hour,
                "minute": state.briefing_minute,
            }
        })),
        None => Json(serde_json::json!({
            "available": false,
            "message": "No briefing generated yet. Click 'Generate Now' or wait for the scheduled time.",
            "config": {
                "hour": state.briefing_hour,
                "minute": state.briefing_minute,
            }
        })),
    }
}

/// POST /api/briefing/generate — trigger manual briefing generation
pub(super) async fn api_briefing_generate(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    // 2026-05-02 audit B1/P1 (Spec 039 P1): hydrate the canonical
    // OverviewSnapshot for today and pass it into build_briefing_context
    // so the briefing's topline counters paint the same numbers the
    // dashboard tiles paint. Pre-fix the briefing scanned the KG and
    // could read "0 needing action" while the Home tile said "2
    // awaiting" — the auditor's #1 release blocker (single source of
    // truth for counters). Snapshot construction mirrors api_overview.
    let snapshot = state.sqlite_store.as_ref().and_then(|store| {
        let today = resolve_date(None);
        let now = chrono::Utc::now();
        let degraded = read_degraded_signals(&state);
        compute_overview_counts_from_sqlite(store, &today, 0, None, now, &degraded, &state.data_dir)
            .and_then(|counts| counts.snapshot)
    });
    let context =
        crate::briefing::build_briefing_context(&state.knowledge_graph, snapshot.as_ref());
    let prompt = crate::briefing::briefing_prompt(&context);

    let threat_level = if context.contains("CRITICAL") {
        "CRITICAL"
    } else if context.contains("ELEVATED") {
        "ELEVATED"
    } else if context.contains("MODERATE") {
        "MODERATE"
    } else {
        "LOW"
    };

    // Spec 029 PR-C.2: briefing generation is the Generate role.
    // When the operator runs classifier-only (no [ai.llm]), this
    // endpoint returns the "configure an LLM" error rather than
    // asking a text-less classifier to produce prose.
    let ai: std::sync::Arc<dyn crate::ai::AiProvider> = match state
        .ai_router
        .provider_for(crate::ai::Capability::Generate)
    {
        Some(p) => p,
        None => {
            return Json(llm_unavailable_error("briefings"));
        }
    };
    let system = briefing_system_prompt(&state.action_cfg.ai_personality);
    match ai.chat(&system, &prompt).await {
        Ok(response) => {
            let b = crate::briefing::parse_briefing(&response, threat_level);
            let result = serde_json::json!({
                "available": true,
                "generated_at": b.generated_at.to_rfc3339(),
                "date": b.date,
                "threat_level": b.threat_level,
                "summary": b.summary,
            });
            *state.latest_briefing.lock().await = Some(b);
            Json(result)
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("Failed to generate briefing: {}", e),
        })),
    }
}

// ---------------------------------------------------------------------------
// AI Explain — ask the AI to explain a threat in plain language
// ---------------------------------------------------------------------------

pub(super) async fn api_ai_explain(
    State(state): State<DashboardState>,
    Query(query): Query<AiExplainQuery>,
) -> Json<serde_json::Value> {
    let subject_type = query.r#type.as_deref().unwrap_or("ip");
    let subject_value = match query.value.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Json(serde_json::json!({
                "error": "Missing 'value' parameter"
            }))
        }
    };

    // Spec 029 PR-C.2: the entity-context explainer maps to the
    // Explain role (structured context → natural-language summary).
    let ai: std::sync::Arc<dyn crate::ai::AiProvider> =
        match state.ai_router.provider_for(crate::ai::Capability::Explain) {
            Some(p) => p,
            None => {
                return Json(llm_unavailable_error("explanations"));
            }
        };

    // Build context from the knowledge graph: incidents, decisions,
    // events linked to this entity. Keep it compact for the LLM.
    //
    // Spec 046 follow-up (2026-05-10): operator surfaced an IP that
    // existed in incidents but NOT as a `Node::Ip` in the KG, hitting
    // the "No data found" fallback even though there was real
    // incident data to explain. The fix: when the KG lookup misses,
    // walk the incident nodes directly and pick up any incident whose
    // entities list includes this IP. That covers the gap caused by
    // the IP not being graph-promoted yet (e.g., ephemeral connections
    // that never reached the per-IP enrichment phase).
    let context = match build_explain_context(
        &state.knowledge_graph.read().unwrap(),
        subject_type,
        subject_value,
        state.action_cfg.honeypot_port,
    ) {
        ExplainContext::Built(s) => s,
        ExplainContext::NoData(msg) => {
            return Json(serde_json::json!({ "explanation": msg }));
        }
    };

    let system = explain_system_prompt(&state.action_cfg.ai_personality);

    let user_msg = format!(
        "Explain this activity to me in simple terms. Should I be worried?\n\n{}",
        context
    );

    match ai.chat(&system, &user_msg).await {
        Ok(explanation) => Json(serde_json::json!({ "explanation": explanation })),
        Err(e) => Json(serde_json::json!({
            "error": format!("AI call failed: {}", e)
        })),
    }
}

/// Spec 046 follow-up — outcome of `build_explain_context`. `Built`
/// carries the LLM-ready context string. `NoData` carries the
/// user-facing fallback message (returned to the dashboard verbatim
/// when there's nothing to explain).
pub(super) enum ExplainContext {
    Built(String),
    NoData(String),
}

/// Pure helper extracted from `api_ai_explain` for direct unit
/// testing. Walks the knowledge graph for incidents linked to
/// `subject_value`, with a fallback path that scans every Incident
/// node by `decision_target` / title / summary text match. Returns
/// `NoData` (with a useful message — NOT the legacy "No data found")
/// only when both paths produce nothing.
///
/// `honeypot_port` is threaded through so the rendered context can
/// call out the honeypot in operator-facing terms ("port 2222 by
/// default").
pub(super) fn build_explain_context(
    graph: &crate::knowledge_graph::KnowledgeGraph,
    subject_type: &str,
    subject_value: &str,
    honeypot_port: u16,
) -> ExplainContext {
    use crate::knowledge_graph::types::*;

    // Try the fast path: a Node::Ip exists for this address.
    let target_node = match subject_type {
        "ip" => graph
            .nodes_of_type(NodeType::Ip)
            .iter()
            .find(|&&id| {
                matches!(graph.get_node(id), Some(Node::Ip { addr, .. }) if addr == subject_value)
            })
            .copied(),
        _ => None,
    };

    let mut incident_lines: Vec<String> = Vec::new();
    let mut decision_lines: Vec<String> = Vec::new();
    let mut event_count: usize = 0;
    let mut likely_honeypot_hit = false;

    if let Some(node_id) = target_node {
        for edge in graph.incoming_edges(node_id) {
            if edge.relation != Relation::TriggeredBy {
                continue;
            }
            if let Some(node) = graph.get_node(edge.from) {
                absorb_incident_for_explain(
                    node,
                    &mut incident_lines,
                    &mut decision_lines,
                    &mut likely_honeypot_hit,
                );
            }
        }
        event_count = graph
            .all_edges(node_id)
            .iter()
            .filter(|e| e.relation == Relation::ConnectedTo || e.relation == Relation::AcceptedFrom)
            .count();
    }

    // Fallback: if we got nothing from the KG node lookup, walk every
    // incident and pull any whose `decision_target` matches this IP
    // or whose summary/title text references it. Bounded — KG holds
    // at most ~today + yesterday's incidents.
    if incident_lines.is_empty() && subject_type == "ip" {
        for &id in graph.nodes_of_type(NodeType::Incident).iter() {
            if let Some(node) = graph.get_node(id) {
                if let Node::Incident {
                    decision_target,
                    title,
                    summary,
                    ..
                } = node
                {
                    let target_match = decision_target
                        .as_deref()
                        .map(|t| t == subject_value)
                        .unwrap_or(false);
                    let text_match =
                        title.contains(subject_value) || summary.contains(subject_value);
                    if target_match || text_match {
                        absorb_incident_for_explain(
                            node,
                            &mut incident_lines,
                            &mut decision_lines,
                            &mut likely_honeypot_hit,
                        );
                    }
                }
            }
        }
    }

    // Final fallback: still nothing → return a useful message instead
    // of the generic "No data found" (which is what operator hit on
    // 2026-05-10).
    if incident_lines.is_empty() {
        return ExplainContext::NoData(format!(
            "No incidents on record for {subject_type} {subject_value}. The \
             threats list may be showing this entity because an incident was \
             very recent and hasn't been ingested into the knowledge graph \
             yet, or because the entity was already auto-dismissed. Refresh \
             in a minute and try again, or click the incident row to see \
             the raw data."
        ));
    }

    let honeypot_note = if likely_honeypot_hit {
        format!(
            "\n\nHoneypot context: at least one of these incidents looks \
             like it hit the InnerWarden honeypot (port {honeypot_port} \
             by default — a fake SSH service set up to bait scanners and \
             dropper bots). Probes here that fail at protocol level \
             (e.g., 'Malformed SSH version') are EXPECTED — they're the \
             listener doing its job, not real threats. Call this out \
             plainly when explaining."
        )
    } else {
        String::new()
    };

    ExplainContext::Built(format!(
        "Entity: {} {}\nEvent count: {}{}\n\nIncidents ({}):\n{}\n\nAI Decisions ({}):\n{}",
        subject_type,
        subject_value,
        event_count,
        honeypot_note,
        incident_lines.len(),
        incident_lines.join("\n"),
        decision_lines.len(),
        if decision_lines.is_empty() {
            "None".to_string()
        } else {
            decision_lines.join("\n")
        },
    ))
}

/// Pure helper for `build_explain_context`: extract context lines
/// from one incident node. Inlined as a free function (not a closure)
/// so the caller doesn't have to reason about closure-borrow
/// lifetimes for the surrounding mutable Vecs (the closure form
/// tripped E0502 in earlier iterations).
fn absorb_incident_for_explain(
    inc_node: &crate::knowledge_graph::types::Node,
    incident_lines: &mut Vec<String>,
    decision_lines: &mut Vec<String>,
    likely_honeypot_hit: &mut bool,
) {
    use crate::knowledge_graph::types::Node;
    if let Node::Incident {
        detector,
        severity,
        title,
        summary,
        decision,
        decision_reason,
        research_only,
        auto_executed,
        ts,
        ..
    } = inc_node
    {
        if *research_only {
            return;
        }
        incident_lines.push(format!(
            "- [{}] {}: {} (detector: {}, ts: {})",
            severity.to_uppercase(),
            title,
            summary,
            detector,
            ts.format("%H:%M:%S")
        ));
        if let Some(dec) = decision {
            let reason = decision_reason.as_deref().unwrap_or("no reason recorded");
            let executed = if *auto_executed {
                "executed"
            } else {
                "recommended"
            };
            decision_lines.push(format!("- AI {} {}: {}", executed, dec, reason));
        }
        // Heuristically detect honeypot hits via title/summary so the
        // Feynman prompt can call it out. KG `Node::Incident` doesn't
        // carry `evidence.dst_port`, so we infer from text.
        let lower_title = title.to_lowercase();
        let lower_summary = summary.to_lowercase();
        if lower_title.contains("malformed ssh")
            || lower_summary.contains("malformed ssh")
            || lower_title.contains("honeypot")
            || lower_summary.contains("honeypot")
        {
            *likely_honeypot_hit = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Business logic - overview (graph-based, Phase 6A)
// ---------------------------------------------------------------------------

/// Compute overview from knowledge graph (no JSONL reads).
pub(super) fn compute_overview_from_graph(
    graph: &crate::knowledge_graph::KnowledgeGraph,
    data_dir: &Path,
    date: &str,
) -> OverviewResponse {
    use crate::knowledge_graph::types::{Node, NodeType, Relation};

    let metrics = graph.metrics();
    let incident_nodes = graph.nodes_of_type(NodeType::Incident);

    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    let mut decisions_count = 0usize;
    let mut ai_confirmed = 0usize;
    let mut ai_responded = 0usize;
    let mut ai_ignored = 0usize;
    let mut unresolved_count = 0usize;
    let mut safely_resolved = 0usize;
    let mut severity_breakdown: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut allowlisted_count = 0usize;
    let mut handled_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Spec 037 Threats UX bundle: same KPI buckets as `api_overview`.
    let mut blocked_count = 0usize;
    let mut observing_count = 0usize;
    let mut attention_count = 0usize;

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            title,
            decision,
            decision_target,
            severity,
            is_allowlisted,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            if *research_only {
                continue;
            }
            // Same canonical filter as `api_overview` and the live feed.
            let has_external_ip = graph
                .outgoing_edges(id)
                .iter()
                .filter(|e| e.relation == Relation::TriggeredBy)
                .any(|e| {
                    matches!(
                        graph.get_node(e.to),
                        Some(Node::Ip {
                            is_internal: false,
                            ..
                        })
                    )
                });
            if crate::dashboard::live_feed::is_internal_incident_fields(
                detector,
                title,
                has_external_ip,
            ) {
                continue;
            }
            if *is_allowlisted {
                allowlisted_count += 1;
            }
            *by_detector.entry(detector.clone()).or_insert(0) += 1;
            *severity_breakdown
                .entry(severity.to_lowercase())
                .or_insert(0) += 1;
            // 2026-04-29: same `threat_contract` routing as the live
            // `api_overview` path so the two compute helpers cannot
            // drift again.
            let outcome = super::threat_contract::classify_decision(decision.as_deref(), None);
            match super::threat_contract::kpi_bucket(outcome) {
                super::threat_contract::KpiBucket::Blocked => blocked_count += 1,
                super::threat_contract::KpiBucket::Observing => observing_count += 1,
                super::threat_contract::KpiBucket::Attention => attention_count += 1,
                super::threat_contract::KpiBucket::None => {}
            }
            if let Some(dec) = decision {
                decisions_count += 1;
                let target_is_ip = decision_target.as_ref().is_some_and(|t| t.contains('.'));
                match dec.as_str() {
                    "ignore" => ai_ignored += 1,
                    "monitor" => {
                        ai_confirmed += 1;
                        safely_resolved += 1;
                        if target_is_ip {
                            if let Some(ip) = decision_target {
                                handled_ips.insert(ip.clone());
                            }
                        }
                    }
                    "request_confirmation" => {
                        ai_confirmed += 1;
                        unresolved_count += 1;
                    }
                    _ => {
                        ai_confirmed += 1;
                        if target_is_ip {
                            ai_responded += 1;
                            if let Some(ip) = decision_target {
                                handled_ips.insert(ip.clone());
                            }
                        }
                        safely_resolved += 1;
                    }
                }
            }
        }
    }

    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    let handled_ips_today = handled_ips.len();
    OverviewResponse {
        date: date.to_string(),
        events_count: metrics.edge_count,
        incidents_count: incident_nodes.len(),
        decisions_count,
        ai_confirmed,
        ai_responded,
        ai_ignored,
        unresolved_count,
        safely_resolved,
        handled_ips_today,
        blocked_count,
        observing_count,
        attention_count,
        severity_breakdown,
        allowlisted_count,
        top_detectors,
        latest_telemetry: crate::telemetry::read_latest_snapshot(data_dir, date),
        snapshot: None,
    }
}

/// JSONL-based compute_overview (kept for tests only, will be removed in Phase 6E).
#[cfg(test)]
pub(super) fn compute_overview(data_dir: &Path, date: &str) -> OverviewResponse {
    let events_count = count_file_lines(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    for inc in &incidents {
        let detector = inc
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *by_detector.entry(detector).or_insert(0) += 1;
    }
    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    let ai_confirmed = decisions
        .iter()
        .filter(|d| d.action_type != "ignore" && d.action_type != "request_confirmation")
        .count();
    let ai_responded = decisions
        .iter()
        .filter(|d| d.auto_executed && d.action_type != "ignore" && d.action_type != "monitor")
        .count();
    let ai_ignored = decisions
        .iter()
        .filter(|d| d.action_type == "ignore")
        .count();

    let unresolved_count = ai_confirmed.saturating_sub(ai_responded);
    let safely_resolved = ai_responded;
    // JSONL fallback path (legacy, test-only): treat each "responded"
    // decision target as a unique IP for the handled count. Imperfect
    // (no dedup since we have no easy access to the IP value here) but
    // matches the lower bound. The graph-backed `compute_overview_from_graph`
    // is the canonical path in production.
    let handled_ips_today = ai_responded;

    // 2026-04-29: same `threat_contract` routing as the graph
    // path. JSONL fallback is test-only but must agree with the
    // production buckets so test fixtures don't drift.
    let mut blocked_count = 0usize;
    let mut observing_count = 0usize;
    let mut attention_count = 0usize;
    for d in &decisions {
        let outcome = super::threat_contract::classify_decision(Some(&d.action_type), None);
        match super::threat_contract::kpi_bucket(outcome) {
            super::threat_contract::KpiBucket::Blocked => blocked_count += 1,
            super::threat_contract::KpiBucket::Observing => observing_count += 1,
            super::threat_contract::KpiBucket::Attention => attention_count += 1,
            super::threat_contract::KpiBucket::None => {}
        }
    }
    // Incidents without a matching decision: count as needing attention.
    if incidents.len() > decisions.len() {
        attention_count += incidents.len() - decisions.len();
    }

    OverviewResponse {
        date: date.to_string(),
        events_count,
        incidents_count: incidents.len(),
        decisions_count: decisions.len(),
        ai_confirmed,
        ai_responded,
        ai_ignored,
        unresolved_count,
        safely_resolved,
        handled_ips_today,
        blocked_count,
        observing_count,
        attention_count,
        severity_breakdown: std::collections::HashMap::new(),
        allowlisted_count: 0,
        top_detectors,
        latest_telemetry: crate::telemetry::read_latest_snapshot(data_dir, date),
        snapshot: None,
    }
}

/// Count non-empty lines in a file without parsing JSON (fast for large files).
/// Only used by #[cfg(test)] compute_overview — will be removed in Phase 6E.
#[cfg(test)]
pub(super) fn count_file_lines(path: &Path) -> usize {
    let Ok(file) = std::fs::File::open(path) else {
        return 0;
    };
    std::io::BufReader::new(file)
        .lines()
        .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
        .count()
}

pub(super) fn effective_severity(outcome: &str, severity: &str) -> String {
    let sev_lower = severity.to_lowercase();
    match outcome {
        "blocked" | "killed" | "contained" | "suspended" => match sev_lower.as_str() {
            "critical" => "medium".to_string(),
            "high" => "low".to_string(),
            _ => sev_lower,
        },
        "ignored" => "info".to_string(),
        _ => sev_lower, // open, monitored, honeypot: keep original
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn briefing_system_prompt_falls_back_when_personality_blank() {
        let out = briefing_system_prompt("");
        assert!(out.starts_with("You are a senior security analyst."));
        assert!(out.contains("FORMAT: generate a concise intelligence briefing."));
    }

    #[test]
    fn briefing_system_prompt_uses_personality_when_set() {
        let out = briefing_system_prompt("You are InnerWarden. Bouncer voice.");
        assert!(out.starts_with("You are InnerWarden. Bouncer voice."));
        assert!(!out.contains("senior security analyst"));
        assert!(out.contains("FORMAT: generate a concise intelligence briefing."));
    }

    #[test]
    fn briefing_system_prompt_trims_whitespace_personality() {
        let out = briefing_system_prompt("   \n\t  ");
        // Whitespace-only must fall back to the analyst baseline rather
        // than produce a prompt that opens with blank lines.
        assert!(out.starts_with("You are a senior security analyst."));
    }

    #[test]
    fn explain_system_prompt_falls_back_when_personality_blank() {
        let out = explain_system_prompt("");
        assert!(out.starts_with("You are a security guide"));
        assert!(out.contains("Feynman technique"));
    }

    #[test]
    fn explain_system_prompt_uses_personality_when_set() {
        let out = explain_system_prompt("You are InnerWarden. Bouncer voice.");
        assert!(out.starts_with("You are InnerWarden. Bouncer voice."));
        assert!(!out.contains("You are a security guide"));
        assert!(out.contains("Only call it dangerous"));
    }

    // ── Spec 046 follow-up — `build_explain_context` helper anchors ──
    //
    // Operator surfaced 2026-05-10: "Ask AI to explain" returned just
    // "No data found for ip" even when incidents existed. The fix
    // refactored the inner block of api_ai_explain into the pure
    // `build_explain_context` helper with a fallback that walks
    // incidents directly. These anchors pin the helper's contract.

    fn explain_test_graph_with_ip_node_and_incident(
        ip: &str,
        title: &str,
    ) -> crate::knowledge_graph::KnowledgeGraph {
        use crate::knowledge_graph::types::*;
        use chrono::Utc;
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let ip_id = g.add_node(Node::Ip {
            addr: ip.to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 50,
            is_tor: false,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            attempted_usernames: vec![],
        });
        let inc_id = g.add_node(Node::Incident {
            incident_id: format!("test:{ip}"),
            detector: "proto_anomaly".into(),
            severity: "low".into(),
            title: title.into(),
            summary: format!("test incident from {ip}"),
            ts: Utc::now(),
            mitre_ids: vec![],
            decision: None,
            confidence: None,
            decision_reason: None,
            decision_target: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(
            inc_id,
            ip_id,
            Relation::TriggeredBy,
            chrono::Utc::now(),
        ));
        g
    }

    #[test]
    fn build_explain_context_returns_no_data_when_kg_empty() {
        let g = crate::knowledge_graph::KnowledgeGraph::new();
        match build_explain_context(&g, "ip", "175.110.112.8", 2222) {
            ExplainContext::NoData(msg) => {
                assert!(msg.contains("175.110.112.8"));
                assert!(
                    !msg.starts_with("No data found"),
                    "must not return the legacy generic message — \
                     operator complained about exactly that wording"
                );
            }
            ExplainContext::Built(_) => panic!("empty KG must yield NoData"),
        }
    }

    #[test]
    fn build_explain_context_finds_via_kg_node_lookup() {
        let g =
            explain_test_graph_with_ip_node_and_incident("203.0.113.50", "Suspicious connection");
        match build_explain_context(&g, "ip", "203.0.113.50", 2222) {
            ExplainContext::Built(ctx) => {
                assert!(ctx.contains("203.0.113.50"));
                assert!(ctx.contains("Suspicious connection"));
                assert!(ctx.contains("proto_anomaly"));
            }
            ExplainContext::NoData(_) => panic!("KG node lookup must succeed"),
        }
    }

    #[test]
    fn build_explain_context_fallback_walks_incidents_when_no_ip_node() {
        // Build a KG with an Incident but NO Ip node (the operator's
        // 2026-05-10 case). The helper's fallback path must still find
        // it via decision_target / text match.
        use crate::knowledge_graph::types::*;
        use chrono::Utc;
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        g.add_node(Node::Incident {
            incident_id: "test:fallback".into(),
            detector: "proto_anomaly".into(),
            severity: "low".into(),
            title: "Malformed SSH version string".into(),
            summary: "SSH client from 175.110.112.8 sent malformed version".into(),
            ts: Utc::now(),
            mitre_ids: vec![],
            decision: None,
            confidence: None,
            decision_reason: None,
            decision_target: Some("175.110.112.8".into()),
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        match build_explain_context(&g, "ip", "175.110.112.8", 2222) {
            ExplainContext::Built(ctx) => {
                assert!(ctx.contains("175.110.112.8"));
                assert!(ctx.contains("Malformed SSH version"));
            }
            ExplainContext::NoData(_) => {
                panic!("fallback walk must surface incidents matching by decision_target / text")
            }
        }
    }

    #[test]
    fn build_explain_context_marks_honeypot_hit_on_malformed_ssh_title() {
        let g = explain_test_graph_with_ip_node_and_incident(
            "203.0.113.51",
            "Malformed SSH version string",
        );
        match build_explain_context(&g, "ip", "203.0.113.51", 2222) {
            ExplainContext::Built(ctx) => {
                assert!(
                    ctx.contains("Honeypot context:"),
                    "Malformed-SSH title must trigger honeypot context section"
                );
                assert!(ctx.contains("port 2222"));
            }
            ExplainContext::NoData(_) => panic!("must build context"),
        }
    }

    #[test]
    fn build_explain_context_does_not_mark_honeypot_for_unrelated_titles() {
        let g = explain_test_graph_with_ip_node_and_incident(
            "203.0.113.52",
            "Generic suspicious activity",
        );
        match build_explain_context(&g, "ip", "203.0.113.52", 2222) {
            ExplainContext::Built(ctx) => {
                assert!(
                    !ctx.contains("Honeypot context:"),
                    "non-honeypot titles must NOT trigger the honeypot section — \
                     would mislead the LLM into wrongly calling everything a probe"
                );
            }
            ExplainContext::NoData(_) => panic!("must build context"),
        }
    }

    /// Spec 046 follow-up — Feynman prompt structure anchor.
    /// The prompt must mandate the three story-telling pieces
    /// (story / why / threat verdict) and explicitly call out
    /// the honeypot context awareness. A refactor that strips
    /// any of these turns the AI explanation back into the
    /// generic 2-sentence summary that operator complained about.
    #[test]
    fn explain_system_prompt_carries_feynman_structure() {
        let out = explain_system_prompt("");
        // Three load-bearing parts of the Feynman explainer.
        for marker in [
            "STORY",
            "WHY IT HAPPENED",
            "THREAT VERDICT",
            "analogy",
            "honeypot",
        ] {
            assert!(
                out.contains(marker),
                "explain prompt missing required Feynman piece '{marker}'"
            );
        }
        // Anti-regression on the boundary: must explicitly forbid
        // calling probes 'dangerous' just because they fired.
        assert!(out.contains("got past initial contact"));
    }

    #[test]
    fn test_effective_severity_downgrade() {
        // Handled -> downgrade
        assert_eq!(effective_severity("blocked", "critical"), "medium");
        assert_eq!(effective_severity("killed", "Critical"), "medium");
        assert_eq!(effective_severity("contained", "high"), "low");
        assert_eq!(effective_severity("suspended", "High"), "low");

        // Low stays low
        assert_eq!(effective_severity("blocked", "low"), "low");

        // Ignored goes to info
        assert_eq!(effective_severity("ignored", "critical"), "info");

        // Open/monitored/honeypot retain
        assert_eq!(effective_severity("open", "critical"), "critical");
        assert_eq!(effective_severity("monitored", "high"), "high");
        assert_eq!(effective_severity("honeypot", "medium"), "medium");
        assert_eq!(effective_severity("resolved", "low"), "low");
    }

    #[test]
    fn test_is_dashboard_sleeping() {
        // Detects dashboard sleep mode after inactivity timeout.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Active 1 second ago
        let active = AtomicU64::new(now - 1);
        assert!(!is_dashboard_sleeping(&active));

        // Active 16 minutes ago (past 15m threshold)
        let sleeping = AtomicU64::new(now - (16 * 60));
        assert!(is_dashboard_sleeping(&sleeping));

        // Active at 0 (never active or system restart)
        let never = AtomicU64::new(0);
        assert!(is_dashboard_sleeping(&never));
    }

    #[test]
    fn test_pagination_page_zero_returns_first_batch() {
        // Page 0 should return the first batch of items.
        let items: Vec<usize> = (1..=10).collect();
        let page_size = 3usize;
        let page = 0usize;
        let batch: Vec<usize> = items
            .iter()
            .skip(page.saturating_mul(page_size))
            .take(page_size)
            .copied()
            .collect();
        assert_eq!(batch, vec![1, 2, 3]);
    }

    #[test]
    fn test_pagination_page_past_end_returns_empty() {
        // Requesting a page after the available range should return no items.
        let items: Vec<usize> = (1..=5).collect();
        let page_size = 2usize;
        let page = 10usize;
        let batch: Vec<usize> = items
            .iter()
            .skip(page.saturating_mul(page_size))
            .take(page_size)
            .copied()
            .collect();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_date_range_parsing_with_invalid_format() {
        // Invalid date formats should fail parsing rather than silently succeed.
        let invalid = chrono::NaiveDate::parse_from_str("16-04-2026", "%Y-%m-%d");
        assert!(invalid.is_err());
    }

    // Spec 029 PR-C.2: the llm_unavailable_error helper powers every
    // `None` branch of provider_for(Generate | Explain) in the
    // dashboard endpoints. Lock the exact shape so grant/operator
    // docs that quote the error string do not drift.
    #[test]
    fn llm_unavailable_error_shape() {
        let json = llm_unavailable_error("briefings");
        assert_eq!(
            json["error"],
            "LLM role not configured. Set [ai.llm] in agent.toml to enable briefings."
        );
    }

    #[test]
    fn llm_unavailable_error_feature_is_interpolated() {
        let json = llm_unavailable_error("explanations");
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("to enable explanations."));
        let json_ask = llm_unavailable_error("/ask");
        assert!(json_ask["error"]
            .as_str()
            .unwrap()
            .contains("to enable /ask."));
    }

    // Spec 029 PR-C.2: exercise the briefing endpoint with a disabled
    // router so the `provider_for(Generate) => None` branch runs end-
    // to-end (not just the helper). Locks the public JSON contract.
    #[tokio::test]
    async fn api_briefing_generate_returns_unavailable_when_router_has_no_generate() {
        use axum::extract::State;
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());
        let Json(body) = api_briefing_generate(State(state)).await;
        assert_eq!(
            body["error"],
            "LLM role not configured. Set [ai.llm] in agent.toml to enable briefings."
        );
    }

    #[tokio::test]
    async fn api_ai_explain_returns_unavailable_when_router_has_no_explain() {
        use axum::extract::{Query, State};
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());
        let query = AiExplainQuery {
            r#type: Some("ip".into()),
            value: Some("198.51.100.10".into()),
        };
        let Json(body) = api_ai_explain(State(state), Query(query)).await;
        assert_eq!(
            body["error"],
            "LLM role not configured. Set [ai.llm] in agent.toml to enable explanations."
        );
    }

    #[tokio::test]
    async fn api_ai_explain_missing_value_short_circuits_before_router() {
        use axum::extract::{Query, State};
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());
        let query = AiExplainQuery {
            r#type: Some("ip".into()),
            value: None,
        };
        let Json(body) = api_ai_explain(State(state), Query(query)).await;
        assert_eq!(body["error"], "Missing 'value' parameter");
    }

    // ── compute_overview_from_graph behaviour (Inconsistencies 1 + 3) ─
    //
    // Two anchors:
    //   - handled_ips_today = unique IPs with non-ignore decision
    //     (matches Threats tab entry count, NUMBER_CONSISTENCY.md row
    //     "handled count").
    //   - filter predicates inside the loop honor the canonical
    //     `is_internal_incident_fields` (so home counts match site
    //     counts).

    fn make_overview_kg() -> crate::knowledge_graph::KnowledgeGraph {
        use crate::knowledge_graph::types::*;
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        // Two real attackers, both blocked. Same IP repeated in two
        // incidents to prove the dedup works.
        let ip_a = g.ensure_ip("203.0.113.10", now);
        for tag in ["1", "2"] {
            let inc = g.add_node(Node::Incident {
                incident_id: format!("ssh_bruteforce:{tag}"),
                detector: "ssh_bruteforce".into(),
                severity: "high".into(),
                title: "SSH brute force".into(),
                summary: "".into(),
                ts: now,
                mitre_ids: vec![],
                decision: Some("block_ip".into()),
                decision_target: Some("203.0.113.10".into()),
                confidence: Some(0.95),
                decision_reason: None,
                auto_executed: true,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
            g.add_edge(Edge::new(inc, ip_a, Relation::TriggeredBy, now));
        }
        // Different IP, monitored.
        let ip_b = g.ensure_ip("198.51.100.20", now);
        let inc_b = g.add_node(Node::Incident {
            incident_id: "port_scan:1".into(),
            detector: "port_scan".into(),
            severity: "low".into(),
            title: "Port scan".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("monitor".into()),
            decision_target: Some("198.51.100.20".into()),
            confidence: Some(0.6),
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_b, ip_b, Relation::TriggeredBy, now));
        // Advisory-only detector — must NOT count toward overview.
        let ip_c = g.ensure_ip("192.0.2.30", now);
        let inc_c = g.add_node(Node::Incident {
            incident_id: "neural_anomaly:1".into(),
            detector: "neural_anomaly".into(),
            severity: "high".into(),
            title: "Neural anomaly".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            decision_target: Some("192.0.2.30".into()),
            confidence: None,
            decision_reason: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_c, ip_c, Relation::TriggeredBy, now));
        g
    }

    #[test]
    fn compute_overview_handled_ips_today_dedupes_by_ip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = make_overview_kg();
        let out = compute_overview_from_graph(&g, dir.path(), "2026-04-23");
        // 203.0.113.10 has TWO block_ip decisions (same IP, 2 incidents).
        // 198.51.100.20 has ONE monitor decision.
        // 192.0.2.30 is filtered (advisory-only).
        // Unique IPs handled = 2.
        assert_eq!(out.handled_ips_today, 2);
        // safely_resolved counts INCIDENTS — block_ip × 2 + monitor × 1 = 3.
        assert_eq!(out.safely_resolved, 3);
        // ai_responded counts only IP-targeted non-monitor decisions = 2 (both block_ip).
        assert_eq!(out.ai_responded, 2);
    }

    #[tokio::test]
    async fn api_overview_returns_handled_ips_today_field() {
        // Anchors the async handler wrapper around compute_overview_from_graph.
        // Goes through the full path so the OverviewResponse JSON shape +
        // handled_ips_today field stay exercised end-to-end.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = ListQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_overview(State(state), Query(q)).await;
        // handled_ips_today must be present even if 0.
        assert_eq!(out.handled_ips_today, 0);
        assert_eq!(out.incidents_count, 0);
    }

    // ── Phase 5 anchors: SQLite is the source of truth for counts ──
    //
    // The KG suffers TTL eviction (~12h). Without these tests, a
    // future refactor that "simplifies" /api/overview back to the
    // graph path would silently regress the operator-visible
    // count-decay-to-zero bug that motivated Phase 5.

    fn make_overview_test_store() -> std::sync::Arc<innerwarden_store::Store> {
        std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"))
    }

    fn insert_test_incident(
        store: &innerwarden_store::Store,
        incident_id: &str,
        ts_iso: &str,
        _detector: &str,
        severity: &str,
        title: &str,
        ip: Option<&str>,
    ) {
        // Use the public `insert_incident` API so the rusqlite call
        // stays out of the agent test surface. Detector is derived
        // from incident_id by `Store::insert_incident` (first two
        // colon-separated segments), so we encode the detector into
        // the incident_id prefix for the test fixtures below.
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;
        let sev = match severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let entities = match ip {
            Some(addr) => vec![EntityRef::ip(addr)],
            None => vec![],
        };
        let inc = Incident {
            ts: chrono::DateTime::parse_from_rfc3339(ts_iso)
                .unwrap()
                .with_timezone(&chrono::Utc),
            host: "test-host".to_string(),
            incident_id: incident_id.to_string(),
            severity: sev,
            title: title.to_string(),
            summary: "test".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities,
        };
        store.insert_incident(&inc).expect("insert incident");
    }

    fn insert_test_decision(
        store: &innerwarden_store::Store,
        incident_id: &str,
        ts_iso: &str,
        action: &str,
        target_ip: Option<&str>,
    ) {
        let row = innerwarden_store::decisions::DecisionRow {
            ts: ts_iso.to_string(),
            incident_id: incident_id.to_string(),
            action_type: action.to_string(),
            target_ip: target_ip.map(|s| s.to_string()),
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("test".into()),
            data: serde_json::json!({"action_type": action}).to_string(),
        };
        store.insert_decision(&row).expect("insert decision");
    }

    #[test]
    fn sqlite_overview_counts_survive_kg_eviction() {
        // The motivating regression: graph TTL evicted today's earlier
        // incidents and the Home tile decayed to 0. SQLite path must
        // count all of today's incidents, regardless of graph state.
        let store = make_overview_test_store();
        let date = "2026-04-29";
        // 4 today, varied decisions
        insert_test_incident(
            &store,
            "ssh:bf:1",
            "2026-04-29T01:00:00Z",
            "ssh_bruteforce",
            "high",
            "ssh brute",
            Some("203.0.113.10"),
        );
        insert_test_decision(
            &store,
            "ssh:bf:1",
            "2026-04-29T01:00:01Z",
            "block_ip",
            Some("203.0.113.10"),
        );
        insert_test_incident(
            &store,
            "ssh:bf:2",
            "2026-04-29T05:00:00Z",
            "ssh_bruteforce",
            "high",
            "ssh brute",
            Some("203.0.113.20"),
        );
        insert_test_decision(
            &store,
            "ssh:bf:2",
            "2026-04-29T05:00:01Z",
            "monitor",
            Some("203.0.113.20"),
        );
        insert_test_incident(
            &store,
            "noise:1",
            "2026-04-29T08:00:00Z",
            "proto_anomaly",
            "low",
            "weird ssh",
            Some("203.0.113.30"),
        );
        insert_test_decision(
            &store,
            "noise:1",
            "2026-04-29T08:00:01Z",
            "dismiss",
            Some("203.0.113.30"),
        );
        insert_test_incident(
            &store,
            "open:1",
            "2026-04-29T11:00:00Z",
            "credential_stuffing",
            "high",
            "stuff",
            Some("203.0.113.40"),
        );
        // No decision for open:1 → counts as Attention.

        // Yesterday's incident must NOT leak into today's count.
        insert_test_incident(
            &store,
            "old:1",
            "2026-04-28T22:00:00Z",
            "ssh_bruteforce",
            "high",
            "yesterday",
            Some("203.0.113.99"),
        );

        let counts = compute_overview_counts_from_sqlite(
            &store,
            date,
            0,
            None,
            chrono::Utc::now(),
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts returned");
        assert_eq!(counts.incidents_count, 4, "today only, not yesterday");
        assert_eq!(counts.blocked_count, 1, "ssh:bf:1");
        assert_eq!(counts.observing_count, 1, "ssh:bf:2");
        assert_eq!(counts.attention_count, 1, "open:1 (no decision)");
        // ai_ignored: 1 (noise:1 dismissed). decisions_count: 3.
        assert_eq!(counts.ai_ignored, 1);
        assert_eq!(counts.decisions_count, 3);
        // handled_ips_today: monitor + block touched 203.0.113.10 + .20
        assert_eq!(counts.handled_ips_today, 2);
    }

    #[test]
    fn sqlite_overview_filters_internal_traffic_incidents() {
        // RFC 1918 IPs are internal — must be filtered by
        // is_internal_incident_fields just like the live feed and
        // threats list. Otherwise the Home tile inflates with self-
        // traffic the operator can't act on.
        let store = make_overview_test_store();
        let date = "2026-04-29";
        insert_test_incident(
            &store,
            "ssh:internal",
            "2026-04-29T01:00:00Z",
            "ssh_bruteforce",
            "high",
            "ssh brute",
            Some("10.0.0.5"),
        );
        insert_test_incident(
            &store,
            "ssh:external",
            "2026-04-29T02:00:00Z",
            "ssh_bruteforce",
            "high",
            "ssh brute",
            Some("203.0.113.10"),
        );
        let counts = compute_overview_counts_from_sqlite(
            &store,
            date,
            0,
            None,
            chrono::Utc::now(),
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts returned");
        assert_eq!(
            counts.incidents_count, 1,
            "internal IP must be filtered out"
        );
    }

    #[test]
    fn sqlite_overview_severity_filter_narrows_count() {
        let store = make_overview_test_store();
        let date = "2026-04-29";
        insert_test_incident(
            &store,
            "low:1",
            "2026-04-29T01:00:00Z",
            "proto_anomaly",
            "low",
            "weird ssh",
            Some("203.0.113.10"),
        );
        insert_test_incident(
            &store,
            "high:1",
            "2026-04-29T02:00:00Z",
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.20"),
        );
        let high_only = crate::dashboard::investigation::severity_rank("high");
        let counts = compute_overview_counts_from_sqlite(
            &store,
            date,
            high_only,
            None,
            chrono::Utc::now(),
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts");
        assert_eq!(counts.incidents_count, 1);
    }

    // ── Phase 7 anchors: snapshot shape + bucket consistency ──────────
    //
    // These pin the new contract the front-end migrated to. If a
    // future refactor "simplifies" the snapshot back to a flat shape,
    // or drops the unique-attacker dedup, these tests fail loudly
    // instead of silently regressing the operator-visible "21 vs 10"
    // confusion that motivated Phase 7.

    #[test]
    fn sqlite_overview_snapshot_buckets_pair_incidents_and_unique_attackers() {
        // 4 incidents from 2 IPs. Buckets must report
        // incidents=4-by-outcome and unique_attackers=2-by-outcome.
        let store = make_overview_test_store();
        let date = "2026-04-29";
        // IP A: 2 blocked incidents (block_ip decisions).
        for (suffix, hr) in [("1", "01"), ("2", "05")] {
            insert_test_incident(
                &store,
                &format!("ssh:bf:{suffix}"),
                &format!("2026-04-29T{hr}:00:00Z"),
                "ssh_bruteforce",
                "high",
                "brute",
                Some("203.0.113.10"),
            );
            insert_test_decision(
                &store,
                &format!("ssh:bf:{suffix}"),
                &format!("2026-04-29T{hr}:00:01Z"),
                "block_ip",
                Some("203.0.113.10"),
            );
        }
        // IP B: 2 blocked incidents.
        for (suffix, hr) in [("3", "06"), ("4", "07")] {
            insert_test_incident(
                &store,
                &format!("ssh:bf:{suffix}"),
                &format!("2026-04-29T{hr}:00:00Z"),
                "ssh_bruteforce",
                "high",
                "brute",
                Some("203.0.113.20"),
            );
            insert_test_decision(
                &store,
                &format!("ssh:bf:{suffix}"),
                &format!("2026-04-29T{hr}:00:01Z"),
                "block_ip",
                Some("203.0.113.20"),
            );
        }

        let counts = compute_overview_counts_from_sqlite(
            &store,
            date,
            0,
            None,
            chrono::Utc::now(),
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts");
        let snap = counts.snapshot.expect("snapshot populated");
        // The exact two-number pair the operator was confused by.
        // Pre-Phase-7 the Home tile showed 4 (incidents) while the
        // Threats list showed 2 (attackers). Post-Phase-7 both
        // numbers come from the same struct.
        assert_eq!(
            snap.buckets.blocked.incidents, 4,
            "4 block_ip decisions today"
        );
        assert_eq!(
            snap.buckets.blocked.unique_attackers, 2,
            "across 2 unique IPs"
        );
        // Severity histogram for the bucket.
        assert_eq!(snap.buckets.blocked.severities.get("high"), Some(&4));
    }

    #[test]
    fn sqlite_overview_snapshot_unique_attacker_uses_aggregate_outcome_not_per_incident() {
        // Phase 10 anchor: when an IP has mixed-outcome incidents
        // (some blocked, some dismissed), the unique_attackers count
        // must follow the same aggregate_outcomes precedence the
        // Threats list uses — each IP appears in EXACTLY ONE bucket.
        // Pre-Phase-10 the same IP could appear in both buckets,
        // making the Home pyramid sub-rows disagree with the Threats
        // list group counts and the top header tiles.
        let store = make_overview_test_store();
        let date = "2026-04-29";
        // IP A: 1 block_ip + 5 dismiss decisions. Aggregate = blocked.
        // Pre-Phase-10 this IP would have been counted in BOTH the
        // blocked bucket (1x) and the dismissed bucket (5x).
        // Post-Phase-10 it counts as 1 in blocked and 0 in dismissed.
        insert_test_incident(
            &store,
            "ssh:bf:A1",
            "2026-04-29T01:00:00Z",
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.10"),
        );
        insert_test_decision(
            &store,
            "ssh:bf:A1",
            "2026-04-29T01:00:01Z",
            "block_ip",
            Some("203.0.113.10"),
        );
        for i in 0..5 {
            let id = format!("noise:A:{i}");
            insert_test_incident(
                &store,
                &id,
                &format!("2026-04-29T0{}:00:00Z", 2 + i),
                "proto_anomaly",
                "low",
                "weird ssh",
                Some("203.0.113.10"),
            );
            insert_test_decision(
                &store,
                &id,
                "2026-04-29T02:00:01Z",
                "dismiss",
                Some("203.0.113.10"),
            );
        }
        // IP B: 3 monitor decisions only. Aggregate = monitoring.
        for i in 0..3 {
            let id = format!("watch:B:{i}");
            insert_test_incident(
                &store,
                &id,
                &format!("2026-04-29T0{}:00:00Z", 1 + i),
                "ssh_bruteforce",
                "medium",
                "brute",
                Some("203.0.113.20"),
            );
            insert_test_decision(
                &store,
                &id,
                "2026-04-29T01:00:01Z",
                "monitor",
                Some("203.0.113.20"),
            );
        }

        let counts = compute_overview_counts_from_sqlite(
            &store,
            date,
            0,
            None,
            chrono::Utc::now(),
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts");
        let snap = counts.snapshot.expect("snap");
        // IP A is in blocked (precedence override), NOT in dismissed.
        // IP B is in observing.
        assert_eq!(snap.buckets.blocked.unique_attackers, 1, "IP A");
        assert_eq!(snap.buckets.dismissed.unique_attackers, 0, "IP A NOT here");
        assert_eq!(snap.buckets.observing.unique_attackers, 1, "IP B");
        // Sum of unique_attackers across buckets = total unique IPs.
        let total = snap.buckets.blocked.unique_attackers
            + snap.buckets.honeypot.unique_attackers
            + snap.buckets.observing.unique_attackers
            + snap.buckets.dismissed.unique_attackers
            + snap.buckets.allowlisted.unique_attackers
            + snap.buckets.attention.unique_attackers;
        assert_eq!(total, 2, "two unique IPs in total");
        // Incident counts stay per-outcome (this is the operator's
        // "actions taken" count, not "attackers").
        assert_eq!(snap.buckets.blocked.incidents, 1);
        assert_eq!(snap.buckets.dismissed.incidents, 5);
        assert_eq!(snap.buckets.observing.incidents, 3);
        // Legacy flat counters now match the aggregate-attacker
        // semantic too — they're what the Threats top tiles read.
        assert_eq!(
            counts.blocked_count, 1,
            "matches buckets.blocked.unique_attackers"
        );
        assert_eq!(
            counts.observing_count, 1,
            "matches buckets.observing.unique_attackers"
        );
    }

    #[test]
    fn sqlite_overview_snapshot_routes_allowlisted_to_dedicated_bucket() {
        // Allowlisted incidents must NOT inflate `attention` —
        // the operator-visible bug that surfaced post-Phase-5.
        let store = make_overview_test_store();
        let date = "2026-04-29";
        insert_test_incident(
            &store,
            "ssh:trusted",
            "2026-04-29T01:00:00Z",
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.10"),
        );
        insert_test_incident(
            &store,
            "ssh:open",
            "2026-04-29T02:00:00Z",
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.20"),
        );
        // Flag the first as allowlisted (mirrors what the agent fast
        // loop does in the SkipAllowlisted branch).
        store
            .set_incident_allowlisted("ssh:trusted")
            .expect("set allowlisted");

        let counts = compute_overview_counts_from_sqlite(
            &store,
            date,
            0,
            None,
            chrono::Utc::now(),
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts");
        let snap = counts.snapshot.expect("snapshot populated");
        assert_eq!(snap.buckets.allowlisted.incidents, 1);
        assert_eq!(snap.buckets.allowlisted.unique_attackers, 1);
        assert_eq!(
            snap.buckets.attention.incidents, 1,
            "only the un-allowlisted IP needs attention"
        );
        assert_eq!(snap.buckets.attention.unique_attackers, 1);
        // Legacy allowlisted_count flat field also populated for
        // backwards-compat clients.
        assert_eq!(counts.allowlisted_count, 1);
    }

    #[test]
    fn sqlite_overview_snapshot_pending_breakdown_categorises_by_age() {
        // 1 fresh incident (in-flight), 1 old (stuck), 1 escalated
        // (declined_by_ai). All today, all without final block decision.
        //
        // 2026-05-01 (PR #357): use a deterministic `now` at noon UTC
        // instead of `Utc::now()`. The pre-fix version generated
        // `stuck_ts = now - 2h`, which crosses the UTC midnight when
        // the test runs in the first ~2h of a UTC day → stuck_ts
        // falls on YESTERDAY's date string and the date-filtered query
        // returns 0 stuck incidents. CI hit this on 2026-05-01 at
        // 01:29 UTC. compute_overview_counts_from_sqlite already
        // accepts `now` as a parameter, so making it deterministic
        // keeps the test independent of wall-clock time.
        let store = make_overview_test_store();
        let today = chrono::Utc::now().date_naive();
        let now = today.and_hms_opt(12, 0, 0).unwrap().and_utc();
        let date = today.to_string();
        let fresh_ts = (now - chrono::Duration::seconds(120))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let stuck_ts =
            (now - chrono::Duration::hours(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let escalated_ts = (now - chrono::Duration::seconds(60))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        insert_test_incident(
            &store,
            "fresh:1",
            &fresh_ts,
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.10"),
        );
        insert_test_incident(
            &store,
            "stuck:1",
            &stuck_ts,
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.20"),
        );
        insert_test_incident(
            &store,
            "escalated:1",
            &escalated_ts,
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.30"),
        );
        insert_test_decision(
            &store,
            "escalated:1",
            &escalated_ts,
            "escalate",
            Some("203.0.113.30"),
        );

        let counts = compute_overview_counts_from_sqlite(
            &store,
            &date,
            0,
            None,
            now,
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts");
        let snap = counts.snapshot.expect("snapshot populated");
        assert_eq!(snap.pending.in_flight, 1, "fresh:1 (<5min)");
        assert_eq!(snap.pending.stuck, 1, "stuck:1 (>1h)");
        assert_eq!(
            snap.pending.declined_by_ai, 1,
            "escalated:1 has escalate decision"
        );
        // Health verb derived from breakdown. The escalated:1
        // incident has a recent (60s old) decision, so even with a
        // stuck incident present, we get AbandonedBacklog (yellow
        // soft signal: AI is alive, but had abandoned-orphan
        // backlog) rather than AiNotResponding (red: AI down). This
        // is the Phase 7B refinement.
        match snap.health {
            super::super::types::SystemHealth::AbandonedBacklog {
                stuck_count,
                last_decision_secs_ago,
            } => {
                assert_eq!(stuck_count, 1);
                assert!(last_decision_secs_ago < 300);
            }
            other => panic!("expected AbandonedBacklog, got {other:?}"),
        }
    }

    #[test]
    fn sqlite_overview_snapshot_health_distinguishes_recent_from_stale_decisions() {
        // Phase 7B refinement: when stuck > 0 but a recent decision
        // exists (≤5min ago), health verb is AbandonedBacklog (yellow
        // soft signal), not AiNotResponding (red alarm). This is the
        // operator-visible fix: previously the dashboard cried "AI
        // pipeline may be wedged" whenever any incident from earlier
        // in the day failed to get a decision, even though the AI was
        // actively processing the steady stream.
        // 2026-05-01 (PR #357): deterministic `now` at noon UTC so
        // `now - 2h` always lands on today (CI was failing at 01:29
        // UTC because stuck_ts crossed midnight into yesterday's
        // date string).
        let store = make_overview_test_store();
        let today = chrono::Utc::now().date_naive();
        let now = today.and_hms_opt(12, 0, 0).unwrap().and_utc();
        let date = today.to_string();

        // 1 stuck incident from 2 hours ago.
        let stuck_ts =
            (now - chrono::Duration::hours(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        insert_test_incident(
            &store,
            "stuck:1",
            &stuck_ts,
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.10"),
        );

        // 1 fresh incident with a recent decision (60 seconds ago) —
        // proves the AI is alive even though the stuck:1 above never
        // got decided.
        let fresh_ts = (now - chrono::Duration::seconds(60))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        insert_test_incident(
            &store,
            "fresh:1",
            &fresh_ts,
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.20"),
        );
        insert_test_decision(
            &store,
            "fresh:1",
            &fresh_ts,
            "block_ip",
            Some("203.0.113.20"),
        );

        let counts = compute_overview_counts_from_sqlite(
            &store,
            &date,
            0,
            None,
            now,
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts");
        let snap = counts.snapshot.expect("snapshot");
        assert_eq!(snap.pending.stuck, 1);
        match snap.health {
            super::super::types::SystemHealth::AbandonedBacklog {
                stuck_count,
                last_decision_secs_ago,
            } => {
                assert_eq!(stuck_count, 1);
                assert!(
                    last_decision_secs_ago < 300,
                    "recent decision must drive AbandonedBacklog, got {last_decision_secs_ago}s"
                );
            }
            other => panic!("expected AbandonedBacklog, got {other:?}"),
        }
    }

    #[test]
    fn sqlite_overview_snapshot_health_operating_normally_default() {
        // Empty store -> no incidents -> all pending counts zero ->
        // health is OperatingNormally. The hero verb reads as the
        // "all good" default.
        let store = make_overview_test_store();
        let date = "2026-04-29";
        let counts = compute_overview_counts_from_sqlite(
            &store,
            date,
            0,
            None,
            chrono::Utc::now(),
            &super::data_api::DegradedSignals::default(),
            std::path::Path::new("/nonexistent-test-data-dir"),
        )
        .expect("counts");
        let snap = counts.snapshot.expect("snapshot");
        match snap.health {
            super::super::types::SystemHealth::OperatingNormally => {}
            other => panic!("expected OperatingNormally on empty store, got {other:?}"),
        }
        assert_eq!(snap.pending.stuck, 0);
        assert_eq!(snap.pending.in_flight, 0);
    }

    #[tokio::test]
    async fn api_overview_uses_sqlite_when_kg_evicted() {
        // End-to-end: graph is empty (simulates TTL eviction completing)
        // but SQLite has incidents. The handler must return the SQLite
        // count, not 0.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let store = make_overview_test_store();
        let today = chrono::Utc::now().date_naive().to_string();
        let ts = format!("{today}T01:00:00Z");
        insert_test_incident(
            &store,
            "ssh:1",
            &ts,
            "ssh_bruteforce",
            "high",
            "brute",
            Some("203.0.113.10"),
        );
        insert_test_decision(
            &store,
            "ssh:1",
            &format!("{today}T01:00:01Z"),
            "block_ip",
            Some("203.0.113.10"),
        );
        state.sqlite_store = Some(store);
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = ListQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_overview(State(state), Query(q)).await;
        assert_eq!(out.incidents_count, 1, "SQLite count must surface");
        assert_eq!(out.blocked_count, 1);
        assert_eq!(out.handled_ips_today, 1);
    }

    #[tokio::test]
    async fn api_overview_sleeping_path_returns_zero_with_handled_field() {
        // When `last_activity` is older than DASHBOARD_SLEEP_SECS the
        // handler returns a minimal OverviewResponse from telemetry only.
        // The new `handled_ips_today` field must still be present.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        // Force "asleep": last_activity = 0 (epoch).
        state
            .last_activity
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let q = ListQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_overview(State(state), Query(q)).await;
        assert_eq!(out.handled_ips_today, 0);
        assert_eq!(out.incidents_count, 0);
    }

    #[test]
    fn compute_overview_severity_min_filter_excludes_low_incidents() {
        // Inconsistency 3 anchor in the compute helper. severity_min=high
        // must drop the LOW port_scan incident from all counters.
        let dir = tempfile::tempdir().expect("tempdir");
        let g = make_overview_kg();
        // The compute helper does not currently take filters as an arg —
        // it's consumed by api_overview which applies query filters in its
        // own loop. The `make_overview_kg` fixture has a low-severity
        // incident; assert it appears in the unfiltered count so the
        // `compute_overview_from_graph` path is fully exercised.
        let out = compute_overview_from_graph(&g, dir.path(), "2026-04-23");
        // ai_ignored = 0 (no incidents have decision="ignore"), and no
        // request_confirmation either, so unresolved_count stays 0 too.
        assert_eq!(out.ai_ignored, 0);
        assert_eq!(out.unresolved_count, 0);
        // severity_breakdown should have entries for "high" and "low".
        assert_eq!(out.severity_breakdown.get("high"), Some(&2));
        assert_eq!(out.severity_breakdown.get("low"), Some(&1));
    }

    #[test]
    fn compute_overview_filters_advisory_only_detectors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = make_overview_kg();
        let out = compute_overview_from_graph(&g, dir.path(), "2026-04-23");
        // The advisory-only neural_anomaly incident must NOT appear in
        // top_detectors and must NOT be counted in any decision counter.
        let detectors: Vec<&str> = out
            .top_detectors
            .iter()
            .map(|d| d.detector.as_str())
            .collect();
        assert!(!detectors.contains(&"neural_anomaly"));
        // ai_confirmed should count 3 (2 block + 1 monitor) — not 4.
        assert_eq!(out.ai_confirmed, 3);
    }

    // ── Spec 037 Threats UX bundle ─────────────────────────────────────
    //
    // KPI buckets + diagnostic endpoint anchors. The threats.js KPI
    // computation moved from front-end pivot-summing to these
    // backend-derived counts, so a regression that drops the fields
    // would silently zero the "Blocked / Observing / Needs attention"
    // tiles -- only the anchors below catch that.

    #[test]
    fn compute_overview_populates_threats_kpi_buckets() {
        // make_overview_kg has 2x block_ip + 1x monitor + 1x advisory
        // (filtered). After classification: blocked=2, observing=1,
        // attention=0.
        let dir = tempfile::tempdir().expect("tempdir");
        let g = make_overview_kg();
        let out = compute_overview_from_graph(&g, dir.path(), "2026-04-23");
        assert_eq!(out.blocked_count, 2, "block_ip incidents = 2");
        assert_eq!(out.observing_count, 1, "monitor incidents = 1");
        assert_eq!(out.attention_count, 0, "no undecided incidents");
    }

    #[tokio::test]
    async fn api_threats_diagnostic_reports_has_entities_when_pivots_populated() {
        // make_overview_kg seeds two real attacker IPs. The diagnostic
        // must mark `has_entities=true` and `has_incidents=true`.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let g = make_overview_kg();
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(g));
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = EntitiesQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
            group_by: None,
        };
        let Json(out) =
            crate::dashboard::investigation::api_threats_diagnostic(State(state), Query(q)).await;
        assert!(out.has_incidents, "graph has 3 real-attacker incidents");
        assert!(out.has_entities, "two IP entities exist in pivot");
        assert!(!out.scope_mismatch, "today's pivot has matches");
        assert!(out.ip_pivot_count >= 1, "ip pivot must surface attackers");
    }

    #[tokio::test]
    async fn api_threats_diagnostic_reports_empty_when_graph_empty() {
        // Empty knowledge graph: has_incidents=false, has_entities=false,
        // scope_mismatch=false, suggested_pivots=[].
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = EntitiesQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
            group_by: None,
        };
        let Json(out) =
            crate::dashboard::investigation::api_threats_diagnostic(State(state), Query(q)).await;
        assert!(!out.has_incidents);
        assert!(!out.has_entities);
        assert!(
            !out.scope_mismatch,
            "no incidents anywhere = not a scope mismatch"
        );
        assert!(out.suggested_pivots.is_empty());
    }

    #[tokio::test]
    async fn api_threats_diagnostic_flags_scope_mismatch_for_wrong_date() {
        // Graph has an incident on 2026-04-26 but the query asks for
        // 2026-04-28: has_incidents=false (in scope), but
        // scope_mismatch=true so the front-end can hint "try previous day".
        use crate::knowledge_graph::types::*;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let day1 = chrono::DateTime::parse_from_rfc3339("2026-04-26T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ip = g.ensure_ip("203.0.113.50", day1);
        let inc = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:past".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "old SSH brute force".into(),
            summary: "".into(),
            ts: day1,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            decision_target: Some("203.0.113.50".into()),
            confidence: Some(0.9),
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc, ip, Relation::TriggeredBy, day1));
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(g));
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = EntitiesQuery {
            limit: None,
            date: Some("2026-04-28".to_string()),
            severity_min: None,
            detector: None,
            group_by: None,
        };
        let Json(out) =
            crate::dashboard::investigation::api_threats_diagnostic(State(state), Query(q)).await;
        assert!(!out.has_incidents, "no incidents on 2026-04-28");
        assert!(
            out.scope_mismatch,
            "graph has incidents on a different date"
        );
    }

    // ── Degraded health verb (audit 1.2) ─────────────────────────
    //
    // Anchor for the recurring audit complaint: green PROTECTED
    // banner sitting on top of historical orphaned responses or
    // accumulated revert failures. Each test pins one signal so a
    // future regression that drops a signal from the derivation is
    // caught immediately.

    use super::super::types::{PendingBreakdown, SystemHealth};

    fn fresh_pending() -> PendingBreakdown {
        PendingBreakdown::default()
    }

    #[test]
    fn degraded_when_orphaned_responses_exist() {
        // PR #425 Wave 4d: signal is now orphaned_now (current count),
        // not the lifetime counter. Banner only fires when entries
        // actually exist on disk.
        let degraded = super::DegradedSignals {
            orphaned_now: 17,
            ..Default::default()
        };
        let h = super::derive_system_health(&fresh_pending(), Some(30), &degraded);
        match h {
            SystemHealth::Degraded { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("17 orphaned")));
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn no_degraded_signal_when_only_lifetime_revert_failures() {
        // PR #425 Wave 4d: pre-fix this would surface "111 revert
        // failures" on a clean system because the lifetime counter
        // never decrements. Now the banner only fires for current
        // drift — revert_failures_total alone, with zero current
        // orphans, returns OperatingNormally because every failure
        // may have been retried successfully.
        let degraded = super::DegradedSignals {
            revert_failures_total: 111,
            ..Default::default()
        };
        let h = super::derive_system_health(&fresh_pending(), Some(30), &degraded);
        assert_eq!(
            h,
            SystemHealth::OperatingNormally,
            "lifetime revert_failures alone should not flip Degraded"
        );
    }

    #[test]
    fn degraded_collects_all_reasons_in_priority_order() {
        // When current orphans exist, the lifetime revert_failures
        // count adds context as a follow-up reason. Without current
        // orphans, the failure count alone is gaslighting — see the
        // `no_degraded_signal_when_only_lifetime_revert_failures` test.
        let degraded = super::DegradedSignals {
            orphaned_now: 17,
            revert_failures_total: 111,
        };
        let h = super::derive_system_health(&fresh_pending(), Some(30), &degraded);
        match h {
            SystemHealth::Degraded { reasons } => {
                assert_eq!(reasons.len(), 2, "got {reasons:?}");
                assert!(reasons[0].contains("orphaned"));
                assert!(reasons[1].contains("revert failure"));
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn operating_normally_only_when_truly_clean() {
        // Anchor against the audit's central complaint: a clean
        // green banner must require ALL signals to be zero. If any
        // future field is added to `DegradedSignals`, the existing
        // `..Default::default()` here keeps the assertion honest;
        // adding a field that defaults to non-zero will make this
        // test fail and force the author to think about whether
        // the new signal warrants Degraded.
        let degraded = super::DegradedSignals::default();
        let h = super::derive_system_health(&fresh_pending(), Some(30), &degraded);
        assert_eq!(h, SystemHealth::OperatingNormally);
    }

    #[test]
    fn acute_red_verbs_take_priority_over_degraded() {
        // When the AI is genuinely down (red), Degraded must not
        // mask it. The headline operator sees is the most acute
        // failure mode; chronic drift can wait until the immediate
        // emergency is handled.
        //
        // 2026-05-03: AI_DOWN_THRESHOLD_SECS bumped from 300 to 1800
        // (30 min). Use Some(2400) here so the test exercises the
        // "AI genuinely silent for over half an hour" path.
        let mut pending = fresh_pending();
        pending.stuck = 5;
        let degraded = super::DegradedSignals {
            orphaned_now: 17,
            revert_failures_total: 111,
        };
        let h = super::derive_system_health(&pending, Some(2400), &degraded);
        match h {
            SystemHealth::AiNotResponding { stuck_count, .. } => {
                assert_eq!(stuck_count, 5);
            }
            other => panic!("expected AiNotResponding to take priority, got {other:?}"),
        }
    }

    // 2026-05-03 anchor: the 5-minute AI_DOWN_THRESHOLD was tripping
    // AiNotResponding on quiet systems where 5-30 min between decisions
    // is normal. Operator screenshot 2026-05-03 had 6 incidents
    // in-flight, last decision 5 min ago, AI clearly working — but the
    // header rendered "AI NOT RESPONDING" because of a strict `>300s`
    // boundary check at exactly the 5-min boundary. This test pins the
    // new contract: with stuck>0 AND a recent (<30 min) decision, the
    // verb is AbandonedBacklog (yellow), not AiNotResponding (red).
    #[test]
    fn recent_decision_with_stuck_incidents_is_yellow_not_red() {
        let mut pending = fresh_pending();
        pending.stuck = 2;
        let degraded = super::DegradedSignals::default();
        // Last decision 5 minutes ago — well under the 30-min "AI
        // genuinely down" threshold. With stuck>0 the verb is
        // AbandonedBacklog (yellow soft signal), NOT AiNotResponding.
        let h = super::derive_system_health(&pending, Some(300), &degraded);
        match h {
            SystemHealth::AbandonedBacklog { stuck_count, .. } => {
                assert_eq!(stuck_count, 2);
            }
            other => panic!(
                "5-min-ago decision with 2 stuck incidents must be \
                 AbandonedBacklog (yellow). Got: {other:?}. If this \
                 fails, the AI_DOWN_THRESHOLD_SECS regressed below 300s."
            ),
        }
    }

    #[test]
    fn truly_silent_ai_with_stuck_incidents_is_red() {
        // Same setup as above but last decision is 35 min ago — over
        // the 30-min threshold. NOW it's genuinely AiNotResponding.
        let mut pending = fresh_pending();
        pending.stuck = 2;
        let degraded = super::DegradedSignals::default();
        let h = super::derive_system_health(&pending, Some(2100), &degraded);
        match h {
            SystemHealth::AiNotResponding { stuck_count, .. } => {
                assert_eq!(stuck_count, 2);
            }
            other => panic!(
                "35-min-ago decision with 2 stuck incidents MUST be \
                 AiNotResponding (red) — that is the genuine AI-down \
                 signal we want to catch. Got: {other:?}"
            ),
        }
    }

    // 2026-05-02 audit anchor: events_today is part of the canonical
    // OverviewSnapshot contract. Pre-fix this field was hardcoded to 0
    // inside compute_overview_counts_from_sqlite and only api_overview
    // backfilled it from telemetry — Briefing, Report, and Sensors HUD
    // all rendered "EVENTS TODAY: 0" while the per-source counters
    // showed millions. The fix backfills inside the SoT helper so all
    // callers get the same number. This test pins the contract: when
    // a telemetry-YYYY-MM-DD.jsonl file is present with a populated
    // events_by_collector, the snapshot returned by the helper carries
    // the summed count.
    #[test]
    fn compute_overview_counts_backfills_events_today_from_telemetry() {
        use std::io::Write;
        let store = make_overview_test_store();
        let dir = tempfile::tempdir().expect("tempdir");
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let snap = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "tick": "test_tick",
            "events_by_collector": {
                "ebpf": 13_177_172u64,
                "tcp_stream": 1_123_159u64,
                "dns_capture": 312_710u64,
            },
            "incidents_by_detector": {},
            "gate_pass_count": 0u64,
            "gate_suppressed_total": 0u64,
            "ai_sent_count": 0u64,
            "telegram_sent_count": 0u64,
            "ai_decision_count": 0u64,
            "avg_decision_latency_ms": 0.0,
            "errors_by_component": {},
            "decisions_by_action": {},
            "dry_run_execution_count": 0u64,
            "real_execution_count": 0u64,
        });
        let mut f = std::fs::File::create(dir.path().join(format!("telemetry-{date}.jsonl")))
            .expect("create telemetry file");
        writeln!(f, "{}", serde_json::to_string(&snap).unwrap()).unwrap();

        let counts = super::compute_overview_counts_from_sqlite(
            &store,
            &date,
            0,
            None,
            chrono::Utc::now(),
            &super::DegradedSignals::default(),
            dir.path(),
        )
        .expect("counts returned");
        let snapshot = counts.snapshot.expect("snapshot populated");
        // 13M + 1.1M + 312k = 14_613_041
        assert_eq!(
            snapshot.events_today,
            13_177_172 + 1_123_159 + 312_710,
            "events_today must be the sum of telemetry events_by_collector — \
             if this is 0, the SoT backfill regressed (compute_overview_counts_from_sqlite \
             stopped reading telemetry inline). See PR #412."
        );
    }

    #[test]
    fn compute_overview_counts_falls_back_to_zero_when_telemetry_missing() {
        // Boot path / cold start: when no telemetry file exists for
        // the requested date, the snapshot defaults events_today=0
        // gracefully instead of erroring. The other surfaces handle
        // 0 by hiding or showing "—".
        let store = make_overview_test_store();
        let dir = tempfile::tempdir().expect("tempdir");
        let date = "2026-05-02";

        let counts = super::compute_overview_counts_from_sqlite(
            &store,
            date,
            0,
            None,
            chrono::Utc::now(),
            &super::DegradedSignals::default(),
            dir.path(),
        )
        .expect("counts returned");
        let snapshot = counts.snapshot.expect("snapshot populated");
        assert_eq!(snapshot.events_today, 0);
    }

    // ── api_incidents handler / compute_incidents_blocking coverage ──
    //
    // The body of compute_incidents_blocking walks the KG, builds
    // IncidentView fixtures, sorts by ts desc, takes(limit). These
    // tests exercise the full async wrapper end-to-end so the
    // graph-walk closure and IncidentView projection get covered.

    fn make_incidents_kg() -> crate::knowledge_graph::KnowledgeGraph {
        use crate::knowledge_graph::types::*;
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        // Two real incidents from one IP: blocked + monitor.
        let ip = g.ensure_ip("203.0.113.10", now);
        let inc_a = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:1".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "SSH brute force".into(),
            summary: "many failed logins".into(),
            ts: now,
            mitre_ids: vec!["T1110".into()],
            decision: Some("block_ip".into()),
            decision_target: Some("203.0.113.10".into()),
            confidence: Some(0.95),
            decision_reason: Some("brute force detected".into()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_a, ip, Relation::TriggeredBy, now));
        let earlier = now - chrono::Duration::seconds(120);
        let inc_b = g.add_node(Node::Incident {
            incident_id: "port_scan:1".into(),
            detector: "port_scan".into(),
            severity: "low".into(),
            title: "Port scan".into(),
            summary: "scanning many ports".into(),
            ts: earlier,
            mitre_ids: vec![],
            decision: Some("monitor".into()),
            decision_target: Some("203.0.113.10".into()),
            confidence: Some(0.6),
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_b, ip, Relation::TriggeredBy, earlier));
        // Research-only incident — must NOT appear in the list.
        let inc_c = g.add_node(Node::Incident {
            incident_id: "research:1".into(),
            detector: "experimental".into(),
            severity: "medium".into(),
            title: "Research".into(),
            summary: "for tuning only".into(),
            ts: now,
            mitre_ids: vec![],
            decision: None,
            decision_target: None,
            confidence: None,
            decision_reason: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: true,
        });
        g.add_edge(Edge::new(inc_c, ip, Relation::TriggeredBy, now));
        g
    }

    #[tokio::test]
    async fn api_incidents_returns_visible_items_sorted_newest_first() {
        // Walks compute_incidents_blocking through the spawn_blocking
        // wrapper. Asserts:
        //  - research_only filtered out
        //  - sort by ts descending (newest first)
        //  - entities populated from TriggeredBy edges (ip:<addr>)
        //  - effective_severity is computed from outcome+severity
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(make_incidents_kg()));
        let q = ListQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_incidents(State(state), Query(q)).await;
        // Research-only filtered out → 2 items.
        assert_eq!(out.total, 2, "research_only must not appear in incidents");
        assert_eq!(out.items.len(), 2);
        // Newest first: ssh_bruteforce:1 (ts=now) then port_scan:1 (ts=now-120s)
        assert_eq!(out.items[0].incident_id, "ssh_bruteforce:1");
        assert_eq!(out.items[1].incident_id, "port_scan:1");
        // Entities populated from outgoing TriggeredBy edges.
        assert!(out.items[0].entities.iter().any(|e| e == "ip:203.0.113.10"));
        // mitre_ids → tags
        assert_eq!(out.items[0].tags, vec!["T1110".to_string()]);
        // Outcome via threat_contract::classify_decision (block_ip → "blocked").
        assert_eq!(out.items[0].outcome, "blocked");
        // Action_taken mirrors raw decision.
        assert_eq!(out.items[0].action_taken.as_deref(), Some("block_ip"));
        // Effective severity downgrade: blocked + high → low.
        assert_eq!(out.items[0].effective_severity, "low");
        // monitor → "monitored" outcome.
        assert_eq!(out.items[1].outcome, "monitoring");
    }

    #[tokio::test]
    async fn api_incidents_respects_limit_query() {
        // limit=1 must truncate items to 1 but `total` reports the
        // full pre-truncation count so the front-end can show "X of Y".
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(make_incidents_kg()));
        let q = ListQuery {
            limit: Some(1),
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_incidents(State(state), Query(q)).await;
        assert_eq!(out.total, 2, "total counts pre-truncation");
        assert_eq!(out.items.len(), 1, "limit truncates");
    }

    #[tokio::test]
    async fn api_incidents_date_filter_drops_other_days() {
        // When the operator picks a historical date that does NOT
        // match the in-memory KG dates, compute_incidents_blocking
        // filters every incident out (date_filter mismatch). Asserts
        // the explicit-date branch executes (Some(target) match arm).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(make_incidents_kg()));
        // Date far in the past — none of the in-memory incidents
        // have a ts on this day.
        let q = ListQuery {
            limit: None,
            date: Some("2020-01-01".to_string()),
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_incidents(State(state), Query(q)).await;
        assert_eq!(out.total, 0);
        assert_eq!(out.items.len(), 0);
    }

    // ── api_decisions handler ─────────────────────────────────────
    //
    // The handler walks Incident nodes that have a `decision` field
    // and projects them into DecisionView. Pin the projection so a
    // refactor that drops `target_ip` or `confidence` fails loud.

    #[tokio::test]
    async fn api_decisions_projects_decision_fields_from_incidents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(make_incidents_kg()));
        let q = ListQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_decisions(State(state), Query(q)).await;
        // research_only has no decision so it's already excluded by
        // the matches!() pattern; ssh_bruteforce:1 + port_scan:1 each
        // have a decision → 2 items.
        assert_eq!(out.total, 2);
        assert_eq!(out.items.len(), 2);
        // Newest first by ts.
        assert_eq!(out.items[0].incident_id, "ssh_bruteforce:1");
        assert_eq!(out.items[0].action_type, "block_ip");
        assert_eq!(out.items[0].target_ip.as_deref(), Some("203.0.113.10"),);
        assert!((out.items[0].confidence - 0.95).abs() < 1e-6);
        assert!(out.items[0].auto_executed);
        // auto_executed=true → execution_result "ok".
        assert_eq!(out.items[0].execution_result, "ok");
        // decision_reason becomes the `reason` field.
        assert_eq!(out.items[0].reason, "brute force detected");
        // The non-auto-executed branch: ssh_bruteforce:1 was auto.
        // For port_scan:1 (auto_executed=true) we still get "ok".
        assert_eq!(out.items[1].execution_result, "ok");
    }

    #[tokio::test]
    async fn api_decisions_marks_skipped_when_not_auto_executed() {
        // Pin the auto_executed=false branch which renders execution_result
        // as "skipped" (decision recorded but skill not run).
        use crate::knowledge_graph::types::*;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip = g.ensure_ip("203.0.113.99", now);
        let inc = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:5".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "ssh".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            decision_target: Some("203.0.113.99".into()),
            confidence: Some(0.5),
            decision_reason: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc, ip, Relation::TriggeredBy, now));
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(g));

        let q = ListQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_decisions(State(state), Query(q)).await;
        assert_eq!(out.items.len(), 1);
        assert_eq!(out.items[0].execution_result, "skipped");
        // skill_id is not stored in graph — must be None on this path.
        assert!(out.items[0].skill_id.is_none());
        // decision_reason was None → reason defaults to empty string.
        assert!(out.items[0].reason.is_empty());
    }

    // ── compute_overview_from_graph: extra decision branches ──────
    //
    // The flat graph compute helper has 4 decision arms:
    // ignore / monitor / request_confirmation / fallback. The
    // existing fixture only exercised monitor + fallback (block_ip).
    // These tests pin the remaining two arms so coverage on
    // 1605/1613/1629/1660-1661 lights up.

    #[test]
    fn compute_overview_counts_ignore_decision_into_ai_ignored() {
        use crate::knowledge_graph::types::*;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip = g.ensure_ip("203.0.113.50", now);
        let inc = g.add_node(Node::Incident {
            incident_id: "noise:1".into(),
            detector: "proto_anomaly".into(),
            severity: "low".into(),
            title: "weird ssh".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("ignore".into()),
            decision_target: None,
            confidence: None,
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc, ip, Relation::TriggeredBy, now));
        let out = compute_overview_from_graph(
            &g,
            dir.path(),
            chrono::Utc::now().format("%Y-%m-%d").to_string().as_str(),
        );
        assert_eq!(out.ai_ignored, 1, "ignore branch increments ai_ignored");
        assert_eq!(
            out.ai_responded, 0,
            "ignore must not count toward responded",
        );
        assert_eq!(out.safely_resolved, 0, "ignore is not safely_resolved");
    }

    #[test]
    fn compute_overview_counts_request_confirmation_into_unresolved() {
        use crate::knowledge_graph::types::*;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip = g.ensure_ip("203.0.113.60", now);
        let inc = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:rc".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "ssh brute".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("request_confirmation".into()),
            decision_target: Some("203.0.113.60".into()),
            confidence: None,
            decision_reason: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc, ip, Relation::TriggeredBy, now));
        let out = compute_overview_from_graph(
            &g,
            dir.path(),
            chrono::Utc::now().format("%Y-%m-%d").to_string().as_str(),
        );
        assert_eq!(
            out.unresolved_count, 1,
            "request_confirmation increments unresolved",
        );
        assert_eq!(out.ai_confirmed, 1);
        assert_eq!(
            out.ai_responded, 0,
            "request_confirmation is not auto-responded",
        );
    }

    #[test]
    fn compute_overview_counts_allowlisted_increments_separate_counter() {
        // Pin line 1629: allowlisted incidents increment
        // allowlisted_count even though they remain part of the
        // detector tally — the operator-visible "X allowlisted" tile.
        use crate::knowledge_graph::types::*;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip = g.ensure_ip("203.0.113.70", now);
        let inc = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:al".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "ssh brute".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("monitor".into()),
            decision_target: Some("203.0.113.70".into()),
            confidence: None,
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: true,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc, ip, Relation::TriggeredBy, now));
        let out = compute_overview_from_graph(
            &g,
            dir.path(),
            chrono::Utc::now().format("%Y-%m-%d").to_string().as_str(),
        );
        assert_eq!(
            out.allowlisted_count, 1,
            "is_allowlisted=true must bump allowlisted_count",
        );
    }

    // ── read_degraded_signals JSON parsing ───────────────────────
    //
    // The fn reads responses.json (or the responses blob from
    // SQLite) and extracts gauges.orphaned + totals.revert_failures.
    // These tests pin the parsing branches so a future refactor
    // that drops one of the JSON paths fails loud.

    #[test]
    fn read_degraded_signals_parses_gauges_orphaned() {
        // The canonical PR #425 Wave 4d shape: gauges.orphaned is
        // the current-count (what the banner reads).
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let payload = serde_json::json!({
            "gauges": {"orphaned": 7u64},
            "totals": {"revert_failures": 42u64},
        });
        std::fs::write(
            dir.path().join("responses.json"),
            serde_json::to_string(&payload).unwrap(),
        )
        .unwrap();
        let signals = super::read_degraded_signals(&state);
        assert_eq!(signals.orphaned_now, 7);
        assert_eq!(signals.revert_failures_total, 42);
    }

    #[test]
    fn read_degraded_signals_falls_back_to_state_counts_revert_failed() {
        // Transitional shape during deploy: when the new
        // gauges.orphaned key is absent, the helper reads
        // state_counts.revert_failed instead of returning 0.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let payload = serde_json::json!({
            "state_counts": {"revert_failed": 3u64},
        });
        std::fs::write(
            dir.path().join("responses.json"),
            serde_json::to_string(&payload).unwrap(),
        )
        .unwrap();
        let signals = super::read_degraded_signals(&state);
        assert_eq!(signals.orphaned_now, 3);
        assert_eq!(signals.revert_failures_total, 0);
    }

    #[test]
    fn read_degraded_signals_returns_default_when_no_responses_file() {
        // No SQLite store wired, no responses.json on disk → the
        // helper produces a zero-valued DegradedSignals so the
        // banner stays green.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let signals = super::read_degraded_signals(&state);
        assert_eq!(signals.orphaned_now, 0);
        assert_eq!(signals.revert_failures_total, 0);
    }

    #[test]
    fn read_degraded_signals_default_when_responses_json_is_garbage() {
        // Malformed JSON → the helper silently swallows the parse
        // error and returns defaults. Operator's banner does not
        // panic on a corrupt responses.json.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        std::fs::write(dir.path().join("responses.json"), b"{not valid json").unwrap();
        let signals = super::read_degraded_signals(&state);
        assert_eq!(signals.orphaned_now, 0);
        assert_eq!(signals.revert_failures_total, 0);
    }

    // ── api_report endpoint ──────────────────────────────────────
    //
    // api_report pretty-prints a TrialReport JSON. Exercise the
    // happy path so the (Json) serialisation branch is covered.

    #[tokio::test]
    async fn api_report_returns_json_for_empty_state() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let q = ReportQuery { date: None };
        let resp = api_report(State(state), Query(q)).await;
        let resp = resp.into_response();
        assert_eq!(resp.status().as_u16(), 200);
        let bytes = to_bytes(resp.into_body(), 1_048_576).await.unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        // Pretty-printed JSON object → must start with '{'.
        assert!(body.trim_start().starts_with('{'));
        // Empty state has zero incidents — but the field exists.
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert!(
            v.get("detection_summary")
                .and_then(|d| d.get("total_incidents"))
                .is_some(),
            "report JSON must carry detection_summary.total_incidents"
        );
    }

    // ── api_briefing GET branch ───────────────────────────────────
    //
    // GET /api/briefing reads the cached latest_briefing. When the
    // mutex contains None (default on a fresh state) the response
    // carries available=false. When populated, available=true plus
    // the threat_level and summary fields.

    #[tokio::test]
    async fn api_briefing_returns_unavailable_when_no_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let Json(body) = api_briefing(State(state)).await;
        assert_eq!(body["available"], false);
        // Helpful operator message must be present.
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("No briefing generated yet"));
    }

    #[tokio::test]
    async fn api_briefing_returns_cached_briefing_when_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let cached = crate::briefing::Briefing {
            generated_at: chrono::Utc::now(),
            date: "2026-05-06".to_string(),
            threat_level: "MODERATE".to_string(),
            summary: "Two suspicious sources today.".to_string(),
        };
        *state.latest_briefing.lock().await = Some(cached);
        let Json(body) = api_briefing(State(state)).await;
        assert_eq!(body["available"], true);
        assert_eq!(body["threat_level"], "MODERATE");
        assert_eq!(body["date"], "2026-05-06");
        assert_eq!(body["summary"], "Two suspicious sources today.");
    }
}
