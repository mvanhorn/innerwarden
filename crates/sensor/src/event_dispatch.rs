//! Event dispatch — the hot loop that fans every collected event out
//! to every detector and writes incidents back to the sinks.
//!
//! Extracted from `main.rs` on 2026-05-25 as PR5a of the sensor
//! decomposition (see SESSION_LOG.md). Pure code motion — zero
//! behaviour change. The 951-LoC `process_event` and the 43-LoC
//! private `write_incident` helper it depends on moved together so
//! the dispatch fan-out stays one logical unit.
//!
//! ## Why this is the load-bearing extraction
//!
//! `process_event` is on every event's hot path:
//!
//!     event from collector → mpsc::channel → process_event
//!
//! It dispatches to 34+ detectors (each `if let Some(ref mut det) =
//! detectors.X { ... }`), runs the dedup cache, and writes both events
//! and incidents to SQLite + the optional CEF syslog sink. The pattern
//! it embodies — "for every detector, give it the event, write any
//! resulting incident" — is the same shape PR5b will use when it
//! splits `async fn main`'s setup phase into smaller boot helpers.
//!
//! ## DetectorSet visibility
//!
//! `DetectorSet` lives in `crate::detector_set` (moved out of
//! `main.rs` on 2026-05-26 as follow-up #2 of the post-PR-F3 punch
//! list — 35 detector imports + ~100 LoC of fields). `WriteStats`
//! still lives in `main.rs` because it's a 4-line stats counter
//! tightly coupled to the event-loop's shutdown log line; moving it
//! would be churn without value. Both stay `pub(crate)` so this
//! module can reach them.
//!
//! The actual DetectorSet constructor still lives in
//! `crate::boot::build_detectors` — that's the right place because
//! it owns the per-config wiring. This module only RUNS the dispatch.
//!
//! ## The anti-regression test
//!
//! `blocked_ip_hint_returns_true_but_does_not_imply_skip` (the
//! 2026-05-23 incident anchor that does `include_str!("…")` to source-
//! grep `process_event` for the forbidden early-return pattern)
//! moved with the function from `main.rs::tests` into
//! `event_dispatch.rs::tests` and now points its `include_str!` at
//! `event_dispatch.rs` instead of `main.rs`.

use std::collections::HashMap;

use tracing::info;

use crate::detector_set::DetectorSet;
use crate::detectors;
use crate::incident_builders::{
    devnode_exposed_incident, page_cache_mismatch_incident, passthrough_incident,
};
use crate::main_helpers::{
    is_passthrough_source, load_blocked_ips, severity_rank, should_use_blocked_ip_hint,
};
use crate::sinks::{self, sqlite::SqliteWriter};
use crate::WriteStats;

pub(crate) fn process_event(
    ev: innerwarden_core::event::Event,
    sqlite: &SqliteWriter,
    detectors: &mut DetectorSet,
    stats: &mut WriteStats,
    syslog: &mut Option<sinks::syslog_cef::SyslogCefWriter>,
    dedup_cache: &mut HashMap<u32, (chrono::DateTime<chrono::Utc>, u8)>,
    threat_datasets: &detectors::datasets::Datasets,
) {
    use innerwarden_core::event::Severity;

    let mut ev = ev;
    let persist = detectors.event_pipeline.should_persist(&mut ev);

    info!(kind = %ev.kind, summary = %ev.summary, "event");
    if persist {
        sqlite.write_event(&ev);
        stats.events_written += 1;
        if let Some(ref mut cef) = syslog {
            cef.write_event(&ev);
        }
    } else {
        stats.events_dropped += 1;
    }

    // LSM blocked execution → immediate Critical incident.
    // The eBPF LSM hook already validated the kill chain pattern in-kernel;
    // promote directly to incident so the agent can auto-enable enforcement,
    // execute the kill-chain-response skill, and notify.
    if ev.kind == "lsm.exec_blocked" {
        use innerwarden_core::incident::Incident;
        let pid = ev.details.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let comm = ev
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let filename = ev
            .details
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let incident = Incident {
            ts: ev.ts,
            host: ev.host.clone(),
            incident_id: format!("lsm:kill_chain:{}:{}",
                pid, ev.ts.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::Critical,
            title: format!("Kill chain blocked: {comm} (PID {pid})"),
            summary: format!(
                "Kernel LSM blocked execution: process {comm} (PID {pid}) attempted to run {filename} \
                 after accumulating kill chain flags. The attack was prevented at kernel level before \
                 the new process image was loaded."
            ),
            evidence: serde_json::json!([ev.details]),
            recommended_checks: vec![
                "Investigate the parent process that accumulated the kill chain".to_string(),
                "Check network connections from this PID for C2 communication".to_string(),
                "Review other processes from the same user/session".to_string(),
            ],
            tags: ev.tags.clone(),
            entities: ev.entities.clone(),
        };
        write_incident(sqlite, stats, incident, syslog, dedup_cache);
    }

    // SUID page-cache mismatch → immediate Critical incident. The periodic
    // detector emits an event because it is file-state telemetry; the sensor
    // promotes it here so the existing agent incident path sees it.
    if ev.kind == "integrity.page_cache_mismatch" {
        let incident = page_cache_mismatch_incident(&ev);
        write_incident(sqlite, stats, incident, syslog, dedup_cache);
    }

    // Kernel devnode exposure → Medium incident. Same shape as above:
    // periodic detector produces a state-telemetry event, the sensor
    // promotes it to an incident so the agent's correlation engine
    // (CL-071) can pair it with subsequent unprivileged opens + privesc.
    if ev.kind == "integrity.devnode_exposed" {
        let incident = devnode_exposed_incident(&ev);
        write_incident(sqlite, stats, incident, syslog, dedup_cache);
    }

    // Event pipeline: reload rules + backstop check (both on the 60s timer inside reload_if_changed).
    if detectors.event_pipeline.reload_if_changed() {
        info!("event_pipeline rules reloaded");
    }
    if let Some(backstop_incident) = detectors.event_pipeline.check_backstop(&ev.host) {
        write_incident(sqlite, stats, backstop_incident, syslog, dedup_cache);
    }

    // Reload dynamic allowlist every 60s (checks file mtime, no-op if unchanged).
    if detectors.allowlist_last_check.elapsed().as_secs() > 60 {
        if detectors.dynamic_allowlist.reload_if_changed() {
            info!("Dynamic allowlist reloaded");
        }
        detectors.allowlist_last_check = std::time::Instant::now();
    }

    // Reload blocked IPs from agent feedback every 60s.
    if detectors.blocked_ips_last_check.elapsed().as_secs() > 60 {
        let refreshed = load_blocked_ips(sqlite.data_dir());
        if refreshed.len() != detectors.blocked_ips.len() {
            info!(count = refreshed.len(), "blocked IPs list refreshed");
        }
        detectors.blocked_ips = refreshed;
        detectors.blocked_ips_last_check = std::time::Instant::now();
    }

    // Blocked-IP awareness, but NO early-return.
    //
    // Pre-2026-05-23 this block returned early for any event whose src_ip was
    // already in `detectors.blocked_ips`. The intent ("don't waste CPU on IPs
    // we already blocked") was reasonable but the side-effect was a silent
    // pipeline kill: ssh_bruteforce, distributed_ssh, kill_chain, mitre_hunt,
    // process_tree, etc all stopped seeing the events, so:
    //   - Detector sliding windows went stale (next firing after the block
    //     expired had no tracked context).
    //   - Dashboard "ongoing activity" panels went dark — operators couldn't
    //     tell if a block was holding or the attacker had given up.
    //   - 135.136.44.2 specifically: blocked May 21, kept sending 12k+ ssh
    //     failures/day for 2 days, ZERO new incidents. Bug discovered when
    //     the operator saw the live attack on the dashboard and asked why
    //     ssh_bruteforce hadn't fired in 48h.
    //
    // The agent's block_ip skill is idempotent (re-issuing a UFW rule that
    // already exists is a no-op), so the original "save CPU" concern was
    // largely moot. Each detector also has its own per-incident dedupe (e.g.
    // ssh_bruteforce suppresses re-alerts for 300s per IP), so removing the
    // early return doesn't flood the incidents table either.
    //
    // The `blocked_ips` set is still loaded (line above) — other code paths
    // may want to use it as a hint (e.g. severity tagging on the dashboard).
    // It just no longer silences the detector pipeline.
    let _blocked_ip_hint = should_use_blocked_ip_hint(&ev, &detectors.blocked_ips);

    // Dynamic allowlist pre-check: skip incident generation for allowlisted
    // processes, IPs, and ports. Events are still logged -- only detectors are skipped.
    {
        let comm = ev
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let src_ip = ev
            .details
            .get("ip")
            .or_else(|| ev.details.get("src_ip"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let dst_port = ev
            .details
            .get("dst_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX) as u16;

        if !comm.is_empty() && detectors.dynamic_allowlist.is_process_allowed(comm, None) {
            return;
        }
        if !src_ip.is_empty() && detectors.dynamic_allowlist.is_ip_allowed(src_ip) {
            return;
        }
        if dst_port != u16::MAX && detectors.dynamic_allowlist.is_port_ignored(dst_port) {
            return;
        }
        // DNS domain allowlist — skip dns_tunneling for allowed domains
        let domain = ev
            .details
            .get("domain")
            .or_else(|| ev.details.get("rrname"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !domain.is_empty() && detectors.dynamic_allowlist.is_dns_domain_allowed(domain) {
            return;
        }
    }

    if is_passthrough_source(&ev.source) {
        let is_actionable = matches!(ev.severity, Severity::High | Severity::Critical);
        if is_actionable {
            if let Some(incident) = passthrough_incident(&ev) {
                write_incident(sqlite, stats, incident, syslog, dedup_cache);
            }
        }
        // Passthrough sources don't need InnerWarden detectors - return early.
        return;
    }

    if let Some(ref mut det) = detectors.ssh {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.credential_stuffing {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.port_scan {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Same post-emit allowlist gate as kernel_module_load above.
    // Operator-reported FP: `apt upgrade` causes the `ubuntu` user to
    // exceed the sudo-rate threshold during normal maintenance.
    let sudo_incident = detectors.sudo_abuse.as_mut().and_then(|d| d.process(&ev));
    if let Some(incident) = sudo_incident {
        if !detectors.is_incident_suppressed(&incident, "sudo_abuse") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.search_abuse {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.web_scan {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.user_agent_scanner {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.execution_guard {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.docker_anomaly {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.integrity_alert]` before writing.
    let integrity_alert_incident = detectors
        .integrity_alert
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = integrity_alert_incident {
        if !detectors.is_incident_suppressed(&incident, "integrity_alert") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.log_tampering]` before writing.
    let log_tampering_incident = detectors
        .log_tampering
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = log_tampering_incident {
        if !detectors.is_incident_suppressed(&incident, "log_tampering") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.distributed_ssh {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.suspicious_login {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.c2_callback {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.process_tree {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.container_escape {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.privesc]` before writing.
    let privesc_incident = detectors.privesc.as_mut().and_then(|d| d.process(&ev));
    if let Some(incident) = privesc_incident {
        if !detectors.is_incident_suppressed(&incident, "privesc") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.fileless]` before writing.
    let fileless_incident = detectors.fileless.as_mut().and_then(|d| d.process(&ev));
    if let Some(incident) = fileless_incident {
        if !detectors.is_incident_suppressed(&incident, "fileless") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.dns_tunneling {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.lateral_movement {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.crypto_miner {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.outbound_anomaly {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.rootkit]` before writing.
    let rootkit_incident = detectors.rootkit.as_mut().and_then(|d| d.process(&ev));
    if let Some(incident) = rootkit_incident {
        if !detectors.is_incident_suppressed(&incident, "rootkit") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.reverse_shell {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.ssh_key_injection]` before writing.
    let ssh_key_injection_incident = detectors
        .ssh_key_injection
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = ssh_key_injection_incident {
        if !detectors.is_incident_suppressed(&incident, "ssh_key_injection") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.web_shell {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (operator-reported 2026-05-16): the legit
    // boot-time module loads (bcache, dm_raid, iscsi_*, cxgb*, libcrc32c)
    // fire every apt upgrade. Detector body doesn't thread the allowlist
    // through, so we extract the incident here and consult per_detector
    // before writing. as_mut().and_then(…) releases the &mut borrow on
    // detectors.kernel_module_load before we read .dynamic_allowlist.
    let kmod_incident = detectors
        .kernel_module_load
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = kmod_incident {
        if !detectors.is_incident_suppressed(&incident, "kernel_module_load") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.crontab_persistence]` before writing.
    let crontab_persistence_incident = detectors
        .crontab_persistence
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = crontab_persistence_incident {
        if !detectors.is_incident_suppressed(&incident, "crontab_persistence") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.data_exfiltration {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.process_injection {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.user_creation]` before writing.
    let user_creation_incident = detectors
        .user_creation
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = user_creation_incident {
        if !detectors.is_incident_suppressed(&incident, "user_creation") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Same post-emit allowlist gate as kernel_module_load above.
    // Operator-reported FPs: `systemctl daemon-reload` and
    // `systemctl --quiet is-enabled crowdsec` (needrestart calls these
    // on every apt upgrade) lit up systemd_persistence as Medium.
    let systemd_incident = detectors
        .systemd_persistence
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = systemd_incident {
        if !detectors.is_incident_suppressed(&incident, "systemd_persistence") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.ransomware {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.credential_harvest {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.packet_flood {
        for incident in det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.sensitive_write]` before writing.
    let sensitive_write_incident = detectors
        .sensitive_write
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = sensitive_write_incident {
        if !detectors.is_incident_suppressed(&incident, "sensitive_write") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Spec 050-PR0 context-aware pre-emit gate. Skip the detector
    // entirely when the event's execution context proves benign
    // (operator interactive shell, package-manager postinst,
    // automation, boot/MOTD) or the comm is on the legacy
    // `DISCOVERY_ALLOWED` / `[detectors.discovery_anomaly]` list. This
    // is the operator-flagged 2026-05-16 fix: a sandcat agent running
    // the same `whoami`/`ps` as a real operator no longer hides behind
    // the blanket allowlist — the context check distinguishes the two.
    let discovery_burst_incident = if detectors.dynamic_allowlist.is_benign_discovery(&ev) {
        None
    } else {
        detectors
            .discovery_burst
            .as_mut()
            .and_then(|d| d.process(&ev))
    };
    if let Some(incident) = discovery_burst_incident {
        // Post-emit allowlist gate retained for the
        // `[detectors.discovery_burst]` TOML section (mirrors
        // kernel_module_load + sudo_abuse + systemd_persistence +
        // mitre_hunt from PR #647). The pre-emit gate above handles
        // the *event* level; this handles the *incident* level for
        // operators allowlisting specific outcomes.
        if !detectors.is_incident_suppressed(&incident, "discovery_burst") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.io_uring_anomaly {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.container_drift]` before writing.
    let container_drift_incident = detectors
        .container_drift
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = container_drift_incident {
        if !detectors.is_incident_suppressed(&incident, "container_drift") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.host_drift]` before writing.
    let host_drift_incident = detectors.host_drift.as_mut().and_then(|d| d.process(&ev));
    if let Some(incident) = host_drift_incident {
        if !detectors.is_incident_suppressed(&incident, "host_drift") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.data_exfil_ebpf {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.imds_ssrf {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.yara_scan {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.sigma_rule {
        let mut sigma_suppress = detectors.dynamic_allowlist.suppress_sigma_rules.clone();
        if let Some(yaml_ids) = detectors
            .event_pipeline
            .incident_suppressions
            .values_for("sigma_rule")
        {
            sigma_suppress.extend(yaml_ids.iter().cloned());
        }
        if let Some(incident) = det.process_with_suppressions(&ev, &sigma_suppress) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Same post-emit allowlist gate as kernel_module_load above.
    // Operator-reported FP: `mitre_hunt::destructive_dd` fires whenever
    // the operator runs `dd` for legitimate reasons (cloning disks,
    // writing installer media). Operators allowlist `dd` per-detector
    // with `[detectors.mitre_hunt] dd = "operator allow-list"`.
    let mitre_incident = detectors.mitre_hunt.as_mut().and_then(|d| d.process(&ev));
    if let Some(incident) = mitre_incident {
        if !detectors.is_incident_suppressed(&incident, "mitre_hunt") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.dns_c2 {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.data_encoding {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    if let Some(ref mut det) = detectors.sandbox_evasion {
        if let Some(incident) = det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Threat intelligence dataset matching (O(1) per lookup).
    if let Some(ref mut det) = detectors.threat_intel {
        if let Some(incident) = det.process(&ev, threat_datasets) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Protocol anomaly detection (works on tcp_stream events).
    if let Some(ref mut det) = detectors.proto_anomaly {
        for incident in det.process(&ev) {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR1 — Reconnaissance trio. Each consults
    // dynamic_allowlist for post-emit suppression so operators can
    // tune via `[detectors.<name>]` without recompile. discovery_anomaly
    // also consults `exec_context::classify` inside its own process().
    let nmap_incident = if detectors.dynamic_allowlist.is_benign_discovery(&ev) {
        None
    } else {
        detectors.nmap_scan.as_mut().and_then(|d| d.process(&ev))
    };
    if let Some(incident) = nmap_incident {
        if !detectors.is_incident_suppressed(&incident, "nmap_scan") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let wordlist_incident = detectors
        .wordlist_scan
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = wordlist_incident {
        if !detectors.is_incident_suppressed(&incident, "wordlist_scan") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let discovery_anomaly_incident = detectors
        .discovery_anomaly
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = discovery_anomaly_incident {
        if !detectors.is_incident_suppressed(&incident, "discovery_anomaly") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR2 — Collection detectors. All five accept the
    // event-loop event directly; post-emit allowlist consultation
    // mirrors PR1's pattern so operators can tune via
    // `[detectors.<name>]` without recompile.
    let clipboard_read_incident = detectors
        .clipboard_read
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = clipboard_read_incident {
        if !detectors.is_incident_suppressed(&incident, "clipboard_read") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let screen_capture_incident = detectors
        .screen_capture
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = screen_capture_incident {
        if !detectors.is_incident_suppressed(&incident, "screen_capture") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let keylogger_bash_trap_incident = detectors
        .keylogger_bash_trap
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = keylogger_bash_trap_incident {
        if !detectors.is_incident_suppressed(&incident, "keylogger_bash_trap") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let archive_pwd_protected_incident = detectors
        .archive_pwd_protected
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = archive_pwd_protected_incident {
        if !detectors.is_incident_suppressed(&incident, "archive_pwd_protected") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let automated_file_collection_incident = detectors
        .automated_file_collection
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = automated_file_collection_incident {
        if !detectors.is_incident_suppressed(&incident, "automated_file_collection") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR3 — C2 variants
    let c2_web_tunnel_incident = detectors
        .c2_web_tunnel
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = c2_web_tunnel_incident {
        if !detectors.is_incident_suppressed(&incident, "c2_web_tunnel") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let c2_protocol_tunneling_incident = detectors
        .c2_protocol_tunneling
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = c2_protocol_tunneling_incident {
        if !detectors.is_incident_suppressed(&incident, "c2_protocol_tunneling") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let c2_non_standard_port_incident = detectors
        .c2_non_standard_port
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = c2_non_standard_port_incident {
        if !detectors.is_incident_suppressed(&incident, "c2_non_standard_port") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR4 — Privilege Escalation + Lateral Movement
    let setuid_exploit_pattern_incident = detectors
        .setuid_exploit_pattern
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = setuid_exploit_pattern_incident {
        if !detectors.is_incident_suppressed(&incident, "setuid_exploit_pattern") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let capabilities_abuse_incident = detectors
        .capabilities_abuse
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = capabilities_abuse_incident {
        if !detectors.is_incident_suppressed(&incident, "capabilities_abuse") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let lateral_egress_ssh_incident = detectors
        .lateral_egress_ssh
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = lateral_egress_ssh_incident {
        if !detectors.is_incident_suppressed(&incident, "lateral_egress_ssh") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let lateral_egress_scp_rsync_incident = detectors
        .lateral_egress_scp_rsync
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = lateral_egress_scp_rsync_incident {
        if !detectors.is_incident_suppressed(&incident, "lateral_egress_scp_rsync") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR5 — Persistence + Defense Evasion
    let pam_module_change_incident = detectors
        .pam_module_change
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = pam_module_change_incident {
        if !detectors.is_incident_suppressed(&incident, "pam_module_change") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let auditd_disable_incident = detectors
        .auditd_disable
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = auditd_disable_incident {
        if !detectors.is_incident_suppressed(&incident, "auditd_disable") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let selinux_apparmor_disable_incident = detectors
        .selinux_apparmor_disable
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = selinux_apparmor_disable_incident {
        if !detectors.is_incident_suppressed(&incident, "selinux_apparmor_disable") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let startup_script_persistence_incident = detectors
        .startup_script_persistence
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = startup_script_persistence_incident {
        if !detectors.is_incident_suppressed(&incident, "startup_script_persistence") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR6 — Impact
    let data_destruction_pattern_incident = detectors
        .data_destruction_pattern
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = data_destruction_pattern_incident {
        if !detectors.is_incident_suppressed(&incident, "data_destruction_pattern") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // 2026-05-17 wave — gap closers
    let symlink_hijack_incident = detectors
        .symlink_hijack
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = symlink_hijack_incident {
        if !detectors.is_incident_suppressed(&incident, "symlink_hijack") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let system_user_interactive_incident = detectors
        .system_user_interactive
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = system_user_interactive_incident {
        if !detectors.is_incident_suppressed(&incident, "system_user_interactive") {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }
}

// passthrough_incident + build_devnode_watchlist + devnode_exposed_incident
// + page_cache_mismatch_incident moved to crates/sensor/src/incident_builders.rs
// as part of the 2026-05-25 main.rs decomposition PR4.

fn write_incident(
    sqlite: &SqliteWriter,
    stats: &mut WriteStats,
    incident: innerwarden_core::incident::Incident,
    syslog: &mut Option<sinks::syslog_cef::SyslogCefWriter>,
    dedup_cache: &mut HashMap<u32, (chrono::DateTime<chrono::Utc>, u8)>,
) {
    // Cross-detector dedup: if the same PID had an incident in the last 10s,
    // only keep the highest severity. This prevents duplicate alerts when
    // multiple detectors fire for the same activity.
    let pid = incident
        .evidence
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|v| v.get("pid"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    if pid > 0 {
        let now = chrono::Utc::now();
        let new_rank = severity_rank(&incident.severity);
        if let Some((ts, prev_rank)) = dedup_cache.get(&pid) {
            let elapsed = now.signed_duration_since(*ts);
            if elapsed.num_seconds() < 10 && new_rank <= *prev_rank {
                // Lower or equal severity within 10s window -- suppress
                return;
            }
        }
        dedup_cache.insert(pid, (now, new_rank));
    }

    info!(
        incident_id = %incident.incident_id,
        severity = ?incident.severity,
        title = %incident.title,
        "INCIDENT"
    );
    sqlite.write_incident(&incident);
    stats.incidents_written += 1;
    // Syslog CEF output for incidents
    if let Some(ref mut cef) = syslog {
        cef.write_incident(&incident);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── Anchor: blocked-IP early-return must STAY removed ────────────────
    //
    // 2026-05-23: an old `process_event` had this pattern just before the
    // detector calls:
    //   if !src_ip.is_empty() && detectors.blocked_ips.contains(src_ip) {
    //       return;
    //   }
    // The "save CPU on already-blocked traffic" intent was reasonable but
    // the side-effect was that ssh_bruteforce / distributed_ssh / kill_chain
    // / mitre_hunt all stopped seeing events from blocked IPs. IP
    // 135.136.44.2 (blocked May 21, kept attacking for 48h with 12k+ ssh
    // failures, ZERO new incidents) made the problem visible.
    //
    // The helper `should_use_blocked_ip_hint` still exists so other code
    // can use the blocked set as a HINT (severity tagging, etc), but the
    // anchor below pins that the function is a *hint*, not a kill-switch:
    // a future contributor must not re-add an `if ... { return; }` around
    // its call in `process_event` without explicitly justifying it. If
    // they do, the regression test below should also be deleted with a
    // comment explaining why the old behaviour is acceptable again.
    //
    // Moved from main.rs::tests on 2026-05-25 (PR5a) when process_event
    // moved to this file; the include_str! target moved with it.
    #[test]
    fn blocked_ip_hint_returns_true_but_does_not_imply_skip() {
        use innerwarden_core::event::{Event, Severity};

        let mut blocked = HashSet::new();
        blocked.insert("135.136.44.2".to_string());

        let ev = Event {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "Failed login from 135.136.44.2".to_string(),
            details: serde_json::json!({
                "ip": "135.136.44.2",
                "user": "root",
                "reason": "invalid_user",
            }),
            tags: vec![],
            entities: vec![],
        };

        // The helper correctly reports that this IP is in the blocked set.
        assert!(
            should_use_blocked_ip_hint(&ev, &blocked),
            "helper must return true when src_ip is in the blocked set"
        );

        // Anti-regression: search the source of `process_event` for the
        // forbidden pattern. If anyone wires `should_use_blocked_ip_hint`
        // to a `return;` inside `process_event`, the silent-pipeline-kill
        // bug from 2026-05-23 comes back. The check is grep-level because
        // we can't easily run the full process_event harness in a unit
        // test (depends on SqliteWriter, DetectorSet, syslog, etc).
        let dispatch_src = include_str!("event_dispatch.rs");
        let process_event_start = dispatch_src
            .find("pub(crate) fn process_event(")
            .expect("process_event function must exist in event_dispatch.rs");
        let process_event_body = &dispatch_src
            [process_event_start..(process_event_start + 8000).min(dispatch_src.len())];
        let forbidden_pattern = "if should_use_blocked_ip_hint";
        assert!(
            !process_event_body.contains(&format!("{forbidden_pattern}(&ev, &detectors.blocked_ips) {{\n        return;")) &&
            !process_event_body.contains(&format!("{forbidden_pattern}(&ev, &detectors.blocked_ips) {{\n            return;")),
            "process_event must NOT short-circuit on blocked IPs — see the 2026-05-23 incident comment in the function body. \
             If you intentionally re-added the early-return, delete THIS test with a comment explaining why."
        );
    }
}
