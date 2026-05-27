//! The consumer-side event loop + shutdown sequence.
//!
//! Extracted from `main.rs` on 2026-05-25 as PR5b3 of the main.rs
//! decomposition (see SESSION_LOG.md). Pure code motion — zero
//! behaviour change. ~88 LoC moved.
//!
//! ## Phases covered
//!
//! - **I. Event loop** — `tokio::select!` between `rx.recv()`,
//!   `ctrl_c`, and (Unix) `SIGTERM`. Each delivered event flows
//!   through [`event_dispatch::process_event`]. The loop exits when
//!   the channel returns `None` (every collector task dropped its
//!   sender) or a signal fires.
//! - **J. Shutdown** — log final stats, snapshot every shared-cursor
//!   Arc into the persistent `State`, write the state file to disk.
//!
//! ## Why these two go together
//!
//! Both phases share the same state (`stats`, `state`, every
//! shared-cursor `Arc`). Splitting them would require either passing
//! a giant tuple of references between sub-functions or introducing
//! an event-loop-context struct — both add noise without solving
//! anything. The shutdown phase's reads from the shared cursors are
//! the natural cleanup hook for the loop above; keeping them in one
//! function makes the data flow obvious.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::Result;
use innerwarden_core::event::Event;
use tokio::sync::mpsc;
use tracing::info;

use crate::boot::cursors::SharedCursors;
use crate::detector_set::DetectorSet;
use crate::detectors::datasets::Datasets;
use crate::event_dispatch;
use crate::sinks;
use crate::sinks::sqlite::SqliteWriter;
use crate::sinks::state::State;
use crate::WriteStats;

/// Drain the event channel into the detector dispatch + write incidents
/// to sinks until either the channel closes (all collectors stopped)
/// or a shutdown signal (SIGINT / SIGTERM) fires. On exit, persist
/// every shared-cursor Arc into the State and write it to disk.
///
/// 2026-05-25 (PR-F2): signature collapsed from 16 params to 9 by
/// taking `&SharedCursors` instead of 8 individual cursor Arcs. The
/// `shared_X` locals destructured below preserve the original body
/// verbatim — pure mechanical refactor, zero behaviour change.
///
/// 9 > clippy's 7-arg threshold, so `#[allow(too_many_arguments)]`
/// stays. PR-F3 will lift these params into a `Sensor` struct so
/// run_event_loop becomes a method on `&mut Sensor` — that's where
/// the allow finally drops.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_event_loop(
    mut rx: mpsc::Receiver<Event>,
    sqlite_writer: &SqliteWriter,
    detectors: &mut DetectorSet,
    syslog_writer: &mut Option<sinks::syslog_cef::SyslogCefWriter>,
    threat_datasets: &mut Datasets,
    state: &mut State,
    state_path: &Path,
    #[cfg(unix)] mut sigterm: tokio::signal::unix::Signal,
    cursors: &SharedCursors,
) -> Result<()> {
    let SharedCursors {
        auth_offset: shared_auth_offset,
        integrity_hashes: shared_integrity_hashes,
        journald_cursor: shared_journald_cursor,
        docker_since: shared_docker_since,
        exec_audit_offset: shared_exec_audit_offset,
        nginx_offset: shared_nginx_offset,
        nginx_error_offset: shared_nginx_error_offset,
        syslog_firewall_offset: shared_syslog_firewall_offset,
    } = cursors.clone();
    // Main loop: drain events, run detectors, write output
    let mut stats = WriteStats::default();

    // Cross-detector dedup cache: PID -> (last_incident_ts, severity_rank).
    // Prevents multiple detectors from emitting incidents for the same PID
    // within a 10-second window. Only the highest severity is kept.
    let mut dedup_cache: HashMap<u32, (chrono::DateTime<chrono::Utc>, u8)> = HashMap::new();

    'main: loop {
        // Receive next event or signal
        #[cfg(unix)]
        let received = tokio::select! {
            event = rx.recv() => event,
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received - shutting down");
                break 'main;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received - shutting down");
                break 'main;
            }
        };

        #[cfg(not(unix))]
        let received = tokio::select! {
            event = rx.recv() => event,
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received - shutting down");
                break 'main;
            }
        };

        let Some(ev) = received else {
            info!("all collectors stopped");
            break 'main;
        };

        // Periodic dataset reload (every hour)
        threat_datasets.maybe_reload();

        event_dispatch::process_event(
            ev,
            sqlite_writer,
            detectors,
            &mut stats,
            syslog_writer,
            &mut dedup_cache,
            threat_datasets,
        );
    }

    info!(
        events_written = stats.events_written,
        events_dropped = stats.events_dropped,
        incidents_written = stats.incidents_written,
        pipeline_rules = detectors.event_pipeline.rule_count(),
        "sensor stopped"
    );

    // Persist collector state using the latest values from the shared Arcs
    let auth_offset = shared_auth_offset.load(Ordering::Relaxed);
    state.set_cursor("auth_log", serde_json::json!(auth_offset));

    let integrity_hashes = shared_integrity_hashes.lock().unwrap().clone();
    if !integrity_hashes.is_empty() {
        state.set_cursor("integrity", serde_json::to_value(&integrity_hashes)?);
    }

    if let Some(cursor) = shared_journald_cursor.lock().unwrap().clone() {
        state.set_cursor("journald", serde_json::json!(cursor));
    }

    if let Some(since) = shared_docker_since.lock().unwrap().clone() {
        state.set_cursor("docker", serde_json::json!(since));
    }

    let exec_audit_offset = shared_exec_audit_offset.load(Ordering::Relaxed);
    state.set_cursor("exec_audit", serde_json::json!(exec_audit_offset));

    let nginx_offset = shared_nginx_offset.load(Ordering::Relaxed);
    state.set_cursor("nginx_access", serde_json::json!(nginx_offset));

    let nginx_error_offset = shared_nginx_error_offset.load(Ordering::Relaxed);
    state.set_cursor("nginx_error", serde_json::json!(nginx_error_offset));

    let syslog_firewall_offset = shared_syslog_firewall_offset.load(Ordering::Relaxed);
    state.set_cursor("syslog_firewall", serde_json::json!(syslog_firewall_offset));

    state.save(state_path)?;
    info!(auth_offset, "state saved");

    Ok(())
}
