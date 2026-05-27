mod boot;
mod collector_health;
mod collectors;
mod config;
mod detector_set;
mod detectors;
mod event_dispatch;
mod event_pipeline;
mod incident_builders;
mod main_helpers;
mod seccomp;
mod sensor;
mod sinks;
mod tracing_init;

use anyhow::Result;
use clap::Parser;
// All collector type imports (AuthLogCollector / CloudTrailCollector /
// DockerCollector / ExecAuditCollector / IntegrityCollector /
// JournaldCollector / MacosLogCollector / NginxAccessCollector /
// NginxErrorCollector / SyslogFirewallCollector) moved to
// crates/sensor/src/boot/spawn_collectors.rs as part of the 2026-05-25
// main.rs decomposition PR5b2 — they're only constructed inside that
// module's spawn fn.
//
// All detector type imports (35 of them: SshBruteforceDetector,
// CredentialStuffingDetector, PortScanDetector, …) moved to
// crates/sensor/src/detector_set.rs as part of follow-up #2 of the
// post-PR-F3 punch list (2026-05-26). They're only mentioned inside
// the DetectorSet struct, which now lives next to them.

#[derive(Parser)]
#[command(
    name = "innerwarden-sensor",
    version,
    about = "Lightweight host observability sensor"
)]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: String,
}

// DetectorSet moved to crates/sensor/src/detector_set.rs as part of
// follow-up #2 of the post-PR-F3 punch list (2026-05-26). It pulled
// 35 detector type imports + ~100 LoC of fields out of main.rs;
// callers that previously imported `crate::DetectorSet` now import
// `crate::detector_set::DetectorSet`.

#[derive(Default)]
pub(crate) struct WriteStats {
    pub(crate) events_written: u64,
    pub(crate) events_dropped: u64,
    pub(crate) incidents_written: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init::init_tracing()?;
    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;
    sensor::run(cfg).await
}

// 11 small helpers (load_blocked_ips, state_path_for, blocked_ips_path_for,
// parse_blocked_ips, should_spawn_integrity_collector, should_enable_syslog_sink,
// parse_syslog_port, choose_syslog_protocol, severity_rank, is_passthrough_source,
// should_use_blocked_ip_hint) moved to crates/sensor/src/main_helpers.rs as part
// of the 2026-05-25 main.rs decomposition PR2. The previous `/// Load blocked
// IPs from the file written by the agent.` doc comment moved with `load_blocked_ips`
// — its body is in main_helpers.rs.

// apply_seccomp_profile + bpf_stmt + bpf_jump + syscall_name_to_nr
// moved to crates/sensor/src/seccomp.rs as part of the 2026-05-25
// main.rs decomposition PR3. The whole module is Linux-gated and
// carries byte-level anchor tests for the `struct sock_filter`
// packing that ARE the seccomp policy.

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    // (parse_blocked_ips / helper_paths_resolve_inside_data_dir /
    //  should_spawn_integrity_collector / parse_syslog_port /
    //  choose_syslog_protocol / severity_rank anchors moved to
    //  crates/sensor/src/main_helpers.rs as part of the 2026-05-25
    //  main.rs decomposition PR2.)

    // (6 incident-builder anchors moved to
    //  crates/sensor/src/incident_builders.rs as part of the 2026-05-25
    //  main.rs decomposition PR4 — page_cache_mismatch_event_promotes_to_critical_incident,
    //  devnode_exposed_event_promotes_to_medium_incident, and the four
    //  build_devnode_watchlist_* tests.)

    // (passthrough_sources_are_disabled_by_default moved to main_helpers.rs
    //  as `is_passthrough_source_returns_false_for_all_known_sources` — same
    //  contract, broader source coverage.)

    #[test]
    fn cli_parses_default_and_custom_config_path() {
        let default_cli =
            Cli::try_parse_from(["innerwarden-sensor"]).expect("default CLI should parse");
        assert_eq!(default_cli.config, "config.toml");

        let custom_cli = Cli::try_parse_from([
            "innerwarden-sensor",
            "--config",
            "/etc/innerwarden/sensor.toml",
        ])
        .expect("custom config CLI should parse");
        assert_eq!(custom_cli.config, "/etc/innerwarden/sensor.toml");
    }

    // (5 helper unit tests moved to main_helpers.rs as part of PR2:
    //  parse_blocked_ips_deduplicates_and_keeps_comment_lines_as_tokens,
    //  load_blocked_ips_returns_empty_for_missing_feedback_file,
    //  load_blocked_ips_reads_agent_feedback_file,
    //  should_enable_syslog_sink_requires_non_empty_host,
    //  parse_syslog_port_rejects_out_of_range_values.)

    // ── Wave 9f anchors (2026-05-04) — journald-detection contract ───────
    //
    // AUDIT-009 root: tracing-subscriber writes plain text to stdout which
    // journald captures with no `PRIORITY=` field. `journalctl -p warning`
    // then silently drops every WARN this crate emits. The fix routes
    // tracing through `tracing-journald` when the binary runs under
    // systemd (detected via JOURNAL_STREAM env var). These anchors pin
    // the detection logic so a future refactor that breaks the env-var
    // contract is caught at test time rather than by the operator one
    // morning when their `journalctl -p warning` query goes silent.

    // (use_journald_layer anchors moved to crates/sensor/src/tracing_init.rs
    //  as part of the 2026-05-25 main.rs decomposition PR1.)

    // (blocked_ip_hint_returns_true_but_does_not_imply_skip + its 2026-05-23
    //  early-return-removal anchor moved to crates/sensor/src/event_dispatch.rs
    //  as part of the 2026-05-25 main.rs decomposition PR5a, alongside
    //  process_event itself. The `include_str!` source-grep target moved
    //  with it from "main.rs" to "event_dispatch.rs".)

    // (build_tracing_env_filter anchor moved to crates/sensor/src/tracing_init.rs
    //  as part of the 2026-05-25 main.rs decomposition PR1.)
}
