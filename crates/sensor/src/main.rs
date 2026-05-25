mod collector_health;
mod collectors;
mod config;
mod detectors;
mod main_helpers;
mod seccomp;
mod sinks;
mod tracing_init;

use main_helpers::{
    choose_syslog_protocol, is_passthrough_source, load_blocked_ips, parse_syslog_port,
    severity_rank, should_enable_syslog_sink, should_spawn_integrity_collector,
    should_use_blocked_ip_hint, state_path_for,
};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;
use collectors::{
    auth_log::AuthLogCollector, cloudtrail::CloudTrailCollector, docker::DockerCollector,
    exec_audit::ExecAuditCollector, integrity::IntegrityCollector, journald::JournaldCollector,
    macos_log::MacosLogCollector, nginx_access::NginxAccessCollector,
    nginx_error::NginxErrorCollector, syslog_firewall::SyslogFirewallCollector,
};
use detectors::c2_callback::C2CallbackDetector;
use detectors::container_escape::ContainerEscapeDetector;
use detectors::credential_harvest::CredentialHarvestDetector;
use detectors::credential_stuffing::CredentialStuffingDetector;
use detectors::crontab_persistence::CrontabPersistenceDetector;
use detectors::crypto_miner::CryptoMinerDetector;
use detectors::data_exfiltration::DataExfiltrationDetector;
use detectors::distributed_ssh::DistributedSshDetector;
use detectors::dns_tunneling::DnsTunnelingDetector;
use detectors::docker_anomaly::DockerAnomalyDetector;
use detectors::execution_guard::{ExecutionGuardDetector, ExecutionMode};
use detectors::fileless::FilelessDetector;
use detectors::integrity_alert::IntegrityAlertDetector;
use detectors::kernel_module_load::KernelModuleLoadDetector;
use detectors::lateral_movement::LateralMovementDetector;
use detectors::log_tampering::LogTamperingDetector;
use detectors::outbound_anomaly::OutboundAnomalyDetector;
use detectors::packet_flood::PacketFloodDetector;
use detectors::port_scan::PortScanDetector;
use detectors::privesc::PrivescDetector;
use detectors::process_injection::ProcessInjectionDetector;
use detectors::process_tree::ProcessTreeDetector;
use detectors::ransomware::RansomwareDetector;
use detectors::reverse_shell::ReverseShellDetector;
use detectors::rootkit::RootkitDetector;
use detectors::search_abuse::SearchAbuseDetector;
use detectors::ssh_bruteforce::SshBruteforceDetector;
use detectors::ssh_key_injection::SshKeyInjectionDetector;
use detectors::sudo_abuse::SudoAbuseDetector;
use detectors::suspicious_login::SuspiciousLoginDetector;
use detectors::systemd_persistence::SystemdPersistenceDetector;
use detectors::user_agent_scanner::UserAgentScannerDetector;
use detectors::user_creation::UserCreationDetector;
use detectors::web_scan::WebScanDetector;
use detectors::web_shell::WebShellDetector;
use sinks::{sqlite::SqliteWriter, state::State};
use tokio::sync::mpsc;
#[allow(unused_imports)]
use tracing::{info, warn};

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

struct DetectorSet {
    /// Dynamic allowlist loaded from /etc/innerwarden/allowlist.toml.
    /// Checked before all detectors -- if a process/IP is allowlisted,
    /// the event is still logged but no incident is generated.
    dynamic_allowlist: detectors::allowlists::DynamicAllowlist,
    /// Last time we checked the allowlist file for changes.
    allowlist_last_check: std::time::Instant,

    /// IPs blocked by the agent. Loaded from blocked-ips.txt and
    /// reloaded every 60s. Events from these IPs skip detection.
    blocked_ips: HashSet<String>,
    /// Last time we reloaded blocked-ips.txt.
    blocked_ips_last_check: std::time::Instant,

    ssh: Option<SshBruteforceDetector>,
    credential_stuffing: Option<CredentialStuffingDetector>,
    port_scan: Option<PortScanDetector>,
    sudo_abuse: Option<SudoAbuseDetector>,
    search_abuse: Option<SearchAbuseDetector>,
    web_scan: Option<WebScanDetector>,
    user_agent_scanner: Option<UserAgentScannerDetector>,
    execution_guard: Option<ExecutionGuardDetector>,
    docker_anomaly: Option<DockerAnomalyDetector>,
    integrity_alert: Option<IntegrityAlertDetector>,
    log_tampering: Option<LogTamperingDetector>,
    distributed_ssh: Option<DistributedSshDetector>,
    suspicious_login: Option<SuspiciousLoginDetector>,
    c2_callback: Option<C2CallbackDetector>,
    process_tree: Option<ProcessTreeDetector>,
    container_escape: Option<ContainerEscapeDetector>,
    privesc: Option<PrivescDetector>,
    fileless: Option<FilelessDetector>,
    dns_tunneling: Option<DnsTunnelingDetector>,
    lateral_movement: Option<LateralMovementDetector>,
    crypto_miner: Option<CryptoMinerDetector>,
    outbound_anomaly: Option<OutboundAnomalyDetector>,
    rootkit: Option<RootkitDetector>,
    reverse_shell: Option<ReverseShellDetector>,
    ssh_key_injection: Option<SshKeyInjectionDetector>,
    web_shell: Option<WebShellDetector>,
    kernel_module_load: Option<KernelModuleLoadDetector>,
    crontab_persistence: Option<CrontabPersistenceDetector>,
    data_exfiltration: Option<DataExfiltrationDetector>,
    process_injection: Option<ProcessInjectionDetector>,
    user_creation: Option<UserCreationDetector>,
    systemd_persistence: Option<SystemdPersistenceDetector>,
    ransomware: Option<RansomwareDetector>,
    credential_harvest: Option<CredentialHarvestDetector>,
    packet_flood: Option<PacketFloodDetector>,
    sensitive_write: Option<detectors::sensitive_write::SensitiveWriteDetector>,
    discovery_burst: Option<detectors::discovery_burst::DiscoveryBurstDetector>,
    io_uring_anomaly: Option<detectors::io_uring_anomaly::IoUringAnomalyDetector>,
    container_drift: Option<detectors::container_drift::ContainerDriftDetector>,
    host_drift: Option<detectors::host_drift::HostDriftDetector>,
    data_exfil_ebpf: Option<detectors::data_exfil_ebpf::DataExfilEbpfDetector>,
    imds_ssrf: Option<detectors::imds_ssrf::ImdsSsrfDetector>,
    yara_scan: Option<detectors::yara_scan::YaraScanDetector>,
    sigma_rule: Option<detectors::sigma_rule::SigmaRuleDetector>,
    mitre_hunt: Option<detectors::mitre_hunt::MitreHuntDetector>,
    dns_c2: Option<detectors::dns_c2::DnsC2Detector>,
    data_encoding: Option<detectors::data_encoding::DataEncodingDetector>,
    sandbox_evasion: Option<detectors::sandbox_evasion::SandboxEvasionDetector>,
    threat_intel: Option<detectors::threat_intel::ThreatIntelDetector>,
    proto_anomaly: Option<detectors::proto_anomaly::ProtoAnomalyDetector>,
    // spec 050-PR1 — Reconnaissance
    nmap_scan: Option<detectors::nmap_scan::NmapScanDetector>,
    wordlist_scan: Option<detectors::wordlist_scan::WordlistScanDetector>,
    discovery_anomaly: Option<detectors::discovery_anomaly::DiscoveryAnomalyDetector>,
    // spec 050-PR2 — Collection
    clipboard_read: Option<detectors::clipboard_read::ClipboardReadDetector>,
    screen_capture: Option<detectors::screen_capture::ScreenCaptureDetector>,
    keylogger_bash_trap: Option<detectors::keylogger_bash_trap::KeyloggerBashTrapDetector>,
    archive_pwd_protected: Option<detectors::archive_pwd_protected::ArchivePwdProtectedDetector>,
    automated_file_collection:
        Option<detectors::automated_file_collection::AutomatedFileCollectionDetector>,
    // spec 050-PR3 — C2 variants
    c2_web_tunnel: Option<detectors::c2_web_tunnel::C2WebTunnelDetector>,
    c2_protocol_tunneling: Option<detectors::c2_protocol_tunneling::C2ProtocolTunnelingDetector>,
    c2_non_standard_port: Option<detectors::c2_non_standard_port::C2NonStandardPortDetector>,
    // spec 050-PR4 — Privilege Escalation + Lateral Movement
    setuid_exploit_pattern: Option<detectors::setuid_exploit_pattern::SetuidExploitPatternDetector>,
    capabilities_abuse: Option<detectors::capabilities_abuse::CapabilitiesAbuseDetector>,
    lateral_egress_ssh: Option<detectors::lateral_egress_ssh::LateralEgressSshDetector>,
    lateral_egress_scp_rsync:
        Option<detectors::lateral_egress_scp_rsync::LateralEgressScpRsyncDetector>,
    // spec 050-PR5 — Persistence + Defense Evasion
    pam_module_change: Option<detectors::pam_module_change::PamModuleChangeDetector>,
    auditd_disable: Option<detectors::auditd_disable::AuditdDisableDetector>,
    selinux_apparmor_disable:
        Option<detectors::selinux_apparmor_disable::SelinuxApparmorDisableDetector>,
    startup_script_persistence:
        Option<detectors::startup_script_persistence::StartupScriptPersistenceDetector>,
    // spec 050-PR6 — Impact
    data_destruction_pattern:
        Option<detectors::data_destruction_pattern::DataDestructionPatternDetector>,
    // 2026-05-17 wave — gap closers
    symlink_hijack: Option<detectors::symlink_hijack::SymlinkHijackDetector>,
    system_user_interactive:
        Option<detectors::system_user_interactive::SystemUserInteractiveDetector>,
}

#[derive(Default)]
struct WriteStats {
    events_written: u64,
    incidents_written: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init::init_tracing()?;

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;

    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden-sensor v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let data_dir = Path::new(&cfg.output.data_dir);
    let state_path = state_path_for(data_dir);

    let mut state = State::load(&state_path)?;
    info!(cursors = state.cursors.len(), "state loaded");

    let write_events = cfg.output.write_events;

    // SQLite is the primary and only event/incident sink.
    let sqlite_writer = SqliteWriter::new(data_dir, write_events)?;
    info!(path = %data_dir.join("innerwarden.db").display(), "sqlite sink enabled");
    // Optional syslog CEF output (configured via env or future config section)
    let mut syslog_writer: Option<sinks::syslog_cef::SyslogCefWriter> = {
        let syslog_host = std::env::var("INNERWARDEN_SYSLOG_HOST").unwrap_or_default();
        if !should_enable_syslog_sink(&syslog_host) {
            None
        } else {
            let syslog_port = std::env::var("INNERWARDEN_SYSLOG_PORT").ok();
            let port = parse_syslog_port(syslog_port.as_deref());
            let protocol = choose_syslog_protocol(std::env::var("INNERWARDEN_SYSLOG_TCP").is_ok());
            info!(host = %syslog_host, port, "Syslog CEF output enabled");
            Some(sinks::syslog_cef::SyslogCefWriter::new(
                sinks::syslog_cef::SyslogCefConfig {
                    host: syslog_host,
                    port,
                    protocol,
                },
                env!("CARGO_PKG_VERSION"),
            ))
        }
    };
    let (tx, mut rx) = mpsc::channel(1024);

    // Shared state - updated by collectors, read on shutdown for persistence.
    let shared_auth_offset = Arc::new(AtomicU64::new(0));
    let shared_integrity_hashes: Arc<Mutex<HashMap<String, String>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let shared_journald_cursor: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_docker_since: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_exec_audit_offset = Arc::new(AtomicU64::new(0));
    let shared_nginx_offset = Arc::new(AtomicU64::new(0));
    let shared_nginx_error_offset = Arc::new(AtomicU64::new(0));
    let shared_syslog_firewall_offset = Arc::new(AtomicU64::new(0));

    // SSH brute force detector (stateful, lives in main loop)
    let ssh_detector = cfg.detectors.ssh_bruteforce.enabled.then(|| {
        let d = &cfg.detectors.ssh_bruteforce;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "ssh_bruteforce detector enabled"
        );
        SshBruteforceDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let credential_stuffing_detector = cfg.detectors.credential_stuffing.enabled.then(|| {
        let d = &cfg.detectors.credential_stuffing;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "credential_stuffing detector enabled"
        );
        CredentialStuffingDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let port_scan_detector = cfg.detectors.port_scan.enabled.then(|| {
        let d = &cfg.detectors.port_scan;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "port_scan detector enabled"
        );
        PortScanDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let sudo_abuse_detector = cfg.detectors.sudo_abuse.enabled.then(|| {
        let d = &cfg.detectors.sudo_abuse;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "sudo_abuse detector enabled"
        );
        let mut det = SudoAbuseDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds);
        det.set_trusted_users(cfg.allowlist.trusted_users.clone());
        det
    });
    let search_abuse_detector = cfg.detectors.search_abuse.enabled.then(|| {
        let d = &cfg.detectors.search_abuse;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            path_prefix = %d.path_prefix,
            "search_abuse detector enabled"
        );
        SearchAbuseDetector::new(
            &cfg.agent.host_id,
            d.threshold,
            d.window_seconds,
            &d.path_prefix,
        )
    });
    let web_scan_detector = cfg.detectors.web_scan.enabled.then(|| {
        let d = &cfg.detectors.web_scan;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "web_scan detector enabled"
        );
        WebScanDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let user_agent_scanner_detector = cfg.detectors.user_agent_scanner.enabled.then(|| {
        info!("user_agent_scanner detector enabled");
        UserAgentScannerDetector::new(&cfg.agent.host_id)
    });
    let execution_guard_detector = cfg.detectors.execution_guard.enabled.then(|| {
        let d = &cfg.detectors.execution_guard;
        info!(
            mode = %d.mode,
            window_seconds = d.window_seconds,
            "execution_guard detector enabled"
        );
        ExecutionGuardDetector::new(
            &cfg.agent.host_id,
            d.window_seconds,
            ExecutionMode::from_str(&d.mode),
        )
    });
    let docker_anomaly_detector = cfg.detectors.docker_anomaly.enabled.then(|| {
        let d = &cfg.detectors.docker_anomaly;
        info!(
            threshold = d.threshold,
            window_seconds = d.window_seconds,
            "docker_anomaly detector enabled"
        );
        DockerAnomalyDetector::new(&cfg.agent.host_id, d.threshold, d.window_seconds)
    });
    let integrity_alert_detector = cfg.detectors.integrity_alert.enabled.then(|| {
        let d = &cfg.detectors.integrity_alert;
        info!(
            cooldown_seconds = d.cooldown_seconds,
            "integrity_alert detector enabled"
        );
        IntegrityAlertDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
    });
    let log_tampering_detector = cfg.detectors.log_tampering.enabled.then(|| {
        let d = &cfg.detectors.log_tampering;
        info!(
            cooldown_seconds = d.cooldown_seconds,
            "log_tampering detector enabled (eBPF openat log file monitoring)"
        );
        LogTamperingDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
    });
    // Distributed SSH detector - always on when ssh_bruteforce is on
    let distributed_ssh_detector = cfg.detectors.ssh_bruteforce.enabled.then(|| {
        info!(
            threshold = 8,
            window_seconds = 300,
            "distributed_ssh detector enabled"
        );
        DistributedSshDetector::new(&cfg.agent.host_id, 8, 300)
    });
    // Load dynamic allowlist from disk (supplements static const lists).
    let allowlist_path = std::path::Path::new("/etc/innerwarden/allowlist.toml");
    let dynamic_allowlist = detectors::allowlists::DynamicAllowlist::load(allowlist_path);

    // Initialize test external IPs so is_internal_ip() respects overrides.
    detectors::init_test_external_ips(dynamic_allowlist.test_external_ips.clone());

    // Initialize host self-awareness (own IPs, listening ports).
    detectors::init_host_inventory();

    // Spec 050-PR0: anchor the sensor-start instant so the
    // exec_context classifier can detect the 60 s boot window.
    detectors::exec_context::init_sensor_start();

    // Load blocked IPs from agent feedback file.
    let blocked_ips = load_blocked_ips(data_dir);
    if !blocked_ips.is_empty() {
        info!(
            count = blocked_ips.len(),
            "loaded blocked IPs from agent feedback"
        );
    }

    let mut detectors = DetectorSet {
        dynamic_allowlist,
        allowlist_last_check: std::time::Instant::now(),
        blocked_ips,
        blocked_ips_last_check: std::time::Instant::now(),
        ssh: ssh_detector,
        credential_stuffing: credential_stuffing_detector,
        port_scan: port_scan_detector,
        sudo_abuse: sudo_abuse_detector,
        search_abuse: search_abuse_detector,
        web_scan: web_scan_detector,
        user_agent_scanner: user_agent_scanner_detector,
        execution_guard: execution_guard_detector,
        docker_anomaly: docker_anomaly_detector,
        integrity_alert: integrity_alert_detector,
        log_tampering: log_tampering_detector,
        distributed_ssh: distributed_ssh_detector,
        suspicious_login: cfg.detectors.ssh_bruteforce.enabled.then(|| {
            let anomaly_hours = cfg.detectors.suspicious_login.anomaly_hours_enabled;
            info!(
                anomaly_hours_enabled = anomaly_hours,
                "suspicious_login detector enabled"
            );
            SuspiciousLoginDetector::new(&cfg.agent.host_id, 300, anomaly_hours)
        }),
        c2_callback: Some({
            info!("c2_callback detector enabled (eBPF network monitoring)");
            C2CallbackDetector::new(&cfg.agent.host_id, 600)
        }),
        process_tree: Some({
            info!("process_tree detector enabled (eBPF parent-child tracking)");
            ProcessTreeDetector::new(&cfg.agent.host_id, 600)
        }),
        container_escape: Some({
            info!("container_escape detector enabled");
            ContainerEscapeDetector::new(&cfg.agent.host_id, 600)
        }),
        privesc: Some({
            info!("privesc detector enabled (eBPF commit_creds kprobe)");
            PrivescDetector::new(&cfg.agent.host_id, 600)
        }),
        fileless: Some({
            info!("fileless detector enabled (eBPF memfd/fd/deleted binary detection)");
            FilelessDetector::new(&cfg.agent.host_id, 600)
        }),
        dns_tunneling: cfg.detectors.dns_tunneling.enabled.then(|| {
            let d = &cfg.detectors.dns_tunneling;
            info!(
                entropy_threshold = d.entropy_threshold,
                volume_threshold = d.volume_threshold,
                length_threshold = d.length_threshold,
                window_seconds = d.window_seconds,
                "dns_tunneling detector enabled"
            );
            DnsTunnelingDetector::new(
                &cfg.agent.host_id,
                d.entropy_threshold,
                d.volume_threshold,
                d.length_threshold,
                d.window_seconds,
            )
        }),
        lateral_movement: cfg.detectors.lateral_movement.enabled.then(|| {
            let d = &cfg.detectors.lateral_movement;
            info!(
                ssh_threshold = d.ssh_threshold,
                scan_threshold = d.scan_threshold,
                window_seconds = d.window_seconds,
                "lateral_movement detector enabled"
            );
            LateralMovementDetector::new(
                &cfg.agent.host_id,
                d.ssh_threshold,
                d.scan_threshold,
                d.window_seconds,
            )
        }),
        crypto_miner: cfg.detectors.crypto_miner.enabled.then(|| {
            let d = &cfg.detectors.crypto_miner;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "crypto_miner detector enabled"
            );
            CryptoMinerDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        outbound_anomaly: cfg.detectors.outbound_anomaly.enabled.then(|| {
            let d = &cfg.detectors.outbound_anomaly;
            info!(
                connection_flood_threshold = d.connection_flood_threshold,
                port_spray_threshold = d.port_spray_threshold,
                udp_flood_threshold = d.udp_flood_threshold,
                fanout_threshold = d.fanout_threshold,
                window_seconds = d.window_seconds,
                cooldown_seconds = d.cooldown_seconds,
                "outbound_anomaly detector enabled"
            );
            OutboundAnomalyDetector::new(
                &cfg.agent.host_id,
                d.connection_flood_threshold,
                d.port_spray_threshold,
                d.udp_flood_threshold,
                d.fanout_threshold,
                d.window_seconds,
                d.cooldown_seconds,
            )
        }),
        rootkit: cfg.detectors.rootkit.enabled.then(|| {
            let d = &cfg.detectors.rootkit;
            info!(
                check_interval_seconds = d.check_interval_seconds,
                cooldown_seconds = d.cooldown_seconds,
                timing_enabled = d.timing_enabled,
                timing_min_samples = d.timing_min_samples,
                timing_z_threshold = d.timing_z_threshold,
                timing_consecutive_threshold = d.timing_consecutive_threshold,
                "rootkit detector enabled"
            );
            RootkitDetector::new(
                &cfg.agent.host_id,
                d.check_interval_seconds,
                d.cooldown_seconds,
            )
            .with_timing_config(
                d.timing_enabled,
                d.timing_min_samples,
                d.timing_z_threshold,
                d.timing_consecutive_threshold,
            )
        }),
        reverse_shell: cfg.detectors.reverse_shell.enabled.then(|| {
            let d = &cfg.detectors.reverse_shell;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "reverse_shell detector enabled"
            );
            ReverseShellDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        ssh_key_injection: cfg.detectors.ssh_key_injection.enabled.then(|| {
            let d = &cfg.detectors.ssh_key_injection;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "ssh_key_injection detector enabled"
            );
            SshKeyInjectionDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        web_shell: cfg.detectors.web_shell.enabled.then(|| {
            let d = &cfg.detectors.web_shell;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "web_shell detector enabled"
            );
            WebShellDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        kernel_module_load: cfg.detectors.kernel_module_load.enabled.then(|| {
            let d = &cfg.detectors.kernel_module_load;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "kernel_module_load detector enabled"
            );
            KernelModuleLoadDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        crontab_persistence: cfg.detectors.crontab_persistence.enabled.then(|| {
            let d = &cfg.detectors.crontab_persistence;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "crontab_persistence detector enabled"
            );
            CrontabPersistenceDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        data_exfiltration: cfg.detectors.data_exfiltration.enabled.then(|| {
            let d = &cfg.detectors.data_exfiltration;
            info!(
                correlation_window_seconds = d.correlation_window_seconds,
                cooldown_seconds = d.cooldown_seconds,
                "data_exfiltration detector enabled"
            );
            DataExfiltrationDetector::new(
                &cfg.agent.host_id,
                d.correlation_window_seconds,
                d.cooldown_seconds,
            )
        }),
        process_injection: cfg.detectors.process_injection.enabled.then(|| {
            let d = &cfg.detectors.process_injection;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "process_injection detector enabled"
            );
            ProcessInjectionDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        user_creation: cfg.detectors.user_creation.enabled.then(|| {
            let d = &cfg.detectors.user_creation;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "user_creation detector enabled"
            );
            UserCreationDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        systemd_persistence: cfg.detectors.systemd_persistence.enabled.then(|| {
            let d = &cfg.detectors.systemd_persistence;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "systemd_persistence detector enabled"
            );
            SystemdPersistenceDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        ransomware: cfg.detectors.ransomware.enabled.then(|| {
            let d = &cfg.detectors.ransomware;
            info!(
                file_threshold = d.file_threshold,
                window_seconds = d.window_seconds,
                cooldown_seconds = d.cooldown_seconds,
                entropy_threshold = d.entropy_threshold,
                entropy_count_threshold = d.entropy_count_threshold,
                "ransomware detector enabled"
            );
            RansomwareDetector::new(
                &cfg.agent.host_id,
                d.file_threshold,
                d.window_seconds,
                d.cooldown_seconds,
                d.entropy_threshold,
                d.entropy_count_threshold,
            )
        }),
        credential_harvest: cfg.detectors.credential_harvest.enabled.then(|| {
            let d = &cfg.detectors.credential_harvest;
            info!(
                cooldown_seconds = d.cooldown_seconds,
                "credential_harvest detector enabled"
            );
            CredentialHarvestDetector::new(&cfg.agent.host_id, d.cooldown_seconds)
        }),
        packet_flood: cfg.detectors.packet_flood.enabled.then(|| {
            let d = &cfg.detectors.packet_flood;
            info!(
                syn_threshold = d.syn_threshold,
                http_threshold = d.http_threshold,
                slowloris_threshold = d.slowloris_threshold,
                udp_threshold = d.udp_threshold,
                rate_multiplier = d.rate_multiplier,
                window_seconds = d.window_seconds,
                cooldown_seconds = d.cooldown_seconds,
                "packet_flood detector enabled (DDoS detection)"
            );
            PacketFloodDetector::new(detectors::packet_flood::PacketFloodParams {
                host: cfg.agent.host_id.clone(),
                syn_threshold: d.syn_threshold,
                http_threshold: d.http_threshold,
                slowloris_threshold: d.slowloris_threshold,
                udp_threshold: d.udp_threshold,
                rate_multiplier: d.rate_multiplier,
                window_seconds: d.window_seconds,
                cooldown_seconds: d.cooldown_seconds,
            })
        }),
        sensitive_write: Some({
            info!("sensitive_write detector enabled (sensitive path protection)");
            detectors::sensitive_write::SensitiveWriteDetector::new(&cfg.agent.host_id, 300)
        }),
        discovery_burst: Some({
            let trusted_uids = cfg.calibration.effective_trusted_uids();
            info!(
                threshold = 5,
                window_seconds = 60,
                trusted_uids = ?trusted_uids,
                "discovery_burst detector enabled"
            );
            detectors::discovery_burst::DiscoveryBurstDetector::new(&cfg.agent.host_id, 5, 60)
                .with_trusted_uids(trusted_uids)
        }),
        io_uring_anomaly: Some({
            info!("io_uring_anomaly detector enabled (io_uring evasion detection)");
            detectors::io_uring_anomaly::IoUringAnomalyDetector::new(&cfg.agent.host_id, 300)
        }),
        container_drift: Some({
            info!("container_drift detector enabled (overlayfs drift detection)");
            detectors::container_drift::ContainerDriftDetector::new(&cfg.agent.host_id, 600)
        }),
        host_drift: Some({
            info!("host_drift detector enabled (non-standard binary execution)");
            detectors::host_drift::HostDriftDetector::new(&cfg.agent.host_id, 600)
        }),
        data_exfil_ebpf: Some({
            info!("data_exfil_ebpf detector enabled (sensitive file read + outbound connect)");
            detectors::data_exfil_ebpf::DataExfilEbpfDetector::new(&cfg.agent.host_id, 60, 600)
        }),
        imds_ssrf: if cfg.detectors.imds_ssrf.enabled {
            info!(
                "imds_ssrf detector enabled (cloud-metadata SSRF; cooldown {}s, operator allowlist={} entries)",
                cfg.detectors.imds_ssrf.cooldown_seconds,
                cfg.detectors.imds_ssrf.allowlist_comms.len(),
            );
            Some(detectors::imds_ssrf::ImdsSsrfDetector::new(
                &cfg.agent.host_id,
                cfg.detectors.imds_ssrf.allowlist_comms.clone(),
                cfg.detectors.imds_ssrf.cooldown_seconds,
            ))
        } else {
            None
        },
        yara_scan: Some({
            let rules_dir = std::path::Path::new("rules/yara");
            info!("YARA binary scanner enabled");
            detectors::yara_scan::YaraScanDetector::new(&cfg.agent.host_id, rules_dir, 3600)
        }),
        sigma_rule: Some({
            // Try multiple paths for Sigma rules: installed location, then relative
            let rules_dir = [
                std::path::PathBuf::from("/etc/innerwarden/rules/sigma"),
                std::path::PathBuf::from("/usr/local/share/innerwarden/rules/sigma"),
                std::path::PathBuf::from("rules/sigma"),
            ]
            .into_iter()
            .find(|p| p.is_dir())
            .unwrap_or_else(|| std::path::PathBuf::from("rules/sigma"));
            info!(path = %rules_dir.display(), "Sigma rule engine enabled");
            detectors::sigma_rule::SigmaRuleDetector::new(&cfg.agent.host_id, &rules_dir, 300)
        }),
        mitre_hunt: Some({
            info!("mitre_hunt detector enabled (10 MITRE ATT&CK techniques)");
            detectors::mitre_hunt::MitreHuntDetector::new(&cfg.agent.host_id, 300)
        }),
        dns_c2: Some({
            info!("dns_c2 detector enabled (T1071.004 DNS C2 channel detection)");
            detectors::dns_c2::DnsC2Detector::new(&cfg.agent.host_id, 6, 300)
        }),
        data_encoding: Some({
            info!("data_encoding detector enabled (T1132 encoded C2/exfil traffic)");
            detectors::data_encoding::DataEncodingDetector::new(&cfg.agent.host_id, 3, 300)
        }),
        sandbox_evasion: Some({
            info!("sandbox_evasion detector enabled (T1497 VM/sandbox evasion checks)");
            detectors::sandbox_evasion::SandboxEvasionDetector::new(&cfg.agent.host_id, 3, 60)
        }),
        threat_intel: Some({
            info!("threat_intel detector enabled (O(1) dataset matching)");
            detectors::threat_intel::ThreatIntelDetector::new(&cfg.agent.host_id, 600)
        }),
        proto_anomaly: Some({
            info!("proto_anomaly detector enabled (protocol violation detection)");
            // Spec 028-a: bumped 300 → 600 so the per-(src_ip, anomaly_type)
            // throttle covers the 10-minute window the spec targets (cuts
            // SshVersionAnomaly volume).
            detectors::proto_anomaly::ProtoAnomalyDetector::new(&cfg.agent.host_id, 600)
        }),
        // spec 050-PR1 — Reconnaissance
        nmap_scan: Some({
            info!("nmap_scan detector enabled (network scanner detection on host)");
            detectors::nmap_scan::NmapScanDetector::new(&cfg.agent.host_id)
        }),
        wordlist_scan: Some({
            info!("wordlist_scan detector enabled (HTTP wordlist enumeration)");
            detectors::wordlist_scan::WordlistScanDetector::new(&cfg.agent.host_id, 8, 60)
        }),
        discovery_anomaly: Some({
            info!("discovery_anomaly detector enabled (context-aware recon burst)");
            detectors::discovery_anomaly::DiscoveryAnomalyDetector::new(&cfg.agent.host_id, 10, 30)
        }),
        // spec 050-PR2 — Collection
        clipboard_read: Some({
            info!("clipboard_read detector enabled (xclip/xsel/wl-paste on headless host)");
            detectors::clipboard_read::ClipboardReadDetector::new(&cfg.agent.host_id)
        }),
        screen_capture: Some({
            info!("screen_capture detector enabled (scrot/grim/flameshot on headless host)");
            detectors::screen_capture::ScreenCaptureDetector::new(&cfg.agent.host_id)
        }),
        keylogger_bash_trap: Some({
            info!("keylogger_bash_trap detector enabled (shell startup file write + trap pattern)");
            detectors::keylogger_bash_trap::KeyloggerBashTrapDetector::new(&cfg.agent.host_id)
        }),
        archive_pwd_protected: Some({
            info!("archive_pwd_protected detector enabled (T1560.001 staging archives)");
            detectors::archive_pwd_protected::ArchivePwdProtectedDetector::new(&cfg.agent.host_id)
        }),
        automated_file_collection: Some({
            info!("automated_file_collection detector enabled (T1119 find sweeps of user data)");
            detectors::automated_file_collection::AutomatedFileCollectionDetector::new(
                &cfg.agent.host_id,
            )
        }),
        // spec 050-PR3 — C2 variants
        c2_web_tunnel: Some({
            info!("c2_web_tunnel detector enabled (ngrok/cloudflared/bore + tunnel DNS)");
            detectors::c2_web_tunnel::C2WebTunnelDetector::new(&cfg.agent.host_id)
        }),
        c2_protocol_tunneling: Some({
            info!("c2_protocol_tunneling detector enabled (DNS/ICMP/SSH-forward tunneling)");
            detectors::c2_protocol_tunneling::C2ProtocolTunnelingDetector::new(&cfg.agent.host_id)
        }),
        c2_non_standard_port: Some({
            info!("c2_non_standard_port detector enabled (T1571 listeners outside well-known set)");
            detectors::c2_non_standard_port::C2NonStandardPortDetector::new(&cfg.agent.host_id)
        }),
        // spec 050-PR4 — Privilege Escalation + Lateral Movement
        setuid_exploit_pattern: Some({
            info!("setuid_exploit_pattern detector enabled (T1548.001 non-baseline SUID exec)");
            detectors::setuid_exploit_pattern::SetuidExploitPatternDetector::new(&cfg.agent.host_id)
        }),
        capabilities_abuse: Some({
            info!("capabilities_abuse detector enabled (T1548.005 dangerous caps + exploit argv)");
            detectors::capabilities_abuse::CapabilitiesAbuseDetector::new(&cfg.agent.host_id)
        }),
        lateral_egress_ssh: Some({
            info!("lateral_egress_ssh detector enabled (T1021.004 ssh from non-operator tree)");
            detectors::lateral_egress_ssh::LateralEgressSshDetector::new(&cfg.agent.host_id)
        }),
        lateral_egress_scp_rsync: Some({
            info!("lateral_egress_scp_rsync detector enabled (T1048.001 staged exfil)");
            detectors::lateral_egress_scp_rsync::LateralEgressScpRsyncDetector::new(
                &cfg.agent.host_id,
            )
        }),
        // spec 050-PR5 — Persistence + Defense Evasion
        pam_module_change: Some({
            info!("pam_module_change detector enabled (T1556.003 PAM tamper)");
            detectors::pam_module_change::PamModuleChangeDetector::new(&cfg.agent.host_id)
        }),
        auditd_disable: Some({
            info!("auditd_disable detector enabled (T1562.001 auditd stop/disable)");
            detectors::auditd_disable::AuditdDisableDetector::new(&cfg.agent.host_id)
        }),
        selinux_apparmor_disable: Some({
            info!("selinux_apparmor_disable detector enabled (T1562.001 MAC disable)");
            detectors::selinux_apparmor_disable::SelinuxApparmorDisableDetector::new(
                &cfg.agent.host_id,
            )
        }),
        startup_script_persistence: Some({
            info!("startup_script_persistence detector enabled (T1037.004 RC scripts)");
            detectors::startup_script_persistence::StartupScriptPersistenceDetector::new(
                &cfg.agent.host_id,
            )
        }),
        // spec 050-PR6 — Impact
        data_destruction_pattern: Some({
            info!(
                "data_destruction_pattern detector enabled (T1485/T1561.001/T1486 wipe & destruction)"
            );
            detectors::data_destruction_pattern::DataDestructionPatternDetector::new(
                &cfg.agent.host_id,
            )
        }),
        // 2026-05-17 wave — gap closers
        symlink_hijack: Some({
            info!("symlink_hijack detector enabled (T1555 / T1574.005 sensitive-path links)");
            detectors::symlink_hijack::SymlinkHijackDetector::new(&cfg.agent.host_id)
        }),
        system_user_interactive: Some({
            info!(
                "system_user_interactive detector enabled (T1059 / T1078.003 service-account shell)"
            );
            detectors::system_user_interactive::SystemUserInteractiveDetector::new(
                &cfg.agent.host_id,
            )
        }),
    };

    // Load threat intelligence datasets (IPs, domains, JA3, hashes, URLs).
    // Downloads public feeds on first run, reloads from disk every 60 min.
    let datasets_dir = data_dir.join("datasets");
    let mut threat_datasets = detectors::datasets::Datasets::load(&datasets_dir, 3600);
    if !threat_datasets.is_loaded() {
        info!("downloading threat intelligence feeds for the first time...");
        let (ok, total) = detectors::datasets::update_all_feeds(&datasets_dir);
        info!(
            feeds_updated = ok,
            total_entries = total,
            "initial feed download complete"
        );
        threat_datasets.reload();
    }

    // Spawn auth_log collector
    if cfg.collectors.auth_log.enabled {
        let offset = state
            .get_cursor("auth_log")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_auth_offset.store(offset, Ordering::Relaxed);

        let collector =
            AuthLogCollector::new(&cfg.collectors.auth_log.path, &cfg.agent.host_id, offset);
        info!(path = %cfg.collectors.auth_log.path, offset, "starting auth_log collector");
        let tx2 = tx.clone();
        let shared = Arc::clone(&shared_auth_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx2, shared).await {
                tracing::error!("auth_log collector error: {e:#}");
            }
        });
    }

    // Spawn integrity collector
    if should_spawn_integrity_collector(
        cfg.collectors.integrity.enabled,
        &cfg.collectors.integrity.paths,
    ) {
        let ic = &cfg.collectors.integrity;
        let known_hashes: HashMap<String, String> = state
            .get_cursor("integrity")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Seed shared hashes with whatever we loaded from state
        *shared_integrity_hashes.lock().unwrap() = known_hashes.clone();

        // Always monitor Inner Warden's own config files for tampering,
        // regardless of user configuration.
        let self_monitor_paths = [
            "/etc/innerwarden/config.toml",
            "/etc/innerwarden/agent.toml",
            "/etc/innerwarden/agent.env",
        ];
        let mut all_paths: Vec<std::path::PathBuf> =
            ic.paths.iter().map(|p| Path::new(p).to_owned()).collect();
        for sp in &self_monitor_paths {
            let p = Path::new(sp).to_owned();
            if !all_paths.contains(&p) {
                all_paths.push(p);
            }
        }

        let collector = IntegrityCollector::new(
            all_paths.clone(),
            &cfg.agent.host_id,
            ic.poll_seconds,
            known_hashes,
        );
        info!(
            paths = all_paths.len(),
            poll_secs = ic.poll_seconds,
            "starting integrity collector (includes self-monitoring)"
        );
        let tx3 = tx.clone();
        let shared = Arc::clone(&shared_integrity_hashes);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx3, shared).await {
                tracing::error!("integrity collector error: {e:#}");
            }
        });
    }

    // Spawn journald collector
    if cfg.collectors.journald.enabled {
        let jc = &cfg.collectors.journald;
        let cursor: Option<String> = state
            .get_cursor("journald")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        *shared_journald_cursor.lock().unwrap() = cursor.clone();
        let collector = JournaldCollector::new(&cfg.agent.host_id, jc.units.clone(), cursor);
        info!(units = ?jc.units, "starting journald collector");
        let tx4 = tx.clone();
        let shared = Arc::clone(&shared_journald_cursor);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx4, shared).await {
                tracing::error!("journald collector error: {e:#}");
            }
        });
    }

    // Spawn docker collector
    if cfg.collectors.docker.enabled {
        let since: Option<String> = state
            .get_cursor("docker")
            .and_then(|v| v.as_str().map(str::to_string));
        *shared_docker_since.lock().unwrap() = since.clone();
        let collector = DockerCollector::new(&cfg.agent.host_id, since);
        info!("starting docker collector");
        let tx5 = tx.clone();
        let shared = Arc::clone(&shared_docker_since);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx5, shared).await {
                tracing::error!("docker collector error: {e:#}");
            }
        });
    }

    // Spawn exec_audit collector
    if cfg.collectors.exec_audit.enabled {
        let ec = &cfg.collectors.exec_audit;
        let offset = state
            .get_cursor("exec_audit")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_exec_audit_offset.store(offset, Ordering::Relaxed);
        let collector =
            ExecAuditCollector::new(&ec.path, &cfg.agent.host_id, offset, ec.include_tty);
        info!(
            path = %ec.path,
            include_tty = ec.include_tty,
            offset,
            "starting exec_audit collector"
        );
        let tx6 = tx.clone();
        let shared = Arc::clone(&shared_exec_audit_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx6, shared).await {
                tracing::error!("exec_audit collector error: {e:#}");
            }
        });
    }

    // Spawn nginx_access collector
    if cfg.collectors.nginx_access.enabled {
        let nc = &cfg.collectors.nginx_access;
        let offset = state
            .get_cursor("nginx_access")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_offset.store(offset, Ordering::Relaxed);
        let collector = NginxAccessCollector::new(&nc.path, &cfg.agent.host_id, offset);
        info!(path = %nc.path, offset, "starting nginx_access collector");
        let tx7 = tx.clone();
        let shared = Arc::clone(&shared_nginx_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx7, shared).await {
                tracing::error!("nginx_access collector error: {e:#}");
            }
        });
    }

    // Spawn nginx_error collector
    if cfg.collectors.nginx_error.enabled {
        let nec = &cfg.collectors.nginx_error;
        let offset = state
            .get_cursor("nginx_error")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_error_offset.store(offset, Ordering::Relaxed);
        let collector = NginxErrorCollector::new(&nec.path, &cfg.agent.host_id, offset);
        info!(path = %nec.path, offset, "starting nginx_error collector");
        let tx_nginx_error = tx.clone();
        let shared = Arc::clone(&shared_nginx_error_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_nginx_error, shared).await {
                tracing::error!("nginx_error collector error: {e:#}");
            }
        });
    }

    // Spawn macos_log collector
    if cfg.collectors.macos_log.enabled {
        let collector = MacosLogCollector::new(&cfg.agent.host_id);
        info!("starting macos_log collector");
        let tx_macos = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_macos).await {
                tracing::error!("macos_log collector error: {e:#}");
            }
        });
    }

    // Spawn syslog_firewall collector
    if cfg.collectors.syslog_firewall.enabled {
        let sc = &cfg.collectors.syslog_firewall;
        let offset = state
            .get_cursor("syslog_firewall")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_syslog_firewall_offset.store(offset, Ordering::Relaxed);
        let collector = SyslogFirewallCollector::new(&sc.path, &cfg.agent.host_id, offset);
        info!(path = %sc.path, offset, "starting syslog_firewall collector");
        let tx_syslog = tx.clone();
        let shared = Arc::clone(&shared_syslog_firewall_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_syslog, shared).await {
                tracing::error!("syslog_firewall collector error: {e:#}");
            }
        });
    }

    // Spawn cloudtrail collector
    if cfg.collectors.cloudtrail.enabled {
        let cc = &cfg.collectors.cloudtrail;
        let collector = CloudTrailCollector::new(&cc.dir, &cfg.agent.host_id);
        info!(dir = %cc.dir, "starting cloudtrail collector");
        let tx_cloudtrail = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_cloudtrail).await {
                tracing::error!("cloudtrail collector error: {e:#}");
            }
        });
    }

    // Spawn eBPF collector (optional - requires Linux 5.8+, CAP_BPF)
    {
        let tx_ebpf = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::ebpf_syscall::run(tx_ebpf, host_id).await;
        });
    }

    // Spawn firmware integrity collector (monitors ESP, UEFI vars, ACPI, DMI, tainted)
    {
        let tx_firmware = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::firmware_integrity::run(tx_firmware, host_id).await;
        });
    }

    // Spawn proc_maps collector (memory forensics: RWX, deleted files, LD_PRELOAD)
    {
        let tx_maps = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::proc_maps::run(tx_maps, host_id, 60).await;
        });
    }

    // Spawn fanotify filesystem monitor (real-time file modification + ransomware detection)
    {
        let tx_fan = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let watch_paths = cfg
            .collectors
            .integrity
            .paths
            .iter()
            .map(|p| p.to_string())
            .collect();
        tokio::spawn(async move {
            collectors::fanotify_watch::run(tx_fan, host_id, watch_paths, 5).await;
        });
    }

    // Spawn kernel integrity monitor (syscall table + eBPF inventory + module baseline)
    {
        let tx_kern = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::kernel_integrity::run(tx_kern, host_id, 120).await;
        });
    }

    // Spawn cgroup resource abuse detector (CPU/memory abuse, cryptominer detection)
    {
        let tx_cg = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            detectors::cgroup_abuse::run(tx_cg, host_id, 30).await;
        });
    }

    // Spawn TLS fingerprint collector (JA3/JA4 — requires CAP_NET_RAW + libc)
    #[cfg(feature = "ebpf")]
    {
        let tx_tls = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::tls_fingerprint::run(tx_tls, host_id, 0).await;
        });
    }

    // DNS query capture (AF_PACKET raw socket, captures UDP:53)
    {
        let tx_dns = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::dns_capture::run(tx_dns, host_id).await;
        });
    }

    // HTTP request capture (AF_PACKET raw socket, captures TCP:80/8080/8787/etc.)
    {
        let tx_http = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::http_capture::run(tx_http, host_id).await;
        });
    }

    // Network snapshot: periodic /proc/net/tcp scan with PID resolution
    {
        let tx_net = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::net_snapshot::run(tx_net, host_id, 30).await;
        });
    }

    // USB device monitoring: detects BadUSB, rubber ducky, unauthorized storage
    {
        let tx_usb = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::usb_monitor::run(tx_usb, host_id, 5).await;
        });
    }

    // SUID binary inventory: baseline + drift detection
    {
        let tx_suid = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::suid_inventory::run(tx_suid, host_id, 300).await;
        });
    }

    // Sysctl drift: monitors 20 security-critical kernel parameters
    {
        let tx_sysctl = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::sysctl_drift::run(tx_sysctl, host_id, 60).await;
        });
    }

    // SUID page-cache integrity: detects Copy Fail / Dirty Frag / Fragnesia-style
    // page-cache poisoning by comparing cached reads with direct-I/O disk reads.
    if cfg.detectors.suid_page_cache_integrity.enabled {
        let d = &cfg.detectors.suid_page_cache_integrity;
        let tx_suid_cache = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let allowlist: Vec<PathBuf> = d.allowlist.iter().map(PathBuf::from).collect();
        let poll_interval_secs = d.poll_interval_secs;
        info!(
            paths = allowlist.len(),
            poll_interval_secs, "starting suid_page_cache_integrity detector"
        );
        tokio::spawn(async move {
            detectors::suid_page_cache_integrity::run(
                tx_suid_cache,
                host_id,
                poll_interval_secs,
                allowlist,
            )
            .await;
        });
    }

    // Kernel devnode exposure: catches sensitive /dev/* nodes whose
    // permissions are more permissive than the documented safe-default.
    // Motivated by Azure mana_ib shipping `/dev/infiniband/uverbs*` mode
    // 0666 by default — see crates/sensor/src/detectors/kernel_devnode_exposed.rs
    // for the full architectural reasoning.
    if cfg.detectors.kernel_devnode_exposed.enabled {
        let d = &cfg.detectors.kernel_devnode_exposed;
        let tx_devnode = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let poll_interval_secs = d.poll_interval_secs;
        let allowlist = d.allowlist.clone();
        let watchlist = build_devnode_watchlist(&d.overrides);
        info!(
            patterns = watchlist.len(),
            poll_interval_secs, "starting kernel_devnode_exposed detector"
        );
        tokio::spawn(async move {
            detectors::kernel_devnode_exposed::run(
                tx_devnode,
                host_id,
                poll_interval_secs,
                watchlist,
                allowlist,
            )
            .await;
        });
    }

    // Systemd unit inventory: detects new/suspicious services
    {
        let tx_sysd = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::systemd_inventory::run(tx_sysd, host_id, 300).await;
        });
    }

    // TCP stream reassembly engine (AF_PACKET, all TCP traffic)
    // Reassembles bidirectional streams, detects protocols on any port,
    // enables deep packet inspection for HTTP, SSH, SMB, etc.
    {
        let tx_tcp = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::tcp_stream::run(tx_tcp, host_id).await;
        });
    }

    // Drop the original tx - each collector holds its own clone.
    // When all collector tasks finish, all senders drop and rx.recv() returns None.
    drop(tx);

    // Apply seccomp profile if configured (Active Defence feature).
    // MUST be after all eBPF programs are loaded and sockets are opened,
    // since seccomp restricts future syscalls. The profile blocks execve,
    // connect, and other syscalls the sensor doesn't need post-startup.
    #[cfg(target_os = "linux")]
    {
        let seccomp_path = data_dir.join("sensor.seccomp.json");
        if seccomp_path.exists() {
            match seccomp::apply_seccomp_profile(&seccomp_path) {
                Ok(count) => info!(
                    syscalls_allowed = count,
                    "seccomp profile applied — sensor hardened"
                ),
                Err(e) => warn!("seccomp profile failed to apply: {e:#} — continuing without"),
            }
        }
    }

    // SIGTERM listener (Unix only)
    #[cfg(unix)]
    let mut sigterm = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())?
    };

    // PR29 — write the boot-time collector health snapshot. Probes
    // each file-backed collector's source path, records whether the
    // path exists / is stale / is missing, and writes the result to
    // `<data_dir>/collector-health.json` for the agent dashboard to
    // read. Errors are logged and swallowed: a missing health file
    // means the dashboard shows the legacy view (per-collector count
    // only), not a crash.
    {
        let now = chrono::Utc::now();
        let statuses = vec![
            collector_health::build_status(
                "auth_log",
                cfg.collectors.auth_log.enabled,
                Some(&cfg.collectors.auth_log.path),
                now,
            ),
            collector_health::build_status("journald", cfg.collectors.journald.enabled, None, now),
            collector_health::build_status(
                "exec_audit",
                cfg.collectors.exec_audit.enabled,
                Some(&cfg.collectors.exec_audit.path),
                now,
            ),
            collector_health::build_status("docker", cfg.collectors.docker.enabled, None, now),
            collector_health::build_status(
                "integrity",
                cfg.collectors.integrity.enabled,
                None,
                now,
            ),
            collector_health::build_status(
                "syslog_firewall",
                cfg.collectors.syslog_firewall.enabled,
                Some(&cfg.collectors.syslog_firewall.path),
                now,
            ),
            collector_health::build_status(
                "nginx_access",
                cfg.collectors.nginx_access.enabled,
                Some(&cfg.collectors.nginx_access.path),
                now,
            ),
            collector_health::build_status(
                "nginx_error",
                cfg.collectors.nginx_error.enabled,
                Some(&cfg.collectors.nginx_error.path),
                now,
            ),
            // NOTE: suricata_eve and osquery_log appear in some
            // operator config files but are NOT in the sensor's
            // CollectorsConfig struct. serde silently ignores those
            // keys, so the sensor never spawns them. Don't include
            // them in the probe; they aren't collectors this binary
            // runs. The right operator action is to remove those
            // sections from config.toml (or open a tracking PR to
            // add proper Suricata/Osquery collectors).
        ];
        if let Err(e) = collector_health::write_status_file(data_dir, &cfg.agent.host_id, &statuses)
        {
            tracing::warn!(error = %e, "failed to write collector-health.json");
        } else {
            info!("collector-health.json written ({} entries)", statuses.len());
        }
    }

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

        process_event(
            ev,
            &sqlite_writer,
            &mut detectors,
            &mut stats,
            &mut syslog_writer,
            &mut dedup_cache,
            &threat_datasets,
        );
    }

    info!(
        events_written = stats.events_written,
        incidents_written = stats.incidents_written,
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

    state.save(&state_path)?;
    info!(auth_offset, "state saved");

    Ok(())
}

// 11 small helpers (load_blocked_ips, state_path_for, blocked_ips_path_for,
// parse_blocked_ips, should_spawn_integrity_collector, should_enable_syslog_sink,
// parse_syslog_port, choose_syslog_protocol, severity_rank, is_passthrough_source,
// should_use_blocked_ip_hint) moved to crates/sensor/src/main_helpers.rs as part
// of the 2026-05-25 main.rs decomposition PR2. The previous `/// Load blocked
// IPs from the file written by the agent.` doc comment moved with `load_blocked_ips`
// — its body is in main_helpers.rs.

fn process_event(
    ev: innerwarden_core::event::Event,
    sqlite: &SqliteWriter,
    detectors: &mut DetectorSet,
    stats: &mut WriteStats,
    syslog: &mut Option<sinks::syslog_cef::SyslogCefWriter>,
    dedup_cache: &mut HashMap<u32, (chrono::DateTime<chrono::Utc>, u8)>,
    threat_datasets: &detectors::datasets::Datasets,
) {
    use innerwarden_core::event::Severity;

    info!(kind = %ev.kind, summary = %ev.summary, "event");
    sqlite.write_event(&ev);
    stats.events_written += 1;
    // Syslog CEF output (if configured)
    if let Some(ref mut cef) = syslog {
        cef.write_event(&ev);
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "sudo_abuse")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "integrity_alert")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "log_tampering")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "privesc")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.fileless]` before writing.
    let fileless_incident = detectors.fileless.as_mut().and_then(|d| d.process(&ev));
    if let Some(incident) = fileless_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "fileless")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "rootkit")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "ssh_key_injection")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "kernel_module_load")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "crontab_persistence")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "user_creation")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "systemd_persistence")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "sensitive_write")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "discovery_burst")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "container_drift")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // Post-emit allowlist gate (mirrors kernel_module_load + sudo_abuse
    // + systemd_persistence + mitre_hunt from PR #647). The detector body
    // does not thread `dynamic_allowlist` through, so we extract the
    // incident here and consult `[detectors.host_drift]` before writing.
    let host_drift_incident = detectors.host_drift.as_mut().and_then(|d| d.process(&ev));
    if let Some(incident) = host_drift_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "host_drift")
        {
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
        if let Some(incident) =
            det.process_with_suppressions(&ev, &detectors.dynamic_allowlist.suppress_sigma_rules)
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "mitre_hunt")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "nmap_scan")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let wordlist_incident = detectors
        .wordlist_scan
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = wordlist_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "wordlist_scan")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let discovery_anomaly_incident = detectors
        .discovery_anomaly
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = discovery_anomaly_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "discovery_anomaly")
        {
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
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "clipboard_read")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let screen_capture_incident = detectors
        .screen_capture
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = screen_capture_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "screen_capture")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let keylogger_bash_trap_incident = detectors
        .keylogger_bash_trap
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = keylogger_bash_trap_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "keylogger_bash_trap")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let archive_pwd_protected_incident = detectors
        .archive_pwd_protected
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = archive_pwd_protected_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "archive_pwd_protected")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let automated_file_collection_incident = detectors
        .automated_file_collection
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = automated_file_collection_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "automated_file_collection")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR3 — C2 variants
    let c2_web_tunnel_incident = detectors
        .c2_web_tunnel
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = c2_web_tunnel_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "c2_web_tunnel")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let c2_protocol_tunneling_incident = detectors
        .c2_protocol_tunneling
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = c2_protocol_tunneling_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "c2_protocol_tunneling")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let c2_non_standard_port_incident = detectors
        .c2_non_standard_port
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = c2_non_standard_port_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "c2_non_standard_port")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR4 — Privilege Escalation + Lateral Movement
    let setuid_exploit_pattern_incident = detectors
        .setuid_exploit_pattern
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = setuid_exploit_pattern_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "setuid_exploit_pattern")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let capabilities_abuse_incident = detectors
        .capabilities_abuse
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = capabilities_abuse_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "capabilities_abuse")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let lateral_egress_ssh_incident = detectors
        .lateral_egress_ssh
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = lateral_egress_ssh_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "lateral_egress_ssh")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let lateral_egress_scp_rsync_incident = detectors
        .lateral_egress_scp_rsync
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = lateral_egress_scp_rsync_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "lateral_egress_scp_rsync")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR5 — Persistence + Defense Evasion
    let pam_module_change_incident = detectors
        .pam_module_change
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = pam_module_change_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "pam_module_change")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let auditd_disable_incident = detectors
        .auditd_disable
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = auditd_disable_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "auditd_disable")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let selinux_apparmor_disable_incident = detectors
        .selinux_apparmor_disable
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = selinux_apparmor_disable_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "selinux_apparmor_disable")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let startup_script_persistence_incident = detectors
        .startup_script_persistence
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = startup_script_persistence_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "startup_script_persistence")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // spec 050-PR6 — Impact
    let data_destruction_pattern_incident = detectors
        .data_destruction_pattern
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = data_destruction_pattern_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "data_destruction_pattern")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    // 2026-05-17 wave — gap closers
    let symlink_hijack_incident = detectors
        .symlink_hijack
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = symlink_hijack_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "symlink_hijack")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }

    let system_user_interactive_incident = detectors
        .system_user_interactive
        .as_mut()
        .and_then(|d| d.process(&ev));
    if let Some(incident) = system_user_interactive_incident {
        if !detectors
            .dynamic_allowlist
            .suppress_incident_for_detector(&incident, "system_user_interactive")
        {
            write_incident(sqlite, stats, incident, syslog, dedup_cache);
        }
    }
}

fn passthrough_incident(
    ev: &innerwarden_core::event::Event,
) -> Option<innerwarden_core::incident::Incident> {
    use innerwarden_core::incident::Incident;

    let incident_id = format!(
        "{}:{}:{}",
        ev.source,
        ev.kind,
        ev.ts.format("%Y-%m-%dT%H:%MZ")
    );

    let recommended_checks = vec!["Review source alert details".to_string()];

    Some(Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id,
        severity: ev.severity.clone(),
        title: ev.summary.clone(),
        summary: format!("[{}] {}", ev.source.to_uppercase(), ev.summary),
        evidence: serde_json::json!([ev.details]),
        recommended_checks,
        tags: ev.tags.clone(),
        entities: ev.entities.clone(),
    })
}

/// Merge the built-in devnode watchlist with operator overrides from
/// TOML. Overrides matched by `pattern` REPLACE the default entry of the
/// same pattern; otherwise they are appended. A malformed
/// `max_allowed_mode_octal` (typo, e.g. "999z") logs a `warn!` and
/// silently keeps the default for that pattern — we never widen the
/// allowed mode through misconfiguration. Returns the resulting
/// watchlist in deterministic insertion order.
fn build_devnode_watchlist(
    overrides: &[config::KernelDevnodeWatchEntryConfig],
) -> Vec<detectors::kernel_devnode_exposed::WatchEntry> {
    use detectors::kernel_devnode_exposed::{default_watchlist, WatchEntry};

    let mut result = default_watchlist();
    for ov in overrides {
        // Accept "0o660", "660", or just plain octal digits.
        let raw = ov.max_allowed_mode_octal.trim().trim_start_matches("0o");
        let parsed = u32::from_str_radix(raw, 8);
        let max_mode = match parsed {
            Ok(v) if v <= 0o7777 => v,
            _ => {
                warn!(
                    pattern = %ov.pattern,
                    raw = %ov.max_allowed_mode_octal,
                    "kernel_devnode_exposed: invalid max_allowed_mode_octal override, keeping default"
                );
                continue;
            }
        };
        let surface = if ov.surface.is_empty() {
            "operator-defined".to_string()
        } else {
            ov.surface.clone()
        };
        if let Some(existing) = result.iter_mut().find(|w| w.pattern == ov.pattern) {
            existing.max_allowed_mode = max_mode;
            existing.surface = surface;
        } else {
            result.push(WatchEntry {
                pattern: ov.pattern.clone(),
                max_allowed_mode: max_mode,
                surface,
            });
        }
    }
    result
}

fn devnode_exposed_incident(
    ev: &innerwarden_core::event::Event,
) -> innerwarden_core::incident::Incident {
    use innerwarden_core::incident::Incident;

    let path = ev
        .details
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let actual = ev
        .details
        .get("actual_mode_octal")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let max = ev
        .details
        .get("max_allowed_mode_octal")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let surface = ev
        .details
        .get("surface")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown kernel surface");
    let path_slug = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id: format!(
            "kernel_devnode_exposed:{}:{}",
            path_slug,
            // hour-bucket so the same exposure does not re-fire every
            // poll, but a permission flip (e.g. operator running chmod
            // mid-investigation) re-emits within the same day cleanly.
            ev.ts.format("%Y-%m-%dT%HZ")
        ),
        severity: innerwarden_core::event::Severity::Medium,
        title: format!("Kernel device exposed: {path} ({surface})"),
        summary: format!(
            "Sensitive kernel device {path} is mode {actual} (safe-default {max}). \
             This exposes {surface} to unprivileged users. If a process subsequently \
             opens this device and gains capabilities, the agent's CL-071 correlation \
             rule will escalate the combined chain to Critical."
        ),
        evidence: serde_json::json!([ev.details.clone()]),
        recommended_checks: vec![
            format!("chmod 0660 {path} (or 0600 for /dev/mem, /dev/kmem, /dev/port)"),
            "Add legitimate users to a dedicated group instead of widening mode".to_string(),
            "If the exposure is intentional, add this path to \
             [detectors.kernel_devnode_exposed.allowlist] in sensor config"
                .to_string(),
        ],
        tags: ev.tags.clone(),
        entities: ev.entities.clone(),
    }
}

fn page_cache_mismatch_incident(
    ev: &innerwarden_core::event::Event,
) -> innerwarden_core::incident::Incident {
    use innerwarden_core::incident::Incident;

    let path = ev
        .details
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let path_slug = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();

    Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        incident_id: format!(
            "suid_page_cache_integrity:{}:{}",
            path_slug,
            ev.ts.format("%Y-%m-%dT%H:%MZ")
        ),
        severity: innerwarden_core::event::Severity::Critical,
        title: format!("SUID binary corrupted in page cache: {path}"),
        summary: format!(
            "SUID-root binary {path} has different SHA-256 content via page cache versus direct disk read. \
             This is consistent with page-cache poisoning used by local privilege-escalation exploits."
        ),
        evidence: serde_json::json!([ev.details.clone()]),
        recommended_checks: vec![
            "Treat the host as potentially compromised; preserve volatile state before rebooting".to_string(),
            "Compare the affected SUID binary with a trusted package copy".to_string(),
            "Check for recent local privilege-escalation activity and suspicious root shells".to_string(),
        ],
        tags: ev.tags.clone(),
        entities: ev.entities.clone(),
    }
}

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

    #[test]
    fn page_cache_mismatch_event_promotes_to_critical_incident() {
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-23T09:12:30Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let event = innerwarden_core::event::Event {
            ts,
            host: "sensor-host".to_string(),
            source: "suid_page_cache_integrity".to_string(),
            kind: "integrity.page_cache_mismatch".to_string(),
            severity: Severity::Critical,
            summary: "SUID binary corrupted in page cache: /usr/bin/su".to_string(),
            details: serde_json::json!({
                "path": "/usr/bin/su",
                "sha256_on_disk": "clean",
                "sha256_via_page_cache": "poisoned",
                "polled_at": ts.to_rfc3339(),
                "mitre_techniques": ["T1014", "T1068"],
            }),
            tags: vec!["integrity".to_string(), "T1068".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::path("/usr/bin/su")],
        };

        let incident = page_cache_mismatch_incident(&event);

        assert!(incident
            .incident_id
            .starts_with("suid_page_cache_integrity:_usr_bin_su:"));
        assert_eq!(incident.severity, Severity::Critical);
        assert_eq!(
            incident.title,
            "SUID binary corrupted in page cache: /usr/bin/su"
        );
        assert_eq!(incident.evidence[0]["path"], "/usr/bin/su");
        assert!(incident.summary.contains("direct disk read"));
    }

    #[test]
    fn devnode_exposed_event_promotes_to_medium_incident() {
        // Mirror of the page_cache promotion test, with the kernel
        // devnode exposure event shape from detectors/kernel_devnode_exposed.rs.
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-24T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let event = innerwarden_core::event::Event {
            ts,
            host: "sensor-host".to_string(),
            source: "kernel_devnode_exposed".to_string(),
            kind: "integrity.devnode_exposed".to_string(),
            severity: Severity::Medium,
            summary: "Kernel device /dev/infiniband/uverbs0 mode 0o666 > safe 0o660".to_string(),
            details: serde_json::json!({
                "path": "/dev/infiniband/uverbs0",
                "actual_mode_octal": "0o666",
                "max_allowed_mode_octal": "0o660",
                "extra_permission_bits_octal": "0o6",
                "surface": "RDMA verbs ioctl ABI (mana_ib / mlx5 / etc.)",
                "polled_at": ts.to_rfc3339(),
                "mitre_techniques": ["T1068"],
            }),
            tags: vec![
                "integrity".to_string(),
                "hardening".to_string(),
                "T1068".to_string(),
            ],
            entities: vec![innerwarden_core::entities::EntityRef::path(
                "/dev/infiniband/uverbs0",
            )],
        };

        let incident = devnode_exposed_incident(&event);
        assert!(incident
            .incident_id
            .starts_with("kernel_devnode_exposed:_dev_infiniband_uverbs0:"));
        assert_eq!(incident.severity, Severity::Medium);
        assert!(incident
            .title
            .starts_with("Kernel device exposed: /dev/infiniband/uverbs0"));
        // Summary must point operators at the CL-071 chain so they
        // understand the Medium signal can escalate to Critical.
        assert!(incident.summary.contains("CL-071"));
        // Recommended_checks must include both the chmod fix AND the
        // allowlist escape hatch — exactly one of each.
        assert!(incident
            .recommended_checks
            .iter()
            .any(|c| c.contains("chmod 0660")));
        assert!(incident
            .recommended_checks
            .iter()
            .any(|c| c.contains("allowlist")));
    }

    #[test]
    fn build_devnode_watchlist_keeps_defaults_when_no_overrides() {
        let wl = build_devnode_watchlist(&[]);
        // Same length as the detector's default
        assert_eq!(
            wl.len(),
            detectors::kernel_devnode_exposed::default_watchlist().len()
        );
        // Some sentinel entries that must remain present
        assert!(wl.iter().any(|w| w.pattern == "/dev/kvm"));
        assert!(wl.iter().any(|w| w.pattern == "/dev/infiniband/uverbs*"));
    }

    #[test]
    fn build_devnode_watchlist_override_replaces_default_for_same_pattern() {
        // Operator says: I actually allow /dev/kvm to be 0o666 because
        // I run untrusted VMs and access KVM as a non-root user.
        let ovs = vec![config::KernelDevnodeWatchEntryConfig {
            pattern: "/dev/kvm".to_string(),
            max_allowed_mode_octal: "0o666".to_string(),
            surface: "operator-permitted KVM".to_string(),
        }];
        let wl = build_devnode_watchlist(&ovs);
        let kvm = wl.iter().find(|w| w.pattern == "/dev/kvm").expect("kvm");
        assert_eq!(kvm.max_allowed_mode, 0o666);
        assert_eq!(kvm.surface, "operator-permitted KVM");
    }

    #[test]
    fn build_devnode_watchlist_appends_unknown_pattern() {
        // Operator adds a brand-new pattern not in defaults
        let ovs = vec![config::KernelDevnodeWatchEntryConfig {
            pattern: "/dev/custom-driver".to_string(),
            max_allowed_mode_octal: "660".to_string(),
            surface: "".to_string(),
        }];
        let wl = build_devnode_watchlist(&ovs);
        let custom = wl
            .iter()
            .find(|w| w.pattern == "/dev/custom-driver")
            .expect("custom appended");
        assert_eq!(custom.max_allowed_mode, 0o660);
        assert_eq!(custom.surface, "operator-defined");
    }

    #[test]
    fn build_devnode_watchlist_keeps_default_on_malformed_mode() {
        // Typo in operator config must NOT widen the allowed mode.
        let ovs = vec![config::KernelDevnodeWatchEntryConfig {
            pattern: "/dev/kvm".to_string(),
            max_allowed_mode_octal: "999z".to_string(),
            surface: "typo".to_string(),
        }];
        let wl = build_devnode_watchlist(&ovs);
        let kvm = wl.iter().find(|w| w.pattern == "/dev/kvm").expect("kvm");
        // Default for /dev/kvm is 0o660 — must stay that way even
        // though the operator supplied garbage.
        assert_eq!(kvm.max_allowed_mode, 0o660);
    }

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
    #[test]
    fn blocked_ip_hint_returns_true_but_does_not_imply_skip() {
        use innerwarden_core::event::{Event, Severity};
        use std::collections::HashSet;

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
        let main_src = include_str!("main.rs");
        let process_event_start = main_src
            .find("fn process_event(")
            .expect("process_event function must exist in main.rs");
        let process_event_body =
            &main_src[process_event_start..(process_event_start + 8000).min(main_src.len())];
        let forbidden_pattern = "if should_use_blocked_ip_hint";
        assert!(
            !process_event_body.contains(&format!("{forbidden_pattern}(&ev, &detectors.blocked_ips) {{\n        return;")) &&
            !process_event_body.contains(&format!("{forbidden_pattern}(&ev, &detectors.blocked_ips) {{\n            return;")),
            "process_event must NOT short-circuit on blocked IPs — see the 2026-05-23 incident comment in the function body. \
             If you intentionally re-added the early-return, delete THIS test with a comment explaining why."
        );
    }

    // (blocked_ip_hint_returns_false_for_unblocked_ip and
    //  blocked_ip_hint_returns_false_when_event_has_no_ip moved to
    //  main_helpers.rs::tests. The anti-regression
    //  `blocked_ip_hint_returns_true_but_does_not_imply_skip` above STAYS
    //  here because it source-greps the process_event body via
    //  `include_str!("main.rs")`.)

    // (build_tracing_env_filter anchor moved to crates/sensor/src/tracing_init.rs
    //  as part of the 2026-05-25 main.rs decomposition PR1.)
}
