//! Synchronous construction of [`DetectorSet`]. Covers every per-detector
//! `cfg.detectors.X.enabled.then(|| ...)` block, the dynamic allowlist
//! load, the blocked-IP feedback file load, and the giant struct literal
//! that assembles them all into one DetectorSet value.
//!
//! Extracted from `main.rs` on 2026-05-25 as PR5b1 of the main.rs
//! decomposition (see SESSION_LOG.md). Pure code motion — zero
//! behaviour change. ~594 LoC moved.
//!
//! ## Why this is the right thing to extract first
//!
//! The DetectorSet literal is **the largest single block** of the
//! pre-decomposition `async fn main` (458 lines on its own, plus
//! the 113 lines of per-detector `let X_detector = ...` constructions
//! above it). It is also the most mechanical: pure sync code, no
//! tokio, no async, no shared cursors, no event loop. The function's
//! only inputs are the operator's config + the data directory.
//!
//! ## Test surface
//!
//! Calling [`build_detector_set`] with a config that disables every
//! detector returns a DetectorSet whose `Option<...>` fields are all
//! `None` — the anchor below pins that contract. A future refactor
//! that swaps the `cfg.X.enabled.then(|| ...)` pattern for a
//! `Some(...)` literal would silently turn detectors on regardless of
//! config and break the operator's "trial install" defaults.

use std::path::Path;

use tracing::info;

use crate::config::Config;
use crate::detector_set::DetectorSet;
use crate::detectors;
use crate::detectors::c2_callback::C2CallbackDetector;
use crate::detectors::container_escape::ContainerEscapeDetector;
use crate::detectors::credential_harvest::CredentialHarvestDetector;
use crate::detectors::credential_stuffing::CredentialStuffingDetector;
use crate::detectors::crontab_persistence::CrontabPersistenceDetector;
use crate::detectors::crypto_miner::CryptoMinerDetector;
use crate::detectors::data_exfiltration::DataExfiltrationDetector;
use crate::detectors::distributed_ssh::DistributedSshDetector;
use crate::detectors::dns_tunneling::DnsTunnelingDetector;
use crate::detectors::docker_anomaly::DockerAnomalyDetector;
use crate::detectors::execution_guard::{ExecutionGuardDetector, ExecutionMode};
use crate::detectors::fileless::FilelessDetector;
use crate::detectors::integrity_alert::IntegrityAlertDetector;
use crate::detectors::kernel_module_load::KernelModuleLoadDetector;
use crate::detectors::lateral_movement::LateralMovementDetector;
use crate::detectors::log_tampering::LogTamperingDetector;
use crate::detectors::outbound_anomaly::OutboundAnomalyDetector;
use crate::detectors::packet_flood::PacketFloodDetector;
use crate::detectors::port_scan::PortScanDetector;
use crate::detectors::privesc::PrivescDetector;
use crate::detectors::process_injection::ProcessInjectionDetector;
use crate::detectors::process_tree::ProcessTreeDetector;
use crate::detectors::ransomware::RansomwareDetector;
use crate::detectors::reverse_shell::ReverseShellDetector;
use crate::detectors::rootkit::RootkitDetector;
use crate::detectors::search_abuse::SearchAbuseDetector;
use crate::detectors::ssh_bruteforce::SshBruteforceDetector;
use crate::detectors::ssh_key_injection::SshKeyInjectionDetector;
use crate::detectors::sudo_abuse::SudoAbuseDetector;
use crate::detectors::suspicious_login::SuspiciousLoginDetector;
use crate::detectors::systemd_persistence::SystemdPersistenceDetector;
use crate::detectors::user_agent_scanner::UserAgentScannerDetector;
use crate::detectors::user_creation::UserCreationDetector;
use crate::detectors::web_scan::WebScanDetector;
use crate::detectors::web_shell::WebShellDetector;
use crate::main_helpers::load_blocked_ips;

/// Build the complete DetectorSet from the operator's config + data
/// directory. Every `Option<...>` field is populated iff the
/// corresponding `cfg.detectors.X.enabled` flag is true. The dynamic
/// allowlist is loaded from `/etc/innerwarden/allowlist.toml` (silently
/// returns an empty allowlist if the file is absent — fresh install
/// path). The blocked-IP set is loaded from
/// `<data_dir>/blocked-ips.txt` (silently empty when absent).
pub(crate) fn build_detector_set(cfg: &Config, data_dir: &Path) -> DetectorSet {
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

    let event_pipeline = {
        let rules_dir = if std::path::Path::new(&cfg.event_pipeline.rules_dir).is_absolute() {
            std::path::PathBuf::from(&cfg.event_pipeline.rules_dir)
        } else {
            data_dir.join(&cfg.event_pipeline.rules_dir)
        };
        if cfg.event_pipeline.enabled {
            info!(rules_dir = %rules_dir.display(), "event_pipeline enabled");
            crate::event_pipeline::EventPipeline::new(&rules_dir, true)
        } else {
            info!("event_pipeline disabled by config");
            crate::event_pipeline::EventPipeline::new_disabled()
        }
    };

    DetectorSet {
        event_pipeline,
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
            let rules_dir = [
                std::path::PathBuf::from("/etc/innerwarden/rules/yara"),
                std::path::PathBuf::from("rules/yara"),
            ]
            .into_iter()
            .find(|p| p.is_dir())
            .unwrap_or_else(|| std::path::PathBuf::from("/etc/innerwarden/rules/yara"));
            info!(path = %rules_dir.display(), "YARA binary scanner enabled");
            detectors::yara_scan::YaraScanDetector::new(&cfg.agent.host_id, &rules_dir, 3600)
        }),
        sigma_rule: Some({
            let rules_dir = [
                std::path::PathBuf::from("/etc/innerwarden/rules/sigma"),
                std::path::PathBuf::from("rules/sigma"),
            ]
            .into_iter()
            .find(|p| p.is_dir())
            .unwrap_or_else(|| std::path::PathBuf::from("/etc/innerwarden/rules/sigma"));
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
    }
}

// No anchor tests added with this PR: `Config` has no `Default` impl
// and constructing a fully-populated config from a TOML literal would
// be brittle (every detector schema change would need an edit here).
// The pre-existing 1413 sensor tests cover every detector's behaviour
// individually, which is the right level for regression coverage.
// A follow-up PR can introduce `Config::test_default()` or similar
// helper to enable the "enabled.then(...) contract" anchor in this
// module.
