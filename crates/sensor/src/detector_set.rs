//! The [`DetectorSet`] god-struct: one field per stateful detector.
//!
//! Extracted from `main.rs` on 2026-05-26 as follow-up #2 of the
//! post-PR-F3 punch list. Pure code motion — zero behaviour change.
//!
//! ## Why this lives in its own file
//!
//! `DetectorSet` is ~100 LoC of struct fields plus ~35 detector
//! type imports to satisfy them. Pre-this it sat inside `main.rs`
//! and made the binary's entry-point file ~280 LoC of detector
//! declarations + 5 LoC of actual `async fn main`. Moving the
//! struct out leaves `main.rs` as the truly minimal "wire CLI →
//! config → sensor::run" file it claims to be.
//!
//! Constructed once at boot by
//! [`crate::boot::build_detectors::build_detector_set`]; consumed
//! mutably by [`crate::boot::event_loop::run_event_loop`] and
//! [`crate::event_dispatch::process_event`]. All three previously
//! imported via `crate::DetectorSet`; that path now lives at
//! `crate::detector_set::DetectorSet`.

use std::collections::HashSet;

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
use crate::detectors::execution_guard::ExecutionGuardDetector;
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

pub(crate) struct DetectorSet {
    /// Dynamic allowlist loaded from /etc/innerwarden/allowlist.toml.
    /// Checked before all detectors -- if a process/IP is allowlisted,
    /// the event is still logged but no incident is generated.
    /// Event pipeline: declarative filter/sample/promote engine.
    /// Controls which events are persisted to disk. `None` when
    /// `[event_pipeline] enabled = false` in config.
    pub(crate) event_pipeline: crate::event_pipeline::EventPipeline,

    /// Dynamic allowlist loaded from /etc/innerwarden/allowlist.toml.
    /// Checked before all detectors -- if a process/IP is allowlisted,
    /// the event is still logged but no incident is generated.
    pub(crate) dynamic_allowlist: detectors::allowlists::DynamicAllowlist,
    /// Last time we checked the allowlist file for changes.
    pub(crate) allowlist_last_check: std::time::Instant,

    /// IPs blocked by the agent. Loaded from blocked-ips.txt and
    /// reloaded every 60s. Events from these IPs skip detection.
    pub(crate) blocked_ips: HashSet<String>,
    /// Last time we reloaded blocked-ips.txt.
    pub(crate) blocked_ips_last_check: std::time::Instant,

    pub(crate) ssh: Option<SshBruteforceDetector>,
    pub(crate) credential_stuffing: Option<CredentialStuffingDetector>,
    pub(crate) port_scan: Option<PortScanDetector>,
    pub(crate) sudo_abuse: Option<SudoAbuseDetector>,
    pub(crate) search_abuse: Option<SearchAbuseDetector>,
    pub(crate) web_scan: Option<WebScanDetector>,
    pub(crate) user_agent_scanner: Option<UserAgentScannerDetector>,
    pub(crate) execution_guard: Option<ExecutionGuardDetector>,
    pub(crate) docker_anomaly: Option<DockerAnomalyDetector>,
    pub(crate) integrity_alert: Option<IntegrityAlertDetector>,
    pub(crate) log_tampering: Option<LogTamperingDetector>,
    pub(crate) distributed_ssh: Option<DistributedSshDetector>,
    pub(crate) suspicious_login: Option<SuspiciousLoginDetector>,
    pub(crate) c2_callback: Option<C2CallbackDetector>,
    pub(crate) process_tree: Option<ProcessTreeDetector>,
    pub(crate) container_escape: Option<ContainerEscapeDetector>,
    pub(crate) privesc: Option<PrivescDetector>,
    pub(crate) fileless: Option<FilelessDetector>,
    pub(crate) dns_tunneling: Option<DnsTunnelingDetector>,
    pub(crate) lateral_movement: Option<LateralMovementDetector>,
    pub(crate) crypto_miner: Option<CryptoMinerDetector>,
    pub(crate) outbound_anomaly: Option<OutboundAnomalyDetector>,
    pub(crate) rootkit: Option<RootkitDetector>,
    pub(crate) reverse_shell: Option<ReverseShellDetector>,
    pub(crate) ssh_key_injection: Option<SshKeyInjectionDetector>,
    pub(crate) web_shell: Option<WebShellDetector>,
    pub(crate) kernel_module_load: Option<KernelModuleLoadDetector>,
    pub(crate) crontab_persistence: Option<CrontabPersistenceDetector>,
    pub(crate) data_exfiltration: Option<DataExfiltrationDetector>,
    pub(crate) process_injection: Option<ProcessInjectionDetector>,
    pub(crate) user_creation: Option<UserCreationDetector>,
    pub(crate) systemd_persistence: Option<SystemdPersistenceDetector>,
    pub(crate) ransomware: Option<RansomwareDetector>,
    pub(crate) credential_harvest: Option<CredentialHarvestDetector>,
    pub(crate) packet_flood: Option<PacketFloodDetector>,
    pub(crate) sensitive_write: Option<detectors::sensitive_write::SensitiveWriteDetector>,
    pub(crate) discovery_burst: Option<detectors::discovery_burst::DiscoveryBurstDetector>,
    pub(crate) io_uring_anomaly: Option<detectors::io_uring_anomaly::IoUringAnomalyDetector>,
    pub(crate) container_drift: Option<detectors::container_drift::ContainerDriftDetector>,
    pub(crate) host_drift: Option<detectors::host_drift::HostDriftDetector>,
    pub(crate) data_exfil_ebpf: Option<detectors::data_exfil_ebpf::DataExfilEbpfDetector>,
    pub(crate) imds_ssrf: Option<detectors::imds_ssrf::ImdsSsrfDetector>,
    pub(crate) yara_scan: Option<detectors::yara_scan::YaraScanDetector>,
    pub(crate) sigma_rule: Option<detectors::sigma_rule::SigmaRuleDetector>,
    pub(crate) mitre_hunt: Option<detectors::mitre_hunt::MitreHuntDetector>,
    pub(crate) dns_c2: Option<detectors::dns_c2::DnsC2Detector>,
    pub(crate) data_encoding: Option<detectors::data_encoding::DataEncodingDetector>,
    pub(crate) sandbox_evasion: Option<detectors::sandbox_evasion::SandboxEvasionDetector>,
    pub(crate) threat_intel: Option<detectors::threat_intel::ThreatIntelDetector>,
    pub(crate) proto_anomaly: Option<detectors::proto_anomaly::ProtoAnomalyDetector>,
    // spec 050-PR1 — Reconnaissance
    pub(crate) nmap_scan: Option<detectors::nmap_scan::NmapScanDetector>,
    pub(crate) wordlist_scan: Option<detectors::wordlist_scan::WordlistScanDetector>,
    pub(crate) discovery_anomaly: Option<detectors::discovery_anomaly::DiscoveryAnomalyDetector>,
    // spec 050-PR2 — Collection
    pub(crate) clipboard_read: Option<detectors::clipboard_read::ClipboardReadDetector>,
    pub(crate) screen_capture: Option<detectors::screen_capture::ScreenCaptureDetector>,
    pub(crate) keylogger_bash_trap:
        Option<detectors::keylogger_bash_trap::KeyloggerBashTrapDetector>,
    pub(crate) archive_pwd_protected:
        Option<detectors::archive_pwd_protected::ArchivePwdProtectedDetector>,
    pub(crate) automated_file_collection:
        Option<detectors::automated_file_collection::AutomatedFileCollectionDetector>,
    // spec 050-PR3 — C2 variants
    pub(crate) c2_web_tunnel: Option<detectors::c2_web_tunnel::C2WebTunnelDetector>,
    pub(crate) c2_protocol_tunneling:
        Option<detectors::c2_protocol_tunneling::C2ProtocolTunnelingDetector>,
    pub(crate) c2_non_standard_port:
        Option<detectors::c2_non_standard_port::C2NonStandardPortDetector>,
    // spec 050-PR4 — Privilege Escalation + Lateral Movement
    pub(crate) setuid_exploit_pattern:
        Option<detectors::setuid_exploit_pattern::SetuidExploitPatternDetector>,
    pub(crate) capabilities_abuse: Option<detectors::capabilities_abuse::CapabilitiesAbuseDetector>,
    pub(crate) lateral_egress_ssh: Option<detectors::lateral_egress_ssh::LateralEgressSshDetector>,
    pub(crate) lateral_egress_scp_rsync:
        Option<detectors::lateral_egress_scp_rsync::LateralEgressScpRsyncDetector>,
    // spec 050-PR5 — Persistence + Defense Evasion
    pub(crate) pam_module_change: Option<detectors::pam_module_change::PamModuleChangeDetector>,
    pub(crate) auditd_disable: Option<detectors::auditd_disable::AuditdDisableDetector>,
    pub(crate) selinux_apparmor_disable:
        Option<detectors::selinux_apparmor_disable::SelinuxApparmorDisableDetector>,
    pub(crate) startup_script_persistence:
        Option<detectors::startup_script_persistence::StartupScriptPersistenceDetector>,
    // spec 050-PR6 — Impact
    pub(crate) data_destruction_pattern:
        Option<detectors::data_destruction_pattern::DataDestructionPatternDetector>,
    // 2026-05-17 wave — gap closers
    pub(crate) symlink_hijack: Option<detectors::symlink_hijack::SymlinkHijackDetector>,
    pub(crate) system_user_interactive:
        Option<detectors::system_user_interactive::SystemUserInteractiveDetector>,
}

impl DetectorSet {
    pub(crate) fn is_incident_suppressed(
        &self,
        incident: &innerwarden_core::incident::Incident,
        detector_name: &str,
    ) -> bool {
        let candidates = detectors::allowlists::DynamicAllowlist::extract_evidence_candidates(
            incident,
            detector_name,
        );
        let refs: Vec<&str> = candidates.iter().map(|s| s.as_str()).collect();
        if self
            .event_pipeline
            .incident_suppressions
            .is_suppressed(detector_name, &refs)
        {
            return true;
        }
        self.dynamic_allowlist
            .suppress_incident_for_detector(incident, detector_name)
    }
}
