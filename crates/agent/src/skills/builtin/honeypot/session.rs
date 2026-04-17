use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::{http_interact, ssh_interact};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

use super::audit::{
    bytes_to_hex, guess_protocol, sanitize_transcript, sha256_hex, truncate_preview,
};
pub(crate) use super::banner::normalize_interaction;
use super::banner::{banner_for_service, is_loopback_bind, normalize_isolation_profile};
#[cfg(test)]
use super::banner::{HTTP_BANNER, SSH_BANNER};
use super::containment::{build_jail_command, build_namespace_command};

const PAYLOAD_READ_TIMEOUT_MS: u64 = 700;
const DEFAULT_LOCK_FILE: &str = "listener-active.lock";
const SANDBOX_GRACE_SECS: u64 = 30;

/// Honeypot skill.
///
/// Modes:
/// - `demo`: controlled marker only.
/// - `listener`: real bounded decoy listeners + selective redirect (optional) + forensics artifacts.
pub struct Honeypot;

#[derive(Debug, Clone)]
struct DecoyEndpoint {
    service: String,
    bind_addr: String,
    listen_port: u16,
    redirect_from_port: u16,
    banner: &'static [u8],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SandboxEndpointSpec {
    service: String,
    bind_addr: String,
    listen_port: u16,
    redirect_from_port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct RedirectRuleStatus {
    service: String,
    target_ip: String,
    from_port: u16,
    to_port: u16,
    add_command: String,
    remove_command: String,
    applied: bool,
    apply_error: Option<String>,
    cleanup_ok: Option<bool>,
    cleanup_error: Option<String>,
    cleanup_verified_absent: Option<bool>,
}

#[derive(Clone)]
struct SessionRuntime {
    session_id: String,
    target_ip: IpAddr,
    strict_target_only: bool,
    duration_secs: u64,
    max_connections: usize,
    max_payload_bytes: usize,
    transcript_preview_bytes: usize,
    isolation_profile: String,
    evidence_path: PathBuf,
    /// `banner` | `medium` | `llm_shell`
    interaction: String,
    ssh_max_auth_attempts: usize,
    http_max_requests: usize,
    /// AI provider used when `interaction = "llm_shell"`.
    /// Not serialized - only available in the direct (non-sandbox) listener path.
    ai_provider: Option<std::sync::Arc<dyn crate::ai::AiProvider>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListenerStats {
    service: String,
    bind_addr: String,
    listen_port: u16,
    accepted: u64,
    rejected: u64,
    payload_bytes_captured: u64,
    read_timeouts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SandboxWorkerSpec {
    session_id: String,
    target_ip: String,
    strict_target_only: bool,
    duration_secs: u64,
    max_connections: usize,
    max_payload_bytes: usize,
    transcript_preview_bytes: usize,
    isolation_profile: String,
    evidence_path: PathBuf,
    endpoints: Vec<SandboxEndpointSpec>,
    interaction: String,
    ssh_max_auth_attempts: usize,
    http_max_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SandboxWorkerResult {
    session_id: String,
    success: bool,
    error: Option<String>,
    service_stats: Vec<ListenerStats>,
}

#[derive(Debug, Clone, Serialize)]
struct ForensicsCleanupStats {
    removed_by_age: usize,
    removed_by_size: usize,
    total_before_bytes: u64,
    total_after_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PcapHandoffStatus {
    enabled: bool,
    attempted: bool,
    timeout_secs: u64,
    max_packets: u64,
    command: Option<String>,
    pcap_file: Option<String>,
    success: bool,
    timed_out: bool,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct SandboxRunOutcome {
    stats: Vec<ListenerStats>,
    spec_path: PathBuf,
    result_path: PathBuf,
    runner: String,
    containment: ContainmentStatus,
}

#[derive(Debug, Clone, Serialize)]
struct ContainmentStatus {
    requested_mode: String,
    effective_mode: String,
    require_success: bool,
    namespace_runner: String,
    namespace_args: Vec<String>,
    jail_runner: String,
    jail_args: Vec<String>,
    jail_profile_requested: String,
    jail_profile_effective: String,
    allow_namespace_fallback: bool,
    check_passed: bool,
    fallback_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AttestationStatus {
    enabled: bool,
    key_env: Option<String>,
    prefix: Option<String>,
    expected_receiver: Option<String>,
    challenge: Option<String>,
    receiver_id: Option<String>,
    matched: Option<bool>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ExternalHandoffStatus {
    enabled: bool,
    attempted: bool,
    command: Option<String>,
    args: Vec<String>,
    timeout_secs: u64,
    require_success: bool,
    command_success: Option<bool>,
    trusted: bool,
    allowlist_enforced: bool,
    allowlist_match: Option<bool>,
    allowed_commands: Vec<String>,
    signature_enabled: bool,
    signature_key_env: Option<String>,
    signature: Option<String>,
    signature_payload_sha256: Option<String>,
    signature_file: Option<String>,
    signature_error: Option<String>,
    attestation: AttestationStatus,
    success: bool,
    timed_out: bool,
    exit_code: Option<i32>,
    error: Option<String>,
    stdout_preview: Option<String>,
    stderr_preview: Option<String>,
    result_file: Option<String>,
}

#[derive(Debug, Clone)]
struct SandboxLaunchConfig {
    runner_path: String,
    clear_env: bool,
    containment_mode: String,
    containment_require_success: bool,
    containment_namespace_runner: String,
    containment_namespace_args: Vec<String>,
    containment_jail_runner: String,
    containment_jail_args: Vec<String>,
    containment_jail_profile: String,
    containment_allow_namespace_fallback: bool,
}

#[derive(Debug, Clone)]
struct ExternalHandoffConfig {
    enabled: bool,
    command: String,
    args: Vec<String>,
    timeout_secs: u64,
    require_success: bool,
    clear_env: bool,
    allowed_commands: Vec<String>,
    enforce_allowlist: bool,
    signature_enabled: bool,
    signature_key_env: String,
    attestation_enabled: bool,
    attestation_key_env: String,
    attestation_prefix: String,
    attestation_expected_receiver: String,
}

#[derive(Debug, Clone)]
struct ParsedAttestationLine {
    receiver_id: String,
    challenge: String,
    hmac_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactLifecycleStatus {
    metadata_exists: bool,
    metadata_bytes: u64,
    evidence_exists: bool,
    evidence_bytes: u64,
    pcap_exists: Option<bool>,
    pcap_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct PayloadCapture {
    bytes_captured: usize,
    payload_hex: String,
    transcript_preview: String,
    protocol_guess: String,
    read_timed_out: bool,
}

#[derive(Debug)]
struct SessionLock {
    path: PathBuf,
}

impl From<&DecoyEndpoint> for SandboxEndpointSpec {
    fn from(value: &DecoyEndpoint) -> Self {
        Self {
            service: value.service.clone(),
            bind_addr: value.bind_addr.clone(),
            listen_port: value.listen_port,
            redirect_from_port: value.redirect_from_port,
        }
    }
}

impl SandboxEndpointSpec {
    fn into_endpoint(self) -> Result<DecoyEndpoint, String> {
        let banner = banner_for_service(&self.service)?;
        Ok(DecoyEndpoint {
            service: self.service,
            bind_addr: self.bind_addr,
            listen_port: self.listen_port,
            redirect_from_port: self.redirect_from_port,
            banner,
        })
    }
}

impl ResponseSkill for Honeypot {
    fn id(&self) -> &'static str {
        "honeypot"
    }
    fn name(&self) -> &'static str {
        "Honeypot"
    }
    fn description(&self) -> &'static str {
        "Runs in demo mode or in bounded real listener mode with multi-service decoys, \
         selective redirection, and lightweight forensic artifacts."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &[]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip_raw = ctx.target_ip.as_deref().unwrap_or("unknown");
            let mode = ctx.honeypot.mode.trim().to_ascii_lowercase();

            if mode != "listener" {
                info!(
                    ip = ip_raw,
                    "[PREMIUM] honeypot demo marker triggered \
                     (DEMO/SIMULATION/DECOY mode; no real honeypot infrastructure)"
                );
                return SkillResult {
                    success: true,
                    message: format!(
                        "[PREMIUM DEMO] Honeypot simulation marker armed for {ip_raw}. \
                         Real decoy infra lives in listener mode."
                    ),
                };
            }

            let target_ip = match ip_raw.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    return SkillResult {
                        success: false,
                        message: format!("honeypot listener: invalid target IP '{ip_raw}'"),
                    };
                }
            };

            let isolation_profile = normalize_isolation_profile(&ctx.honeypot.isolation_profile);
            let strict_profile = isolation_profile == "strict_local";

            if strict_profile
                && (!ctx.honeypot.strict_target_only
                    || ctx.honeypot.allow_public_listener
                    || !ctx.honeypot.require_high_ports)
            {
                return SkillResult {
                    success: false,
                    message: "honeypot listener: strict_local profile requires strict_target_only=true, allow_public_listener=false and require_high_ports=true".to_string(),
                };
            }

            if !ctx.honeypot.allow_public_listener && !is_loopback_bind(&ctx.honeypot.bind_addr) {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: bind_addr {} rejected by isolation guard (set honeypot.allow_public_listener=true if intentional)",
                        ctx.honeypot.bind_addr
                    ),
                };
            }

            let endpoints = match build_endpoints(&ctx.honeypot, &ctx.honeypot.bind_addr) {
                Ok(endpoints) => endpoints,
                Err(msg) => {
                    return SkillResult {
                        success: false,
                        message: format!("honeypot listener: {msg}"),
                    };
                }
            };

            if ctx.honeypot.require_high_ports
                && endpoints.iter().any(|endpoint| endpoint.listen_port < 1024)
            {
                return SkillResult {
                    success: false,
                    message: "honeypot listener: high-port guard enabled (set honeypot.require_high_ports=false to override)".to_string(),
                };
            }

            let redirect_preview = preview_redirect_commands(
                &endpoints,
                target_ip,
                ctx.honeypot.redirect_enabled,
                &ctx.honeypot.redirect_backend,
            );

            if dry_run {
                let services = endpoints
                    .iter()
                    .map(|e| format!("{}:{}", e.service, e.listen_port))
                    .collect::<Vec<_>>()
                    .join(", ");
                let redirect_note = if redirect_preview.is_empty() {
                    "redirect disabled".to_string()
                } else {
                    format!("redirect rules: {}", redirect_preview.join(" | "))
                };
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would start honeypot listeners ({services}) for {}s targeting {target_ip}; interaction={}; profile={isolation_profile}; containment={}/{}; external_handoff={}; external_attestation={}; {redirect_note}",
                        ctx.honeypot.duration_secs,
                        ctx.honeypot.interaction.trim().to_ascii_lowercase(),
                        ctx.honeypot.containment_mode,
                        ctx.honeypot.containment_jail_profile,
                        ctx.honeypot.external_handoff_enabled,
                        ctx.honeypot.external_handoff_attestation_enabled,
                    ),
                };
            }

            if ctx.honeypot.redirect_enabled
                && !ctx
                    .honeypot
                    .redirect_backend
                    .eq_ignore_ascii_case("iptables")
            {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: redirect backend '{}' not supported (supported: iptables)",
                        ctx.honeypot.redirect_backend
                    ),
                };
            }

            let session_dir = ctx.data_dir.join("honeypot");
            if let Err(e) = tokio::fs::create_dir_all(&session_dir).await {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: failed to create session dir {}: {e}",
                        session_dir.display()
                    ),
                };
            }

            let cleanup_stats = match cleanup_old_forensics(
                &session_dir,
                ctx.honeypot.forensics_keep_days,
                ctx.honeypot.forensics_max_total_mb,
            )
            .await
            {
                Ok(stats) => stats,
                Err(e) => {
                    warn!(
                        path = %session_dir.display(),
                        "honeypot forensics cleanup failed (continuing fail-open): {e}"
                    );
                    ForensicsCleanupStats {
                        removed_by_age: 0,
                        removed_by_size: 0,
                        total_before_bytes: 0,
                        total_after_bytes: 0,
                    }
                }
            };

            let session_id = format!(
                "{}-{}",
                Utc::now().format("%Y%m%dT%H%M%SZ"),
                target_ip.to_string().replace(':', "_")
            );
            let metadata_path = session_dir.join(format!("listener-session-{session_id}.json"));
            let evidence_path = session_dir.join(format!("listener-session-{session_id}.jsonl"));

            let lock_path = session_dir.join(DEFAULT_LOCK_FILE);
            let session_lock = match SessionLock::acquire(
                lock_path.clone(),
                &session_id,
                ctx.honeypot.lock_stale_secs,
            )
            .await
            {
                Ok(lock) => lock,
                Err(e) => {
                    return SkillResult {
                        success: false,
                        message: format!("honeypot listener: {e}"),
                    };
                }
            };

            let mut bound = Vec::new();
            let mut bind_errors = Vec::new();
            if !ctx.honeypot.sandbox_enabled {
                for endpoint in &endpoints {
                    let bind_target = format!("{}:{}", endpoint.bind_addr, endpoint.listen_port);
                    match TcpListener::bind(&bind_target).await {
                        Ok(listener) => {
                            info!(service = %endpoint.service, bind = %bind_target, "honeypot listener bound");
                            bound.push((endpoint.clone(), listener));
                        }
                        Err(e) => bind_errors.push(format!("{bind_target}: {e}")),
                    }
                }
            }

            if !ctx.honeypot.sandbox_enabled && bound.is_empty() {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: failed to bind all decoys: {}",
                        bind_errors.join("; ")
                    ),
                };
            }

            let mut redirect_rules = if ctx.honeypot.redirect_enabled {
                apply_redirect_rules(&endpoints, target_ip, &ctx.honeypot.redirect_backend).await
            } else {
                vec![]
            };

            let start_metadata = serde_json::json!({
                "ts": Utc::now().to_rfc3339(),
                "status": "running",
                "mode": "listener",
                "host": ctx.host,
                "incident_id": ctx.incident.incident_id,
                "target_ip": target_ip.to_string(),
                "bind_addr": ctx.honeypot.bind_addr,
                "duration_secs": ctx.honeypot.duration_secs,
                "services": endpoints.iter().map(|ep| serde_json::json!({
                    "service": ep.service.clone(),
                    "listen_port": ep.listen_port,
                    "redirect_from_port": ep.redirect_from_port,
                })).collect::<Vec<_>>(),
                "strict_target_only": ctx.honeypot.strict_target_only,
                "max_connections": ctx.honeypot.max_connections,
                "max_payload_bytes": ctx.honeypot.max_payload_bytes,
                "isolation_profile": isolation_profile,
                "require_high_ports": ctx.honeypot.require_high_ports,
                "forensics_keep_days": ctx.honeypot.forensics_keep_days,
                "forensics_max_total_mb": ctx.honeypot.forensics_max_total_mb,
                "transcript_preview_bytes": ctx.honeypot.transcript_preview_bytes,
                "lock_stale_secs": ctx.honeypot.lock_stale_secs,
                "lock_file": lock_path,
                "forensics_cleanup": cleanup_stats,
                "sandbox": {
                    "enabled": ctx.honeypot.sandbox_enabled,
                    "runner_path": ctx.honeypot.sandbox_runner_path,
                    "clear_env": ctx.honeypot.sandbox_clear_env,
                },
                "containment": {
                    "mode": ctx.honeypot.containment_mode,
                    "require_success": ctx.honeypot.containment_require_success,
                    "namespace_runner": ctx.honeypot.containment_namespace_runner,
                    "namespace_args": ctx.honeypot.containment_namespace_args,
                    "jail_runner": ctx.honeypot.containment_jail_runner,
                    "jail_args": ctx.honeypot.containment_jail_args,
                    "jail_profile": ctx.honeypot.containment_jail_profile,
                    "allow_namespace_fallback": ctx.honeypot.containment_allow_namespace_fallback,
                },
                "pcap_handoff": {
                    "enabled": ctx.honeypot.pcap_handoff_enabled,
                    "timeout_secs": ctx.honeypot.pcap_handoff_timeout_secs,
                    "max_packets": ctx.honeypot.pcap_handoff_max_packets,
                },
                "external_handoff": {
                    "enabled": ctx.honeypot.external_handoff_enabled,
                    "command": ctx.honeypot.external_handoff_command,
                    "args": ctx.honeypot.external_handoff_args,
                    "timeout_secs": ctx.honeypot.external_handoff_timeout_secs,
                    "require_success": ctx.honeypot.external_handoff_require_success,
                    "clear_env": ctx.honeypot.external_handoff_clear_env,
                    "allowed_commands": ctx.honeypot.external_handoff_allowed_commands,
                    "enforce_allowlist": ctx.honeypot.external_handoff_enforce_allowlist,
                    "signature_enabled": ctx.honeypot.external_handoff_signature_enabled,
                    "signature_key_env": ctx.honeypot.external_handoff_signature_key_env,
                    "attestation_enabled": ctx.honeypot.external_handoff_attestation_enabled,
                    "attestation_key_env": ctx.honeypot.external_handoff_attestation_key_env,
                    "attestation_prefix": ctx.honeypot.external_handoff_attestation_prefix,
                    "attestation_expected_receiver": ctx.honeypot.external_handoff_attestation_expected_receiver,
                },
                "redirect": {
                    "enabled": ctx.honeypot.redirect_enabled,
                    "backend": ctx.honeypot.redirect_backend,
                    "rules": redirect_rules.clone(),
                },
                "interaction": ctx.honeypot.interaction.trim().to_ascii_lowercase(),
                "ssh_max_auth_attempts": ctx.honeypot.ssh_max_auth_attempts,
                "http_max_requests": ctx.honeypot.http_max_requests,
                "note": "Real honeypot listener session. Bounded and fail-open."
            });
            if let Err(e) = write_json_file(&metadata_path, &start_metadata).await {
                return SkillResult {
                    success: false,
                    message: format!(
                        "honeypot listener: failed to write metadata {}: {e}",
                        metadata_path.display()
                    ),
                };
            }

            if let Err(e) = append_json_line(
                &evidence_path,
                &serde_json::json!({
                    "ts": Utc::now().to_rfc3339(),
                    "type": "session_started",
                    "session_id": session_id.clone(),
                    "target_ip": target_ip.to_string(),
                    "isolation_profile": isolation_profile,
                    "forensics_cleanup": cleanup_stats,
                    "sandbox_enabled": ctx.honeypot.sandbox_enabled,
                    "pcap_handoff_enabled": ctx.honeypot.pcap_handoff_enabled,
                }),
            )
            .await
            {
                warn!(path = %evidence_path.display(), "failed to append honeypot session start line: {e}");
            }

            let runtime = SessionRuntime {
                session_id: session_id.clone(),
                target_ip,
                strict_target_only: ctx.honeypot.strict_target_only,
                duration_secs: ctx.honeypot.duration_secs,
                max_connections: ctx.honeypot.max_connections,
                max_payload_bytes: ctx.honeypot.max_payload_bytes,
                transcript_preview_bytes: ctx.honeypot.transcript_preview_bytes,
                isolation_profile: isolation_profile.to_string(),
                evidence_path: evidence_path.clone(),
                interaction: normalize_interaction(&ctx.honeypot.interaction),
                ssh_max_auth_attempts: ctx.honeypot.ssh_max_auth_attempts,
                http_max_requests: ctx.honeypot.http_max_requests,
                ai_provider: ctx.honeypot.ai_provider.clone(),
            };

            let metadata_path_bg = metadata_path.clone();
            let evidence_path_bg = evidence_path.clone();
            let session_dir_bg = session_dir.clone();
            let endpoints_bg = endpoints.clone();
            let sandbox_enabled = ctx.honeypot.sandbox_enabled;
            let sandbox_config = SandboxLaunchConfig {
                runner_path: ctx.honeypot.sandbox_runner_path.clone(),
                clear_env: ctx.honeypot.sandbox_clear_env,
                containment_mode: ctx.honeypot.containment_mode.clone(),
                containment_require_success: ctx.honeypot.containment_require_success,
                containment_namespace_runner: ctx.honeypot.containment_namespace_runner.clone(),
                containment_namespace_args: ctx.honeypot.containment_namespace_args.clone(),
                containment_jail_runner: ctx.honeypot.containment_jail_runner.clone(),
                containment_jail_args: ctx.honeypot.containment_jail_args.clone(),
                containment_jail_profile: ctx.honeypot.containment_jail_profile.clone(),
                containment_allow_namespace_fallback: ctx
                    .honeypot
                    .containment_allow_namespace_fallback,
            };
            let pcap_handoff_enabled = ctx.honeypot.pcap_handoff_enabled;
            let pcap_handoff_timeout_secs = ctx.honeypot.pcap_handoff_timeout_secs;
            let pcap_handoff_max_packets = ctx.honeypot.pcap_handoff_max_packets;
            let external_handoff_config = ExternalHandoffConfig {
                enabled: ctx.honeypot.external_handoff_enabled,
                command: ctx.honeypot.external_handoff_command.clone(),
                args: ctx.honeypot.external_handoff_args.clone(),
                timeout_secs: ctx.honeypot.external_handoff_timeout_secs,
                require_success: ctx.honeypot.external_handoff_require_success,
                clear_env: ctx.honeypot.external_handoff_clear_env,
                allowed_commands: ctx.honeypot.external_handoff_allowed_commands.clone(),
                enforce_allowlist: ctx.honeypot.external_handoff_enforce_allowlist,
                signature_enabled: ctx.honeypot.external_handoff_signature_enabled,
                signature_key_env: ctx.honeypot.external_handoff_signature_key_env.clone(),
                attestation_enabled: ctx.honeypot.external_handoff_attestation_enabled,
                attestation_key_env: ctx.honeypot.external_handoff_attestation_key_env.clone(),
                attestation_prefix: ctx.honeypot.external_handoff_attestation_prefix.clone(),
                attestation_expected_receiver: ctx
                    .honeypot
                    .external_handoff_attestation_expected_receiver
                    .clone(),
            };
            tokio::spawn(async move {
                let _session_lock = session_lock;
                let mut sandbox_error = None::<String>;
                let mut sandbox_info = serde_json::json!({
                    "enabled": sandbox_enabled,
                    "used": sandbox_enabled,
                });
                let task_stats = if sandbox_enabled {
                    match run_sandbox_session(
                        runtime.clone(),
                        endpoints_bg,
                        &session_dir_bg,
                        &sandbox_config,
                    )
                    .await
                    {
                        Ok(outcome) => {
                            sandbox_info = serde_json::json!({
                                "enabled": true,
                                "used": true,
                                "runner": outcome.runner,
                                "spec_file": outcome.spec_path,
                                "result_file": outcome.result_path,
                                "clear_env": sandbox_config.clear_env,
                                "containment": outcome.containment,
                            });
                            outcome.stats
                        }
                        Err(e) => {
                            sandbox_error = Some(e.clone());
                            sandbox_info = serde_json::json!({
                                "enabled": true,
                                "used": true,
                                "clear_env": sandbox_config.clear_env,
                                "containment_mode": sandbox_config.containment_mode,
                                "containment_jail_profile": sandbox_config.containment_jail_profile,
                                "error": e,
                            });
                            vec![]
                        }
                    }
                } else {
                    run_bound_listeners(bound, runtime.clone()).await
                };

                cleanup_redirect_rules(&mut redirect_rules).await;
                let redirect_cleanup_verified = redirect_rules
                    .iter()
                    .all(|rule| rule.cleanup_verified_absent.unwrap_or(true));

                let pcap_handoff = if pcap_handoff_enabled {
                    run_pcap_handoff(
                        &session_dir_bg,
                        &runtime.session_id,
                        runtime.target_ip,
                        pcap_handoff_timeout_secs,
                        pcap_handoff_max_packets,
                    )
                    .await
                } else {
                    PcapHandoffStatus {
                        enabled: false,
                        attempted: false,
                        timeout_secs: pcap_handoff_timeout_secs,
                        max_packets: pcap_handoff_max_packets,
                        command: None,
                        pcap_file: None,
                        success: false,
                        timed_out: false,
                        error: None,
                    }
                };

                let artifact_checks = collect_artifact_lifecycle(
                    &metadata_path_bg,
                    &evidence_path_bg,
                    pcap_handoff.pcap_file.as_deref(),
                )
                .await;

                let external_handoff = if external_handoff_config.enabled {
                    run_external_handoff(
                        &session_dir_bg,
                        &runtime,
                        &metadata_path_bg,
                        &evidence_path_bg,
                        pcap_handoff.pcap_file.as_deref(),
                        &external_handoff_config,
                    )
                    .await
                } else {
                    ExternalHandoffStatus {
                        enabled: false,
                        attempted: false,
                        command: None,
                        args: vec![],
                        timeout_secs: external_handoff_config.timeout_secs,
                        require_success: external_handoff_config.require_success,
                        command_success: None,
                        trusted: false,
                        allowlist_enforced: external_handoff_config.enforce_allowlist,
                        allowlist_match: None,
                        allowed_commands: external_handoff_config.allowed_commands.clone(),
                        signature_enabled: external_handoff_config.signature_enabled,
                        signature_key_env: if external_handoff_config
                            .signature_key_env
                            .trim()
                            .is_empty()
                        {
                            None
                        } else {
                            Some(external_handoff_config.signature_key_env.clone())
                        },
                        signature: None,
                        signature_payload_sha256: None,
                        signature_file: None,
                        signature_error: None,
                        attestation: AttestationStatus {
                            enabled: external_handoff_config.attestation_enabled,
                            key_env: if external_handoff_config
                                .attestation_key_env
                                .trim()
                                .is_empty()
                            {
                                None
                            } else {
                                Some(external_handoff_config.attestation_key_env.clone())
                            },
                            prefix: if external_handoff_config.attestation_prefix.trim().is_empty()
                            {
                                None
                            } else {
                                Some(external_handoff_config.attestation_prefix.clone())
                            },
                            expected_receiver: if external_handoff_config
                                .attestation_expected_receiver
                                .trim()
                                .is_empty()
                            {
                                None
                            } else {
                                Some(
                                    external_handoff_config
                                        .attestation_expected_receiver
                                        .clone(),
                                )
                            },
                            challenge: None,
                            receiver_id: None,
                            matched: None,
                            error: None,
                        },
                        success: false,
                        timed_out: false,
                        exit_code: None,
                        error: None,
                        stdout_preview: None,
                        stderr_preview: None,
                        result_file: None,
                    }
                };

                if external_handoff.require_success
                    && external_handoff.attempted
                    && !external_handoff.success
                {
                    let reason = external_handoff
                        .error
                        .clone()
                        .unwrap_or_else(|| "external handoff failed".to_string());
                    sandbox_error = Some(match sandbox_error {
                        Some(prev) => format!("{prev}; external handoff: {reason}"),
                        None => format!("external handoff: {reason}"),
                    });
                }

                if let Err(e) = append_json_line(
                    &evidence_path_bg,
                    &serde_json::json!({
                        "ts": Utc::now().to_rfc3339(),
                        "type": "session_finished",
                        "session_id": runtime.session_id.clone(),
                        "services": task_stats,
                        "redirect_cleanup_verified": redirect_cleanup_verified,
                        "sandbox": sandbox_info,
                        "sandbox_error": sandbox_error,
                        "artifact_checks": artifact_checks,
                        "pcap_handoff": pcap_handoff,
                        "external_handoff": external_handoff,
                    }),
                )
                .await
                {
                    warn!(path = %evidence_path_bg.display(), "failed to append honeypot completion line: {e}");
                }

                let final_metadata = serde_json::json!({
                    "ts": Utc::now().to_rfc3339(),
                    "status": if sandbox_error.is_none() { "completed" } else { "completed_with_errors" },
                    "session_id": runtime.session_id.clone(),
                    "target_ip": runtime.target_ip.to_string(),
                    "strict_target_only": runtime.strict_target_only,
                    "duration_secs": runtime.duration_secs,
                    "max_connections": runtime.max_connections,
                    "max_payload_bytes": runtime.max_payload_bytes,
                    "isolation_profile": runtime.isolation_profile,
                    "service_stats": task_stats,
                    "sandbox": sandbox_info,
                    "sandbox_error": sandbox_error,
                    "redirect_rules": redirect_rules,
                    "redirect_cleanup_verified": redirect_cleanup_verified,
                    "artifact_checks": artifact_checks,
                    "pcap_handoff": pcap_handoff,
                    "external_handoff": external_handoff,
                    "forensics_file": evidence_path_bg,
                });
                if let Err(e) = write_json_file(&metadata_path_bg, &final_metadata).await {
                    warn!(path = %metadata_path_bg.display(), "failed to write honeypot final metadata: {e}");
                }
            });

            let warning_suffix = if bind_errors.is_empty() {
                String::new()
            } else {
                format!(" | warnings: {}", bind_errors.join("; "))
            };

            SkillResult {
                success: true,
                message: format!(
                    "Honeypot listeners started (session {session_id}, profile {isolation_profile}, pruned age={} size={}, cap={}MB, sandbox={}, containment={}/{}, pcap_handoff={}, external_handoff={}, external_attestation={}). metadata: {} evidence: {}{}",
                    cleanup_stats.removed_by_age,
                    cleanup_stats.removed_by_size,
                    ctx.honeypot.forensics_max_total_mb,
                    ctx.honeypot.sandbox_enabled,
                    ctx.honeypot.containment_mode,
                    ctx.honeypot.containment_jail_profile,
                    ctx.honeypot.pcap_handoff_enabled,
                    ctx.honeypot.external_handoff_enabled,
                    ctx.honeypot.external_handoff_attestation_enabled,
                    metadata_path.display(),
                    evidence_path.display(),
                    warning_suffix
                ),
            }
        })
    }
}

pub(crate) async fn run_sandbox_worker(spec_path: &Path, result_path: &Path) -> anyhow::Result<()> {
    let mut session_id = "unknown".to_string();
    let execution = async {
        let spec_body = tokio::fs::read_to_string(spec_path).await?;
        let spec: SandboxWorkerSpec = serde_json::from_str(&spec_body)?;
        session_id = spec.session_id.clone();
        let target_ip: IpAddr = spec.target_ip.parse()?;
        let mut endpoints = Vec::with_capacity(spec.endpoints.len());
        for endpoint in spec.endpoints {
            endpoints.push(endpoint.into_endpoint().map_err(|e| anyhow::anyhow!(e))?);
        }
        let runtime = SessionRuntime {
            session_id: spec.session_id.clone(),
            target_ip,
            strict_target_only: spec.strict_target_only,
            duration_secs: spec.duration_secs,
            max_connections: spec.max_connections,
            max_payload_bytes: spec.max_payload_bytes,
            transcript_preview_bytes: spec.transcript_preview_bytes,
            isolation_profile: spec.isolation_profile,
            evidence_path: spec.evidence_path,
            interaction: normalize_interaction(&spec.interaction),
            ssh_max_auth_attempts: spec.ssh_max_auth_attempts,
            http_max_requests: spec.http_max_requests,
            // Sandbox workers run in a subprocess - AI provider is not available.
            // llm_shell interaction falls back to RejectAll in the sandbox path.
            ai_provider: None,
        };

        let stats = run_listeners_from_endpoints(endpoints, runtime)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok::<Vec<ListenerStats>, anyhow::Error>(stats)
    }
    .await;

    let result = match execution {
        Ok(stats) => SandboxWorkerResult {
            session_id,
            success: true,
            error: None,
            service_stats: stats,
        },
        Err(e) => SandboxWorkerResult {
            session_id,
            success: false,
            error: Some(e.to_string()),
            service_stats: vec![],
        },
    };

    let value = serde_json::to_value(&result)?;
    write_json_file(result_path, &value).await?;
    if result.success {
        Ok(())
    } else {
        anyhow::bail!(
            "sandbox worker failed: {}",
            result.error.as_deref().unwrap_or("unknown error")
        )
    }
}

async fn run_bound_listeners(
    bound: Vec<(DecoyEndpoint, TcpListener)>,
    runtime: SessionRuntime,
) -> Vec<ListenerStats> {
    let mut task_stats = Vec::new();
    let mut tasks = Vec::new();
    for (endpoint, listener) in bound {
        let runtime = runtime.clone();
        tasks.push(tokio::spawn(async move {
            run_listener(endpoint, listener, runtime).await
        }));
    }

    for task in tasks {
        match task.await {
            Ok(stats) => task_stats.push(stats),
            Err(e) => warn!("honeypot listener task join error: {e}"),
        }
    }
    task_stats
}

async fn run_listeners_from_endpoints(
    endpoints: Vec<DecoyEndpoint>,
    runtime: SessionRuntime,
) -> Result<Vec<ListenerStats>, String> {
    let mut bound = Vec::new();
    let mut bind_errors = Vec::new();
    for endpoint in endpoints {
        let bind_target = format!("{}:{}", endpoint.bind_addr, endpoint.listen_port);
        match TcpListener::bind(&bind_target).await {
            Ok(listener) => {
                info!(
                    service = %endpoint.service,
                    bind = %bind_target,
                    "honeypot sandbox listener bound"
                );
                bound.push((endpoint, listener));
            }
            Err(e) => {
                warn!(
                    service = %endpoint.service,
                    bind = %bind_target,
                    "honeypot sandbox listener bind failed: {e}"
                );
                bind_errors.push(format!("{bind_target}: {e}"));
            }
        }
    }
    if bound.is_empty() {
        return Err(format!(
            "sandbox worker: failed to bind all decoys: {}",
            bind_errors.join("; ")
        ));
    }
    Ok(run_bound_listeners(bound, runtime).await)
}

async fn run_sandbox_session(
    runtime: SessionRuntime,
    endpoints: Vec<DecoyEndpoint>,
    session_dir: &Path,
    sandbox: &SandboxLaunchConfig,
) -> Result<SandboxRunOutcome, String> {
    let runner = if sandbox.runner_path.trim().is_empty() {
        std::env::current_exe()
            .map_err(|e| format!("sandbox runner: cannot resolve current executable: {e}"))?
    } else {
        PathBuf::from(&sandbox.runner_path)
    };
    let runner_label = runner.display().to_string();
    let requested_mode = normalize_containment_mode(&sandbox.containment_mode).to_string();
    let mut effective_mode = requested_mode.clone();
    let mut fallback_reason = None::<String>;
    let namespace_runner = if sandbox.containment_namespace_runner.trim().is_empty() {
        "unshare".to_string()
    } else {
        sandbox.containment_namespace_runner.trim().to_string()
    };
    let namespace_args = if sandbox.containment_namespace_args.is_empty() {
        vec![
            "--fork".to_string(),
            "--pid".to_string(),
            "--mount-proc".to_string(),
        ]
    } else {
        sandbox.containment_namespace_args.clone()
    };
    let jail_runner = if sandbox.containment_jail_runner.trim().is_empty() {
        "bwrap".to_string()
    } else {
        sandbox.containment_jail_runner.trim().to_string()
    };
    let requested_jail_profile =
        normalize_jail_profile(&sandbox.containment_jail_profile).to_string();
    let mut effective_jail_profile = requested_jail_profile.clone();
    let mut jail_args = sandbox.containment_jail_args.clone();
    if requested_mode == "jail" && requested_jail_profile == "strict" {
        if is_bwrap_runner(&jail_runner) {
            append_unique_args(&mut jail_args, &strict_jail_profile_args());
        } else if sandbox.containment_require_success {
            return Err(format!(
                "sandbox containment strict jail profile requires bwrap-compatible runner, got '{}'",
                jail_runner
            ));
        } else {
            effective_jail_profile = "standard".to_string();
            push_fallback_reason(
                &mut fallback_reason,
                format!(
                    "strict jail profile requested but runner '{}' is not bwrap-compatible; using standard profile",
                    jail_runner
                ),
            );
        }
    }
    let spec_path = session_dir.join(format!(
        "listener-session-{}.sandbox-spec.json",
        runtime.session_id
    ));
    let result_path = session_dir.join(format!(
        "listener-session-{}.sandbox-result.json",
        runtime.session_id
    ));
    let spec = SandboxWorkerSpec {
        session_id: runtime.session_id.clone(),
        target_ip: runtime.target_ip.to_string(),
        strict_target_only: runtime.strict_target_only,
        duration_secs: runtime.duration_secs,
        max_connections: runtime.max_connections,
        max_payload_bytes: runtime.max_payload_bytes,
        transcript_preview_bytes: runtime.transcript_preview_bytes,
        isolation_profile: runtime.isolation_profile.clone(),
        evidence_path: runtime.evidence_path.clone(),
        endpoints: endpoints.iter().map(SandboxEndpointSpec::from).collect(),
        interaction: runtime.interaction.clone(),
        ssh_max_auth_attempts: runtime.ssh_max_auth_attempts,
        http_max_requests: runtime.http_max_requests,
    };
    let spec_value = serde_json::to_value(spec)
        .map_err(|e| format!("sandbox runner: spec serialize failed: {e}"))?;
    write_json_file(&spec_path, &spec_value)
        .await
        .map_err(|e| {
            format!(
                "sandbox runner: failed writing spec {}: {e}",
                spec_path.display()
            )
        })?;

    let mut cmd = if requested_mode == "jail" {
        if binary_exists(&jail_runner) {
            build_jail_command(&jail_runner, &jail_args, &runner)
        } else if sandbox.containment_allow_namespace_fallback && binary_exists(&namespace_runner) {
            effective_mode = "namespace".to_string();
            push_fallback_reason(
                &mut fallback_reason,
                format!(
                    "jail runner '{}' not found; falling back to namespace runner '{}'",
                    jail_runner, namespace_runner
                ),
            );
            build_namespace_command(&namespace_runner, &namespace_args, &runner)
        } else if sandbox.containment_require_success {
            let _ = tokio::fs::remove_file(&spec_path).await;
            return Err(format!(
                "sandbox containment requested jail mode but runner '{}' was not found",
                jail_runner
            ));
        } else {
            effective_mode = "process".to_string();
            push_fallback_reason(
                &mut fallback_reason,
                format!(
                    "jail runner '{}' not found; falling back to process mode",
                    jail_runner
                ),
            );
            Command::new(&runner)
        }
    } else if requested_mode == "namespace" {
        if binary_exists(&namespace_runner) {
            build_namespace_command(&namespace_runner, &namespace_args, &runner)
        } else if sandbox.containment_require_success {
            let _ = tokio::fs::remove_file(&spec_path).await;
            return Err(format!(
                "sandbox containment requested namespace mode but runner '{}' was not found",
                namespace_runner
            ));
        } else {
            effective_mode = "process".to_string();
            push_fallback_reason(
                &mut fallback_reason,
                format!(
                    "namespace runner '{}' not found; falling back to process mode",
                    namespace_runner
                ),
            );
            Command::new(&runner)
        }
    } else {
        Command::new(&runner)
    };
    cmd.arg("--honeypot-sandbox-spec")
        .arg(&spec_path)
        .arg("--honeypot-sandbox-result")
        .arg(&result_path);
    if effective_mode == "process" {
        cmd.arg("--honeypot-sandbox-runner");
    }

    if sandbox.clear_env {
        cmd.env_clear();
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("sandbox runner: failed to spawn {}: {e}", runner.display()))?;

    let wait_timeout =
        Duration::from_secs(runtime.duration_secs.saturating_add(SANDBOX_GRACE_SECS));
    let waited = tokio::time::timeout(wait_timeout, child.wait()).await;
    let status = match waited {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            let _ = child.kill().await;
            return Err(format!("sandbox runner: wait failed: {e}"));
        }
        Err(_) => {
            let _ = child.kill().await;
            return Err(format!(
                "sandbox runner: timed out after {}s",
                runtime.duration_secs.saturating_add(SANDBOX_GRACE_SECS)
            ));
        }
    };

    let result_body = tokio::fs::read_to_string(&result_path).await.map_err(|e| {
        format!(
            "sandbox runner: missing result {}: {e}",
            result_path.display()
        )
    })?;
    let result: SandboxWorkerResult = serde_json::from_str(&result_body).map_err(|e| {
        format!(
            "sandbox runner: invalid result JSON {}: {e}",
            result_path.display()
        )
    })?;

    if !status.success() {
        let _ = tokio::fs::remove_file(&spec_path).await;
        let _ = tokio::fs::remove_file(&result_path).await;
        return Err(format!(
            "sandbox runner exited with status {} ({})",
            status,
            result
                .error
                .unwrap_or_else(|| "no error details from worker".to_string())
        ));
    }
    if !result.success {
        let _ = tokio::fs::remove_file(&spec_path).await;
        let _ = tokio::fs::remove_file(&result_path).await;
        return Err(result
            .error
            .unwrap_or_else(|| "sandbox worker reported failure".to_string()));
    }

    Ok(SandboxRunOutcome {
        stats: result.service_stats,
        spec_path,
        result_path,
        runner: runner_label,
        containment: ContainmentStatus {
            requested_mode: requested_mode.clone(),
            effective_mode: effective_mode.clone(),
            require_success: sandbox.containment_require_success,
            namespace_runner,
            namespace_args,
            jail_runner,
            jail_args,
            jail_profile_requested: requested_jail_profile.clone(),
            jail_profile_effective: effective_jail_profile.clone(),
            allow_namespace_fallback: sandbox.containment_allow_namespace_fallback,
            check_passed: requested_mode == effective_mode
                && requested_jail_profile == effective_jail_profile,
            fallback_reason,
        },
    })
}

async fn run_pcap_handoff(
    session_dir: &Path,
    session_id: &str,
    target_ip: IpAddr,
    timeout_secs: u64,
    max_packets: u64,
) -> PcapHandoffStatus {
    if timeout_secs == 0 || max_packets == 0 {
        return PcapHandoffStatus {
            enabled: true,
            attempted: false,
            timeout_secs,
            max_packets,
            command: None,
            pcap_file: None,
            success: false,
            timed_out: false,
            error: Some("pcap handoff skipped: timeout_secs or max_packets is zero".to_string()),
        };
    }

    let pcap_path = session_dir.join(format!("listener-session-{session_id}.pcap"));
    let cmd = format!(
        "sudo -n timeout {timeout_secs}s tcpdump -nn -i any host {target_ip} -c {max_packets} -w {}",
        pcap_path.display()
    );
    let mut status = PcapHandoffStatus {
        enabled: true,
        attempted: true,
        timeout_secs,
        max_packets,
        command: Some(cmd),
        pcap_file: Some(pcap_path.display().to_string()),
        success: false,
        timed_out: false,
        error: None,
    };
    let args = vec![
        "timeout".to_string(),
        format!("{timeout_secs}s"),
        "tcpdump".to_string(),
        "-nn".to_string(),
        "-i".to_string(),
        "any".to_string(),
        "host".to_string(),
        target_ip.to_string(),
        "-c".to_string(),
        max_packets.to_string(),
        "-w".to_string(),
        pcap_path.display().to_string(),
    ];
    match Command::new("sudo").arg("-n").args(&args).output().await {
        Ok(out) => {
            let code = out.status.code().unwrap_or_default();
            if out.status.success() || code == 124 {
                status.success = true;
                status.timed_out = code == 124;
            } else {
                status.error = Some(String::from_utf8_lossy(&out.stderr).trim().to_string());
            }
        }
        Err(e) => {
            status.error = Some(e.to_string());
        }
    }
    status
}

async fn collect_artifact_lifecycle(
    metadata_path: &Path,
    evidence_path: &Path,
    pcap_path: Option<&str>,
) -> ArtifactLifecycleStatus {
    let (metadata_exists, metadata_bytes) = file_exists_with_size(metadata_path).await;
    let (evidence_exists, evidence_bytes) = file_exists_with_size(evidence_path).await;
    let (pcap_exists, pcap_bytes) = match pcap_path {
        Some(path) if !path.is_empty() => {
            let p = PathBuf::from(path);
            let (exists, bytes) = file_exists_with_size(&p).await;
            (Some(exists), Some(bytes))
        }
        _ => (None, None),
    };

    ArtifactLifecycleStatus {
        metadata_exists,
        metadata_bytes,
        evidence_exists,
        evidence_bytes,
        pcap_exists,
        pcap_bytes,
    }
}

async fn file_exists_with_size(path: &Path) -> (bool, u64) {
    match tokio::fs::metadata(path).await {
        Ok(meta) => (true, meta.len()),
        Err(_) => (false, 0),
    }
}

async fn run_external_handoff(
    session_dir: &Path,
    runtime: &SessionRuntime,
    metadata_path: &Path,
    evidence_path: &Path,
    pcap_path: Option<&str>,
    config: &ExternalHandoffConfig,
) -> ExternalHandoffStatus {
    let result_path = session_dir.join(format!(
        "listener-session-{}.external-handoff.json",
        runtime.session_id
    ));
    let attestation_key_env_name = normalize_attestation_key_env(&config.attestation_key_env);
    let attestation_prefix_value = normalize_attestation_prefix(&config.attestation_prefix);
    let attestation_expected_receiver_value =
        if config.attestation_expected_receiver.trim().is_empty() {
            None
        } else {
            Some(config.attestation_expected_receiver.trim().to_string())
        };
    let mut status = ExternalHandoffStatus {
        enabled: true,
        attempted: false,
        command: None,
        args: vec![],
        timeout_secs: config.timeout_secs,
        require_success: config.require_success,
        command_success: None,
        trusted: false,
        allowlist_enforced: config.enforce_allowlist,
        allowlist_match: None,
        allowed_commands: config.allowed_commands.clone(),
        signature_enabled: config.signature_enabled,
        signature_key_env: if config.signature_key_env.trim().is_empty() {
            None
        } else {
            Some(config.signature_key_env.trim().to_string())
        },
        signature: None,
        signature_payload_sha256: None,
        signature_file: None,
        signature_error: None,
        attestation: AttestationStatus {
            enabled: config.attestation_enabled,
            key_env: if config.attestation_enabled {
                Some(attestation_key_env_name.clone())
            } else {
                None
            },
            prefix: if config.attestation_enabled {
                Some(attestation_prefix_value.clone())
            } else {
                None
            },
            expected_receiver: attestation_expected_receiver_value.clone(),
            challenge: None,
            receiver_id: None,
            matched: None,
            error: None,
        },
        success: false,
        timed_out: false,
        exit_code: None,
        error: None,
        stdout_preview: None,
        stderr_preview: None,
        result_file: Some(result_path.display().to_string()),
    };

    if config.timeout_secs == 0 {
        status.error = Some("external handoff skipped: timeout_secs is zero".to_string());
        let _ = write_json_file(
            &result_path,
            &serde_json::to_value(&status).unwrap_or_default(),
        )
        .await;
        return status;
    }
    if config.command.trim().is_empty() {
        status.error = Some("external handoff enabled but command is empty".to_string());
        let _ = write_json_file(
            &result_path,
            &serde_json::to_value(&status).unwrap_or_default(),
        )
        .await;
        return status;
    }
    status.attempted = true;
    status.command = Some(config.command.clone());

    if config.enforce_allowlist {
        let matched = is_command_allowed(&config.command, &config.allowed_commands);
        status.allowlist_match = Some(matched);
        if !matched {
            status.error = Some(format!(
                "external handoff blocked: command '{}' is not in allowlist",
                config.command
            ));
            let _ = write_json_file(
                &result_path,
                &serde_json::to_value(&status).unwrap_or_default(),
            )
            .await;
            return status;
        }
    }

    let pcap_path_value = pcap_path.unwrap_or("").to_string();
    status.args = config.args.clone();

    let mut attestation_key = None::<String>;
    if config.attestation_enabled {
        match std::env::var(&attestation_key_env_name) {
            Ok(value) if !value.trim().is_empty() => {
                attestation_key = Some(value);
            }
            Ok(_) => {
                status.attestation.error = Some(format!(
                    "attestation key env var '{}' is empty",
                    attestation_key_env_name
                ));
                status.error = Some("external handoff attestation key is empty".to_string());
                let _ = write_json_file(
                    &result_path,
                    &serde_json::to_value(&status).unwrap_or_default(),
                )
                .await;
                return status;
            }
            Err(_) => {
                status.attestation.error = Some(format!(
                    "missing attestation key in env var '{}'",
                    attestation_key_env_name
                ));
                status.error = Some("external handoff attestation key is missing".to_string());
                let _ = write_json_file(
                    &result_path,
                    &serde_json::to_value(&status).unwrap_or_default(),
                )
                .await;
                return status;
            }
        }
        status.attestation.challenge = Some(build_attestation_challenge(runtime));
    }

    let mut cmd = Command::new(&config.command);
    cmd.args(&config.args);
    if config.clear_env {
        cmd.env_clear();
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    }
    cmd.env("INNERWARDEN_SESSION_ID", &runtime.session_id);
    cmd.env("INNERWARDEN_TARGET_IP", runtime.target_ip.to_string());
    cmd.env(
        "INNERWARDEN_METADATA_PATH",
        metadata_path.display().to_string(),
    );
    cmd.env(
        "INNERWARDEN_EVIDENCE_PATH",
        evidence_path.display().to_string(),
    );
    cmd.env("INNERWARDEN_PCAP_PATH", &pcap_path_value);
    if config.attestation_enabled {
        if let Some(challenge) = status.attestation.challenge.as_deref() {
            cmd.env("INNERWARDEN_HANDOFF_ATTEST_CHALLENGE", challenge);
            cmd.env(
                "INNERWARDEN_HANDOFF_ATTEST_PREFIX",
                &attestation_prefix_value,
            );
        }
        if let Some(key) = attestation_key.as_deref() {
            cmd.env(&attestation_key_env_name, key);
        }
    }

    let mut stdout_raw = String::new();
    let mut stderr_raw = String::new();
    let waited = tokio::time::timeout(Duration::from_secs(config.timeout_secs), cmd.output()).await;
    match waited {
        Ok(Ok(out)) => {
            status.exit_code = out.status.code();
            status.command_success = Some(out.status.success());
            stdout_raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
            stderr_raw = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if !stdout_raw.is_empty() {
                status.stdout_preview = Some(truncate_preview(&stdout_raw, 512));
            }
            if !stderr_raw.is_empty() {
                status.stderr_preview = Some(truncate_preview(&stderr_raw, 512));
            }
            if !out.status.success() {
                status.error = Some(format!(
                    "external handoff command exited with status {}",
                    out.status
                ));
            }
        }
        Ok(Err(e)) => {
            status.error = Some(e.to_string());
            status.command_success = Some(false);
        }
        Err(_) => {
            status.timed_out = true;
            status.command_success = Some(false);
            status.error = Some(format!(
                "external handoff timed out after {}s",
                config.timeout_secs
            ));
        }
    }

    let pcap_path_value = pcap_path.unwrap_or("").to_string();
    let allowlist_ok = !config.enforce_allowlist || status.allowlist_match.unwrap_or(false);
    let mut signature_ok = !config.signature_enabled;
    if config.signature_enabled {
        match sign_external_handoff(
            session_dir,
            runtime,
            metadata_path,
            evidence_path,
            &pcap_path_value,
            &status,
            &config.signature_key_env,
        )
        .await
        {
            Ok((signature, payload_sha256, signature_file)) => {
                status.signature = Some(signature);
                status.signature_payload_sha256 = Some(payload_sha256);
                status.signature_file = Some(signature_file);
                signature_ok = true;
            }
            Err(e) => {
                status.signature_error = Some(e.clone());
                signature_ok = false;
                if status.error.is_none() {
                    status.error = Some(format!("external handoff signature failed: {e}"));
                }
            }
        }
    }
    let mut attestation_ok = !config.attestation_enabled;
    if config.attestation_enabled {
        let challenge = status.attestation.challenge.clone().unwrap_or_default();
        let key = attestation_key.unwrap_or_default();
        match verify_attestation_output(
            &stdout_raw,
            &stderr_raw,
            &attestation_prefix_value,
            attestation_expected_receiver_value.as_deref(),
            &challenge,
            &key,
            runtime,
        ) {
            Ok(parsed) => {
                status.attestation.receiver_id = Some(parsed.receiver_id);
                status.attestation.matched = Some(true);
                attestation_ok = true;
            }
            Err(e) => {
                status.attestation.matched = Some(false);
                status.attestation.error = Some(e.clone());
                attestation_ok = false;
                if status.error.is_none() {
                    status.error = Some(format!("external handoff attestation failed: {e}"));
                }
            }
        }
    }
    status.trusted = allowlist_ok && signature_ok && attestation_ok;
    status.success = status.command_success.unwrap_or(false) && status.trusted;
    if !status.success && status.error.is_none() {
        status.error = Some("external handoff failed trust checks".to_string());
    }

    let _ = write_json_file(
        &result_path,
        &serde_json::to_value(&status).unwrap_or_default(),
    )
    .await;
    status
}

async fn sign_external_handoff(
    session_dir: &Path,
    runtime: &SessionRuntime,
    metadata_path: &Path,
    evidence_path: &Path,
    pcap_path: &str,
    status: &ExternalHandoffStatus,
    signature_key_env: &str,
) -> Result<(String, String, String), String> {
    let key_env = if signature_key_env.trim().is_empty() {
        "INNERWARDEN_HANDOFF_SIGNING_KEY"
    } else {
        signature_key_env.trim()
    };
    let signing_key = std::env::var(key_env)
        .map_err(|_| format!("missing signing key in env var '{}'", key_env))?;
    if signing_key.is_empty() {
        return Err(format!("signing key env var '{}' is empty", key_env));
    }

    let payload = serde_json::json!({
        "signed_at": Utc::now().to_rfc3339(),
        "session_id": runtime.session_id,
        "target_ip": runtime.target_ip.to_string(),
        "command": status.command,
        "args": status.args,
        "command_success": status.command_success,
        "exit_code": status.exit_code,
        "timed_out": status.timed_out,
        "error": status.error,
        "metadata_path": metadata_path.display().to_string(),
        "evidence_path": evidence_path.display().to_string(),
        "pcap_path": pcap_path,
    });
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| format!("failed to serialize payload: {e}"))?;
    let payload_sha256 = sha256_hex(&payload_bytes);
    let signature = hmac_sha256_hex(signing_key.as_bytes(), &payload_bytes)
        .map_err(|e| format!("failed to initialize HMAC signer: {e}"))?;

    let signature_path = session_dir.join(format!(
        "listener-session-{}.external-handoff.sig",
        runtime.session_id
    ));
    let signature_doc = serde_json::json!({
        "algorithm": "HMAC-SHA256",
        "key_env": key_env,
        "payload_sha256": payload_sha256,
        "signature_hmac_sha256": signature,
        "payload": payload,
    });
    write_json_file(&signature_path, &signature_doc)
        .await
        .map_err(|e| {
            format!(
                "failed to write signature file {}: {e}",
                signature_path.display()
            )
        })?;

    Ok((
        signature,
        payload_sha256,
        signature_path.display().to_string(),
    ))
}

fn normalize_attestation_key_env(value: &str) -> String {
    if value.trim().is_empty() {
        "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string()
    } else {
        value.trim().to_string()
    }
}

fn normalize_attestation_prefix(value: &str) -> String {
    if value.trim().is_empty() {
        "IW_ATTEST".to_string()
    } else {
        value.trim().to_string()
    }
}

fn build_attestation_challenge(runtime: &SessionRuntime) -> String {
    let seed = format!(
        "{}:{}:{}:{}",
        runtime.session_id,
        runtime.target_ip,
        Utc::now().to_rfc3339(),
        std::process::id()
    );
    sha256_hex(seed.as_bytes())
}

fn parse_attestation_line(line: &str, prefix: &str) -> Option<ParsedAttestationLine> {
    let needle = format!("{prefix}:");
    let body = line.trim().strip_prefix(&needle)?;
    let mut parts = body.splitn(3, ':');
    let receiver_id = parts.next()?.trim();
    let challenge = parts.next()?.trim();
    let hmac_hex = parts.next()?.trim();
    if receiver_id.is_empty() || challenge.is_empty() || hmac_hex.is_empty() {
        return None;
    }
    Some(ParsedAttestationLine {
        receiver_id: receiver_id.to_string(),
        challenge: challenge.to_string(),
        hmac_hex: hmac_hex.to_string(),
    })
}

fn verify_attestation_output(
    stdout: &str,
    stderr: &str,
    prefix: &str,
    expected_receiver: Option<&str>,
    challenge: &str,
    key: &str,
    runtime: &SessionRuntime,
) -> Result<ParsedAttestationLine, String> {
    let parsed = stdout
        .lines()
        .find_map(|line| parse_attestation_line(line, prefix))
        .or_else(|| {
            stderr
                .lines()
                .find_map(|line| parse_attestation_line(line, prefix))
        })
        .ok_or_else(|| format!("missing attestation line (expected prefix '{prefix}:')"))?;

    if parsed.challenge != challenge {
        return Err("attestation challenge mismatch".to_string());
    }
    if let Some(expected) = expected_receiver {
        if !expected.trim().is_empty() && parsed.receiver_id != expected.trim() {
            return Err(format!(
                "attestation receiver mismatch: expected '{}' got '{}'",
                expected.trim(),
                parsed.receiver_id
            ));
        }
    }

    let payload = format!(
        "{}:{}:{}:{}",
        parsed.receiver_id, challenge, runtime.session_id, runtime.target_ip
    );
    let expected_hmac = hmac_sha256_hex(key.as_bytes(), payload.as_bytes())
        .map_err(|e| format!("attestation HMAC init failed: {e}"))?;
    if expected_hmac != parsed.hmac_hex {
        return Err("attestation HMAC mismatch".to_string());
    }
    Ok(parsed)
}

fn hmac_sha256_hex(key: &[u8], payload: &[u8]) -> Result<String, hmac::digest::InvalidLength> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(payload);
    Ok(bytes_to_hex(&mac.finalize().into_bytes()))
}

fn is_command_allowed(command: &str, allowed_commands: &[String]) -> bool {
    let command_trim = command.trim();
    if command_trim.is_empty() {
        return false;
    }
    // Canonicalize to resolve symlinks and path traversal
    let canonical = match std::fs::canonicalize(command_trim) {
        Ok(p) => p,
        Err(_) => return false, // command doesn't exist or can't be resolved
    };
    let command_file_name = canonical.file_name().and_then(|s| s.to_str()).unwrap_or("");
    allowed_commands.iter().any(|allowed| {
        let allowed_trim = allowed.trim();
        if allowed_trim.is_empty() {
            return false;
        }
        if allowed_trim.contains('/') {
            // Full path: canonicalize and compare
            std::fs::canonicalize(allowed_trim)
                .map(|p| p == canonical)
                .unwrap_or(false)
        } else {
            // Basename only: match against canonical basename
            allowed_trim == command_file_name
        }
    })
}

async fn run_listener(
    endpoint: DecoyEndpoint,
    listener: TcpListener,
    runtime: SessionRuntime,
) -> ListenerStats {
    info!(
        service = %endpoint.service,
        bind_addr = %endpoint.bind_addr,
        port = endpoint.listen_port,
        target_ip = %runtime.target_ip,
        strict_target_only = runtime.strict_target_only,
        interaction = %runtime.interaction,
        "honeypot listener started"
    );

    let mut stats = ListenerStats {
        service: endpoint.service.clone(),
        bind_addr: endpoint.bind_addr.clone(),
        listen_port: endpoint.listen_port,
        accepted: 0,
        rejected: 0,
        payload_bytes_captured: 0,
        read_timeouts: 0,
    };

    let is_medium = runtime.interaction == "medium";
    let is_llm_shell = runtime.interaction == "llm_shell";
    let needs_russh = is_medium || is_llm_shell;

    // Build SSH config once for this listener (ephemeral key per session).
    let ssh_config: Option<Arc<russh::server::Config>> = if needs_russh && endpoint.service == "ssh"
    {
        Some(ssh_interact::build_ssh_config(
            runtime.ssh_max_auth_attempts,
        ))
    } else {
        None
    };

    // Per-connection timeout: 60s max (protocol interaction is bounded).
    let conn_timeout = Duration::from_secs(60);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(runtime.duration_secs);
    while tokio::time::Instant::now() < deadline {
        if (stats.accepted + stats.rejected) >= runtime.max_connections as u64 {
            break;
        }

        let now = tokio::time::Instant::now();
        let accept_timeout = deadline.duration_since(now);
        let accepted = tokio::time::timeout(accept_timeout, listener.accept()).await;

        let (mut socket, peer) = match accepted {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                warn!(service = %endpoint.service, "honeypot listener accept error: {e}");
                break;
            }
            Err(_) => break,
        };

        let is_target = peer.ip() == runtime.target_ip;
        let allowed = !runtime.strict_target_only || is_target;

        if !allowed {
            stats.rejected += 1;
            let entry = serde_json::json!({
                "ts": Utc::now().to_rfc3339(),
                "type": "connection_rejected",
                "session_id": runtime.session_id.clone(),
                "service": endpoint.service.clone(),
                "peer_ip": peer.ip().to_string(),
                "target_ip": runtime.target_ip.to_string(),
                "target_match": false,
                "interaction": runtime.interaction.clone(),
                "isolation_profile": runtime.isolation_profile.clone(),
            });
            if let Err(e) = append_json_line(&runtime.evidence_path, &entry).await {
                warn!(path = %runtime.evidence_path.display(), "failed to append rejection evidence: {e}");
            }
            continue;
        }

        stats.accepted += 1;

        if needs_russh {
            // Medium / LLM-shell interaction: full protocol emulation.
            let entry = match endpoint.service.as_str() {
                "ssh" => {
                    let cfg = ssh_config
                        .clone()
                        .expect("SSH config must be set for medium/llm_shell mode");
                    let mode = if is_llm_shell {
                        if let Some(ai) = runtime.ai_provider.clone() {
                            ssh_interact::SshInteractionMode::LlmShell {
                                ai,
                                hostname: "srv-prod-01".to_string(),
                            }
                        } else {
                            // No AI provider available - fall back to RejectAll.
                            ssh_interact::SshInteractionMode::RejectAll
                        }
                    } else {
                        ssh_interact::SshInteractionMode::RejectAll
                    };
                    let evidence =
                        ssh_interact::handle_connection(socket, cfg, conn_timeout, mode).await;
                    serde_json::json!({
                        "ts": Utc::now().to_rfc3339(),
                        "type": "ssh_connection",
                        "session_id": runtime.session_id.clone(),
                        "service": "ssh",
                        "bind_addr": endpoint.bind_addr.clone(),
                        "listen_port": endpoint.listen_port,
                        "peer_ip": peer.ip().to_string(),
                        "target_ip": runtime.target_ip.to_string(),
                        "target_match": is_target,
                        "accepted": true,
                        "interaction": runtime.interaction.clone(),
                        "isolation_profile": runtime.isolation_profile.clone(),
                        "auth_attempts": evidence.auth_attempts,
                        "auth_attempts_count": evidence.auth_attempts.len(),
                        "shell_commands": evidence.shell_commands,
                        "shell_commands_count": evidence.shell_commands.len(),
                    })
                }
                "http" => {
                    let evidence = http_interact::handle_connection(
                        &mut socket,
                        runtime.http_max_requests,
                        runtime.max_payload_bytes,
                        runtime.transcript_preview_bytes,
                        conn_timeout,
                    )
                    .await;
                    serde_json::json!({
                        "ts": Utc::now().to_rfc3339(),
                        "type": "http_connection",
                        "session_id": runtime.session_id.clone(),
                        "service": "http",
                        "bind_addr": endpoint.bind_addr.clone(),
                        "listen_port": endpoint.listen_port,
                        "peer_ip": peer.ip().to_string(),
                        "target_ip": runtime.target_ip.to_string(),
                        "target_match": is_target,
                        "accepted": true,
                        "interaction": runtime.interaction.clone(),
                        "isolation_profile": runtime.isolation_profile.clone(),
                        "http_requests": evidence.requests,
                        "http_requests_count": evidence.requests.len(),
                    })
                }
                other => {
                    // Unsupported service in this interaction mode: fallback to banner.
                    warn!(
                        service = other,
                        interaction = %runtime.interaction,
                        "interaction mode not supported for service, falling back to banner"
                    );
                    let payload = capture_payload(
                        &mut socket,
                        runtime.max_payload_bytes,
                        runtime.transcript_preview_bytes,
                    )
                    .await;
                    if payload.read_timed_out {
                        stats.read_timeouts += 1;
                    }
                    stats.payload_bytes_captured += payload.bytes_captured as u64;
                    let _ = socket.write_all(endpoint.banner).await;
                    serde_json::json!({
                        "ts": Utc::now().to_rfc3339(),
                        "type": "connection",
                        "session_id": runtime.session_id.clone(),
                        "service": other,
                        "bind_addr": endpoint.bind_addr.clone(),
                        "listen_port": endpoint.listen_port,
                        "peer_ip": peer.ip().to_string(),
                        "target_ip": runtime.target_ip.to_string(),
                        "target_match": is_target,
                        "accepted": true,
                        "interaction": "banner",
                        "bytes_captured": payload.bytes_captured,
                        "payload_hex": payload.payload_hex,
                        "transcript_preview": payload.transcript_preview,
                        "protocol_guess": payload.protocol_guess,
                        "read_timed_out": payload.read_timed_out,
                        "isolation_profile": runtime.isolation_profile.clone(),
                    })
                }
            };
            if let Err(e) = append_json_line(&runtime.evidence_path, &entry).await {
                warn!(path = %runtime.evidence_path.display(), "failed to append connection evidence: {e}");
            }
        } else {
            // Banner mode (default): read one payload, send static banner.
            let payload = capture_payload(
                &mut socket,
                runtime.max_payload_bytes,
                runtime.transcript_preview_bytes,
            )
            .await;

            if payload.read_timed_out {
                stats.read_timeouts += 1;
            }
            stats.payload_bytes_captured += payload.bytes_captured as u64;
            let _ = socket.write_all(endpoint.banner).await;

            let entry = serde_json::json!({
                "ts": Utc::now().to_rfc3339(),
                "type": "connection",
                "session_id": runtime.session_id.clone(),
                "service": endpoint.service.clone(),
                "bind_addr": endpoint.bind_addr.clone(),
                "listen_port": endpoint.listen_port,
                "peer": peer.to_string(),
                "peer_ip": peer.ip().to_string(),
                "target_ip": runtime.target_ip.to_string(),
                "target_match": is_target,
                "accepted": allowed,
                "interaction": "banner",
                "bytes_captured": payload.bytes_captured,
                "payload_hex": payload.payload_hex,
                "transcript_preview": payload.transcript_preview,
                "protocol_guess": payload.protocol_guess,
                "read_timed_out": payload.read_timed_out,
                "isolation_profile": runtime.isolation_profile.clone(),
            });
            if let Err(e) = append_json_line(&runtime.evidence_path, &entry).await {
                warn!(path = %runtime.evidence_path.display(), "failed to append honeypot evidence line: {e}");
            }
        }
    }

    info!(
        service = %endpoint.service,
        accepted = stats.accepted,
        rejected = stats.rejected,
        interaction = %runtime.interaction,
        "honeypot listener finished"
    );
    stats
}

async fn capture_payload(
    socket: &mut tokio::net::TcpStream,
    max_bytes: usize,
    transcript_preview_bytes: usize,
) -> PayloadCapture {
    if max_bytes == 0 {
        return PayloadCapture {
            bytes_captured: 0,
            payload_hex: String::new(),
            transcript_preview: String::new(),
            protocol_guess: "none".to_string(),
            read_timed_out: false,
        };
    }

    let read_cap = max_bytes.min(4096);
    let mut buf = vec![0u8; read_cap];
    match tokio::time::timeout(
        Duration::from_millis(PAYLOAD_READ_TIMEOUT_MS),
        socket.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) => {
            let n = n.min(read_cap);
            let payload = &buf[..n];
            PayloadCapture {
                bytes_captured: n,
                payload_hex: bytes_to_hex(payload),
                transcript_preview: sanitize_transcript(payload, transcript_preview_bytes),
                protocol_guess: guess_protocol(payload),
                read_timed_out: false,
            }
        }
        Ok(Err(_)) => PayloadCapture {
            bytes_captured: 0,
            payload_hex: String::new(),
            transcript_preview: String::new(),
            protocol_guess: "unknown".to_string(),
            read_timed_out: false,
        },
        Err(_) => PayloadCapture {
            bytes_captured: 0,
            payload_hex: String::new(),
            transcript_preview: String::new(),
            protocol_guess: "unknown".to_string(),
            read_timed_out: true,
        },
    }
}

fn build_endpoints(
    runtime: &crate::skills::HoneypotRuntimeConfig,
    bind_addr: &str,
) -> Result<Vec<DecoyEndpoint>, String> {
    let mut services = runtime
        .services
        .iter()
        .map(|svc| svc.trim().to_ascii_lowercase())
        .filter(|svc| !svc.is_empty())
        .collect::<Vec<_>>();
    if services.is_empty() {
        services.push("ssh".to_string());
    }

    let mut dedup = HashSet::new();
    services.retain(|svc| dedup.insert(svc.clone()));

    let mut endpoints = Vec::new();
    for service in services {
        match service.as_str() {
            "ssh" => endpoints.push(DecoyEndpoint {
                service,
                bind_addr: bind_addr.to_string(),
                listen_port: runtime.port,
                redirect_from_port: 22,
                banner: banner_for_service("ssh")?,
            }),
            "http" => endpoints.push(DecoyEndpoint {
                service,
                bind_addr: bind_addr.to_string(),
                listen_port: runtime.http_port,
                redirect_from_port: 80,
                banner: banner_for_service("http")?,
            }),
            other => {
                return Err(format!(
                    "unsupported service '{other}' (supported: ssh, http)"
                ));
            }
        }
    }

    let mut ports = HashSet::new();
    for endpoint in &endpoints {
        if endpoint.listen_port == 0 {
            return Err(format!("service '{}' has invalid port 0", endpoint.service));
        }
        if !ports.insert(endpoint.listen_port) {
            return Err(format!(
                "duplicate listener port {} in honeypot services",
                endpoint.listen_port
            ));
        }
    }

    Ok(endpoints)
}

fn normalize_containment_mode(mode: &str) -> &'static str {
    if mode.eq_ignore_ascii_case("namespace") {
        "namespace"
    } else if mode.eq_ignore_ascii_case("jail") {
        "jail"
    } else {
        "process"
    }
}

fn normalize_jail_profile(profile: &str) -> &'static str {
    if profile.eq_ignore_ascii_case("strict") {
        "strict"
    } else {
        "standard"
    }
}

fn strict_jail_profile_args() -> Vec<String> {
    vec![
        "--die-with-parent".to_string(),
        "--new-session".to_string(),
        "--unshare-user".to_string(),
        "--unshare-pid".to_string(),
        "--unshare-uts".to_string(),
        "--unshare-ipc".to_string(),
    ]
}

fn is_bwrap_runner(runner: &str) -> bool {
    let runner_name = Path::new(runner)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    runner_name == "bwrap" || runner_name == "bubblewrap"
}

fn append_unique_args(target: &mut Vec<String>, extras: &[String]) {
    for arg in extras {
        if !target.iter().any(|existing| existing == arg) {
            target.push(arg.clone());
        }
    }
}

fn push_fallback_reason(fallback_reason: &mut Option<String>, new_reason: String) {
    match fallback_reason {
        Some(prev) => {
            prev.push_str("; ");
            prev.push_str(&new_reason);
        }
        None => *fallback_reason = Some(new_reason),
    }
}

fn binary_exists(bin: &str) -> bool {
    let path = Path::new(bin);
    if path.is_absolute() {
        return path.exists();
    }
    std::env::var("PATH")
        .ok()
        .map(|p| {
            p.split(':')
                .filter(|part| !part.is_empty())
                .any(|part| Path::new(part).join(bin).exists())
        })
        .unwrap_or(false)
}

async fn cleanup_old_forensics(
    session_dir: &Path,
    keep_days: usize,
    max_total_mb: usize,
) -> std::io::Result<ForensicsCleanupStats> {
    let cutoff = Utc::now().date_naive() - chrono::Duration::days(keep_days as i64);
    let candidates = list_forensics_files(session_dir).await?;
    let total_before_bytes = candidates.iter().map(|f| f.size).sum::<u64>();

    let mut removed_by_age = 0usize;
    let mut remaining = Vec::new();
    for file in candidates {
        let remove_for_age = file
            .name
            .as_deref()
            .and_then(extract_listener_artifact_date)
            .map(|file_date| file_date < cutoff)
            .unwrap_or(false);
        if remove_for_age && tokio::fs::remove_file(&file.path).await.is_ok() {
            removed_by_age += 1;
            continue;
        }
        remaining.push(file);
    }

    let max_bytes = (max_total_mb as u64).saturating_mul(1024 * 1024);
    let mut removed_by_size = 0usize;
    let mut total_after_bytes = remaining.iter().map(|f| f.size).sum::<u64>();
    if max_bytes > 0 && total_after_bytes > max_bytes {
        remaining.sort_by_key(|f| f.modified);
        for file in remaining {
            if total_after_bytes <= max_bytes {
                break;
            }
            if tokio::fs::remove_file(&file.path).await.is_ok() {
                removed_by_size += 1;
                total_after_bytes = total_after_bytes.saturating_sub(file.size);
            }
        }
    }

    Ok(ForensicsCleanupStats {
        removed_by_age,
        removed_by_size,
        total_before_bytes,
        total_after_bytes,
    })
}

#[derive(Debug)]
struct ForensicsFile {
    path: PathBuf,
    name: Option<String>,
    size: u64,
    modified: std::time::SystemTime,
}

async fn list_forensics_files(session_dir: &Path) -> std::io::Result<Vec<ForensicsFile>> {
    let mut out = Vec::new();
    let mut entries = tokio::fs::read_dir(session_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let name = name.to_string();
        if !name.starts_with("listener-session-") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let meta = match entry.metadata().await {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        out.push(ForensicsFile {
            path,
            name: Some(name),
            size: meta.len(),
            modified: meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
        });
    }
    Ok(out)
}

fn extract_listener_artifact_date(name: &str) -> Option<chrono::NaiveDate> {
    if !name.starts_with("listener-session-") {
        return None;
    }
    let ts = name.trim_start_matches("listener-session-");
    let ts = ts.split('-').next()?;
    let parsed = chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%dT%H%M%SZ").ok()?;
    Some(parsed.date())
}

fn preview_redirect_commands(
    endpoints: &[DecoyEndpoint],
    target_ip: IpAddr,
    enabled: bool,
    backend: &str,
) -> Vec<String> {
    if !enabled || !backend.eq_ignore_ascii_case("iptables") {
        return Vec::new();
    }
    endpoints
        .iter()
        .map(|endpoint| {
            format!(
                "sudo -n iptables -t nat -A PREROUTING -p tcp -s {} --dport {} -j REDIRECT --to-ports {}",
                target_ip, endpoint.redirect_from_port, endpoint.listen_port
            )
        })
        .collect()
}

async fn apply_redirect_rules(
    endpoints: &[DecoyEndpoint],
    target_ip: IpAddr,
    backend: &str,
) -> Vec<RedirectRuleStatus> {
    if !backend.eq_ignore_ascii_case("iptables") {
        return vec![];
    }

    let mut statuses = Vec::new();
    for endpoint in endpoints {
        let add_args = vec![
            "iptables".to_string(),
            "-t".to_string(),
            "nat".to_string(),
            "-A".to_string(),
            "PREROUTING".to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "-s".to_string(),
            target_ip.to_string(),
            "--dport".to_string(),
            endpoint.redirect_from_port.to_string(),
            "-j".to_string(),
            "REDIRECT".to_string(),
            "--to-ports".to_string(),
            endpoint.listen_port.to_string(),
        ];
        let del_args = vec![
            "iptables".to_string(),
            "-t".to_string(),
            "nat".to_string(),
            "-D".to_string(),
            "PREROUTING".to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "-s".to_string(),
            target_ip.to_string(),
            "--dport".to_string(),
            endpoint.redirect_from_port.to_string(),
            "-j".to_string(),
            "REDIRECT".to_string(),
            "--to-ports".to_string(),
            endpoint.listen_port.to_string(),
        ];

        let add_cmd = format!("sudo -n {}", add_args.join(" "));
        let del_cmd = format!("sudo -n {}", del_args.join(" "));

        let output = Command::new("sudo")
            .arg("-n")
            .args(&add_args)
            .output()
            .await;
        let status = match output {
            Ok(out) if out.status.success() => RedirectRuleStatus {
                service: endpoint.service.clone(),
                target_ip: target_ip.to_string(),
                from_port: endpoint.redirect_from_port,
                to_port: endpoint.listen_port,
                add_command: add_cmd,
                remove_command: del_cmd,
                applied: true,
                apply_error: None,
                cleanup_ok: None,
                cleanup_error: None,
                cleanup_verified_absent: None,
            },
            Ok(out) => RedirectRuleStatus {
                service: endpoint.service.clone(),
                target_ip: target_ip.to_string(),
                from_port: endpoint.redirect_from_port,
                to_port: endpoint.listen_port,
                add_command: add_cmd,
                remove_command: del_cmd,
                applied: false,
                apply_error: Some(String::from_utf8_lossy(&out.stderr).trim().to_string()),
                cleanup_ok: None,
                cleanup_error: None,
                cleanup_verified_absent: None,
            },
            Err(e) => RedirectRuleStatus {
                service: endpoint.service.clone(),
                target_ip: target_ip.to_string(),
                from_port: endpoint.redirect_from_port,
                to_port: endpoint.listen_port,
                add_command: add_cmd,
                remove_command: del_cmd,
                applied: false,
                apply_error: Some(e.to_string()),
                cleanup_ok: None,
                cleanup_error: None,
                cleanup_verified_absent: None,
            },
        };

        if !status.applied {
            warn!(service = %endpoint.service, "honeypot redirect rule not applied: {:?}", status.apply_error);
        }
        statuses.push(status);
    }

    statuses
}

async fn cleanup_redirect_rules(rules: &mut [RedirectRuleStatus]) {
    for rule in rules.iter_mut() {
        if !rule.applied {
            continue;
        }

        let del_args = redirect_rule_args(rule, "D");
        match Command::new("sudo")
            .arg("-n")
            .args(&del_args)
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                rule.cleanup_ok = Some(true);
                rule.cleanup_error = None;
            }
            Ok(out) => {
                rule.cleanup_ok = Some(false);
                rule.cleanup_error = Some(String::from_utf8_lossy(&out.stderr).trim().to_string());
            }
            Err(e) => {
                rule.cleanup_ok = Some(false);
                rule.cleanup_error = Some(e.to_string());
            }
        }

        let check_args = redirect_rule_args(rule, "C");
        match Command::new("sudo")
            .arg("-n")
            .args(&check_args)
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                rule.cleanup_verified_absent = Some(false);
                if rule.cleanup_error.is_none() {
                    rule.cleanup_error =
                        Some("redirect rule still present after cleanup".to_string());
                }
            }
            Ok(_) => {
                rule.cleanup_verified_absent = Some(true);
            }
            Err(e) => {
                rule.cleanup_verified_absent = None;
                if rule.cleanup_error.is_none() {
                    rule.cleanup_error = Some(format!("redirect cleanup verification failed: {e}"));
                }
            }
        }
    }
}

fn redirect_rule_args(rule: &RedirectRuleStatus, op: &str) -> Vec<String> {
    vec![
        "iptables".to_string(),
        "-t".to_string(),
        "nat".to_string(),
        format!("-{op}"),
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        rule.target_ip.clone(),
        "--dport".to_string(),
        rule.from_port.to_string(),
        "-j".to_string(),
        "REDIRECT".to_string(),
        "--to-ports".to_string(),
        rule.to_port.to_string(),
    ]
}

impl SessionLock {
    async fn acquire(path: PathBuf, session_id: &str, stale_secs: u64) -> Result<Self, String> {
        let lock_body = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "session_id": session_id,
        });
        for attempt in 0..2 {
            match tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .await
            {
                Ok(mut file) => {
                    if let Err(e) = file.write_all(format!("{lock_body}\n").as_bytes()).await {
                        return Err(format!(
                            "failed to write session lock {}: {e}",
                            path.display()
                        ));
                    }
                    return Ok(Self { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if attempt == 0 && is_lock_stale(&path, stale_secs).await {
                        warn!(path = %path.display(), "stale honeypot session lock detected; removing");
                        let _ = tokio::fs::remove_file(&path).await;
                        continue;
                    }
                    return Err(format!(
                        "another honeypot listener session is active (lock: {})",
                        path.display()
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "failed to create session lock {}: {e}",
                        path.display()
                    ));
                }
            }
        }
        Err(format!(
            "another honeypot listener session is active (lock: {})",
            path.display()
        ))
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn is_lock_stale(path: &Path, stale_secs: u64) -> bool {
    if stale_secs == 0 {
        return false;
    }

    if let Ok(content) = tokio::fs::read_to_string(path).await {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(ts) = value.get("ts").and_then(|v| v.as_str()) {
                if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
                    let age = Utc::now() - parsed.with_timezone(&Utc);
                    return age.num_seconds() > stale_secs as i64;
                }
            }
        }
    }

    if let Ok(meta) = tokio::fs::metadata(path).await {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                return elapsed.as_secs() > stale_secs;
            }
        }
    }
    false
}

async fn append_json_line(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(format!("{value}\n").as_bytes()).await?;
    file.flush().await
}

async fn write_json_file(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    tokio::fs::write(path, format!("{value}\n")).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::HoneypotRuntimeConfig;
    use innerwarden_core::{event::Severity, incident::Incident};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ctx(mode: &str) -> SkillContext {
        SkillContext {
            incident: Incident {
                ts: Utc::now(),
                host: "host-a".to_string(),
                incident_id: "incident-1".to_string(),
                severity: Severity::High,
                title: "t".to_string(),
                summary: "s".to_string(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "host-a".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: HoneypotRuntimeConfig {
                mode: mode.to_string(),
                bind_addr: "127.0.0.1".to_string(),
                port: 2222,
                http_port: 8080,
                duration_secs: 30,
                services: vec!["ssh".to_string()],
                strict_target_only: true,
                allow_public_listener: false,
                max_connections: 8,
                max_payload_bytes: 256,
                isolation_profile: "strict_local".to_string(),
                require_high_ports: true,
                forensics_keep_days: 7,
                forensics_max_total_mb: 128,
                transcript_preview_bytes: 96,
                lock_stale_secs: 1800,
                sandbox_enabled: false,
                sandbox_runner_path: String::new(),
                sandbox_clear_env: true,
                pcap_handoff_enabled: false,
                pcap_handoff_timeout_secs: 15,
                pcap_handoff_max_packets: 120,
                containment_mode: "process".to_string(),
                containment_require_success: false,
                containment_namespace_runner: "unshare".to_string(),
                containment_namespace_args: vec![
                    "--fork".to_string(),
                    "--pid".to_string(),
                    "--mount-proc".to_string(),
                ],
                containment_jail_runner: "bwrap".to_string(),
                containment_jail_args: vec![],
                containment_jail_profile: "standard".to_string(),
                containment_allow_namespace_fallback: true,
                external_handoff_enabled: false,
                external_handoff_command: String::new(),
                external_handoff_args: vec![],
                external_handoff_timeout_secs: 20,
                external_handoff_require_success: false,
                external_handoff_clear_env: true,
                external_handoff_allowed_commands: vec![],
                external_handoff_enforce_allowlist: false,
                external_handoff_signature_enabled: false,
                external_handoff_signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
                external_handoff_attestation_enabled: false,
                external_handoff_attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
                    .to_string(),
                external_handoff_attestation_prefix: "IW_ATTEST".to_string(),
                external_handoff_attestation_expected_receiver: String::new(),
                redirect_enabled: false,
                redirect_backend: "iptables".to_string(),
                interaction: "banner".to_string(),
                ssh_max_auth_attempts: 6,
                http_max_requests: 10,
                ai_provider: None,
            },
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn demo_mode_returns_demo_message() {
        let result = Honeypot.execute(&ctx("demo"), false).await;
        assert!(result.success);
        assert!(result.message.contains("PREMIUM DEMO"));
    }

    #[tokio::test]
    async fn listener_mode_dry_run_returns_preview() {
        let result = Honeypot.execute(&ctx("listener"), true).await;
        assert!(result.success);
        assert!(result.message.contains("would start honeypot listeners"));
    }

    #[tokio::test]
    async fn listener_rejects_public_bind_when_guard_enabled() {
        let mut context = ctx("listener");
        context.honeypot.bind_addr = "0.0.0.0".to_string();
        context.honeypot.allow_public_listener = false;
        let result = Honeypot.execute(&context, false).await;
        assert!(!result.success);
        assert!(result.message.contains("isolation guard"));
    }

    #[test]
    fn builds_multiple_services() {
        let runtime = HoneypotRuntimeConfig {
            services: vec!["ssh".to_string(), "http".to_string()],
            ..HoneypotRuntimeConfig::default()
        };
        let endpoints = build_endpoints(&runtime, "127.0.0.1").unwrap();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().any(|e| e.service == "ssh"));
        assert!(endpoints.iter().any(|e| e.service == "http"));
    }

    #[test]
    fn rejects_unknown_service() {
        let runtime = HoneypotRuntimeConfig {
            services: vec!["smtp".to_string()],
            ..HoneypotRuntimeConfig::default()
        };
        let err = build_endpoints(&runtime, "127.0.0.1").unwrap_err();
        assert!(err.contains("unsupported service"));
    }

    #[tokio::test]
    async fn strict_profile_enforces_listener_guards() {
        let mut context = ctx("listener");
        context.honeypot.allow_public_listener = true;
        let result = Honeypot.execute(&context, false).await;
        assert!(!result.success);
        assert!(result.message.contains("strict_local profile"));
    }

    #[tokio::test]
    async fn high_port_guard_blocks_privileged_listener_ports() {
        let mut context = ctx("listener");
        context.honeypot.port = 22;
        context.honeypot.require_high_ports = true;
        let result = Honeypot.execute(&context, false).await;
        assert!(!result.success);
        assert!(result.message.contains("high-port guard"));
    }

    #[test]
    fn transcript_preview_and_protocol_guess() {
        let payload = b"GET /admin HTTP/1.1\r\nHost: demo\r\n";
        let transcript = sanitize_transcript(payload, 12);
        assert!(transcript.contains("GET /admin"));
        assert_eq!(guess_protocol(payload), "http");
        assert_eq!(guess_protocol(b"SSH-2.0-test"), "ssh");
    }

    #[test]
    fn parses_listener_artifact_date() {
        let date = extract_listener_artifact_date("listener-session-20260313T162200Z-1.2.3.4.json")
            .expect("date should parse");
        assert_eq!(date.format("%Y-%m-%d").to_string(), "2026-03-13");
    }

    #[tokio::test]
    async fn forensics_cleanup_applies_size_cap() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let file_a = base.join("listener-session-20260313T162200Z-a.jsonl");
        let file_b = base.join("listener-session-20260313T162300Z-b.jsonl");
        tokio::fs::write(&file_a, vec![b'a'; 700_000])
            .await
            .unwrap();
        tokio::fs::write(&file_b, vec![b'b'; 700_000])
            .await
            .unwrap();

        let stats = cleanup_old_forensics(base, 365, 1).await.unwrap();
        assert_eq!(stats.removed_by_age, 0);
        assert_eq!(stats.removed_by_size, 1);
        assert!(stats.total_after_bytes <= 1_048_576);
    }

    #[tokio::test]
    async fn forensics_cleanup_removes_old_artifacts() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let old = base.join("listener-session-20240101T000000Z-old.json");
        tokio::fs::write(&old, b"{}").await.unwrap();

        let stats = cleanup_old_forensics(base, 1, 128).await.unwrap();
        assert_eq!(stats.removed_by_age, 1);
    }

    #[test]
    fn containment_mode_normalization_is_stable() {
        assert_eq!(normalize_containment_mode("namespace"), "namespace");
        assert_eq!(normalize_containment_mode("NAMESPACE"), "namespace");
        assert_eq!(normalize_containment_mode("jail"), "jail");
        assert_eq!(normalize_containment_mode("JAIL"), "jail");
        assert_eq!(normalize_containment_mode("process"), "process");
        assert_eq!(normalize_containment_mode("unknown"), "process");
    }

    #[test]
    fn jail_profile_normalization_is_stable() {
        assert_eq!(normalize_jail_profile("strict"), "strict");
        assert_eq!(normalize_jail_profile("STRICT"), "strict");
        assert_eq!(normalize_jail_profile("standard"), "standard");
        assert_eq!(normalize_jail_profile("unknown"), "standard");
    }

    #[test]
    fn strict_jail_profile_args_are_present() {
        let args = strict_jail_profile_args();
        assert!(args.contains(&"--die-with-parent".to_string()));
        assert!(args.contains(&"--new-session".to_string()));
        assert!(args.contains(&"--unshare-user".to_string()));
    }

    #[test]
    fn external_handoff_allowlist_matches_path_and_basename() {
        // Use /bin/ls which exists on all platforms
        let ls_path = if std::path::Path::new("/bin/ls").exists() {
            "/bin/ls"
        } else {
            "/usr/bin/ls"
        };
        let ls_canonical = std::fs::canonicalize(ls_path).expect("ls must exist for this test");

        // Full path match (canonicalized)
        assert!(is_command_allowed(
            ls_path,
            &[ls_canonical.display().to_string()]
        ));
        // Basename match
        assert!(is_command_allowed(ls_path, &["ls".to_string()]));
        // Non-matching basename
        assert!(!is_command_allowed(ls_path, &["other-cmd".to_string()]));
        // Non-existent command always rejected
        assert!(!is_command_allowed(
            "/nonexistent/path/to/binary",
            &["/nonexistent/path/to/binary".to_string()]
        ));
        // Empty command rejected
        assert!(!is_command_allowed("", &["ls".to_string()]));
    }

    #[test]
    fn attestation_line_parsing_works() {
        let line = "IW_ATTEST:receiver-a:challenge-1:abc123";
        let parsed = parse_attestation_line(line, "IW_ATTEST").expect("attestation should parse");
        assert_eq!(parsed.receiver_id, "receiver-a");
        assert_eq!(parsed.challenge, "challenge-1");
        assert_eq!(parsed.hmac_hex, "abc123");
    }

    #[test]
    fn attestation_verification_checks_hmac_and_receiver() {
        let runtime = SessionRuntime {
            session_id: "s1".to_string(),
            target_ip: "1.2.3.4".parse().unwrap(),
            strict_target_only: true,
            duration_secs: 30,
            max_connections: 8,
            max_payload_bytes: 128,
            transcript_preview_bytes: 64,
            isolation_profile: "strict_local".to_string(),
            evidence_path: PathBuf::from("/tmp/evidence.jsonl"),
            interaction: "banner".to_string(),
            ssh_max_auth_attempts: 6,
            http_max_requests: 10,
            ai_provider: None,
        };
        let challenge = "challenge-1";
        let receiver = "receiver-a";
        let payload = format!(
            "{}:{}:{}:{}",
            receiver, challenge, runtime.session_id, runtime.target_ip
        );
        let hmac = hmac_sha256_hex(b"attest-key", payload.as_bytes()).unwrap();
        let stdout = format!("IW_ATTEST:{receiver}:{challenge}:{hmac}");
        let parsed = verify_attestation_output(
            &stdout,
            "",
            "IW_ATTEST",
            Some("receiver-a"),
            challenge,
            "attest-key",
            &runtime,
        )
        .expect("attestation should validate");
        assert_eq!(parsed.receiver_id, "receiver-a");

        let err = verify_attestation_output(
            &stdout,
            "",
            "IW_ATTEST",
            Some("receiver-b"),
            challenge,
            "attest-key",
            &runtime,
        )
        .unwrap_err();
        assert!(err.contains("receiver mismatch"));
    }

    #[test]
    fn sha256_hex_is_stable() {
        let digest = sha256_hex(b"innerwarden");
        assert_eq!(
            digest,
            "de10c070ac7779a62bda785e6cf5708cfc82f0c131d093a47f963cc1443c1d6f"
        );
    }

    #[test]
    fn interaction_normalization_is_stable() {
        assert_eq!(normalize_interaction("medium"), "medium");
        assert_eq!(normalize_interaction("MEDIUM"), "medium");
        assert_eq!(normalize_interaction("Medium"), "medium");
        assert_eq!(normalize_interaction("banner"), "banner");
        assert_eq!(normalize_interaction("BANNER"), "banner");
        assert_eq!(normalize_interaction("unknown"), "banner");
        assert_eq!(normalize_interaction(""), "banner");
        assert_eq!(normalize_interaction("llm_shell"), "llm_shell");
        assert_eq!(normalize_interaction("LLM_SHELL"), "llm_shell");
        assert_eq!(normalize_interaction("Llm_Shell"), "llm_shell");
    }

    #[tokio::test]
    async fn listener_medium_dry_run_shows_interaction() {
        let mut context = ctx("listener");
        context.honeypot.interaction = "medium".to_string();
        let result = Honeypot.execute(&context, true).await;
        assert!(result.success);
        assert!(
            result.message.contains("interaction=medium"),
            "message: {}",
            result.message
        );
    }

    #[test]
    fn config_defaults_to_banner_interaction() {
        let runtime = HoneypotRuntimeConfig::default();
        assert_eq!(runtime.interaction, "banner");
        assert_eq!(runtime.ssh_max_auth_attempts, 6);
        assert_eq!(runtime.http_max_requests, 10);
        assert!(runtime.ai_provider.is_none());
    }

    #[tokio::test]
    async fn listener_llm_shell_dry_run_shows_interaction() {
        let mut context = ctx("listener");
        context.honeypot.interaction = "llm_shell".to_string();
        let result = Honeypot.execute(&context, true).await;
        assert!(result.success);
        assert!(
            result.message.contains("interaction=llm_shell"),
            "message: {}",
            result.message
        );
    }

    #[test]
    fn test_is_bwrap_runner() {
        assert!(is_bwrap_runner("bwrap"));
        assert!(is_bwrap_runner("/usr/bin/bwrap"));
        assert!(is_bwrap_runner("bubblewrap"));
        assert!(!is_bwrap_runner("other"));
    }

    #[tokio::test]
    async fn test_is_lock_stale_detection() {
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join("session.lock");

        // Zero stale_secs means never stale
        assert!(!is_lock_stale(&lock_path, 0).await);

        // Write a lock file with old timestamp
        let lock_body = serde_json::json!({
            "ts": "2020-01-01T00:00:00Z",
            "session_id": "test_stale",
        });
        tokio::fs::write(&lock_path, format!("{lock_body}\n"))
            .await
            .unwrap();

        // 10 seconds stale should trigger since it's from 2020
        assert!(is_lock_stale(&lock_path, 10).await);

        // Update it to now
        let lock_body_now = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "session_id": "test_fresh",
        });
        tokio::fs::write(&lock_path, format!("{lock_body_now}\n"))
            .await
            .unwrap();

        // Now it shouldn't be stale
        assert!(!is_lock_stale(&lock_path, 10).await);
    }

    #[test]
    fn test_append_unique_args() {
        let mut target = vec!["--foo".to_string(), "--bar".to_string()];
        let extras = vec!["--bar".to_string(), "--baz".to_string()];
        append_unique_args(&mut target, &extras);
        assert_eq!(target, vec!["--foo", "--bar", "--baz"]);
    }

    #[test]
    fn banner_lookup_is_case_insensitive_and_rejects_unknown_services() {
        let ssh = banner_for_service("SSH").expect("ssh banner should exist");
        let http = banner_for_service("Http").expect("http banner should exist");
        let err = banner_for_service("smtp").expect_err("smtp should be rejected");

        assert_eq!(ssh, SSH_BANNER);
        assert_eq!(http, HTTP_BANNER);
        assert!(err.contains("unsupported service"));
    }

    #[test]
    fn build_endpoints_defaults_and_dedups_services() {
        let default_runtime = HoneypotRuntimeConfig {
            services: vec![],
            ..HoneypotRuntimeConfig::default()
        };
        let default_endpoints = build_endpoints(&default_runtime, "127.0.0.1")
            .expect("default endpoints should be valid");
        assert_eq!(default_endpoints.len(), 1);
        assert_eq!(default_endpoints[0].service, "ssh");

        let dedup_runtime = HoneypotRuntimeConfig {
            services: vec![
                "ssh".to_string(),
                "ssh".to_string(),
                "http".to_string(),
                "http".to_string(),
            ],
            ..HoneypotRuntimeConfig::default()
        };
        let dedup_endpoints =
            build_endpoints(&dedup_runtime, "127.0.0.1").expect("dedup endpoints should be valid");
        assert_eq!(dedup_endpoints.len(), 2);
    }

    #[test]
    fn build_endpoints_rejects_invalid_ports() {
        let zero_port_runtime = HoneypotRuntimeConfig {
            services: vec!["ssh".to_string()],
            port: 0,
            ..HoneypotRuntimeConfig::default()
        };
        let zero_err =
            build_endpoints(&zero_port_runtime, "127.0.0.1").expect_err("port 0 must be rejected");
        assert!(zero_err.contains("invalid port 0"));

        let duplicate_port_runtime = HoneypotRuntimeConfig {
            services: vec!["ssh".to_string(), "http".to_string()],
            port: 2222,
            http_port: 2222,
            ..HoneypotRuntimeConfig::default()
        };
        let dup_err = build_endpoints(&duplicate_port_runtime, "127.0.0.1")
            .expect_err("duplicate ports must be rejected");
        assert!(dup_err.contains("duplicate listener port"));
    }

    #[test]
    fn isolation_and_bind_guards_cover_non_loopback_and_invalid_ip() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("not-an-ip"));

        assert_eq!(normalize_isolation_profile("standard"), "standard");
        assert_eq!(normalize_isolation_profile("STANDARD"), "standard");
        assert_eq!(normalize_isolation_profile("anything-else"), "strict_local");
    }

    #[test]
    fn preview_redirect_commands_respects_flags_and_backend() {
        let endpoints = vec![
            DecoyEndpoint {
                service: "ssh".to_string(),
                bind_addr: "127.0.0.1".to_string(),
                listen_port: 2222,
                redirect_from_port: 22,
                banner: SSH_BANNER,
            },
            DecoyEndpoint {
                service: "http".to_string(),
                bind_addr: "127.0.0.1".to_string(),
                listen_port: 8080,
                redirect_from_port: 80,
                banner: HTTP_BANNER,
            },
        ];
        let ip = "1.2.3.4".parse::<IpAddr>().expect("IP should parse");

        assert!(preview_redirect_commands(&endpoints, ip, false, "iptables").is_empty());
        assert!(preview_redirect_commands(&endpoints, ip, true, "nftables").is_empty());

        let commands = preview_redirect_commands(&endpoints, ip, true, "iptables");
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("--dport 22"));
        assert!(commands[1].contains("--dport 80"));
    }

    #[test]
    fn redirect_rule_args_changes_operation_flag() {
        let rule = RedirectRuleStatus {
            service: "ssh".to_string(),
            target_ip: "1.2.3.4".to_string(),
            from_port: 22,
            to_port: 2222,
            add_command: String::new(),
            remove_command: String::new(),
            applied: true,
            apply_error: None,
            cleanup_ok: None,
            cleanup_error: None,
            cleanup_verified_absent: None,
        };
        let delete_args = redirect_rule_args(&rule, "D");
        let check_args = redirect_rule_args(&rule, "C");
        assert!(delete_args.iter().any(|arg| arg == "-D"));
        assert!(check_args.iter().any(|arg| arg == "-C"));
    }

    #[test]
    fn protocol_guess_handles_text_and_binary_payloads() {
        assert_eq!(guess_protocol(b"hello world\n"), "text");
        assert_eq!(guess_protocol(&[0, 159, 146, 150]), "binary");
    }

    #[test]
    fn transcript_and_preview_helpers_cover_control_characters() {
        let transcript = sanitize_transcript(b"a\tb\rc\n\x01", 16);
        assert!(transcript.contains("\\t"));
        assert!(transcript.contains("\\r"));
        assert!(transcript.contains("\\n"));
        assert!(transcript.contains('.'));

        assert_eq!(truncate_preview("abc", 8), "abc");
        assert_eq!(truncate_preview("123456789", 5), "12345...");
    }

    #[test]
    fn attestation_defaults_and_parser_failures_are_handled() {
        assert_eq!(
            normalize_attestation_key_env(""),
            "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
        );
        assert_eq!(
            normalize_attestation_key_env("  CUSTOM_KEY  "),
            "CUSTOM_KEY"
        );
        assert_eq!(normalize_attestation_prefix(""), "IW_ATTEST");
        assert_eq!(normalize_attestation_prefix("  IW2  "), "IW2");

        assert!(parse_attestation_line("IW_ATTEST:only-two-parts", "IW_ATTEST").is_none());
        assert!(parse_attestation_line("WRONG:receiver:challenge:hmac", "IW_ATTEST").is_none());
    }

    #[test]
    fn verify_attestation_output_covers_error_branches() {
        let runtime = SessionRuntime {
            session_id: "s1".to_string(),
            target_ip: "1.2.3.4".parse().expect("IP should parse"),
            strict_target_only: true,
            duration_secs: 30,
            max_connections: 8,
            max_payload_bytes: 128,
            transcript_preview_bytes: 64,
            isolation_profile: "strict_local".to_string(),
            evidence_path: PathBuf::from("/tmp/evidence.jsonl"),
            interaction: "banner".to_string(),
            ssh_max_auth_attempts: 6,
            http_max_requests: 10,
            ai_provider: None,
        };
        let challenge = "challenge-1";
        let payload = format!(
            "{}:{}:{}:{}",
            "receiver-a", challenge, runtime.session_id, runtime.target_ip
        );
        let hmac =
            hmac_sha256_hex(b"attest-key", payload.as_bytes()).expect("hmac should be generated");
        let good_line = format!("IW_ATTEST:receiver-a:{challenge}:{hmac}");

        let missing_line = verify_attestation_output(
            "no attestation here",
            "",
            "IW_ATTEST",
            None,
            challenge,
            "attest-key",
            &runtime,
        )
        .expect_err("missing attestation line should fail");
        assert!(missing_line.contains("missing attestation line"));

        let mismatch = verify_attestation_output(
            &good_line,
            "",
            "IW_ATTEST",
            None,
            "other-challenge",
            "attest-key",
            &runtime,
        )
        .expect_err("challenge mismatch should fail");
        assert!(mismatch.contains("challenge mismatch"));

        let bad_hmac = verify_attestation_output(
            "IW_ATTEST:receiver-a:challenge-1:deadbeef",
            "",
            "IW_ATTEST",
            None,
            challenge,
            "attest-key",
            &runtime,
        )
        .expect_err("HMAC mismatch should fail");
        assert!(bad_hmac.contains("HMAC mismatch"));
    }

    #[test]
    fn fallback_reason_and_binary_resolution_helpers() {
        let mut reason = None;
        push_fallback_reason(&mut reason, "first".to_string());
        push_fallback_reason(&mut reason, "second".to_string());
        assert_eq!(reason.as_deref(), Some("first; second"));

        let ls_path = if std::path::Path::new("/bin/ls").exists() {
            "/bin/ls"
        } else {
            "/usr/bin/ls"
        };
        assert!(binary_exists(ls_path));
        assert!(!binary_exists("innerwarden-nonexistent-binary"));
    }

    #[test]
    fn artifact_date_parser_rejects_invalid_names() {
        assert!(extract_listener_artifact_date("listener-session-invalid.json").is_none());
        assert!(extract_listener_artifact_date("other-prefix-20260313T162200Z.json").is_none());
    }

    #[tokio::test]
    async fn file_size_and_artifact_lifecycle_checks_work() {
        let dir = tempdir().expect("tempdir should be created");
        let metadata = dir.path().join("meta.json");
        let evidence = dir.path().join("evidence.jsonl");
        let pcap = dir.path().join("capture.pcap");
        tokio::fs::write(&metadata, b"{\"ok\":true}\n")
            .await
            .expect("metadata should be written");
        tokio::fs::write(&evidence, b"{\"line\":1}\n")
            .await
            .expect("evidence should be written");
        tokio::fs::write(&pcap, b"pcap")
            .await
            .expect("pcap should be written");

        let (exists_meta, meta_size) = file_exists_with_size(&metadata).await;
        assert!(exists_meta);
        assert!(meta_size > 0);

        let lifecycle =
            collect_artifact_lifecycle(&metadata, &evidence, Some(pcap.to_string_lossy().as_ref()))
                .await;
        assert!(lifecycle.metadata_exists);
        assert!(lifecycle.evidence_exists);
        assert_eq!(lifecycle.pcap_exists, Some(true));
        assert!(lifecycle.metadata_bytes > 0);
        assert!(lifecycle.evidence_bytes > 0);
        assert!(lifecycle.pcap_bytes.unwrap_or_default() > 0);
    }

    #[tokio::test]
    async fn run_pcap_handoff_skips_when_limits_are_zero() {
        let dir = tempdir().expect("tempdir should be created");
        let status = run_pcap_handoff(
            dir.path(),
            "session-test",
            "1.2.3.4".parse().expect("IP should parse"),
            0,
            0,
        )
        .await;

        assert!(status.enabled);
        assert!(!status.attempted);
        assert!(!status.success);
        assert!(status.error.is_some());
    }

    fn free_local_port() -> u16 {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral listener should bind");
        let port = listener
            .local_addr()
            .expect("listener should expose local address")
            .port();
        drop(listener);
        port
    }

    fn build_runtime_for_tests(temp_root: &Path) -> SessionRuntime {
        SessionRuntime {
            session_id: "test-session".to_string(),
            target_ip: "127.0.0.1".parse().expect("target IP should parse"),
            strict_target_only: true,
            duration_secs: 1,
            max_connections: 1,
            max_payload_bytes: 256,
            transcript_preview_bytes: 64,
            isolation_profile: "strict_local".to_string(),
            evidence_path: temp_root.join("evidence.jsonl"),
            interaction: "banner".to_string(),
            ssh_max_auth_attempts: 6,
            http_max_requests: 10,
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn listener_mode_executes_real_session_and_writes_artifacts() {
        let dir = tempdir().expect("tempdir should be created");
        let mut context = ctx("listener");
        context.target_ip = Some("127.0.0.1".to_string());
        context.data_dir = dir.path().to_path_buf();
        context.honeypot.bind_addr = "127.0.0.1".to_string();
        context.honeypot.port = free_local_port();
        context.honeypot.duration_secs = 1;
        context.honeypot.max_connections = 1;
        context.honeypot.max_payload_bytes = 128;
        context.honeypot.transcript_preview_bytes = 64;
        context.honeypot.redirect_enabled = false;
        context.honeypot.sandbox_enabled = false;
        context.honeypot.pcap_handoff_enabled = false;
        context.honeypot.external_handoff_enabled = false;

        let result = Honeypot.execute(&context, false).await;
        assert!(
            result.success,
            "listener run should start: {}",
            result.message
        );
        assert!(result.message.contains("Honeypot listeners started"));

        let mut stream =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", context.honeypot.port))
                .await
                .expect("test client should connect");
        stream
            .write_all(b"PING")
            .await
            .expect("payload should be sent");
        let mut response = [0u8; 64];
        let bytes = stream
            .read(&mut response)
            .await
            .expect("banner should be read");
        assert!(bytes > 0);

        tokio::time::sleep(Duration::from_secs(2)).await;
        let session_dir = dir.path().join("honeypot");
        let entries = std::fs::read_dir(&session_dir)
            .expect("session dir should exist")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "session should generate artifacts");
        assert!(entries.iter().any(|path| {
            path.file_name()
                .and_then(|v| v.to_str())
                .map(|name| name.ends_with(".json"))
                .unwrap_or(false)
        }));
        assert!(entries.iter().any(|path| {
            path.file_name()
                .and_then(|v| v.to_str())
                .map(|name| name.ends_with(".jsonl"))
                .unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn sandbox_worker_runs_from_spec_and_writes_result_file() {
        let dir = tempdir().expect("tempdir should be created");
        let port = free_local_port();
        let runtime = build_runtime_for_tests(dir.path());
        let spec = SandboxWorkerSpec {
            session_id: runtime.session_id.clone(),
            target_ip: runtime.target_ip.to_string(),
            strict_target_only: runtime.strict_target_only,
            duration_secs: runtime.duration_secs,
            max_connections: runtime.max_connections,
            max_payload_bytes: runtime.max_payload_bytes,
            transcript_preview_bytes: runtime.transcript_preview_bytes,
            isolation_profile: runtime.isolation_profile.clone(),
            evidence_path: runtime.evidence_path.clone(),
            endpoints: vec![SandboxEndpointSpec {
                service: "ssh".to_string(),
                bind_addr: "127.0.0.1".to_string(),
                listen_port: port,
                redirect_from_port: 22,
            }],
            interaction: runtime.interaction.clone(),
            ssh_max_auth_attempts: runtime.ssh_max_auth_attempts,
            http_max_requests: runtime.http_max_requests,
        };

        let spec_path = dir.path().join("sandbox-spec.json");
        let result_path = dir.path().join("sandbox-result.json");
        tokio::fs::write(
            &spec_path,
            serde_json::to_string(&spec).expect("spec should serialize"),
        )
        .await
        .expect("spec should be written");

        let connect_port = port;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(mut stream) =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{connect_port}")).await
            {
                let _ = stream.write_all(b"HELLO").await;
            }
        });

        run_sandbox_worker(&spec_path, &result_path)
            .await
            .expect("sandbox worker should succeed");

        let body = tokio::fs::read_to_string(&result_path)
            .await
            .expect("result should be readable");
        let result: SandboxWorkerResult =
            serde_json::from_str(&body).expect("result should deserialize");
        assert!(result.success);
        assert_eq!(result.service_stats.len(), 1);
    }

    #[tokio::test]
    async fn external_handoff_success_path_sets_trusted_and_success() {
        let dir = tempdir().expect("tempdir should be created");
        let runtime = build_runtime_for_tests(dir.path());
        let metadata_path = dir.path().join("metadata.json");
        let evidence_path = dir.path().join("evidence.jsonl");
        tokio::fs::write(&metadata_path, b"{}\n")
            .await
            .expect("metadata should be created");
        tokio::fs::write(&evidence_path, b"{}\n")
            .await
            .expect("evidence should be created");

        let command_path = if Path::new("/bin/echo").exists() {
            "/bin/echo"
        } else {
            "/usr/bin/echo"
        };
        let cfg = ExternalHandoffConfig {
            enabled: true,
            command: command_path.to_string(),
            args: vec!["ok".to_string()],
            timeout_secs: 5,
            require_success: false,
            clear_env: false,
            allowed_commands: vec![],
            enforce_allowlist: false,
            signature_enabled: false,
            signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
            attestation_enabled: false,
            attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string(),
            attestation_prefix: "IW_ATTEST".to_string(),
            attestation_expected_receiver: String::new(),
        };

        let status = run_external_handoff(
            dir.path(),
            &runtime,
            &metadata_path,
            &evidence_path,
            None,
            &cfg,
        )
        .await;
        assert!(status.attempted);
        assert_eq!(status.command_success, Some(true));
        assert!(status.trusted);
        assert!(status.success);
        assert!(status.result_file.is_some());
    }

    #[tokio::test]
    async fn external_handoff_enforced_allowlist_blocks_disallowed_command() {
        let dir = tempdir().expect("tempdir should be created");
        let runtime = build_runtime_for_tests(dir.path());
        let metadata_path = dir.path().join("metadata.json");
        let evidence_path = dir.path().join("evidence.jsonl");
        tokio::fs::write(&metadata_path, b"{}\n")
            .await
            .expect("metadata should be created");
        tokio::fs::write(&evidence_path, b"{}\n")
            .await
            .expect("evidence should be created");

        let cfg = ExternalHandoffConfig {
            enabled: true,
            command: "/bin/echo".to_string(),
            args: vec!["blocked".to_string()],
            timeout_secs: 5,
            require_success: false,
            clear_env: false,
            allowed_commands: vec!["/bin/false".to_string()],
            enforce_allowlist: true,
            signature_enabled: false,
            signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
            attestation_enabled: false,
            attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string(),
            attestation_prefix: "IW_ATTEST".to_string(),
            attestation_expected_receiver: String::new(),
        };

        let status = run_external_handoff(
            dir.path(),
            &runtime,
            &metadata_path,
            &evidence_path,
            None,
            &cfg,
        )
        .await;
        assert!(status.attempted);
        assert!(!status.success);
        assert_eq!(status.allowlist_match, Some(false));
        assert!(status
            .error
            .unwrap_or_default()
            .contains("not in allowlist"));
    }

    #[tokio::test]
    async fn external_handoff_signature_creates_signature_artifact() {
        let dir = tempdir().expect("tempdir should be created");
        let runtime = build_runtime_for_tests(dir.path());
        let metadata_path = dir.path().join("metadata.json");
        let evidence_path = dir.path().join("evidence.jsonl");
        tokio::fs::write(&metadata_path, b"{}\n")
            .await
            .expect("metadata should be created");
        tokio::fs::write(&evidence_path, b"{}\n")
            .await
            .expect("evidence should be created");

        let command_path = if Path::new("/bin/echo").exists() {
            "/bin/echo"
        } else {
            "/usr/bin/echo"
        };
        std::env::set_var("IW_TEST_HANDOFF_SIGNING_KEY", "test-signing-key");
        let cfg = ExternalHandoffConfig {
            enabled: true,
            command: command_path.to_string(),
            args: vec!["signed".to_string()],
            timeout_secs: 5,
            require_success: false,
            clear_env: false,
            allowed_commands: vec![],
            enforce_allowlist: false,
            signature_enabled: true,
            signature_key_env: "IW_TEST_HANDOFF_SIGNING_KEY".to_string(),
            attestation_enabled: false,
            attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string(),
            attestation_prefix: "IW_ATTEST".to_string(),
            attestation_expected_receiver: String::new(),
        };

        let status = run_external_handoff(
            dir.path(),
            &runtime,
            &metadata_path,
            &evidence_path,
            None,
            &cfg,
        )
        .await;
        assert!(status.success);
        assert!(status.signature.is_some());
        assert!(status.signature_payload_sha256.is_some());
        assert!(status.signature_file.is_some());
    }

    #[tokio::test]
    async fn external_handoff_attestation_missing_env_fails_early() {
        let dir = tempdir().expect("tempdir should be created");
        let runtime = build_runtime_for_tests(dir.path());
        let metadata_path = dir.path().join("metadata.json");
        let evidence_path = dir.path().join("evidence.jsonl");
        tokio::fs::write(&metadata_path, b"{}\n")
            .await
            .expect("metadata should be created");
        tokio::fs::write(&evidence_path, b"{}\n")
            .await
            .expect("evidence should be created");

        std::env::remove_var("IW_TEST_MISSING_ATTEST");
        let cfg = ExternalHandoffConfig {
            enabled: true,
            command: "/bin/echo".to_string(),
            args: vec!["attest".to_string()],
            timeout_secs: 5,
            require_success: false,
            clear_env: false,
            allowed_commands: vec![],
            enforce_allowlist: false,
            signature_enabled: false,
            signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
            attestation_enabled: true,
            attestation_key_env: "IW_TEST_MISSING_ATTEST".to_string(),
            attestation_prefix: "IW_ATTEST".to_string(),
            attestation_expected_receiver: String::new(),
        };

        let status = run_external_handoff(
            dir.path(),
            &runtime,
            &metadata_path,
            &evidence_path,
            None,
            &cfg,
        )
        .await;
        assert!(status.attempted);
        assert!(!status.success);
        assert!(status
            .error
            .unwrap_or_default()
            .contains("attestation key is missing"));
    }

    #[tokio::test]
    async fn run_pcap_handoff_attempted_path_sets_command_metadata() {
        let dir = tempdir().expect("tempdir should be created");
        let status = run_pcap_handoff(
            dir.path(),
            "session-test",
            "1.2.3.4".parse().expect("IP should parse"),
            1,
            1,
        )
        .await;

        assert!(status.enabled);
        assert!(status.attempted);
        assert_eq!(status.timeout_secs, 1);
        assert_eq!(status.max_packets, 1);
        assert!(status.command.is_some());
        assert!(status.pcap_file.is_some());
    }

    #[tokio::test]
    async fn external_handoff_timeout_and_empty_command_paths_are_reported() {
        let dir = tempdir().expect("tempdir should be created");
        let runtime = build_runtime_for_tests(dir.path());
        let metadata_path = dir.path().join("metadata.json");
        let evidence_path = dir.path().join("evidence.jsonl");
        tokio::fs::write(&metadata_path, b"{}\n")
            .await
            .expect("metadata should be created");
        tokio::fs::write(&evidence_path, b"{}\n")
            .await
            .expect("evidence should be created");

        let empty_cfg = ExternalHandoffConfig {
            enabled: true,
            command: String::new(),
            args: vec![],
            timeout_secs: 5,
            require_success: false,
            clear_env: false,
            allowed_commands: vec![],
            enforce_allowlist: false,
            signature_enabled: false,
            signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
            attestation_enabled: false,
            attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string(),
            attestation_prefix: "IW_ATTEST".to_string(),
            attestation_expected_receiver: String::new(),
        };
        let empty = run_external_handoff(
            dir.path(),
            &runtime,
            &metadata_path,
            &evidence_path,
            None,
            &empty_cfg,
        )
        .await;
        assert!(!empty.attempted);
        assert!(!empty.success);
        assert!(empty.error.unwrap_or_default().contains("command is empty"));

        let timeout_cfg = ExternalHandoffConfig {
            enabled: true,
            command: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "sleep 2".to_string()],
            timeout_secs: 1,
            require_success: false,
            clear_env: false,
            allowed_commands: vec![],
            enforce_allowlist: false,
            signature_enabled: false,
            signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
            attestation_enabled: false,
            attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string(),
            attestation_prefix: "IW_ATTEST".to_string(),
            attestation_expected_receiver: String::new(),
        };
        let timed_out = run_external_handoff(
            dir.path(),
            &runtime,
            &metadata_path,
            &evidence_path,
            None,
            &timeout_cfg,
        )
        .await;
        assert!(timed_out.attempted);
        assert!(timed_out.timed_out);
        assert_eq!(timed_out.command_success, Some(false));
        assert!(!timed_out.success);
        assert!(timed_out.error.unwrap_or_default().contains("timed out"));
    }

    #[tokio::test]
    async fn external_handoff_signature_and_attestation_failure_paths_are_reported() {
        let dir = tempdir().expect("tempdir should be created");
        let runtime = build_runtime_for_tests(dir.path());
        let metadata_path = dir.path().join("metadata.json");
        let evidence_path = dir.path().join("evidence.jsonl");
        tokio::fs::write(&metadata_path, b"{}\n")
            .await
            .expect("metadata should be created");
        tokio::fs::write(&evidence_path, b"{}\n")
            .await
            .expect("evidence should be created");

        std::env::remove_var("IW_TEST_MISSING_SIGNATURE_KEY");
        let signature_cfg = ExternalHandoffConfig {
            enabled: true,
            command: "/bin/echo".to_string(),
            args: vec!["sig".to_string()],
            timeout_secs: 5,
            require_success: false,
            clear_env: false,
            allowed_commands: vec![],
            enforce_allowlist: false,
            signature_enabled: true,
            signature_key_env: "IW_TEST_MISSING_SIGNATURE_KEY".to_string(),
            attestation_enabled: false,
            attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string(),
            attestation_prefix: "IW_ATTEST".to_string(),
            attestation_expected_receiver: String::new(),
        };
        let signature_status = run_external_handoff(
            dir.path(),
            &runtime,
            &metadata_path,
            &evidence_path,
            None,
            &signature_cfg,
        )
        .await;
        assert!(signature_status.attempted);
        assert!(!signature_status.success);
        assert!(signature_status.signature_error.is_some());
        assert!(signature_status
            .signature_error
            .unwrap_or_default()
            .contains("missing signing key"));

        std::env::set_var("IW_TEST_ATTEST_KEY", "attestation-key");
        let attestation_cfg = ExternalHandoffConfig {
            enabled: true,
            command: "/bin/echo".to_string(),
            args: vec!["IW_ATTEST:receiver-a:wrong:deadbeef".to_string()],
            timeout_secs: 5,
            require_success: false,
            clear_env: false,
            allowed_commands: vec![],
            enforce_allowlist: false,
            signature_enabled: false,
            signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
            attestation_enabled: true,
            attestation_key_env: "IW_TEST_ATTEST_KEY".to_string(),
            attestation_prefix: "IW_ATTEST".to_string(),
            attestation_expected_receiver: "receiver-a".to_string(),
        };
        let attestation_status = run_external_handoff(
            dir.path(),
            &runtime,
            &metadata_path,
            &evidence_path,
            None,
            &attestation_cfg,
        )
        .await;
        assert!(attestation_status.attempted);
        assert_eq!(attestation_status.attestation.matched, Some(false));
        assert!(!attestation_status.success);
        assert!(attestation_status.attestation.error.is_some());
    }

    fn write_runner_script(path: &Path, body: &str) {
        std::fs::write(path, body).expect("runner script should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)
                .expect("runner metadata should be available")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).expect("runner script should be executable");
        }
    }

    fn sandbox_config_for_runner(path: &Path) -> SandboxLaunchConfig {
        SandboxLaunchConfig {
            runner_path: path.display().to_string(),
            clear_env: false,
            containment_mode: "process".to_string(),
            containment_require_success: false,
            containment_namespace_runner: "unshare".to_string(),
            containment_namespace_args: vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string(),
            ],
            containment_jail_runner: "bwrap".to_string(),
            containment_jail_args: vec![],
            containment_jail_profile: "standard".to_string(),
            containment_allow_namespace_fallback: true,
        }
    }

    fn test_endpoints() -> Vec<DecoyEndpoint> {
        vec![DecoyEndpoint {
            service: "ssh".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            listen_port: free_local_port(),
            redirect_from_port: 22,
            banner: SSH_BANNER,
        }]
    }

    #[tokio::test]
    async fn run_sandbox_worker_reports_missing_and_invalid_spec_errors() {
        let dir = tempdir().expect("tempdir should be created");
        let missing_spec = dir.path().join("missing-spec.json");
        let missing_result = dir.path().join("missing-result.json");
        let err = run_sandbox_worker(&missing_spec, &missing_result)
            .await
            .expect_err("missing spec should fail");
        assert!(err.to_string().contains("sandbox worker failed"));
        let missing_body = tokio::fs::read_to_string(&missing_result)
            .await
            .expect("result should be written on failure");
        let missing_out: SandboxWorkerResult =
            serde_json::from_str(&missing_body).expect("result should deserialize");
        assert!(!missing_out.success);

        let invalid_spec = dir.path().join("invalid-spec.json");
        let invalid_result = dir.path().join("invalid-result.json");
        tokio::fs::write(&invalid_spec, "{invalid-json")
            .await
            .expect("invalid spec should be written");
        let err = run_sandbox_worker(&invalid_spec, &invalid_result)
            .await
            .expect_err("invalid spec should fail");
        assert!(err.to_string().contains("sandbox worker failed"));
        let invalid_body = tokio::fs::read_to_string(&invalid_result)
            .await
            .expect("result should be written on failure");
        let invalid_out: SandboxWorkerResult =
            serde_json::from_str(&invalid_body).expect("result should deserialize");
        assert!(!invalid_out.success);
    }

    #[tokio::test]
    async fn run_sandbox_session_success_and_failure_paths() {
        let dir = tempdir().expect("tempdir should be created");
        let runtime = build_runtime_for_tests(dir.path());
        let endpoints = test_endpoints();

        let success_runner = dir.path().join("runner-success.sh");
        write_runner_script(
            &success_runner,
            r#"#!/bin/sh
result=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--honeypot-sandbox-result" ]; then
    result="$2"
    shift 2
    continue
  fi
  shift
done
printf '{"session_id":"test-session","success":true,"error":null,"service_stats":[]}\n' > "$result"
exit 0
"#,
        );

        let outcome = run_sandbox_session(
            runtime.clone(),
            endpoints.clone(),
            dir.path(),
            &sandbox_config_for_runner(&success_runner),
        )
        .await
        .expect("sandbox session should succeed with helper runner");
        assert!(outcome.stats.is_empty());
        assert_eq!(outcome.containment.effective_mode, "process");
        assert!(outcome.spec_path.exists());
        assert!(outcome.result_path.exists());

        let failure_runner = dir.path().join("runner-failure.sh");
        write_runner_script(
            &failure_runner,
            r#"#!/bin/sh
result=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--honeypot-sandbox-result" ]; then
    result="$2"
    shift 2
    continue
  fi
  shift
done
printf '{"session_id":"test-session","success":false,"error":"runner-failed","service_stats":[]}\n' > "$result"
exit 0
"#,
        );

        let err = run_sandbox_session(
            runtime.clone(),
            endpoints.clone(),
            dir.path(),
            &sandbox_config_for_runner(&failure_runner),
        )
        .await
        .expect_err("sandbox session should fail when worker result is unsuccessful");
        assert!(err.contains("runner-failed"));
    }

    #[tokio::test]
    async fn run_sandbox_session_containment_require_success_paths() {
        let dir = tempdir().expect("tempdir should be created");
        let runtime = build_runtime_for_tests(dir.path());
        let endpoints = test_endpoints();

        let success_runner = dir.path().join("runner-ok.sh");
        write_runner_script(
            &success_runner,
            r#"#!/bin/sh
result=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--honeypot-sandbox-result" ]; then
    result="$2"
    shift 2
    continue
  fi
  shift
done
printf '{"session_id":"test-session","success":true,"error":null,"service_stats":[]}\n' > "$result"
exit 0
"#,
        );

        let mut namespace_required = sandbox_config_for_runner(&success_runner);
        namespace_required.containment_mode = "namespace".to_string();
        namespace_required.containment_require_success = true;
        namespace_required.containment_namespace_runner =
            "definitely-missing-namespace-runner".to_string();
        let err = run_sandbox_session(
            runtime.clone(),
            endpoints.clone(),
            dir.path(),
            &namespace_required,
        )
        .await
        .expect_err("missing namespace runner with require_success should fail");
        assert!(err.contains("requested namespace mode"));

        let mut strict_jail_required = sandbox_config_for_runner(&success_runner);
        strict_jail_required.containment_mode = "jail".to_string();
        strict_jail_required.containment_jail_profile = "strict".to_string();
        strict_jail_required.containment_require_success = true;
        strict_jail_required.containment_jail_runner = "/bin/sh".to_string();
        let err = run_sandbox_session(
            runtime.clone(),
            endpoints.clone(),
            dir.path(),
            &strict_jail_required,
        )
        .await
        .expect_err("strict jail with non-bwrap runner should fail");
        assert!(err.contains("strict jail profile requires bwrap-compatible runner"));

        let mut namespace_fallback = sandbox_config_for_runner(&success_runner);
        namespace_fallback.containment_mode = "namespace".to_string();
        namespace_fallback.containment_require_success = false;
        namespace_fallback.containment_namespace_runner =
            "definitely-missing-namespace-runner".to_string();
        let fallback = run_sandbox_session(runtime, endpoints, dir.path(), &namespace_fallback)
            .await
            .expect("namespace fallback to process should succeed");
        assert_eq!(fallback.containment.requested_mode, "namespace");
        assert_eq!(fallback.containment.effective_mode, "process");
        assert!(fallback.containment.fallback_reason.is_some());
    }

    #[tokio::test]
    async fn run_listener_rejects_non_target_connections() {
        let dir = tempdir().expect("tempdir should be created");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        let endpoint = DecoyEndpoint {
            service: "ssh".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            listen_port: addr.port(),
            redirect_from_port: 22,
            banner: SSH_BANNER,
        };
        let mut runtime = build_runtime_for_tests(dir.path());
        runtime.target_ip = "127.0.0.2".parse().expect("target IP should parse");
        runtime.strict_target_only = true;
        runtime.duration_secs = 1;
        runtime.max_connections = 1;
        runtime.evidence_path = dir.path().join("rejections.jsonl");

        let run_task = tokio::spawn(run_listener(endpoint, listener, runtime.clone()));
        let _client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let stats = run_task.await.expect("listener task should finish");
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.rejected, 1);

        let evidence = tokio::fs::read_to_string(&runtime.evidence_path)
            .await
            .expect("rejection evidence should be written");
        assert!(evidence.contains("connection_rejected"));
        assert!(evidence.contains("\"target_match\":false"));
    }

    #[tokio::test]
    async fn run_listener_medium_http_records_http_evidence() {
        let dir = tempdir().expect("tempdir should be created");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        let endpoint = DecoyEndpoint {
            service: "http".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            listen_port: addr.port(),
            redirect_from_port: 80,
            banner: HTTP_BANNER,
        };
        let mut runtime = build_runtime_for_tests(dir.path());
        runtime.interaction = "medium".to_string();
        runtime.strict_target_only = false;
        runtime.duration_secs = 2;
        runtime.max_connections = 1;
        runtime.evidence_path = dir.path().join("http-medium.jsonl");

        let run_task = tokio::spawn(run_listener(endpoint, listener, runtime.clone()));
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("client should connect");
        client
            .write_all(b"GET /login HTTP/1.1\r\nHost: honeypot\r\nConnection: close\r\n\r\n")
            .await
            .expect("request should be sent");
        let mut response = vec![0u8; 2048];
        let n = client
            .read(&mut response)
            .await
            .expect("response should be read");
        assert!(n > 0);
        client.shutdown().await.expect("client should shutdown");

        let stats = run_task.await.expect("listener task should finish");
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.rejected, 0);

        let evidence = tokio::fs::read_to_string(&runtime.evidence_path)
            .await
            .expect("http evidence should be written");
        assert!(evidence.contains("http_connection"));
        assert!(evidence.contains("http_requests_count"));
    }

    #[tokio::test]
    async fn run_listener_medium_unknown_service_falls_back_to_banner_mode() {
        let dir = tempdir().expect("tempdir should be created");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        let endpoint = DecoyEndpoint {
            service: "smtp".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            listen_port: addr.port(),
            redirect_from_port: 25,
            banner: b"220 smtp honeypot\r\n",
        };
        let mut runtime = build_runtime_for_tests(dir.path());
        runtime.interaction = "medium".to_string();
        runtime.strict_target_only = false;
        runtime.duration_secs = 2;
        runtime.max_connections = 1;
        runtime.evidence_path = dir.path().join("fallback.jsonl");

        let run_task = tokio::spawn(run_listener(endpoint, listener, runtime.clone()));
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("client should connect");
        client
            .write_all(b"EHLO attacker.example\r\n")
            .await
            .expect("payload should be sent");
        let mut response = [0u8; 64];
        let n = client
            .read(&mut response)
            .await
            .expect("banner should be read");
        assert!(n > 0);
        client.shutdown().await.expect("client should shutdown");

        let stats = run_task.await.expect("listener task should finish");
        assert_eq!(stats.accepted, 1);
        assert!(stats.payload_bytes_captured > 0);

        let evidence = tokio::fs::read_to_string(&runtime.evidence_path)
            .await
            .expect("fallback evidence should be written");
        assert!(evidence.contains("\"service\":\"smtp\""));
        assert!(evidence.contains("\"interaction\":\"banner\""));
    }

    #[tokio::test]
    async fn capture_payload_zero_limit_and_timeout_paths_are_handled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        let client =
            tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        let (mut server_stream, _) = listener.accept().await.expect("server should accept");
        let _client_stream = client.await.expect("client task should complete");

        let zero = capture_payload(&mut server_stream, 0, 64).await;
        assert_eq!(zero.bytes_captured, 0);
        assert_eq!(zero.protocol_guess, "none");
        assert!(!zero.read_timed_out);

        let timed_out = capture_payload(&mut server_stream, 64, 64).await;
        assert_eq!(timed_out.bytes_captured, 0);
        assert_eq!(timed_out.protocol_guess, "unknown");
        assert!(timed_out.read_timed_out);
    }

    #[tokio::test]
    async fn redirect_apply_and_cleanup_branches_record_failures() {
        let endpoints = vec![DecoyEndpoint {
            service: "ssh".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            listen_port: 2222,
            redirect_from_port: 22,
            banner: SSH_BANNER,
        }];
        let target_ip: IpAddr = "1.2.3.4".parse().expect("IP should parse");

        let statuses = apply_redirect_rules(&endpoints, target_ip, "iptables").await;
        assert_eq!(statuses.len(), 1);
        assert!(statuses[0].apply_error.is_some() || statuses[0].applied);

        let mut synthetic = vec![RedirectRuleStatus {
            service: "ssh".to_string(),
            target_ip: "1.2.3.4".to_string(),
            from_port: 22,
            to_port: 2222,
            add_command: "sudo iptables -t nat -A ...".to_string(),
            remove_command: "sudo iptables -t nat -D ...".to_string(),
            applied: true,
            apply_error: None,
            cleanup_ok: None,
            cleanup_error: None,
            cleanup_verified_absent: None,
        }];
        cleanup_redirect_rules(&mut synthetic).await;
        assert!(synthetic[0].cleanup_ok.is_some());
    }

    #[tokio::test]
    async fn session_lock_acquire_and_stale_recovery_paths() {
        let dir = tempdir().expect("tempdir should be created");
        let lock_path = dir.path().join("listener.lock");

        let lock = SessionLock::acquire(lock_path.clone(), "session-a", 60)
            .await
            .expect("initial lock should be acquired");
        assert!(lock_path.exists());
        drop(lock);
        assert!(!lock_path.exists());

        let stale_content = serde_json::json!({
            "ts": "2020-01-01T00:00:00Z",
            "session_id": "old-session",
        });
        tokio::fs::write(&lock_path, format!("{stale_content}\n"))
            .await
            .expect("stale lock should be written");
        let stale_lock = SessionLock::acquire(lock_path.clone(), "session-b", 1)
            .await
            .expect("stale lock should be replaced");
        assert!(lock_path.exists());
        drop(stale_lock);
        assert!(!lock_path.exists());
    }
}
