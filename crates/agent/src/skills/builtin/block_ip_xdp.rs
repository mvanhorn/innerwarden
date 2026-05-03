use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// XDP firewall block - drops packets at the network driver level.
///
/// Instead of adding a firewall rule (ufw/iptables), this inserts the IP
/// into a BPF hash map that the XDP program checks on every incoming packet.
/// Drop rate: 10-25 million packets per second, zero CPU overhead.
///
/// Supports both IPv4 and IPv6. Uses separate pinned maps:
///   - /sys/fs/bpf/innerwarden/blocklist    (IPv4, key: 4 bytes)
///   - /sys/fs/bpf/innerwarden/blocklist_v6 (IPv6, key: 16 bytes)
pub struct BlockIpXdp;

/// Path where the XDP IPv4 blocklist map is pinned.
const BLOCKLIST_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist";
/// Path where the XDP IPv6 blocklist map is pinned.
const BLOCKLIST_V6_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist_v6";

impl ResponseSkill for BlockIpXdp {
    fn id(&self) -> &'static str {
        "block-ip-xdp"
    }
    fn name(&self) -> &'static str {
        "Block IP via XDP (wire-speed)"
    }
    fn description(&self) -> &'static str {
        "Drops packets from the attacking IP at the network driver level using XDP. \
         10-25 million pps drop rate, zero CPU overhead. \
         The fastest possible firewall - packets never reach the kernel network stack."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &[
            "ssh_bruteforce",
            "port_scan",
            "credential_stuffing",
            "c2_callback",
            "distributed_ssh",
            "reverse_shell",
            "lateral_movement",
            "data_exfiltration",
            "data_exfil_ebpf",
            "ransomware",
            "process_injection",
            "container_escape",
            "web_shell",
            "dns_tunneling",
            "crypto_miner",
            "packet_flood",
            "fileless",
            "web_scan",
            "ssh_key_injection",
            "suspicious_login",
        ]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip = match &ctx.target_ip {
                Some(ip) => ip.clone(),
                None => {
                    return SkillResult {
                        success: false,
                        message: "block-ip-xdp: no target IP in context".to_string(),
                    }
                }
            };

            // Determine IP version and prepare key bytes + map path
            let (map_pin, key_args): (&str, Vec<String>) = if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                let b = v4.octets();
                (
                    BLOCKLIST_PIN,
                    vec![
                        b[0].to_string(),
                        b[1].to_string(),
                        b[2].to_string(),
                        b[3].to_string(),
                    ],
                )
            } else if let Ok(v6) = ip.parse::<Ipv6Addr>() {
                let b = v6.octets();
                (BLOCKLIST_V6_PIN, b.iter().map(|x| x.to_string()).collect())
            } else {
                return SkillResult {
                    success: false,
                    message: format!("block-ip-xdp: invalid IP address: {ip}"),
                };
            };

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would insert {ip} into XDP blocklist (wire-speed drop)"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via XDP (wire-speed)"),
                };
            }

            // Check if pinned map exists.
            //
            // 2026-05-03 (Wave 5b PR-2): no per-call WARN here. The
            // `xdp_availability` gate in `decision_block_ip` is the
            // canonical surface for XDP-unavailable warnings; it
            // emits one operator-actionable WARN per 5 min with the
            // recovery recipe. Logging here AS WELL would re-create
            // the spam this PR fixes (operator's prod was producing
            // two WARN lines per block decision, one from each path).
            // The skill still returns success=false so the caller
            // can call `xdp_availability::mark_failed` and gate
            // future attempts.
            if !std::path::Path::new(map_pin).exists() {
                return SkillResult {
                    success: false,
                    message: format!(
                        "XDP not available (map not found at {map_pin}). \
                         Ensure innerwarden-sensor is running with XDP attached."
                    ),
                };
            }

            // Insert into pinned BPF map via bpftool
            let mut args = vec![
                "bpftool".to_string(),
                "map".to_string(),
                "update".to_string(),
                "pinned".to_string(),
                map_pin.to_string(),
                "key".to_string(),
            ];
            args.extend(key_args);
            args.extend([
                "value".to_string(),
                "1".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "any".to_string(),
            ]);

            let output = tokio::process::Command::new("sudo")
                .args(&args[..])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "blocked via XDP (wire-speed drop)");
                    SkillResult {
                        success: true,
                        message: format!("Blocked {ip} via XDP - wire-speed drop active"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "bpftool map update failed");
                    SkillResult {
                        success: false,
                        message: format!("XDP block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn bpftool");
                    SkillResult {
                        success: false,
                        message: format!("failed to run bpftool: {e}"),
                    }
                }
            }
        })
    }
}

/// Check if XDP firewall is available on this system.
#[allow(dead_code)]
pub fn is_xdp_available() -> bool {
    std::path::Path::new(BLOCKLIST_PIN).exists()
}

/// Remove an IP from the XDP blocklist (unblock).
#[allow(dead_code)]
pub async fn xdp_unblock_ip(ip: &str) -> Result<(), String> {
    let addr: Ipv4Addr = ip.parse().map_err(|e| format!("invalid IP: {e}"))?;
    let ip_bytes = addr.octets();

    let output = tokio::process::Command::new("sudo")
        .args([
            "bpftool",
            "map",
            "delete",
            "pinned",
            BLOCKLIST_PIN,
            "key",
            &ip_bytes[0].to_string(),
            &ip_bytes[1].to_string(),
            &ip_bytes[2].to_string(),
            &ip_bytes[3].to_string(),
        ])
        .output()
        .await
        .map_err(|e| format!("failed to run bpftool: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::{HoneypotRuntimeConfig, SkillContext};

    fn make_ctx(ip: Option<&str>) -> SkillContext {
        SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: "h".into(),
                incident_id: "id".into(),
                severity: innerwarden_core::event::Severity::High,
                title: "t".into(),
                summary: "s".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: ip.map(str::to_string),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "h".into(),
            data_dir: std::env::temp_dir(),
            honeypot: HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dry_run_xdp_ipv4() {
        let ctx = make_ctx(Some("1.2.3.4"));
        let result = BlockIpXdp.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("1.2.3.4"));
    }

    #[tokio::test]
    async fn dry_run_xdp_ipv6() {
        let ctx = make_ctx(Some("2001:db8::1"));
        let result = BlockIpXdp.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("2001:db8::1"));
    }

    #[tokio::test]
    async fn invalid_ip_xdp() {
        let ctx = make_ctx(Some("not-an-ip"));
        let result = BlockIpXdp.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("invalid IP"));
    }

    #[tokio::test]
    async fn no_target_ip_xdp() {
        let ctx = make_ctx(None);
        let result = BlockIpXdp.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[test]
    fn skill_metadata_xdp() {
        assert_eq!(BlockIpXdp.id(), "block-ip-xdp");
        assert!(BlockIpXdp.name().contains("XDP"));
        assert_eq!(BlockIpXdp.tier(), SkillTier::Open);
        // XDP handles many more detectors than other skills
        assert!(BlockIpXdp.applicable_to().len() > 10);
        assert!(BlockIpXdp.applicable_to().contains(&"reverse_shell"));
        assert!(BlockIpXdp.applicable_to().contains(&"ransomware"));
    }
}
