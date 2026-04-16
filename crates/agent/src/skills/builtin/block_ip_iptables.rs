use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use super::firewall_target::is_valid_firewall_target;
use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

pub struct BlockIpIptables;

impl ResponseSkill for BlockIpIptables {
    fn id(&self) -> &'static str {
        "block-ip-iptables"
    }
    fn name(&self) -> &'static str {
        "Block IP via iptables"
    }
    fn description(&self) -> &'static str {
        "Blocks the attacking IP by appending a DROP rule to the INPUT chain using iptables. \
         Requires: sudo iptables -A INPUT ... (configured in /etc/sudoers.d/innerwarden). \
         Note: rules are lost on reboot unless persisted with iptables-save."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &["ssh_bruteforce", "port_scan", "credential_stuffing"]
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
                        message: "block-ip-iptables: no target IP in context".to_string(),
                    }
                }
            };

            if !is_valid_firewall_target(&ip) {
                warn!(ip, "block-ip-iptables: rejecting invalid target before invoking iptables");
                return SkillResult {
                    success: false,
                    message: format!("block-ip-iptables: {ip} is not a valid IP/CIDR"),
                };
            }

            if dry_run {
                info!(ip, "DRY RUN: would execute: sudo iptables -A INPUT -s {ip} -j DROP -m comment --comment innerwarden");
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via iptables"),
                };
            }

            let output = tokio::process::Command::new("sudo")
                .args([
                    "iptables",
                    "-A",
                    "INPUT",
                    "-s",
                    &ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    "innerwarden",
                ])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "blocked via iptables");
                    SkillResult {
                        success: true,
                        message: format!("Blocked {ip} via iptables"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "iptables block command failed");
                    SkillResult {
                        success: false,
                        message: format!("iptables block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn iptables command");
                    SkillResult {
                        success: false,
                        message: format!("failed to run iptables: {e}"),
                    }
                }
            }
        })
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
    async fn dry_run_iptables() {
        let ctx = make_ctx(Some("10.0.0.1"));
        let result = BlockIpIptables.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("10.0.0.1"));
    }

    #[tokio::test]
    async fn no_target_ip_iptables() {
        let ctx = make_ctx(None);
        let result = BlockIpIptables.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[test]
    fn skill_metadata_iptables() {
        assert_eq!(BlockIpIptables.id(), "block-ip-iptables");
        assert!(BlockIpIptables.name().contains("iptables"));
        assert_eq!(BlockIpIptables.tier(), SkillTier::Open);
        assert!(BlockIpIptables.applicable_to().contains(&"port_scan"));
    }

    #[tokio::test]
    async fn rejects_invalid_target_before_spawn() {
        for bad in ["129.950.5.0", "130.890.9.0", "not-an-ip", ""] {
            let ctx = make_ctx(Some(bad));
            let result = BlockIpIptables.execute(&ctx, true).await;
            assert!(!result.success, "'{bad}' should be rejected");
            assert!(
                result.message.contains("not a valid") || result.message.contains("no target IP"),
                "message for '{bad}' should explain rejection: {}",
                result.message
            );
        }
    }

    #[tokio::test]
    async fn dry_run_accepts_valid_cidr() {
        let ctx = make_ctx(Some("10.0.0.0/24"));
        let result = BlockIpIptables.execute(&ctx, true).await;
        assert!(result.success);
    }
}
