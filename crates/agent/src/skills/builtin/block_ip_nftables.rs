use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use super::firewall_target::is_valid_firewall_target;
use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

pub struct BlockIpNftables;

impl ResponseSkill for BlockIpNftables {
    fn id(&self) -> &'static str {
        "block-ip-nftables"
    }
    fn name(&self) -> &'static str {
        "Block IP via nftables"
    }
    fn description(&self) -> &'static str {
        "Adds the attacking IP to a named blacklist set in nftables. \
         Requires an 'inet filter blacklist' set pre-configured in nftables.conf. \
         Requires: sudo nft add element ... (configured in /etc/sudoers.d/innerwarden)."
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
                        message: "block-ip-nftables: no target IP in context".to_string(),
                    }
                }
            };

            if !is_valid_firewall_target(&ip) {
                warn!(ip, "block-ip-nftables: rejecting invalid target before invoking nft");
                return SkillResult {
                    success: false,
                    message: format!("block-ip-nftables: {ip} is not a valid IP/CIDR"),
                };
            }

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would execute: sudo nft add element inet filter blacklist {{ {ip} }}"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via nftables"),
                };
            }

            let element = format!("{{ {ip} }}");
            let output = tokio::process::Command::new("sudo")
                .args([
                    "nft",
                    "add",
                    "element",
                    "inet",
                    "filter",
                    "blacklist",
                    &element,
                ])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "added to nftables blacklist");
                    SkillResult {
                        success: true,
                        message: format!("Added {ip} to nftables blacklist"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "nftables block command failed");
                    SkillResult {
                        success: false,
                        message: format!("nftables block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn nft command");
                    SkillResult {
                        success: false,
                        message: format!("failed to run nft: {e}"),
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
    async fn dry_run_nftables() {
        let ctx = make_ctx(Some("1.2.3.4"));
        let result = BlockIpNftables.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("1.2.3.4"));
    }

    #[tokio::test]
    async fn no_target_ip_nftables() {
        let ctx = make_ctx(None);
        let result = BlockIpNftables.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[test]
    fn skill_metadata_nftables() {
        assert_eq!(BlockIpNftables.id(), "block-ip-nftables");
        assert!(BlockIpNftables.name().contains("nftables"));
        assert_eq!(BlockIpNftables.tier(), SkillTier::Open);
        assert!(BlockIpNftables.applicable_to().contains(&"ssh_bruteforce"));
    }

    #[tokio::test]
    async fn rejects_invalid_target_before_spawn() {
        for bad in ["129.950.5.0", "130.890.9.0", "not-an-ip", ""] {
            let ctx = make_ctx(Some(bad));
            let result = BlockIpNftables.execute(&ctx, true).await;
            assert!(!result.success, "'{bad}' should be rejected");
        }
    }

    #[tokio::test]
    async fn dry_run_accepts_valid_cidr() {
        let ctx = make_ctx(Some("10.0.0.0/24"));
        let result = BlockIpNftables.execute(&ctx, true).await;
        assert!(result.success);
    }
}
