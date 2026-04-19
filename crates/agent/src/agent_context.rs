use std::path::Path;

use crate::{bot_helpers, config, knowledge_graph, telegram};

pub(crate) fn incident_detector(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("unknown")
}

/// Returns the current guardian mode based on responder configuration.
pub(crate) fn guardian_mode(cfg: &config::AgentConfig) -> telegram::GuardianMode {
    if !cfg.responder.enabled {
        telegram::GuardianMode::Watch
    } else if cfg.responder.dry_run {
        telegram::GuardianMode::DryRun
    } else {
        telegram::GuardianMode::Guard
    }
}

/// Builds a rich system-state context string injected into every AI chat call.
/// The AI uses this to answer self-awareness questions accurately and give
/// correct configuration advice.
pub(crate) fn build_agent_context(
    cfg: &config::AgentConfig,
    data_dir: &Path,
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
) -> String {
    let mode = guardian_mode(cfg);
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let incident_count = bot_helpers::graph_count(kg, "incidents");
    let decision_count = bot_helpers::graph_count(kg, "decisions");
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());

    let skills_list = cfg.responder.allowed_skills.join(", ");
    let block_backend = &cfg.responder.block_backend;
    let ai_status = if cfg.ai.enabled {
        format!(
            "ENABLED - provider={}, model={}",
            cfg.ai.provider, cfg.ai.model
        )
    } else {
        "DISABLED".to_string()
    };
    let responder_status = if !cfg.responder.enabled {
        "DISABLED (watch-only mode)".to_string()
    } else if cfg.responder.dry_run {
        "ENABLED - dry-run (simulates actions, no real execution)".to_string()
    } else {
        format!("ENABLED - live mode (backend={block_backend})")
    };
    let telegram_status = if cfg.telegram.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let abuseipdb_status = if cfg.abuseipdb.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let geoip_status = if cfg.geoip.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let fail2ban_status = if cfg.fail2ban.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let slack_status = if cfg.slack.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let cloudflare_status = if cfg.cloudflare.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };

    format!(
        "=== INNERWARDEN SYSTEM STATE ===\n\
         Host: {host}\n\
         Version: {version}\n\
         Mode: {mode_label} - {mode_desc}\n\
         Data dir: {data_dir}\n\
         \n\
         Today ({today}): {incident_count} intrusion attempts, {decision_count} actions taken\n\
         \n\
         === ACTIVE CONFIGURATION ===\n\
         Responder: {responder_status}\n\
         Allowed skills: {skills_list}\n\
         AI analysis: {ai_status}\n\
         Telegram bot: {telegram_status}\n\
         AbuseIPDB enrichment: {abuseipdb_status}\n\
         GeoIP enrichment: {geoip_status}\n\
         Fail2ban integration: {fail2ban_status}\n\
         Slack notifications: {slack_status}\n\
         Cloudflare edge blocking: {cloudflare_status}\n\
         \n\
         === AVAILABLE CAPABILITIES (innerwarden enable/disable <id>) ===\n\
         - ai: AI-powered incident analysis (params: provider=openai|anthropic|ollama, model=...)\n\
         - block-ip: Firewall blocking of attacking IPs (params: backend=ufw|iptables|nftables|pf)\n\
         - sudo-protection: Detect sudo abuse + auto-suspend attacker privileges\n\
         - shell-audit: Audit shell command execution (privacy gate required)\n\
         - search-protection: Protect search/API endpoints from scraping bots\n\
         \n\
         === AVAILABLE SKILLS (agent execution layer) ===\n\
         Open tier: block-ip-ufw, block-ip-iptables, block-ip-nftables, block-ip-pf, suspend-user-sudo, rate-limit-nginx\n\
         Premium tier: monitor-ip (packet capture), honeypot (attacker trap)\n\
         \n\
         === CLI REFERENCE ===\n\
         innerwarden enable <capability>         # activate a capability\n\
         innerwarden disable <capability>        # deactivate a capability\n\
         innerwarden status                      # full system overview\n\
         innerwarden doctor                      # health check with fix hints\n\
         innerwarden scan                        # detect installed tools, recommend modules\n\
         innerwarden list                        # list all capabilities with status\n\
         innerwarden configure responder         # set GUARD/WATCH/DRY-RUN mode\n\
         innerwarden notify telegram             # setup Telegram bot\n\
         innerwarden notify slack                # setup Slack webhook\n\
         innerwarden integrate abuseipdb         # IP reputation enrichment\n\
         innerwarden integrate geoip             # GeoIP enrichment (free)\n\
         innerwarden integrate fail2ban          # sync with fail2ban bans\n\
         innerwarden block <ip> --reason <r>     # manual IP block\n\
         innerwarden unblock <ip>                # remove IP block\n\
         innerwarden incidents --days 7          # list recent incidents\n\
         innerwarden decisions --days 7          # list recent decisions\n\
         innerwarden report                      # show operational report\n\
         innerwarden tune                        # auto-tune detector thresholds\n\
         ",
        host = host,
        version = env!("CARGO_PKG_VERSION"),
        mode_label = mode.label(),
        mode_desc = mode.description(),
        data_dir = data_dir.display(),
    )
}

/// Merge a persona string, the runtime snapshot, recent incidents, and recent
/// decisions into one system prompt. Empty-string inputs are skipped so the
/// prompt never carries dangling "RECENT INCIDENTS:" headers with no body.
/// Centralised here so every chat surface (Telegram bot, dashboard briefing,
/// dashboard explain) composes the same prompt shape.
pub(crate) fn compose_system_prompt(
    persona: &str,
    runtime_snapshot: &str,
    recent_incidents: &str,
    recent_decisions: &str,
) -> String {
    let mut out = String::with_capacity(
        persona.len()
            + runtime_snapshot.len()
            + recent_incidents.len()
            + recent_decisions.len()
            + 128,
    );
    out.push_str(persona.trim_end());
    if !runtime_snapshot.is_empty() {
        out.push_str("\n\n");
        out.push_str(runtime_snapshot.trim_end());
    }
    if !recent_incidents.is_empty() {
        out.push_str("\n\nRECENT INCIDENTS:\n");
        out.push_str(recent_incidents.trim_end());
    }
    if !recent_decisions.is_empty() {
        out.push_str("\n\nRECENT DECISIONS:\n");
        out.push_str(recent_decisions.trim_end());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::Node;

    #[test]
    fn incident_detector_parses_prefix() {
        assert_eq!(
            incident_detector("ssh_bruteforce:1.2.3.4:abc"),
            "ssh_bruteforce"
        );
        assert_eq!(incident_detector("singleword"), "singleword");
    }

    #[test]
    fn guardian_mode_maps_responder_state() {
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = false;
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Watch));

        cfg.responder.enabled = true;
        cfg.responder.dry_run = true;
        assert!(matches!(
            guardian_mode(&cfg),
            telegram::GuardianMode::DryRun
        ));

        cfg.responder.dry_run = false;
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Guard));
    }

    #[test]
    fn build_agent_context_includes_runtime_snapshot() {
        let mut cfg = config::AgentConfig::default();
        cfg.ai.enabled = true;
        cfg.ai.provider = "openai".to_string();
        cfg.ai.model = "gpt-5".to_string();
        cfg.responder.enabled = true;
        cfg.responder.dry_run = false;
        cfg.responder.block_backend = "ufw".to_string();
        cfg.responder.allowed_skills = vec!["block-ip-ufw".to_string(), "honeypot".to_string()];
        cfg.telegram.enabled = true;
        cfg.abuseipdb.enabled = true;
        cfg.geoip.enabled = true;
        cfg.fail2ban.enabled = true;
        cfg.slack.enabled = true;
        cfg.cloudflare.enabled = true;

        let mut graph = knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:198.51.100.10:1".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "SSH brute-force".to_string(),
            summary: "many attempts".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".to_string()),
            confidence: Some(0.95),
            decision_reason: Some("clear brute force".to_string()),
            decision_target: Some("198.51.100.10".to_string()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_node(Node::Incident {
            incident_id: "port_scan:198.51.100.11:2".to_string(),
            detector: "port_scan".to_string(),
            severity: "medium".to_string(),
            title: "Port scan".to_string(),
            summary: "multiple ports".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: None,
            confidence: None,
            decision_reason: None,
            decision_target: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));

        let context = build_agent_context(&cfg, std::path::Path::new("/tmp/innerwarden"), &kg);

        assert!(context.contains("INNERWARDEN SYSTEM STATE"));
        assert!(context.contains("Mode: 🟢 GUARD"));
        assert!(context.contains("intrusion attempts, 1 actions taken"));
        assert!(context.contains("AI analysis: ENABLED - provider=openai, model=gpt-5"));
        assert!(context.contains("Telegram bot: ENABLED"));
        assert!(context.contains("Cloudflare edge blocking: ENABLED"));
        assert!(context.contains("Allowed skills: block-ip-ufw, honeypot"));
    }

    #[test]
    fn compose_system_prompt_includes_persona_only_when_others_empty() {
        let out = compose_system_prompt("persona-body", "", "", "");
        assert_eq!(out, "persona-body");
    }

    #[test]
    fn compose_system_prompt_appends_runtime_when_present() {
        let out = compose_system_prompt("p", "SNAP", "", "");
        assert!(out.starts_with("p"));
        assert!(out.contains("SNAP"));
        assert!(!out.contains("RECENT INCIDENTS"));
        assert!(!out.contains("RECENT DECISIONS"));
    }

    #[test]
    fn compose_system_prompt_labels_recent_sections() {
        let out = compose_system_prompt(
            "p",
            "SNAP",
            "[high] title - summary",
            "- block_ip 1.2.3.4 (auto)",
        );
        assert!(out.contains("RECENT INCIDENTS:\n[high] title - summary"));
        assert!(out.contains("RECENT DECISIONS:\n- block_ip 1.2.3.4 (auto)"));
        // Sections must appear in the stable order persona -> snapshot -> incidents -> decisions.
        let idx_snap = out.find("SNAP").unwrap();
        let idx_inc = out.find("RECENT INCIDENTS").unwrap();
        let idx_dec = out.find("RECENT DECISIONS").unwrap();
        assert!(idx_snap < idx_inc && idx_inc < idx_dec);
    }

    #[test]
    fn compose_system_prompt_omits_headers_for_empty_sections() {
        // An empty decisions string should not leave a dangling "RECENT
        // DECISIONS:" header in the prompt.
        let out = compose_system_prompt("p", "", "[high] x - y", "");
        assert!(out.contains("RECENT INCIDENTS"));
        assert!(!out.contains("RECENT DECISIONS"));
    }

    #[test]
    fn test_incident_detector_edge_cases() {
        assert_eq!(incident_detector(""), "");
        assert_eq!(incident_detector(":"), "");
        assert_eq!(incident_detector("ssh:brute:force"), "ssh");
    }

    #[test]
    fn test_guardian_mode_default_state() {
        let cfg = config::AgentConfig::default();
        // default responder.enabled is false
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Watch));
    }

    #[test]
    fn test_build_agent_context_all_disabled() {
        let mut cfg = config::AgentConfig::default();
        // Explicitly disable things that might be enabled by default in AgentConfig::default()
        cfg.firmware.enabled = false;
        cfg.hypervisor.enabled = false;
        cfg.killchain.enabled = false;
        cfg.dna.enabled = false;
        cfg.shield.enabled = false;
        cfg.narrative.enabled = false;
        cfg.briefing.enabled = false;

        let graph = knowledge_graph::KnowledgeGraph::new();
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));

        let context = build_agent_context(&cfg, std::path::Path::new("/var/lib/innerwarden"), &kg);

        assert!(context.contains("Mode: 🔵 WATCH"));
        assert!(context.contains("AI analysis: DISABLED"));
        assert!(context.contains("Telegram bot: DISABLED"));
        assert!(context.contains("AbuseIPDB enrichment: DISABLED"));
        assert!(context.contains("GeoIP enrichment: DISABLED"));
        assert!(context.contains("Fail2ban integration: DISABLED"));
        assert!(context.contains("Slack notifications: DISABLED"));
        assert!(context.contains("Cloudflare edge blocking: DISABLED"));
    }
}
