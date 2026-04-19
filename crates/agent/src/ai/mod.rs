mod anthropic;
mod azure_openai;
#[cfg(feature = "local-classifier")]
mod local_classifier;
mod ollama;
mod openai;
mod shadow;
mod stub;

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;
use async_trait::async_trait;
use innerwarden_core::{entities::EntityType, event::Event, incident::Incident};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::AiConfig;

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// The action the AI recommends (and may auto-execute).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AiAction {
    /// Block the attacking IP immediately via the configured firewall backend.
    /// `skill_id` is the skill the AI selected (e.g. "block-ip-ufw").
    BlockIp { ip: String, skill_id: String },

    /// Shadow-monitor the IP - log all its activity without blocking.
    /// Premium feature stub; community can implement full tracking.
    Monitor { ip: String },

    /// Trigger honeypot response.
    /// Behavior depends on runtime mode:
    /// - `demo`: synthetic marker
    /// - `listener`: bounded multi-service decoy listeners with optional redirect
    Honeypot { ip: String },

    /// Temporarily suspend sudo privileges for a user.
    /// Implemented by the `suspend-user-sudo` skill using a sudoers drop-in.
    SuspendUserSudo { user: String, duration_secs: u64 },

    /// Kill all processes owned by a user (pkill -9 -u <user>).
    /// Used for suspicious execution incidents.
    KillProcess { user: String, duration_secs: u64 },

    /// Pause or stop a Docker container in response to an anomaly.
    /// `action` is "pause" (default, reversible) or "stop".
    BlockContainer {
        container_id: String,
        action: String,
    },

    /// Send a confirmation request to the operator webhook before acting.
    RequestConfirmation { summary: String },

    /// Execute the kill-chain-response skill: kill process, block C2, capture forensics.
    /// Triggered when the eBPF LSM blocks a kill chain pattern.
    KillChainResponse { reason: String },

    /// No action required - false positive or already handled.
    Ignore { reason: String },
}

/// The structured decision returned by an AI provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDecision {
    pub action: AiAction,

    /// Confidence score 0.0–1.0. Below the configured threshold, the decision
    /// is logged but NOT auto-executed even if `auto_execute` is true.
    pub confidence: f32,

    /// Whether the AI considers this safe to execute automatically.
    pub auto_execute: bool,

    /// Human-readable explanation of the reasoning.
    pub reason: String,

    /// Alternative actions the AI considered.
    pub alternatives: Vec<String>,

    /// Estimated threat level: "low" | "medium" | "high" | "critical"
    pub estimated_threat: String,
}

impl AiAction {
    /// Short name used as the action key in trust rules (e.g. "block_ip").
    pub fn name(&self) -> &'static str {
        match self {
            AiAction::BlockIp { .. } => "block_ip",
            AiAction::Monitor { .. } => "monitor",
            AiAction::Honeypot { .. } => "honeypot",
            AiAction::SuspendUserSudo { .. } => "suspend_user_sudo",
            AiAction::KillProcess { .. } => "kill_process",
            AiAction::BlockContainer { .. } => "block_container",
            AiAction::RequestConfirmation { .. } => "request_confirmation",
            AiAction::KillChainResponse { .. } => "kill_chain_response",
            AiAction::Ignore { .. } => "ignore",
        }
    }
}

impl AiDecision {
    /// Convenience constructor for a no-op decision.
    #[allow(dead_code)]
    pub fn ignore(reason: impl Into<String>) -> Self {
        Self {
            action: AiAction::Ignore {
                reason: reason.into(),
            },
            confidence: 1.0,
            auto_execute: false,
            reason: String::new(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Context passed to the AI provider
// ---------------------------------------------------------------------------

pub struct DecisionContext<'a> {
    pub incident: &'a Incident,
    /// Recent events from the same entity (IP/user) for contextual analysis
    pub recent_events: Vec<&'a Event>,
    /// Temporally correlated incidents sharing pivot(s) (ip/user/detector kind)
    pub related_incidents: Vec<&'a Incident>,
    /// IPs already in the blocklist (to avoid duplicate blocks)
    pub already_blocked: Vec<String>,
    /// Available skill IDs (sent to the AI so it can select the right one)
    pub available_skills: Vec<SkillInfo>,
    /// Optional AbuseIPDB reputation data for the primary IP (enrichment).
    pub ip_reputation: Option<crate::abuseipdb::IpReputation>,
    /// Optional geolocation data for the primary IP (enrichment via ip-api.com).
    pub ip_geo: Option<crate::geoip::GeoInfo>,
    /// Knowledge graph context: attack narrative + impact analysis.
    /// Generated by `knowledge_graph::narrative::attack_narrative()`.
    ///
    /// Kept as a fallback — when `graph_subgraph` is populated, provider
    /// `build_prompt` implementations prefer the structured JSON. The
    /// prose form is still generated because the decision audit trail and
    /// the dashboard narrative consume it.
    pub graph_context: Option<String>,
    /// Spec 025: same neighbourhood as `graph_context`, rendered as a
    /// compact `{nodes, edges}` JSON payload. Measured on qwen2.5:3b:
    /// 53% → 73% action accuracy when the LLM consumes the subgraph
    /// directly instead of re-deriving structure from prose.
    pub graph_subgraph: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkillInfo {
    pub id: String,
    /// Incident kinds this skill applies to (empty = all).
    /// Serialized to AI so it can match skills to incident types.
    pub applicable_to: Vec<String>,
}

// ---------------------------------------------------------------------------
// AiProvider trait - implement this to add a new provider
// ---------------------------------------------------------------------------

/// Implement this trait to add a new AI provider to Inner Warden.
///
/// Open-source contributions welcome: https://github.com/InnerWarden/innerwarden
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Short identifier shown in logs, e.g. "openai", "anthropic".
    fn name(&self) -> &'static str;

    /// Analyse an incident and return a decision.
    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision>;

    /// Send a free-form chat message with a system prompt and get a plain-text response.
    /// Used by the Telegram conversational bot.
    async fn chat(&self, system_prompt: &str, user_message: &str) -> Result<String>;
}

// ---------------------------------------------------------------------------
// Algorithm gate - runs BEFORE calling the AI (no I/O, no cost)
// ---------------------------------------------------------------------------

/// Returns true if the incident is worth sending to the AI provider.
///
/// Avoids wasting API calls on noise or already-handled incidents.
pub fn should_invoke_ai(
    incident: &Incident,
    already_blocked: &HashSet<String>,
    min_severity: &innerwarden_core::event::Severity,
) -> bool {
    use innerwarden_core::event::Severity;

    // Check against configured minimum severity
    let dominated_by_min = match min_severity {
        Severity::Low => matches!(incident.severity, Severity::Debug | Severity::Info),
        Severity::Medium => matches!(
            incident.severity,
            Severity::Debug | Severity::Info | Severity::Low
        ),
        Severity::High => !matches!(incident.severity, Severity::High | Severity::Critical),
        Severity::Critical => !matches!(incident.severity, Severity::Critical),
        _ => true,
    };
    if dominated_by_min {
        return false;
    }

    // Extract the primary IP entity from the incident
    let ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.as_str());

    if let Some(ip_str) = ip {
        // Skip if already blocked
        if already_blocked.contains(ip_str) {
            return false;
        }

        // Skip RFC1918 / loopback / link-local - these are internal and
        // should not be auto-blocked without deeper investigation
        if let Ok(addr) = ip_str.parse::<IpAddr>() {
            if is_private_or_loopback(addr) {
                info!(ip = ip_str, "skipping AI analysis for private/loopback IP");
                return false;
            }
        }
    }

    true
}

/// Check if incident severity is strictly below the configured min_severity threshold.
/// Extracted so `incident_flow` can distinguish "below severity" from other skip reasons.
pub fn is_below_severity_threshold(
    severity: &innerwarden_core::event::Severity,
    min_severity: &innerwarden_core::event::Severity,
) -> bool {
    use innerwarden_core::event::Severity;
    match min_severity {
        Severity::Low => matches!(severity, Severity::Debug | Severity::Info),
        Severity::Medium => matches!(severity, Severity::Debug | Severity::Info | Severity::Low),
        Severity::High => !matches!(severity, Severity::High | Severity::Critical),
        Severity::Critical => !matches!(severity, Severity::Critical),
        _ => true,
    }
}

/// Check if an IP is private (RFC1918, link-local, etc.).
/// Exported for use by enrichment backfill to skip non-routable IPs.
pub fn is_private_ip(addr: IpAddr) -> bool {
    is_private_or_loopback(addr)
}

fn is_private_or_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// Factory - creates the right provider based on config
// ---------------------------------------------------------------------------

/// Known OpenAI-compatible providers and their default base URLs + models.
/// Any provider that speaks the `/v1/chat/completions` format works here.
const OPENAI_COMPATIBLE: &[(&str, &str, &str)] = &[
    // (provider name, default base_url, default model)
    ("openai", "https://api.openai.com", "gpt-4o-mini"),
    (
        "groq",
        "https://api.groq.com/openai",
        "llama-3.3-70b-versatile",
    ),
    ("deepseek", "https://api.deepseek.com", "deepseek-chat"),
    (
        "together",
        "https://api.together.xyz",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    ),
    ("minimax", "https://api.minimaxi.chat", "MiniMax-Text-01"),
    ("mistral", "https://api.mistral.ai", "mistral-small-latest"),
    ("xai", "https://api.x.ai", "grok-3-mini-fast"),
    (
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-2.0-flash",
    ),
    (
        "fireworks",
        "https://api.fireworks.ai/inference",
        "accounts/fireworks/models/llama-v3p3-70b-instruct",
    ),
    (
        "openrouter",
        "https://openrouter.ai/api",
        "meta-llama/llama-3.3-70b-instruct",
    ),
];

/// Reject plain HTTP for remote AI provider endpoints.
/// Only `localhost` / `127.0.0.1` / `[::1]` are allowed over HTTP.
fn validate_ai_base_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Ok(());
    }
    if url.starts_with("http://") {
        let host_part = url.strip_prefix("http://").unwrap_or("");
        let host = host_part
            .split(':')
            .next()
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("");
        if host != "localhost" && host != "127.0.0.1" && host != "::1" && host != "[::1]" {
            anyhow::bail!(
                "HTTP is not allowed for remote AI providers (use HTTPS). Got: {}",
                url
            );
        }
    }
    Ok(())
}

pub fn build_provider(cfg: &AiConfig) -> Result<Box<dyn AiProvider>> {
    let primary = build_single(
        &cfg.provider,
        cfg.resolved_api_key(),
        &cfg.model,
        &cfg.base_url,
        &cfg.api_version,
        cfg.confidence_threshold,
    )?;

    if cfg.shadow.enabled {
        if cfg.shadow.provider.is_empty() {
            anyhow::bail!("[ai.shadow].enabled is true but provider is empty");
        }
        if cfg.shadow.provider == cfg.provider
            && cfg.shadow.base_url == cfg.base_url
            && cfg.shadow.model == cfg.model
        {
            anyhow::bail!(
                "[ai.shadow] must differ from [ai] primary (same provider+base_url+model configured)"
            );
        }
        let shadow = build_single(
            &cfg.shadow.provider,
            cfg.shadow.resolved_api_key(),
            &cfg.shadow.model,
            &cfg.shadow.base_url,
            &cfg.shadow.api_version,
            cfg.confidence_threshold,
        )?;
        tracing::info!(
            primary = %cfg.provider,
            shadow = %cfg.shadow.provider,
            log_path = %cfg.shadow.log_path,
            "shadow mode enabled"
        );
        return Ok(Box::new(shadow::ShadowProvider::new(
            primary,
            shadow,
            &cfg.shadow.log_path,
        )));
    }

    Ok(primary)
}

/// Build a single provider from flat parameters. Extracted so the same logic
/// can be reused by the shadow-mode path.
fn build_single(
    provider: &str,
    api_key: String,
    model: &str,
    base_url: &str,
    api_version: &str,
    #[allow(unused_variables)] confidence_threshold: f32,
) -> Result<Box<dyn AiProvider>> {
    // Suppress unused warning when local-classifier feature is off
    let _ = confidence_threshold;
    // Spec 024 — deterministic stub used by the scenario-qa harness. Returns
    // fixed decisions per detector kind so scenario envelopes stay stable
    // across runs. Opt-in only (provider = "stub"); has no effect on
    // production configs.
    if provider == "stub" {
        return Ok(Box::new(stub::StubAiProvider::new()));
    }

    // Check if provider is OpenAI-compatible (including "openai" itself)
    if let Some(&(_, default_url, default_model)) = OPENAI_COMPATIBLE
        .iter()
        .find(|&&(name, _, _)| name == provider)
    {
        let base_url = if base_url.is_empty() {
            default_url.to_string()
        } else {
            validate_ai_base_url(base_url)?;
            base_url.to_string()
        };
        let model = if model.is_empty() {
            default_model.to_string()
        } else {
            model.to_string()
        };
        return Ok(Box::new(openai::OpenAiProvider::with_base_url(
            api_key, model, base_url,
        )));
    }

    match provider {
        #[cfg(feature = "local-classifier")]
        "local_classifier" => {
            if base_url.is_empty() {
                anyhow::bail!(
                    "local_classifier requires base_url = <dir with model.onnx + tokenizer.json>"
                );
            }
            let dir = std::path::Path::new(base_url);
            let threshold = if confidence_threshold > 0.0 {
                confidence_threshold
            } else {
                0.85
            };
            Ok(Box::new(local_classifier::LocalClassifier::from_dir(
                dir, threshold,
            )?))
        }
        #[cfg(not(feature = "local-classifier"))]
        "local_classifier" => {
            anyhow::bail!(
                "local_classifier provider requires building innerwarden-agent with --features local-classifier"
            )
        }
        "azure_openai" => {
            if base_url.is_empty() {
                anyhow::bail!(
                    "azure_openai requires base_url (e.g. https://<resource>.openai.azure.com)"
                );
            }
            validate_ai_base_url(base_url)?;
            if model.is_empty() {
                anyhow::bail!(
                    "azure_openai requires model = <deployment-name> (as configured in Azure AI Foundry)"
                );
            }
            let api_version = if api_version.is_empty() {
                "2024-12-01-preview".to_string()
            } else {
                api_version.to_string()
            };
            Ok(Box::new(azure_openai::AzureOpenAiProvider::new(
                api_key,
                model.to_string(),
                base_url.to_string(),
                api_version,
            )))
        }
        "anthropic" => Ok(Box::new(anthropic::AnthropicProvider::new(
            api_key,
            model.to_string(),
        ))),
        "ollama" => {
            let api_key_opt = if api_key.is_empty() { None } else { Some(api_key) };

            let base_url = if !base_url.is_empty() {
                validate_ai_base_url(base_url)?;
                base_url.to_string()
            } else if api_key_opt.is_some() {
                "https://api.ollama.com".to_string()
            } else {
                let env_url = std::env::var("OLLAMA_BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:11434".to_string());
                validate_ai_base_url(&env_url)?;
                env_url
            };

            let model = if model.is_empty() || model == "gpt-4o-mini" {
                if api_key_opt.is_some() {
                    "qwen3-coder:480b".to_string()
                } else {
                    "llama3.2".to_string()
                }
            } else {
                model.to_string()
            };
            Ok(Box::new(ollama::OllamaProvider::new(
                base_url, model, api_key_opt,
            )))
        }
        other => {
            // SEC-017: Unknown provider name — require explicit base_url.
            // If base_url is set, treat as OpenAI-compatible endpoint.
            // Without base_url, fail closed to prevent accidental data egress.
            if !base_url.is_empty() {
                validate_ai_base_url(base_url)?;
                tracing::info!(
                    provider = other,
                    base_url = %base_url,
                    "treating unknown provider as OpenAI-compatible via base_url"
                );
                Ok(Box::new(openai::OpenAiProvider::with_base_url(
                    api_key,
                    model.to_string(),
                    base_url.to_string(),
                )))
            } else {
                anyhow::bail!(
                    "unknown AI provider '{}'. Set provider to 'openai', 'anthropic', \
                     or 'ollama', or provide a base_url for OpenAI-compatible endpoints.",
                    other
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};

    fn make_incident(severity: Severity, ip: &str) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "host".into(),
            incident_id: "test-id".into(),
            severity,
            title: "Test".into(),
            summary: "test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    #[test]
    fn gate_passes_high_severity_external_ip() {
        let inc = make_incident(Severity::High, "1.2.3.4");
        assert!(should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn gate_passes_medium_severity_with_medium_config() {
        let inc = make_incident(Severity::Medium, "1.2.3.4");
        assert!(should_invoke_ai(&inc, &HashSet::new(), &Severity::Medium));
    }

    #[test]
    fn gate_blocks_medium_with_high_config() {
        let inc = make_incident(Severity::Medium, "1.2.3.4");
        assert!(!should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn gate_blocks_already_blocked_ip() {
        let inc = make_incident(Severity::High, "1.2.3.4");
        let mut blocked = HashSet::new();
        blocked.insert("1.2.3.4".to_string());
        assert!(!should_invoke_ai(&inc, &blocked, &Severity::High));
    }

    #[test]
    fn gate_blocks_low_severity() {
        let inc = make_incident(Severity::Low, "1.2.3.4");
        assert!(!should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn gate_blocks_private_ip() {
        let inc = make_incident(Severity::High, "192.168.1.100");
        assert!(!should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn gate_blocks_loopback() {
        let inc = make_incident(Severity::Critical, "127.0.0.1");
        assert!(!should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn ignore_decision_helper() {
        let d = AiDecision::ignore("test reason");
        assert!(matches!(d.action, AiAction::Ignore { .. }));
        assert!(!d.auto_execute);
    }

    // SEC-017: Unknown provider without base_url must fail.
    #[test]
    fn build_provider_unknown_no_base_url_fails() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "nonexistent-provider".into(),
            base_url: String::new(),
            ..Default::default()
        };
        let result = build_provider(&cfg);
        assert!(
            result.is_err(),
            "should fail for unknown provider without base_url"
        );
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("unknown AI provider"),
            "expected 'unknown AI provider' error, got: {err}"
        );
    }

    #[test]
    fn build_provider_unknown_with_base_url_succeeds() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "custom-llm".into(),
            base_url: "https://my-llm.example.com".into(),
            api_key: "test-key".into(),
            model: "my-model".into(),
            ..Default::default()
        };
        let result = build_provider(&cfg);
        assert!(
            result.is_ok(),
            "should accept unknown provider with base_url"
        );
    }

    #[test]
    fn build_provider_known_provider_succeeds() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "ollama".into(),
            ..Default::default()
        };
        let result = build_provider(&cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn build_provider_stub_succeeds_without_api_key() {
        // Spec 024: the scenario-qa harness must be able to build a provider
        // without any API key or external service. This is the contract.
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let provider = build_provider(&cfg).expect("stub provider must build offline");
        assert_eq!(provider.name(), "stub");
    }
}
