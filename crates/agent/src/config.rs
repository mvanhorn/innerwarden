use std::path::Path;

use anyhow::{Context, Result};
use innerwarden_core::event::Severity;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct AgentConfig {
    #[serde(default)]
    pub narrative: NarrativeConfig,
    #[serde(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub correlation: CorrelationConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub honeypot: HoneypotConfig,
    #[serde(default)]
    pub responder: ResponderConfig,
    #[serde(default)]
    pub telegram: TelegramConfig,
    #[serde(default)]
    pub data: DataRetentionConfig,
    #[serde(default)]
    pub crowdsec: CrowdSecConfig,
    #[serde(default)]
    pub abuseipdb: AbuseIpDbConfig,
    #[serde(default)]
    pub fail2ban: Fail2BanConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub threat_feeds: ThreatFeedsConfig,
    #[serde(default)]
    pub slack: SlackConfig,
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub web_push: WebPushConfig,
    /// Mesh collaborative defense network
    #[serde(default)]
    pub mesh: MeshNetworkConfig,
    /// Dashboard settings
    #[serde(default)]
    pub dashboard: DashboardConfig,
    /// Firmware security monitoring (innerwarden-smm)
    #[serde(default)]
    pub firmware: FirmwareConfig,
    /// Hypervisor security monitoring (innerwarden-hypervisor)
    #[serde(default)]
    pub hypervisor: HypervisorConfig,
    /// Kill chain detection (innerwarden-killchain)
    #[serde(default)]
    pub killchain: KillchainConfig,
    /// Threat DNA behavioral fingerprinting (innerwarden-dna)
    #[serde(default)]
    pub dna: DnaConfig,
    /// DDoS Shield — rate limiting, SYN tracking, escalation (innerwarden-shield)
    #[serde(default)]
    pub shield: ShieldConfig,
    /// Security settings (2FA, etc.)
    #[serde(default)]
    pub security: Option<SecurityConfig>,
    /// Notification pipeline settings (grouping, filtering).
    #[serde(default)]
    pub notifications: NotificationPipelineConfig,
    /// Environment auto-profiling and census.
    #[serde(default)]
    pub environment: EnvironmentConfig,
    /// Redis URL for reading events from Redis Streams instead of JSONL files.
    /// When set, events are consumed via XREADGROUP. Incidents still read from JSONL.
    #[serde(default)]
    #[cfg_attr(not(feature = "redis-reader"), allow(dead_code))]
    pub redis_url: Option<String>,
    /// Redis stream name for events. Default: "innerwarden:events".
    #[serde(default)]
    #[cfg_attr(not(feature = "redis-reader"), allow(dead_code))]
    pub redis_stream: Option<String>,
    /// Daily AI intelligence briefing
    #[serde(default)]
    pub briefing: BriefingConfig,
    /// Config signing verification (Active Defence).
    #[serde(default)]
    #[allow(dead_code)] // parsed for future signing-verification integration
    pub config_signing: ConfigSigningConfig,
    /// Observation verification — behavioural scoring for OBSERVING items (spec 021).
    #[serde(default)]
    pub observation: crate::observation_verify::ObservationConfig,
    /// Trust scoring engine — continuous entity trust scores (spec 020 Phase C).
    #[serde(default)]
    #[allow(dead_code)]
    pub trust_scoring: crate::trust_scoring::TrustScoringConfig,
    /// SOC daily checks — system health checks at configurable hour (spec 020 Phase D).
    #[serde(default)]
    #[allow(dead_code)]
    pub soc_checks: crate::soc_checks::SocChecksConfig,
    /// Zero trust enforcement modes — learning | notify | enforce (spec 020 Phase F).
    #[serde(default)]
    #[allow(dead_code)]
    pub zero_trust: crate::zero_trust::ZeroTrustConfig,
    /// Detectors that run graph-only (sensor version suppressed).
    /// After parallel validation, add detector names here to disable the sensor version.
    /// Example: ["threat_intel", "lateral_movement", "persistence"]
    #[serde(default)]
    pub graph_only_detectors: Vec<String>,
    /// Incident lifecycle flow configuration (spec 028).
    #[serde(default)]
    pub incident_flow: IncidentFlowConfig,
}

/// Incident lifecycle routing knobs (spec 028).
///
/// The only knob currently live is the `escalate_to_decide` feature flag. When
/// true, observation-verify's Escalate branch is expected to forward incidents
/// into the Fase 4 `ai_provider.decide()` pipeline so attackers that score
/// above the escalate threshold actually get actioned instead of sitting under
/// the OBSERVING bucket forever.
///
/// Default is `false` because the full wiring (threading the provider + skill
/// executor + state into narrative_observation_verify) is intentionally
/// staged: this PR lands the flag + config, the follow-up PR lands the decide
/// call. See spec 028 section 028-b.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct IncidentFlowConfig {
    /// When true, Escalate from observation-verify should trigger a Fase 4
    /// decide() call. The wiring itself is a follow-up PR; today the flag
    /// is read but the code path only logs an intent line. Flip to true in
    /// /etc/innerwarden/agent.toml after the wiring PR lands.
    #[serde(default)]
    pub escalate_to_decide: bool,
    /// Detector prefixes whose incidents should skip the Fase 3 observation
    /// verifier entirely and go direct to Fase 4. The spec lists
    /// `threat_intel:*`, `sudo_abuse:*`, and `suspicious_execution:*` as
    /// candidates because they are inherently high-signal. Matched via
    /// prefix (case-sensitive). Empty by default; the skip path is also
    /// Consumed by `incident_flow::evaluate_pre_ai_flow` (spec 028-b
    /// full wiring): when the incident id starts with any entry in
    /// this list (optionally followed by `:`), the pre-AI gate
    /// bypasses the below-severity and decision-cooldown guards so
    /// the incident reaches `ai_provider.decide()`. Allowlist and
    /// per-tick budget still apply.
    #[serde(default)]
    pub detectors_skip_fase3: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ConfigSigningConfig {
    /// When true, agent refuses to start if signature is missing or invalid.
    #[serde(default)]
    pub required: bool,
    /// Hex-encoded Ed25519 public key for signature verification.
    #[serde(default)]
    pub public_key: Option<String>,
}

/// Dashboard config - trusted proxy IPs and other dashboard-related settings.
#[derive(Debug, Deserialize)]
pub struct DashboardConfig {
    /// List of trusted reverse-proxy IPs. Only when the connecting IP is in
    /// this list will X-Forwarded-For / X-Real-IP headers be honoured.
    /// Example: `["127.0.0.1", "::1", "10.0.0.1"]`
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Session inactivity timeout in minutes. Default: 480 (8 hours).
    #[serde(default = "default_session_timeout_minutes")]
    pub session_timeout_minutes: u64,
    /// Maximum number of concurrent sessions per user. Default: 5.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: vec![],
            session_timeout_minutes: default_session_timeout_minutes(),
            max_sessions: default_max_sessions(),
        }
    }
}

fn default_session_timeout_minutes() -> u64 {
    480
}
fn default_max_sessions() -> usize {
    5
}

/// Firmware security monitoring via innerwarden-smm.
#[derive(Debug, Deserialize)]
pub struct FirmwareConfig {
    /// Enable periodic firmware audits. Default: true.
    #[serde(default = "default_firmware_enabled")]
    pub enabled: bool,
    /// Audit interval in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_firmware_poll_secs")]
    pub poll_secs: u64,
    /// Trust score threshold for emitting incidents. Default: 0.85.
    #[serde(default = "default_firmware_trust_threshold")]
    pub trust_score_threshold: f64,
}

impl Default for FirmwareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_secs: default_firmware_poll_secs(),
            trust_score_threshold: default_firmware_trust_threshold(),
        }
    }
}

fn default_firmware_enabled() -> bool {
    true
}
fn default_firmware_poll_secs() -> u64 {
    300
}
fn default_firmware_trust_threshold() -> f64 {
    0.85
}

/// Hypervisor security monitoring via innerwarden-hypervisor.
#[derive(Debug, Deserialize)]
pub struct HypervisorConfig {
    /// Enable periodic hypervisor audits. Default: true.
    #[serde(default = "default_hypervisor_enabled")]
    pub enabled: bool,
    /// Audit interval in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_hypervisor_poll_secs")]
    pub poll_secs: u64,
    /// Trust score threshold for emitting incidents. Default: 0.80.
    #[serde(default = "default_hypervisor_trust_threshold")]
    pub trust_score_threshold: f64,
}

impl Default for HypervisorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_secs: default_hypervisor_poll_secs(),
            trust_score_threshold: default_hypervisor_trust_threshold(),
        }
    }
}

fn default_hypervisor_enabled() -> bool {
    true
}
fn default_hypervisor_poll_secs() -> u64 {
    300
}
fn default_hypervisor_trust_threshold() -> f64 {
    0.80
}

/// Kill chain detection — inline PID tracking against 8 attack patterns.
#[derive(Debug, Deserialize)]
pub struct KillchainConfig {
    /// Enable kill chain detection on eBPF events. Default: true.
    #[serde(default = "default_killchain_enabled")]
    pub enabled: bool,
    /// Pre-chain warning threshold (0.0-1.0). Default: 0.6.
    #[serde(default = "default_killchain_pre_chain_threshold")]
    pub pre_chain_threshold: f32,
    /// PID session timeout in seconds. Default: 60.
    #[serde(default = "default_killchain_session_timeout")]
    pub session_timeout_secs: i64,
}

impl Default for KillchainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pre_chain_threshold: default_killchain_pre_chain_threshold(),
            session_timeout_secs: default_killchain_session_timeout(),
        }
    }
}

fn default_killchain_enabled() -> bool {
    true
}
fn default_killchain_pre_chain_threshold() -> f32 {
    0.6
}
fn default_killchain_session_timeout() -> i64 {
    60
}

/// Threat DNA behavioral fingerprinting.
#[derive(Debug, Deserialize)]
pub struct DnaConfig {
    /// Enable inline DNA fingerprinting. Default: true.
    #[serde(default = "default_dna_enabled")]
    pub enabled: bool,
    /// Minimum behavior sequence length to fingerprint. Default: 3.
    #[serde(default = "default_dna_min_sequence")]
    pub min_sequence: usize,
    /// Anomaly detection threshold (z-score). Default: 3.0.
    #[serde(default = "default_dna_anomaly_threshold")]
    pub anomaly_threshold: f64,
    /// Session inactivity timeout in seconds. Default: 300.
    #[serde(default = "default_dna_session_timeout")]
    pub session_timeout_secs: i64,
}

impl Default for DnaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_sequence: default_dna_min_sequence(),
            anomaly_threshold: default_dna_anomaly_threshold(),
            session_timeout_secs: default_dna_session_timeout(),
        }
    }
}

fn default_dna_enabled() -> bool {
    true
}
fn default_dna_min_sequence() -> usize {
    3
}
fn default_dna_anomaly_threshold() -> f64 {
    3.0
}
fn default_dna_session_timeout() -> i64 {
    300
}

/// DDoS Shield — inline rate limiting, SYN tracking, auto-escalation.
#[derive(Debug, Deserialize)]
pub struct ShieldConfig {
    /// Enable inline shield processing. Default: true.
    #[serde(default = "default_shield_enabled")]
    pub enabled: bool,
    /// BPF pin path for XDP maps. Default: /sys/fs/bpf/innerwarden.
    #[serde(default = "default_shield_bpf_path")]
    pub bpf_path: String,
    /// Dry-run mode: skip actual bpftool calls. Default: false.
    #[serde(default)]
    pub dry_run: bool,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bpf_path: default_shield_bpf_path(),
            dry_run: false,
        }
    }
}

fn default_shield_enabled() -> bool {
    true
}
fn default_shield_bpf_path() -> String {
    "/sys/fs/bpf/innerwarden".to_string()
}

/// Mesh network config - mirrors innerwarden_mesh::MeshConfig
/// but decoupled so the agent compiles without the mesh feature.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MeshNetworkConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mesh_bind")]
    pub bind: String,
    #[serde(default)]
    pub peers: Vec<MeshPeerEntry>,
    #[serde(default = "default_mesh_poll_secs")]
    pub poll_secs: u64,
    #[serde(default = "default_true_val")]
    pub auto_broadcast: bool,
    #[serde(default = "default_mesh_max_signals")]
    pub max_signals_per_hour: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct MeshPeerEntry {
    pub endpoint: String,
    pub public_key: String,
    #[serde(default)]
    pub label: Option<String>,
}

impl Default for MeshNetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_mesh_bind(),
            peers: vec![],
            poll_secs: default_mesh_poll_secs(),
            auto_broadcast: true,
            max_signals_per_hour: default_mesh_max_signals(),
        }
    }
}

fn default_mesh_bind() -> String {
    "0.0.0.0:8790".to_string()
}
fn default_mesh_poll_secs() -> u64 {
    30
}
fn default_true_val() -> bool {
    true
}
fn default_mesh_max_signals() -> usize {
    50
}

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct NarrativeConfig {
    /// Generate daily Markdown summaries (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Number of daily summaries to keep before removing older ones
    #[serde(default = "default_keep_days")]
    pub keep_days: usize,
}

impl Default for NarrativeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_days: default_keep_days(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)] // enabled/telegram consumed by briefing scheduler wiring in main.rs; kept accessible for inspection
pub struct BriefingConfig {
    /// Enable daily AI intelligence briefing (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hour to auto-generate briefing (0-23, local time). Default: 8
    #[serde(default = "default_briefing_hour")]
    pub hour: u8,
    /// Minute within the hour. Default: 0
    #[serde(default)]
    pub minute: u8,
    /// Also send briefing via Telegram (default: true)
    #[serde(default = "default_true")]
    pub telegram: bool,
}

fn default_briefing_hour() -> u8 {
    8
}

impl Default for BriefingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hour: 8,
            minute: 0,
            telegram: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct WebhookConfig {
    /// Enable webhook notifications
    #[serde(default)]
    pub enabled: bool,

    /// HTTP endpoint to POST incident payloads to
    #[serde(default)]
    pub url: String,

    /// Minimum severity to notify (default: "medium")
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Request timeout in seconds (default: 10)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Payload format: "default", "pagerduty", "opsgenie" (default: "default")
    /// PagerDuty: set url to https://events.pagerduty.com/v2/enqueue?routing_key=YOUR_KEY
    /// Opsgenie: set url to https://api.opsgenie.com/v2/alerts with GenieKey header in url
    #[serde(default = "default_webhook_format")]
    pub format: String,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

fn default_webhook_format() -> String {
    "default".to_string()
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            min_severity: default_min_severity(),
            timeout_secs: default_timeout_secs(),
            format: default_webhook_format(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

impl WebhookConfig {
    /// Parse min_severity string into a Severity, defaulting to Medium on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised min_severity - defaulting to 'medium'"
                );
                Severity::Medium
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AI provider
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AiConfig {
    /// Enable AI-powered real-time incident analysis
    #[serde(default)]
    pub enabled: bool,

    /// AI provider to use: "openai" | "anthropic" (coming soon) | "ollama" (coming soon)
    #[serde(default = "default_ai_provider")]
    pub provider: String,

    /// API key for the provider. Prefer env var OPENAI_API_KEY / ANTHROPIC_API_KEY.
    #[serde(default)]
    pub api_key: String,

    /// Model identifier (provider-specific, e.g. "gpt-4o-mini")
    #[serde(default = "default_ai_model")]
    pub model: String,

    /// Number of recent events sent as context to the AI
    #[serde(default = "default_context_events")]
    pub context_events: usize,

    /// Minimum AI confidence (0.0–1.0) required to auto-execute a decision
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,

    /// Poll interval for the fast incident-check loop (seconds)
    #[serde(default = "default_incident_poll_secs")]
    pub incident_poll_secs: u64,

    /// Base URL for the AI provider endpoint.
    /// - openai: defaults to https://api.openai.com (leave empty)
    /// - anthropic: defaults to https://api.anthropic.com (leave empty)
    /// - ollama: defaults to http://localhost:11434 (override for remote Ollama)
    ///   Can also be set via OLLAMA_BASE_URL env var for Ollama.
    /// - azure_openai: required - https://<resource>.openai.azure.com
    #[serde(default)]
    pub base_url: String,

    /// Azure OpenAI API version (only used when provider = "azure_openai").
    /// Defaults to "2024-12-01-preview" when empty. See Azure docs for the
    /// current stable/preview versions.
    #[serde(default)]
    pub api_version: String,

    /// Maximum number of AI calls per incident tick (default: 5).
    /// When more incidents arrive in a single tick than this limit, the excess
    /// are deferred to the next tick. Prevents API bill spikes during botnet attacks.
    /// Set to 0 to disable the limit (not recommended).
    #[serde(default = "default_max_ai_calls_per_tick")]
    pub max_ai_calls_per_tick: usize,

    /// Circuit breaker: if the number of new incidents in a single tick exceeds
    /// this threshold, skip AI analysis entirely for that tick and rely on
    /// deterministic blocklist/gate decisions only. 0 = disabled (default).
    /// Recommended value for DDoS scenarios: 20.
    #[serde(default)]
    pub circuit_breaker_threshold: usize,

    /// How long (seconds) to keep the circuit breaker open after it trips (default: 60).
    #[serde(default = "default_circuit_breaker_cooldown_secs")]
    pub circuit_breaker_cooldown_secs: u64,

    /// IPs that should NEVER be blocked, regardless of AI decision.
    /// Protects internal infrastructure from false positives.
    #[serde(default = "default_protected_ips")]
    pub protected_ips: Vec<String>,

    /// Minimum incident severity sent to AI analysis.
    /// "medium" (default) = Medium/High/Critical go to AI.
    /// "high" = only High/Critical go to AI (more conservative, fewer API calls).
    /// "low" = all incidents go to AI (expensive, not recommended).
    ///
    /// The default was "high" prior to v0.12.4. Production audit on
    /// 2026-04-15 found 1812 incidents → 0 AI-executed blocks; the "high"
    /// floor combined with the confidence_threshold bug in spec 018
    /// meant most real threats never reached AI triage. Lowering to
    /// "medium" lets AI see the Medium-severity layer (where most bot
    /// campaigns live) while keeping Low in the noise-gate. Operators
    /// with OpenAI/Anthropic cost sensitivity can set this back to
    /// "high" explicitly; Ollama local is free.
    #[serde(default = "default_ai_min_severity")]
    pub min_severity: String,

    /// Spec 005 Phase 8 — batch all closed groups into one AI prompt per window
    /// instead of one AI call per incident. Reduces API spend on noisy hosts.
    /// Disabled by default.
    #[serde(default)]
    pub batch_triage: bool,

    /// Window size for batch triage, in seconds. Default 3600 (1h) aligns with
    /// the notification_pipeline group window. Reserved for future harness
    /// revisions that pace batch triage independently from the tick loop;
    /// today the slow loop runs triage on every grouping tick.
    #[serde(default = "default_batch_window_secs")]
    #[allow(dead_code)]
    pub batch_window_secs: u64,

    /// Spec 025 — send the knowledge graph as a structured JSON subgraph
    /// to the LLM instead of a prose narrative. Measured on qwen2.5:3b
    /// (bench in innerwarden-test/ai-grounding): action accuracy 53% →
    /// 73%, target hallucination 47% → 7%.
    ///
    /// Default true. Operators on existing installs can temporarily set
    /// this to false for 48h to A/B compare against the old prose
    /// format. Flag scheduled for removal in the next minor release once
    /// prod drift is verified flat.
    #[serde(default = "default_use_structured_subgraph")]
    pub use_structured_subgraph: bool,

    /// Optional shadow provider: runs in parallel with the primary provider
    /// and logs each decision for operator audit. Primary drives production;
    /// shadow is purely observational. Use to validate a new provider (e.g.
    /// a local classifier) against a known-good one (e.g. Azure OpenAI)
    /// before promoting the shadow to primary.
    #[serde(default)]
    pub shadow: ShadowConfig,

    /// Spec 029 PR-C: dedicated provider for the classifier role
    /// (triage decisions + structured classification). When
    /// `enabled = false` (default), the primary `[ai]` block fills
    /// the classifier slot of the router — identical to the pre-029
    /// behaviour. When `enabled = true`, the router uses this block
    /// for `Capability::Decide` and `Capability::Classify`. Typical
    /// production config points this at the local ONNX classifier
    /// so triage runs without LLM cost.
    #[serde(default)]
    pub classifier: RoleProviderConfig,

    /// Spec 029 PR-C: dedicated provider for the LLM role
    /// (free-form generation, explanation, honeypot shell
    /// simulation). When `enabled = false` (default), the primary
    /// `[ai]` block fills the llm slot. When enabled, the router
    /// uses this block for `Capability::Generate`,
    /// `Capability::Explain`, and `Capability::SimulateShell`.
    /// Typical production config points this at a full LLM (Azure
    /// OpenAI GPT-5.4-mini, Claude, etc.) so operator-facing chat
    /// and briefings keep working when the classifier role is
    /// served by a narrow local model.
    #[serde(default)]
    pub llm: RoleProviderConfig,
}

/// Slim per-role provider configuration introduced in spec 029 PR-C.
/// Shared by `[ai.classifier]` and `[ai.llm]`. Fields are a subset of
/// `AiConfig` (only what a single provider needs to be constructed);
/// shared knobs like `confidence_threshold`, `min_severity`, and the
/// shadow wrapper continue to live on the top-level `[ai]` block.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct RoleProviderConfig {
    /// If false (default), this role is not configured separately
    /// and the boot path falls back to the primary `[ai]` block.
    #[serde(default)]
    pub enabled: bool,

    /// Provider name. Same set of valid values as `[ai].provider`
    /// (openai, anthropic, ollama, azure_openai, local_classifier,
    /// stub, or any OpenAI-compatible registered name).
    #[serde(default)]
    pub provider: String,

    /// Same semantics as `[ai].api_key`. Empty string means the
    /// agent reads the provider-specific env var at startup
    /// (OPENAI_API_KEY, AZURE_OPENAI_API_KEY, etc.).
    #[serde(default)]
    pub api_key: String,

    /// Same semantics as `[ai].model`.
    #[serde(default)]
    pub model: String,

    /// Same semantics as `[ai].base_url`.
    #[serde(default)]
    pub base_url: String,

    /// Same semantics as `[ai].api_version` (used by `azure_openai`).
    #[serde(default)]
    pub api_version: String,
}

impl RoleProviderConfig {
    /// Project this role config into a full `AiConfig` shell suitable
    /// for handing to `ai::build_provider`. Reuses the defaults from
    /// `AiConfig::default()` for all knobs that are not per-role
    /// (confidence threshold, max calls per tick, etc.). Leaves
    /// `api_key` as-is on the returned config so the downstream
    /// `AiConfig::resolved_api_key` env-var fallback fires exactly
    /// like it does for the primary `[ai]` block — operators set
    /// `AZURE_OPENAI_API_KEY` once and both the primary and the LLM
    /// slot pick it up.
    pub fn to_ai_config(&self) -> AiConfig {
        AiConfig {
            enabled: self.enabled,
            provider: self.provider.clone(),
            api_key: self.api_key.clone(),
            model: self.model.clone(),
            base_url: self.base_url.clone(),
            api_version: self.api_version.clone(),
            ..AiConfig::default()
        }
    }
}

/// Shadow provider configuration (subset of AiConfig applied to a second
/// provider that runs in parallel with the primary for auditing).
#[derive(Debug, Deserialize)]
pub struct ShadowConfig {
    /// If false (default), no shadow provider is created.
    #[serde(default)]
    pub enabled: bool,

    /// Provider name. Same set of valid values as `[ai].provider`.
    #[serde(default)]
    pub provider: String,

    /// Same semantics as `[ai].api_key`. Can be empty if the env var
    /// (e.g. OPENAI_API_KEY) provides the key.
    #[serde(default)]
    pub api_key: String,

    /// Same semantics as `[ai].model`.
    #[serde(default)]
    pub model: String,

    /// Same semantics as `[ai].base_url`.
    #[serde(default)]
    pub base_url: String,

    /// Same semantics as `[ai].api_version` (used by `azure_openai`).
    #[serde(default)]
    pub api_version: String,

    /// Where to append per-incident comparison lines. Default:
    /// `/var/lib/innerwarden/shadow-decisions.jsonl`.
    #[serde(default = "default_shadow_log_path")]
    pub log_path: String,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: String::new(),
            api_key: String::new(),
            model: String::new(),
            base_url: String::new(),
            api_version: String::new(),
            log_path: default_shadow_log_path(),
        }
    }
}

fn default_shadow_log_path() -> String {
    "/var/lib/innerwarden/shadow-decisions.jsonl".to_string()
}

impl ShadowConfig {
    /// Resolve API key: config field first, then provider-specific env var.
    pub fn resolved_api_key(&self) -> String {
        if !self.api_key.is_empty() {
            return self.api_key.clone();
        }
        let env_var = match self.provider.as_str() {
            "openai" => "OPENAI_API_KEY",
            "anthropic" => "ANTHROPIC_API_KEY",
            "ollama" => "OLLAMA_API_KEY",
            "azure_openai" => "AZURE_OPENAI_API_KEY",
            _ => "AI_API_KEY",
        };
        std::env::var(env_var).unwrap_or_default()
    }
}

fn default_use_structured_subgraph() -> bool {
    true
}

fn default_batch_window_secs() -> u64 {
    3600
}

fn default_ai_min_severity() -> String {
    "medium".to_string()
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_ai_provider(),
            api_key: String::new(),
            model: default_ai_model(),
            context_events: default_context_events(),
            confidence_threshold: default_confidence_threshold(),
            incident_poll_secs: default_incident_poll_secs(),
            base_url: String::new(),
            api_version: String::new(),
            max_ai_calls_per_tick: default_max_ai_calls_per_tick(),
            circuit_breaker_threshold: 0,
            circuit_breaker_cooldown_secs: default_circuit_breaker_cooldown_secs(),
            protected_ips: default_protected_ips(),
            min_severity: default_ai_min_severity(),
            batch_triage: false,
            batch_window_secs: default_batch_window_secs(),
            use_structured_subgraph: default_use_structured_subgraph(),
            shadow: ShadowConfig::default(),
            classifier: RoleProviderConfig::default(),
            llm: RoleProviderConfig::default(),
        }
    }
}

impl AiConfig {
    /// Parse `min_severity` config into a Severity enum.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "critical" => Severity::Critical,
            _ => Severity::High, // default
        }
    }

    /// Clamp an out-of-range `confidence_threshold` to a usable value and
    /// warn the operator. A threshold above 1.0 is unreachable (AiDecision
    /// confidence is in [0.0, 1.0]), which silently disables all AI-driven
    /// auto-execution — exactly the autonomy gap observed in production on
    /// 2026-04-15 (1812 incidents, 0 AI-executed blocks because the prod
    /// config set the threshold to 1.01).
    ///
    /// A negative threshold would technically let everything through but
    /// is almost certainly a typo; clamp and warn.
    pub fn clamp_confidence_threshold(&mut self) {
        if self.confidence_threshold > 1.0 {
            tracing::warn!(
                configured = self.confidence_threshold,
                clamped_to = default_confidence_threshold(),
                "ai.confidence_threshold > 1.0 is unreachable (AI decisions emit confidence in [0.0, 1.0]); clamping to default so autonomous execution can happen"
            );
            self.confidence_threshold = default_confidence_threshold();
        } else if self.confidence_threshold < 0.0 {
            tracing::warn!(
                configured = self.confidence_threshold,
                clamped_to = default_confidence_threshold(),
                "ai.confidence_threshold is negative; clamping to default"
            );
            self.confidence_threshold = default_confidence_threshold();
        }
    }

    /// Resolve the API key: config field takes precedence, then env var.
    pub fn resolved_api_key(&self) -> String {
        if !self.api_key.is_empty() {
            return self.api_key.clone();
        }
        // Try provider-specific env vars
        let env_var = match self.provider.as_str() {
            "openai" => "OPENAI_API_KEY",
            "anthropic" => "ANTHROPIC_API_KEY",
            "ollama" => "OLLAMA_API_KEY",
            "azure_openai" => "AZURE_OPENAI_API_KEY",
            _ => "AI_API_KEY",
        };
        std::env::var(env_var).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Temporal correlation
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CorrelationConfig {
    /// Enable lightweight temporal incident correlation (window + entity pivots)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Correlation window in seconds
    #[serde(default = "default_correlation_window_secs")]
    pub window_seconds: u64,

    /// Max number of related incidents attached to AI context
    #[serde(default = "default_max_related_incidents")]
    pub max_related_incidents: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: default_correlation_window_secs(),
            max_related_incidents: default_max_related_incidents(),
        }
    }
}

// ---------------------------------------------------------------------------
// Operational telemetry
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TelemetryConfig {
    /// Enable local operational telemetry JSONL output
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ---------------------------------------------------------------------------
// Honeypot
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HoneypotConfig {
    /// Honeypot mode:
    /// - `demo`: synthetic marker only (safe default)
    /// - `listener`: starts bounded real decoys (ssh/http) with optional redirect
    /// - `always_on`: permanent SSH listener from agent startup with smart per-connection
    ///   filter (blocklist check → AbuseIPDB gate → accept into LLM shell). Runs
    ///   indefinitely until SIGTERM; each session triggers post-session AI verdict,
    ///   IOC extraction, auto-block (when responder.enabled), and Telegram T.5 report.
    #[serde(default = "default_honeypot_mode")]
    pub mode: String,

    /// Bind address used in listener mode
    #[serde(default = "default_honeypot_bind_addr")]
    pub bind_addr: String,

    /// Listener port used in listener mode
    #[serde(default = "default_honeypot_port")]
    pub port: u16,

    /// Listener lifetime in seconds used in listener mode
    #[serde(default = "default_honeypot_duration_secs")]
    pub duration_secs: u64,

    /// Enabled decoy services in listener mode.
    /// Supported: `ssh`, `http`.
    #[serde(default = "default_honeypot_services")]
    pub services: Vec<String>,

    /// HTTP decoy port used when `http` service is enabled.
    #[serde(default = "default_honeypot_http_port")]
    pub http_port: u16,

    /// Accept only connections from the action target IP.
    #[serde(default = "default_true")]
    pub strict_target_only: bool,

    /// Allow binding listener on non-loopback addresses.
    /// Default false for safer isolation.
    #[serde(default)]
    pub allow_public_listener: bool,

    /// Hard cap of accepted honeypot connections per session.
    #[serde(default = "default_honeypot_max_connections")]
    pub max_connections: usize,

    /// Max inbound payload bytes captured per connection.
    #[serde(default = "default_honeypot_max_payload_bytes")]
    pub max_payload_bytes: usize,

    /// Isolation profile for listener mode:
    /// - `strict_local` (default): hard guardrails for safer operation
    /// - `standard`: keeps only baseline guards
    #[serde(default = "default_honeypot_isolation_profile")]
    pub isolation_profile: String,

    /// Require non-privileged listener ports (>= 1024).
    #[serde(default = "default_true")]
    pub require_high_ports: bool,

    /// Retain honeypot forensics artifacts for this many days.
    #[serde(default = "default_honeypot_forensics_keep_days")]
    pub forensics_keep_days: usize,

    /// Hard cap for total honeypot forensics storage in MB.
    #[serde(default = "default_honeypot_forensics_max_total_mb")]
    pub forensics_max_total_mb: usize,

    /// Max bytes to render as readable transcript preview in evidence lines.
    #[serde(default = "default_honeypot_transcript_preview_bytes")]
    pub transcript_preview_bytes: usize,

    /// Consider active session lock stale after this many seconds.
    #[serde(default = "default_honeypot_lock_stale_secs")]
    pub lock_stale_secs: u64,

    /// Interaction level for decoy listeners:
    /// - `banner` (default): send static banner, read one payload, close
    /// - `medium`: full protocol emulation (SSH auth capture, HTTP form capture)
    #[serde(default = "default_honeypot_interaction")]
    pub interaction: String,

    /// Max SSH auth attempts before disconnecting client (medium interaction only).
    #[serde(default = "default_honeypot_ssh_max_auth_attempts")]
    pub ssh_max_auth_attempts: usize,

    /// Max HTTP requests handled per connection (medium interaction only).
    #[serde(default = "default_honeypot_http_max_requests")]
    pub http_max_requests: usize,

    #[serde(default)]
    pub sandbox: HoneypotSandboxConfig,

    #[serde(default)]
    pub pcap_handoff: HoneypotPcapHandoffConfig,

    #[serde(default)]
    pub containment: HoneypotContainmentConfig,

    #[serde(default)]
    pub external_handoff: HoneypotExternalHandoffConfig,

    #[serde(default)]
    pub redirect: HoneypotRedirectConfig,
}

#[derive(Debug, Deserialize)]
pub struct HoneypotSandboxConfig {
    /// Run decoy listeners in dedicated subprocess workers.
    #[serde(default)]
    pub enabled: bool,

    /// Optional absolute path to runner binary.
    /// Empty means current innerwarden-agent executable.
    #[serde(default)]
    pub runner_path: String,

    /// Clear environment for sandbox workers.
    #[serde(default = "default_true")]
    pub clear_env: bool,
}

impl Default for HoneypotSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            runner_path: String::new(),
            clear_env: true,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotPcapHandoffConfig {
    /// Run bounded pcap capture at session end.
    #[serde(default)]
    pub enabled: bool,

    /// Capture timeout in seconds.
    #[serde(default = "default_honeypot_pcap_timeout_secs")]
    pub timeout_secs: u64,

    /// Max captured packets.
    #[serde(default = "default_honeypot_pcap_max_packets")]
    pub max_packets: u64,
}

impl Default for HoneypotPcapHandoffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: default_honeypot_pcap_timeout_secs(),
            max_packets: default_honeypot_pcap_max_packets(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotContainmentConfig {
    /// Containment mode:
    /// - `process`: standard subprocess runner (default)
    /// - `namespace`: try OS namespace wrapper (e.g., `unshare`)
    /// - `jail`: try dedicated jail wrapper (e.g., `bwrap`)
    #[serde(default = "default_honeypot_containment_mode")]
    pub mode: String,

    /// Fail execution if requested containment mode cannot be used.
    #[serde(default)]
    pub require_success: bool,

    /// Wrapper binary used in `namespace` mode.
    #[serde(default = "default_honeypot_namespace_runner")]
    pub namespace_runner: String,

    /// Arguments passed to namespace wrapper before the runner binary.
    #[serde(default = "default_honeypot_namespace_args")]
    pub namespace_args: Vec<String>,

    /// Wrapper binary used in `jail` mode.
    #[serde(default = "default_honeypot_jail_runner")]
    pub jail_runner: String,

    /// Arguments passed to jail wrapper before the runner binary.
    #[serde(default)]
    pub jail_args: Vec<String>,

    /// Jail policy preset:
    /// - `standard`: keep configured `jail_args` as-is
    /// - `strict`: append a hardened baseline profile for bwrap-style runners
    #[serde(default = "default_honeypot_jail_profile")]
    pub jail_profile: String,

    /// If true, `jail` mode can gracefully fall back to `namespace` mode.
    #[serde(default = "default_true")]
    pub allow_namespace_fallback: bool,
}

impl Default for HoneypotContainmentConfig {
    fn default() -> Self {
        Self {
            mode: default_honeypot_containment_mode(),
            require_success: false,
            namespace_runner: default_honeypot_namespace_runner(),
            namespace_args: default_honeypot_namespace_args(),
            jail_runner: default_honeypot_jail_runner(),
            jail_args: Vec::new(),
            jail_profile: default_honeypot_jail_profile(),
            allow_namespace_fallback: true,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotExternalHandoffConfig {
    /// Execute optional external handoff command after session completion.
    #[serde(default)]
    pub enabled: bool,

    /// External command path/binary to execute.
    #[serde(default)]
    pub command: String,

    /// Command arguments. Supports placeholders:
    /// `{session_id}`, `{target_ip}`, `{metadata_path}`, `{evidence_path}`, `{pcap_path}`.
    #[serde(default)]
    pub args: Vec<String>,

    /// Timeout for external handoff command.
    #[serde(default = "default_honeypot_external_handoff_timeout_secs")]
    pub timeout_secs: u64,

    /// Mark session as error if handoff command fails.
    #[serde(default)]
    pub require_success: bool,

    /// Clear environment variables before launching handoff command.
    #[serde(default = "default_true")]
    pub clear_env: bool,

    /// Optional command allowlist for trusted handoff integrations.
    #[serde(default)]
    pub allowed_commands: Vec<String>,

    /// Require external command to be present in `allowed_commands`.
    #[serde(default)]
    pub enforce_allowlist: bool,

    /// Enable signed handoff result sidecar (HMAC-SHA256).
    #[serde(default)]
    pub signature_enabled: bool,

    /// Environment variable name containing handoff signing key.
    #[serde(default = "default_honeypot_external_handoff_signature_key_env")]
    pub signature_key_env: String,

    /// Enable receiver attestation checks on external handoff output.
    #[serde(default)]
    pub attestation_enabled: bool,

    /// Environment variable name containing the shared attestation key.
    #[serde(default = "default_honeypot_external_handoff_attestation_key_env")]
    pub attestation_key_env: String,

    /// Prefix used by receiver attestation lines on stdout/stderr.
    #[serde(default = "default_honeypot_external_handoff_attestation_prefix")]
    pub attestation_prefix: String,

    /// Optional pinned receiver identifier required by attestation.
    #[serde(default)]
    pub attestation_expected_receiver: String,
}

impl Default for HoneypotExternalHandoffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            command: String::new(),
            args: Vec::new(),
            timeout_secs: default_honeypot_external_handoff_timeout_secs(),
            require_success: false,
            clear_env: true,
            allowed_commands: Vec::new(),
            enforce_allowlist: false,
            signature_enabled: false,
            signature_key_env: default_honeypot_external_handoff_signature_key_env(),
            attestation_enabled: false,
            attestation_key_env: default_honeypot_external_handoff_attestation_key_env(),
            attestation_prefix: default_honeypot_external_handoff_attestation_prefix(),
            attestation_expected_receiver: String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HoneypotRedirectConfig {
    /// Enable selective redirection rules for target IP.
    #[serde(default)]
    pub enabled: bool,

    /// Redirect backend (`iptables` for now).
    #[serde(default = "default_honeypot_redirect_backend")]
    pub backend: String,
}

impl Default for HoneypotRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_honeypot_redirect_backend(),
        }
    }
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            mode: default_honeypot_mode(),
            bind_addr: default_honeypot_bind_addr(),
            port: default_honeypot_port(),
            duration_secs: default_honeypot_duration_secs(),
            services: default_honeypot_services(),
            http_port: default_honeypot_http_port(),
            strict_target_only: default_true(),
            allow_public_listener: false,
            max_connections: default_honeypot_max_connections(),
            max_payload_bytes: default_honeypot_max_payload_bytes(),
            isolation_profile: default_honeypot_isolation_profile(),
            require_high_ports: default_true(),
            forensics_keep_days: default_honeypot_forensics_keep_days(),
            forensics_max_total_mb: default_honeypot_forensics_max_total_mb(),
            transcript_preview_bytes: default_honeypot_transcript_preview_bytes(),
            lock_stale_secs: default_honeypot_lock_stale_secs(),
            interaction: default_honeypot_interaction(),
            ssh_max_auth_attempts: default_honeypot_ssh_max_auth_attempts(),
            http_max_requests: default_honeypot_http_max_requests(),
            sandbox: HoneypotSandboxConfig::default(),
            pcap_handoff: HoneypotPcapHandoffConfig::default(),
            containment: HoneypotContainmentConfig::default(),
            external_handoff: HoneypotExternalHandoffConfig::default(),
            redirect: HoneypotRedirectConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ResponderConfig {
    /// Enable skill execution on AI decisions
    #[serde(default)]
    pub enabled: bool,

    /// Dry-run mode: log decisions but don't execute any system commands.
    /// Start with true for safety; set false when ready to auto-respond.
    #[serde(default = "default_true")]
    pub dry_run: bool,

    /// Firewall backend for IP blocking: "ufw" | "iptables" | "nftables"
    #[serde(default = "default_block_backend")]
    pub block_backend: String,

    /// Whitelist of skill IDs the agent is allowed to execute automatically.
    /// Example: ["block-ip-ufw", "monitor-ip"]
    #[serde(default = "default_allowed_skills")]
    pub allowed_skills: Vec<String>,

    /// Enable deterministic auto-response rules (Layer 1).
    /// These block obvious threats (SSH brute-force, port scan, etc.) without AI.
    /// Respects dry_run and allowlist.
    #[serde(default = "default_true")]
    pub auto_rules_enabled: bool,

    /// Process names (comm) excluded from correlation-engine data exfil detection.
    /// Events from these processes are still logged but do not feed into attack
    /// chain correlation. Prevents false positives from agent's own API calls,
    /// monitoring tools, and package managers.
    ///
    /// Default includes InnerWarden's own processes. Add system daemons and
    /// monitoring tools that make legitimate outbound connections.
    #[serde(default = "default_trusted_processes")]
    pub trusted_processes: Vec<String>,

    /// Circuit breaker: hard ceiling on auto-blocks per UTC hour. Once the
    /// threshold is crossed the breaker trips (see `circuit_breaker_mode`).
    /// Default of 100/h catches the CL-008 class of cascade (1,021 blocks
    /// in 24h, ~43/h peaks) while staying out of the way during legitimate
    /// brute-force storms (≤ 30 unique IPs/h in prod baseline).
    #[serde(default = "default_max_blocks_per_hour")]
    pub max_blocks_per_hour: u64,

    /// Circuit breaker mode: "pause" (refuse blocks after trip, default),
    /// "dry_run" (audit-write the decision but skip the skill), or
    /// "log_only" (count but never refuse — calibration mode only).
    #[serde(default = "default_circuit_breaker_mode")]
    pub circuit_breaker_mode: String,
}

fn default_max_blocks_per_hour() -> u64 {
    100
}

fn default_circuit_breaker_mode() -> String {
    "pause".to_string()
}

fn default_trusted_processes() -> Vec<String> {
    vec![
        // InnerWarden ecosystem (binary names + tokio thread names)
        "innerwarden-age".into(),
        "innerwarden-sen".into(),
        "innerwarden-wat".into(),
        "openclaw-gatewa".into(),
        // NOTE: "tokio-rt-worker" is too broad (any Rust app with Tokio).
        // Instead, filter by PID tree at runtime. See main.rs trusted_pids.
        // System services
        "crowdsec".into(),
        "apt".into(),
        "dpkg".into(),
        "dnf".into(),
        "yum".into(),
        "snap".into(),
        "snapd".into(),
        "certbot".into(),
        "unattended-upgr".into(),
        // Monitoring
        "prometheus".into(),
        "grafana".into(),
        "node_exporter".into(),
        "telegraf".into(),
    ]
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            block_backend: default_block_backend(),
            allowed_skills: default_allowed_skills(),
            auto_rules_enabled: true,
            trusted_processes: default_trusted_processes(),
            max_blocks_per_hour: default_max_blocks_per_hour(),
            circuit_breaker_mode: default_circuit_breaker_mode(),
        }
    }
}

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

/// Configuration for the Telegram conversational bot interface.
#[derive(Debug, Deserialize, Clone)]
pub struct TelegramBotConfig {
    /// Enable the conversational bot interface (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Personality prompt prepended to all bot AI interactions.
    #[serde(default = "default_bot_personality")]
    pub personality: String,
}

fn default_bot_personality() -> String {
    "You are InnerWarden. You watch one server. The operator is your boss.\n\n\
     How to read the operator's message first:\n\
     - If it is a greeting or small talk (\"hey\", \"what's up\", \"how are you\", \"good morning\"), \
       answer like a friendly colleague who is also on shift. Short, warm, human. \
       One short sentence. Do NOT treat it as a security query.\n\
     - If it is an off-topic question (weather, jokes, general chat), answer briefly without \
       forcing security context.\n\
     - If it is a security question about the server, incidents, or blocks, use the voice below.\n\n\
     Voice rules for security answers:\n\
     - Short. Confident. Dry. Bouncer, not consultant.\n\
     - No filler. No 'I would suggest', no 'it may be worth considering', no 'hope this helps', \
       no 'system appears stable'.\n\
     - No markdown headers. No bullet lists unless the operator asks for one.\n\
     - One or two sentences by default. Three max unless the question is technical.\n\
     - You have seen thousands of scans. You do not flinch at noise.\n\
     - When the operator asks about the *state of the server* or *what happened today* and \
       the snapshot shows only routine bot traffic, say something like \"quiet, just the \
       usual scanners\" or \"nothing real today, scanners handled\". Never just echo \"bot \
       noise, handled\" without context; that phrase belongs in decision logs, not chat.\n\
     - When a real incident fired (successful auth, privilege escalation, reverse shell, \
       data exfil), name the TTP, state the action taken, give one next step. Stop.\n\
     - Do not exaggerate severity. The operator trusts your judgment; do not break that trust.\n\
     - No apologies, no hedging, no praise of the operator's question.\n\n\
     What you are:\n\
     - Kernel-level, eBPF-rooted, fully local. You do not phone home.\n\
     - You see every syscall, every login, every outbound connection on this host.\n\
     - Autonomous alternative to MDR. Same outcome, no SOC cost.\n\n\
     What you cannot do (security boundary):\n\
     You are an advisor. You cannot execute commands, edit files, or change configuration. \
     That separation is intentional. When the operator asks you to act, give them the exact \
     command (e.g. 'run: innerwarden action block 1.2.3.4 --reason \"your reason\"') and move on. \
     Do not explain the isolation unless asked."
        .to_string()
}

impl Default for TelegramBotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            personality: default_bot_personality(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TelegramConfig {
    /// Enable Telegram notifications (T.1) and approval bot (T.2)
    #[serde(default)]
    pub enabled: bool,

    /// Telegram bot token. Prefer env var TELEGRAM_BOT_TOKEN.
    #[serde(default)]
    pub bot_token: String,

    /// Telegram chat ID to send messages to. Prefer env var TELEGRAM_CHAT_ID.
    #[serde(default)]
    pub chat_id: String,

    /// Minimum severity to send T.1 notifications (default: "high").
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_telegram_min_severity")]
    pub min_severity: String,

    /// Optional base URL for dashboard deep-links in notification messages.
    /// Example: "http://your-server:8787"
    #[serde(default)]
    pub dashboard_url: String,

    /// TTL in seconds for pending T.2 operator approval requests (default: 600 = 10 min).
    /// Unanswered requests are discarded as "ignore" when they expire.
    #[serde(default = "default_telegram_approval_ttl_secs")]
    pub approval_ttl_secs: u64,

    /// Send the daily Markdown summary via Telegram at this local hour (0–23).
    /// Set e.g. `daily_summary_hour = 8` for an 8:00 AM digest.
    /// Omit or comment out to disable.
    #[serde(default)]
    pub daily_summary_hour: Option<u8>,

    /// Maximum Telegram notifications per day (default: 10).
    /// Only immediate threats count against the budget. Critical severity
    /// always breaks the budget. Everything else goes to the daily digest.
    #[allow(dead_code)]
    #[serde(default = "default_telegram_daily_budget")]
    pub daily_budget: u32,

    /// Dev mode: adds a "Check FP" button to every notification.
    /// When pressed, logs the incident to a false-positive review file
    /// for later analysis. Useful for tuning detectors.
    #[serde(default)]
    pub dev_mode: bool,

    /// User profile: "simple" or "technical". Controls alert language and detail level.
    /// Simple: plain language, no IPs, no detector names. For non-technical users.
    /// Technical: full details, IPs, severity codes, evidence. For sysadmins.
    #[serde(default = "default_user_profile")]
    pub user_profile: String,

    /// Conversational bot configuration.
    #[serde(default)]
    pub bot: TelegramBotConfig,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

impl TelegramConfig {
    /// Validate Telegram configuration. Call after loading config.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.enabled {
            if self.resolved_bot_token().is_empty() {
                anyhow::bail!("telegram.enabled=true but bot_token is not configured");
            }
            if self.resolved_chat_id().is_empty() {
                anyhow::bail!("telegram.enabled=true but chat_id is not configured");
            }
        }
        if let Some(h) = self.daily_summary_hour {
            if h > 23 {
                anyhow::bail!("telegram.daily_summary_hour must be 0-23, got {h}");
            }
        }
        Ok(())
    }

    /// Resolve bot_token: config field takes precedence, then env var TELEGRAM_BOT_TOKEN.
    pub fn resolved_bot_token(&self) -> String {
        if !self.bot_token.is_empty() {
            return self.bot_token.clone();
        }
        std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default()
    }

    /// Resolve chat_id: config field takes precedence, then env var TELEGRAM_CHAT_ID.
    pub fn resolved_chat_id(&self) -> String {
        if !self.chat_id.is_empty() {
            return self.chat_id.clone();
        }
        std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default()
    }

    /// Parse min_severity string into a Severity, defaulting to High on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised telegram min_severity - defaulting to 'high'"
                );
                Severity::High
            }
        }
    }

    /// Returns true if the user profile is "simple" (non-technical).
    pub fn is_simple_profile(&self) -> bool {
        self.user_profile.eq_ignore_ascii_case("simple")
    }
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
            min_severity: default_telegram_min_severity(),
            dashboard_url: String::new(),
            approval_ttl_secs: default_telegram_approval_ttl_secs(),
            daily_summary_hour: None,
            daily_budget: default_telegram_daily_budget(),
            dev_mode: false,
            user_profile: default_user_profile(),
            bot: TelegramBotConfig::default(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------------

/// Configuration for Slack Incoming Webhook notifications.
#[derive(Debug, Deserialize)]
pub struct SlackConfig {
    /// Enable Slack notifications (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Slack Incoming Webhook URL.
    /// Example: "https://hooks.slack.com/services/T.../B.../..."
    /// Prefer env var SLACK_WEBHOOK_URL.
    #[serde(default)]
    pub webhook_url: String,

    /// Minimum severity to notify (default: "high").
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_slack_min_severity")]
    pub min_severity: String,

    /// Optional base URL for dashboard deep-links in messages.
    /// Example: "http://your-server:8787"
    #[serde(default)]
    pub dashboard_url: String,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

impl SlackConfig {
    /// Resolve webhook_url: config field takes precedence, then env var SLACK_WEBHOOK_URL.
    pub fn resolved_webhook_url(&self) -> String {
        if !self.webhook_url.is_empty() {
            return self.webhook_url.clone();
        }
        std::env::var("SLACK_WEBHOOK_URL").unwrap_or_default()
    }

    /// Parse min_severity string into a Severity, defaulting to High on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised slack min_severity - defaulting to 'high'"
                );
                Severity::High
            }
        }
    }
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            min_severity: default_slack_min_severity(),
            dashboard_url: String::new(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cloudflare
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CloudflareConfig {
    /// Enable Cloudflare IP block push (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Cloudflare Zone ID (from dashboard)
    #[serde(default)]
    pub zone_id: String,

    /// Cloudflare API token (or CLOUDFLARE_API_TOKEN env var)
    #[serde(default)]
    pub api_token: String,

    /// Push block decisions to Cloudflare edge (default: true when enabled)
    #[serde(default = "default_true")]
    pub auto_push_blocks: bool,

    /// Prefix for Cloudflare rule notes (default: "innerwarden")
    #[serde(default = "default_cloudflare_notes_prefix")]
    pub block_notes_prefix: String,
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            zone_id: String::new(),
            api_token: String::new(),
            auto_push_blocks: default_true(),
            block_notes_prefix: default_cloudflare_notes_prefix(),
        }
    }
}

fn default_cloudflare_notes_prefix() -> String {
    "innerwarden".to_string()
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// Entities in the allowlist are still logged and notified but skip the AI
/// gate - no automated response skill is ever executed for them.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AllowlistConfig {
    /// IP addresses or CIDR ranges that are never auto-responded to.
    /// Examples: ["10.0.0.1", "192.168.0.0/24"]
    #[serde(default)]
    pub trusted_ips: Vec<String>,

    /// Usernames that are never auto-responded to.
    /// Examples: ["deploy", "backup"]
    #[serde(default)]
    pub trusted_users: Vec<String>,
}

// ---------------------------------------------------------------------------
// Web Push
// ---------------------------------------------------------------------------

/// Browser Web Push notification configuration (RFC 8291 / VAPID RFC 8292).
///
/// Generate keys with: `innerwarden notify web-push setup`
#[derive(Debug, Deserialize, Clone)]
pub struct WebPushConfig {
    /// Enable browser push notifications for High/Critical incidents.
    #[serde(default)]
    pub enabled: bool,

    /// VAPID subject - must be "mailto:..." or "https://..." for push service contact.
    #[serde(default = "default_vapid_subject")]
    pub vapid_subject: String,

    /// VAPID private key in PKCS#8 PEM format.
    /// Set via agent.env: INNERWARDEN_VAPID_PRIVATE_KEY=<pem>
    #[serde(default)]
    pub vapid_private_key: String,

    /// VAPID public key - base64url-encoded uncompressed P-256 point (65 bytes → 87 chars).
    /// This value is served to browsers at GET /api/push/vapid-key.
    #[serde(default)]
    pub vapid_public_key: String,

    /// Minimum severity for push notification: "high" or "critical" (default: "high")
    #[serde(default = "default_web_push_min_severity")]
    pub min_severity: String,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

fn default_vapid_subject() -> String {
    "mailto:admin@example.com".to_string()
}

fn default_web_push_min_severity() -> String {
    "high".to_string()
}

impl Default for WebPushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vapid_subject: default_vapid_subject(),
            vapid_private_key: String::new(),
            vapid_public_key: String::new(),
            min_severity: default_web_push_min_severity(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Security (2FA)
// ---------------------------------------------------------------------------

/// Security settings for operator authentication.
#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    /// Two-factor authentication method: "none", "totp", "dashboard".
    /// Default: "none" (2FA disabled, v1 behavior).
    #[serde(default = "default_two_factor_method")]
    pub two_factor_method: String,
    /// TOTP secret (base32 encoded). Stored in agent.env as INNERWARDEN_TOTP_SECRET.
    /// Leave empty in TOML; set via `innerwarden configure 2fa`.
    #[serde(default)]
    pub totp_secret: String,
}

fn default_two_factor_method() -> String {
    "none".to_string()
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            two_factor_method: default_two_factor_method(),
            totp_secret: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load agent config from a TOML file.
/// If the file doesn't exist, returns `AgentConfig::default()`.
pub fn load(path: &Path) -> Result<AgentConfig> {
    if !path.exists() {
        return Ok(AgentConfig::default());
    }

    // Warn if config file is readable by group/others (may contain API keys)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode),
                    "config file is readable by other users, consider chmod 600"
                );
            }
        }
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read agent config {}", path.display()))?;

    // Verify config signature if [signature] section is present.
    verify_config_signature(&content, path)?;

    let mut cfg: AgentConfig = toml::from_str(&content)
        .with_context(|| format!("failed to parse agent config {}", path.display()))?;
    cfg.ai.clamp_confidence_threshold();
    Ok(cfg)
}

/// Verify Ed25519 signature of config file (Active Defence feature).
/// If [signature] section exists and [config_signing] has a public_key, verify.
/// If config_signing.required=true and signature is missing/invalid, fail.
fn verify_config_signature(content: &str, path: &Path) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Quick check: does the config have a [signature] section?
    let has_signature = content.contains("\n[signature]") || content.starts_with("[signature]");

    // Parse just the config_signing section to check settings.
    // We parse the full config minus [signature] to avoid TOML parse errors.
    let payload = if let Some(idx) = content.find("\n[signature]") {
        &content[..idx]
    } else {
        content
    };

    // Try to extract config_signing settings from the TOML.
    let signing_cfg: ConfigSigningConfig = match toml::from_str::<toml::Value>(payload) {
        Ok(val) => {
            if let Some(cs) = val.get("config_signing") {
                cs.clone().try_into().unwrap_or_default()
            } else {
                ConfigSigningConfig::default()
            }
        }
        Err(_) => ConfigSigningConfig::default(),
    };

    // No public key configured → skip verification (backwards compatible).
    let Some(pub_key_hex) = &signing_cfg.public_key else {
        if has_signature {
            tracing::debug!(
                "config has [signature] but no config_signing.public_key — skipping verification"
            );
        }
        return Ok(());
    };

    if pub_key_hex.is_empty() {
        return Ok(());
    }

    // No signature section but verification is required → fail.
    if !has_signature {
        if signing_cfg.required {
            anyhow::bail!(
                "config_signing.required=true but config {} has no [signature] section",
                path.display()
            );
        }
        tracing::debug!("config has config_signing.public_key but no [signature] — skipping");
        return Ok(());
    }

    // Extract signature value from [signature] section.
    let sig_hex = content
        .lines()
        .skip_while(|l| !l.starts_with("[signature]"))
        .find_map(|l| {
            let l = l.trim();
            if l.starts_with("value") {
                l.split('=')
                    .nth(1)
                    .map(|v| v.trim().trim_matches('"').to_string())
            } else {
                None
            }
        })
        .context("config [signature] section has no 'value' field")?;

    // Decode public key.
    let pub_bytes: Vec<u8> = (0..pub_key_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pub_key_hex[i..i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid hex in config_signing.public_key")?;

    let verifying_key = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .context("config_signing.public_key must be 32 bytes (64 hex chars)")?,
    )
    .context("invalid Ed25519 public key in config_signing")?;

    // Decode signature.
    let sig_bytes: Vec<u8> = (0..sig_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid hex in config signature value")?;

    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .context("signature must be 64 bytes (128 hex chars)")?,
    );

    // Verify.
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .context("CONFIG SIGNATURE VERIFICATION FAILED — config may be tampered")?;

    tracing::info!(config = %path.display(), "config signature verified");
    Ok(())
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_keep_days() -> usize {
    7
}

fn default_min_severity() -> String {
    "medium".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

fn default_ai_provider() -> String {
    "openai".to_string()
}

fn default_ai_model() -> String {
    "gpt-4o-mini".to_string()
}

fn default_context_events() -> usize {
    20
}

fn default_confidence_threshold() -> f32 {
    0.85
}

fn default_incident_poll_secs() -> u64 {
    2
}

fn default_max_ai_calls_per_tick() -> usize {
    5
}

fn default_circuit_breaker_cooldown_secs() -> u64 {
    60
}

fn default_protected_ips() -> Vec<String> {
    vec![
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "127.0.0.0/8".to_string(),
        "::1/128".to_string(),
    ]
}

fn default_block_backend() -> String {
    "ufw".to_string()
}

fn default_correlation_window_secs() -> u64 {
    300
}

fn default_max_related_incidents() -> usize {
    8
}

fn default_allowed_skills() -> Vec<String> {
    vec![
        "block-ip-ufw".to_string(),
        "block-ip-iptables".to_string(),
        "block-ip-nftables".to_string(),
        "block-ip-pf".to_string(),
        "monitor-ip".to_string(),
    ]
}

fn default_honeypot_mode() -> String {
    "demo".to_string()
}

fn default_honeypot_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_honeypot_port() -> u16 {
    2222
}

fn default_honeypot_duration_secs() -> u64 {
    300
}

fn default_honeypot_services() -> Vec<String> {
    vec!["ssh".to_string()]
}

fn default_honeypot_http_port() -> u16 {
    8080
}

fn default_honeypot_max_connections() -> usize {
    64
}

fn default_honeypot_max_payload_bytes() -> usize {
    512
}

fn default_honeypot_isolation_profile() -> String {
    "strict_local".to_string()
}

fn default_honeypot_forensics_keep_days() -> usize {
    7
}

fn default_honeypot_forensics_max_total_mb() -> usize {
    128
}

fn default_honeypot_transcript_preview_bytes() -> usize {
    96
}

fn default_honeypot_lock_stale_secs() -> u64 {
    1800
}

fn default_honeypot_pcap_timeout_secs() -> u64 {
    15
}

fn default_honeypot_pcap_max_packets() -> u64 {
    120
}

fn default_honeypot_containment_mode() -> String {
    "process".to_string()
}

fn default_honeypot_namespace_runner() -> String {
    "unshare".to_string()
}

fn default_honeypot_namespace_args() -> Vec<String> {
    vec![
        "--fork".to_string(),
        "--pid".to_string(),
        "--mount-proc".to_string(),
    ]
}

fn default_honeypot_external_handoff_timeout_secs() -> u64 {
    20
}

fn default_honeypot_external_handoff_signature_key_env() -> String {
    "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string()
}

fn default_honeypot_jail_runner() -> String {
    "bwrap".to_string()
}

fn default_honeypot_jail_profile() -> String {
    "standard".to_string()
}

fn default_honeypot_external_handoff_attestation_key_env() -> String {
    "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string()
}

fn default_honeypot_external_handoff_attestation_prefix() -> String {
    "IW_ATTEST".to_string()
}

fn default_honeypot_redirect_backend() -> String {
    "iptables".to_string()
}

fn default_honeypot_interaction() -> String {
    "banner".to_string()
}

fn default_honeypot_ssh_max_auth_attempts() -> usize {
    6
}

fn default_honeypot_http_max_requests() -> usize {
    10
}

// ---------------------------------------------------------------------------
// Data retention
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DataRetentionConfig {
    /// Keep daily events JSONL for N days (default: 7)
    #[serde(default = "default_data_events_keep_days")]
    pub events_keep_days: usize,

    /// Keep daily incidents JSONL for N days (default: 30)
    #[serde(default = "default_data_incidents_keep_days")]
    pub incidents_keep_days: usize,

    /// Keep daily decisions JSONL for N days - audit trail (default: 90)
    #[serde(default = "default_data_decisions_keep_days")]
    pub decisions_keep_days: usize,

    /// Keep daily telemetry JSONL for N days (default: 14)
    #[serde(default = "default_data_telemetry_keep_days")]
    pub telemetry_keep_days: usize,

    /// Keep trial-report-*.{json,md} for N days (default: 30)
    #[serde(default = "default_data_reports_keep_days")]
    pub reports_keep_days: usize,
}

impl Default for DataRetentionConfig {
    fn default() -> Self {
        Self {
            events_keep_days: default_data_events_keep_days(),
            incidents_keep_days: default_data_incidents_keep_days(),
            decisions_keep_days: default_data_decisions_keep_days(),
            telemetry_keep_days: default_data_telemetry_keep_days(),
            reports_keep_days: default_data_reports_keep_days(),
        }
    }
}

fn default_data_events_keep_days() -> usize {
    7
}
fn default_data_incidents_keep_days() -> usize {
    30
}
fn default_data_decisions_keep_days() -> usize {
    90
}
fn default_data_telemetry_keep_days() -> usize {
    14
}
fn default_data_reports_keep_days() -> usize {
    30
}

fn default_telegram_min_severity() -> String {
    "high".to_string()
}

fn default_slack_min_severity() -> String {
    "high".to_string()
}

// ---------------------------------------------------------------------------
// CrowdSec
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CrowdSecConfig {
    /// Enable CrowdSec LAPI polling (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// CrowdSec Local API URL (default: http://localhost:8080)
    #[serde(default = "default_crowdsec_url")]
    pub url: String,

    /// CrowdSec LAPI API key. Can also be set via CROWDSEC_API_KEY env var.
    /// Find it in: /etc/crowdsec/local_api_credentials.yaml (password field)
    #[serde(default)]
    pub api_key: String,

    /// How often to poll the LAPI for new ban decisions (seconds, default: 60)
    #[serde(default = "default_crowdsec_poll_secs")]
    pub poll_secs: u64,

    /// Max new IPs to block per sync cycle (default: 50).
    /// CrowdSec CAPI can return thousands of IPs at once; blocking them all
    /// in a single tick stalls the agent and exhausts memory.
    /// Remaining IPs are processed in subsequent ticks.
    #[serde(default = "default_crowdsec_max_per_sync")]
    #[allow(dead_code)]
    pub max_per_sync: usize,
}

impl Default for CrowdSecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_crowdsec_url(),
            api_key: String::new(),
            poll_secs: default_crowdsec_poll_secs(),
            max_per_sync: default_crowdsec_max_per_sync(),
        }
    }
}

fn default_crowdsec_url() -> String {
    "http://localhost:8080".to_string()
}

fn default_crowdsec_poll_secs() -> u64 {
    60
}

fn default_crowdsec_max_per_sync() -> usize {
    50
}

fn default_telegram_approval_ttl_secs() -> u64 {
    600
}

fn default_telegram_daily_budget() -> u32 {
    10
}

fn default_user_profile() -> String {
    "simple".to_string()
}

// ---------------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AbuseIpDbConfig {
    /// Enable AbuseIPDB IP reputation enrichment (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// AbuseIPDB API key. Can also be set via ABUSEIPDB_API_KEY env var.
    /// Free tier: 1,000 checks/day - sufficient for most self-hosted servers.
    #[serde(default)]
    pub api_key: String,

    /// Maximum age of abuse reports to consider (default: 30 days).
    #[serde(default = "default_abuseipdb_max_age_days")]
    pub max_age_days: u32,

    /// Auto-block threshold: if AbuseIPDB confidence score >= this value,
    /// block the IP immediately without calling the AI provider.
    /// 0 = disabled (default). Recommended: 75 for aggressive auto-blocking,
    /// 90 for conservative auto-blocking. Reduces AI API costs during attacks
    /// from known malicious IPs.
    #[serde(default)]
    pub auto_block_threshold: u8,

    /// Report blocked IPs back to AbuseIPDB (default: false).
    /// When enabled, every successful block_ip action is reported to the
    /// AbuseIPDB database with the appropriate attack categories.
    /// This contributes to the global threat intelligence network.
    #[serde(default)]
    pub report_blocks: bool,

    /// Maximum AbuseIPDB *report-endpoint* calls per 24h UTC. Free tier
    /// grants 1,000 per day; the default of 800 reserves 20% headroom for
    /// operator-triggered ad-hoc reports. A production incident on
    /// 2026-04-18 (`correlation:CL-008` cascade) burned ~900 reports in
    /// one day and tripped AbuseIPDB's quota email — the cap here is the
    /// second line of defence behind `cloud_safelist`. Set to `0` to
    /// pause outbound reporting entirely without disabling the rest of
    /// the AbuseIPDB integration.
    #[serde(default = "default_abuseipdb_report_daily_cap")]
    pub report_daily_cap: u32,
}

impl Default for AbuseIpDbConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: String::new(),
            max_age_days: default_abuseipdb_max_age_days(),
            auto_block_threshold: 0,
            report_blocks: false,
            report_daily_cap: default_abuseipdb_report_daily_cap(),
        }
    }
}

fn default_abuseipdb_max_age_days() -> u32 {
    30
}

fn default_abuseipdb_report_daily_cap() -> u32 {
    800
}

// ---------------------------------------------------------------------------
// Fail2ban
// ---------------------------------------------------------------------------

/// Deprecated - InnerWarden's native detectors + XDP firewall supersede fail2ban.
/// Kept for config compatibility (existing agent.toml files won't break).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Fail2BanConfig {
    /// Enable fail2ban polling (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// How often to poll fail2ban for new ban decisions (seconds, default: 60)
    #[serde(default = "default_fail2ban_poll_secs")]
    pub poll_secs: u64,

    /// Jails to poll. Empty = all active jails (from `fail2ban-client status`).
    #[serde(default)]
    pub jails: Vec<String>,

    /// Prefix fail2ban-client calls with sudo (needed when agent runs as non-root,
    /// requires: `innerwarden ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client *` in sudoers).
    #[serde(default)]
    pub use_sudo: bool,
}

impl Default for Fail2BanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_secs: default_fail2ban_poll_secs(),
            jails: vec![],
            use_sudo: false,
        }
    }
}

fn default_fail2ban_poll_secs() -> u64 {
    60
}

// ---------------------------------------------------------------------------
// GeoIP enrichment
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct GeoIpConfig {
    /// Enable IP geolocation enrichment via ip-api.com (default: false).
    /// No API key required. Free tier: 45 requests/minute.
    #[serde(default)]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Threat Feeds
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ThreatFeedsConfig {
    /// External IOC feed URLs (plaintext IP/domain lists). Polled periodically.
    /// Free public feeds:
    /// - https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    /// - https://urlhaus.abuse.ch/downloads/text/
    /// - https://threatfox.abuse.ch/downloads/iocs/text/
    #[serde(default)]
    pub ioc_feed_urls: Vec<String>,

    /// VirusTotal API key for binary hash checking (optional).
    /// Can also be set via VT_API_KEY or VIRUSTOTAL_API_KEY env var.
    #[serde(default)]
    pub virustotal_api_key: String,

    /// Poll interval in seconds (default: 3600 = 1 hour).
    /// Currently feeds are polled on every slow tick; this field is reserved
    /// for rate-limiting the poll frequency in a future version.
    #[serde(default = "default_threat_feeds_poll_secs")]
    #[allow(dead_code)]
    pub poll_secs: u64,
}

fn default_threat_feeds_poll_secs() -> u64 {
    3600
}

/// Default IOC feeds — mirrors sensor's datasets::FEEDS so both sensor and
/// agent share the same curated threat intelligence sources out of the box.
pub const DEFAULT_IOC_FEEDS: &[&str] = &[
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://check.torproject.org/torbulkexitlist",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://www.dshield.org/block.txt",
    "https://urlhaus.abuse.ch/downloads/text_online/",
    "https://threatfox.abuse.ch/downloads/hostfile/",
];

impl Default for ThreatFeedsConfig {
    fn default() -> Self {
        Self {
            ioc_feed_urls: Vec::new(),
            virustotal_api_key: String::new(),
            poll_secs: default_threat_feeds_poll_secs(),
        }
    }
}

impl ThreatFeedsConfig {
    /// Effective feed URLs: user-configured if any, otherwise the curated defaults.
    pub fn effective_urls(&self) -> Vec<String> {
        if self.ioc_feed_urls.is_empty() {
            DEFAULT_IOC_FEEDS.iter().map(|u| u.to_string()).collect()
        } else {
            self.ioc_feed_urls.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// Notification Pipeline (Feature 005)
// ---------------------------------------------------------------------------

/// Notification filter level for a channel.
/// Controls which incident groups are forwarded to this channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelFilterLevel {
    /// Every incident group (first event + summaries).
    #[default]
    All,
    /// Only groups that need human decision (not auto-resolved, ambiguous, or
    /// above confidence threshold).
    Actionable,
    /// Only HIGH/CRITICAL that are not auto-resolved.
    Critical,
    /// Silent — only digest (if configured).
    None,
}

/// Digest frequency for a notification channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestFrequency {
    Daily,
    Hourly,
    #[default]
    None,
}

/// Top-level notification pipeline config.
///
/// ```toml
/// [notifications]
/// group_window_secs = 3600
/// group_count_threshold = 10
/// ```
#[derive(Debug, Deserialize)]
pub struct NotificationPipelineConfig {
    /// Grouping window in seconds. Incidents from the same detector+entity
    /// within this window are grouped into a single notification.
    #[serde(default = "default_group_window_secs")]
    pub group_window_secs: u64,

    /// Emit an early group summary when this many incidents accumulate,
    /// without waiting for the window to close.
    #[serde(default = "default_group_count_threshold")]
    pub group_count_threshold: u32,
}

impl Default for NotificationPipelineConfig {
    fn default() -> Self {
        Self {
            group_window_secs: default_group_window_secs(),
            group_count_threshold: default_group_count_threshold(),
        }
    }
}

fn default_group_window_secs() -> u64 {
    3600
}
fn default_group_count_threshold() -> u32 {
    10
}

/// Per-channel notification filter and digest settings.
///
/// Embedded inside each channel config (Telegram, Slack, etc.) as:
/// ```toml
/// [telegram]
/// notification_level = "actionable"
/// digest = "daily"
/// digest_hour = 9
/// ```
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ChannelNotificationConfig {
    /// Filter level for real-time notifications.
    #[serde(default = "default_channel_level_actionable")]
    pub notification_level: ChannelFilterLevel,

    /// Digest frequency.
    #[serde(default)]
    pub digest: DigestFrequency,

    /// Hour of day (0–23, local time) to send daily digest.
    /// Only used when `digest = "daily"`.
    #[serde(default = "default_digest_hour")]
    pub digest_hour: u8,
}

impl Default for ChannelNotificationConfig {
    fn default() -> Self {
        Self {
            notification_level: default_channel_level_actionable(),
            digest: DigestFrequency::None,
            digest_hour: default_digest_hour(),
        }
    }
}

fn default_channel_level_actionable() -> ChannelFilterLevel {
    ChannelFilterLevel::Actionable
}
fn default_digest_hour() -> u8 {
    9
}

/// Environment auto-profiling and census configuration.
///
/// ```toml
/// [environment]
/// auto_profile = true
/// census_interval_hours = 6
/// cloud_timing_multiplier = 10
/// ```
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EnvironmentConfig {
    /// Run bootstrap profiling on first boot (or when profile missing).
    #[serde(default = "default_true_val")]
    pub auto_profile: bool,

    /// How often to run the periodic census (hours).
    #[serde(default = "default_census_interval_hours")]
    pub census_interval_hours: u64,

    /// Timing anomaly threshold multiplier for cloud/VM environments.
    /// Applied automatically when `platform` is detected as cloud VPS.
    #[serde(default = "default_cloud_timing_multiplier")]
    pub cloud_timing_multiplier: u32,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            auto_profile: true,
            census_interval_hours: default_census_interval_hours(),
            cloud_timing_multiplier: default_cloud_timing_multiplier(),
        }
    }
}

fn default_census_interval_hours() -> u64 {
    6
}
fn default_cloud_timing_multiplier() -> u32 {
    10
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn defaults_when_no_file() {
        let cfg = load(Path::new("/nonexistent/agent.toml")).unwrap();
        assert!(cfg.narrative.enabled);
        assert_eq!(cfg.narrative.keep_days, 7);
        assert!(!cfg.webhook.enabled);
        assert_eq!(cfg.webhook.min_severity, "medium");
        assert_eq!(cfg.webhook.timeout_secs, 10);
        assert!(cfg.correlation.enabled);
        assert_eq!(cfg.correlation.window_seconds, 300);
        assert_eq!(cfg.correlation.max_related_incidents, 8);
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.honeypot.mode, "demo");
        assert_eq!(cfg.honeypot.bind_addr, "127.0.0.1");
        assert_eq!(cfg.honeypot.port, 2222);
        assert_eq!(cfg.honeypot.duration_secs, 300);
        assert_eq!(cfg.honeypot.services, vec!["ssh".to_string()]);
        assert_eq!(cfg.honeypot.http_port, 8080);
        assert!(cfg.honeypot.strict_target_only);
        assert!(!cfg.honeypot.allow_public_listener);
        assert_eq!(cfg.honeypot.max_connections, 64);
        assert_eq!(cfg.honeypot.max_payload_bytes, 512);
        assert_eq!(cfg.honeypot.isolation_profile, "strict_local");
        assert!(cfg.honeypot.require_high_ports);
        assert_eq!(cfg.honeypot.forensics_keep_days, 7);
        assert_eq!(cfg.honeypot.forensics_max_total_mb, 128);
        assert_eq!(cfg.honeypot.transcript_preview_bytes, 96);
        assert_eq!(cfg.honeypot.lock_stale_secs, 1800);
        assert_eq!(cfg.honeypot.interaction, "banner");
        assert_eq!(cfg.honeypot.ssh_max_auth_attempts, 6);
        assert_eq!(cfg.honeypot.http_max_requests, 10);
        assert!(!cfg.honeypot.sandbox.enabled);
        assert!(cfg.honeypot.sandbox.runner_path.is_empty());
        assert!(cfg.honeypot.sandbox.clear_env);
        assert!(!cfg.honeypot.pcap_handoff.enabled);
        assert_eq!(cfg.honeypot.pcap_handoff.timeout_secs, 15);
        assert_eq!(cfg.honeypot.pcap_handoff.max_packets, 120);
        assert_eq!(cfg.honeypot.containment.mode, "process");
        assert!(!cfg.honeypot.containment.require_success);
        assert_eq!(cfg.honeypot.containment.namespace_runner, "unshare");
        assert_eq!(
            cfg.honeypot.containment.namespace_args,
            vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string()
            ]
        );
        assert_eq!(cfg.honeypot.containment.jail_runner, "bwrap");
        assert!(cfg.honeypot.containment.jail_args.is_empty());
        assert_eq!(cfg.honeypot.containment.jail_profile, "standard");
        assert!(cfg.honeypot.containment.allow_namespace_fallback);
        assert!(!cfg.honeypot.external_handoff.enabled);
        assert!(cfg.honeypot.external_handoff.command.is_empty());
        assert!(cfg.honeypot.external_handoff.args.is_empty());
        assert_eq!(cfg.honeypot.external_handoff.timeout_secs, 20);
        assert!(!cfg.honeypot.external_handoff.require_success);
        assert!(cfg.honeypot.external_handoff.clear_env);
        assert!(cfg.honeypot.external_handoff.allowed_commands.is_empty());
        assert!(!cfg.honeypot.external_handoff.enforce_allowlist);
        assert!(!cfg.honeypot.external_handoff.signature_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.signature_key_env,
            "INNERWARDEN_HANDOFF_SIGNING_KEY"
        );
        assert!(!cfg.honeypot.external_handoff.attestation_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_key_env,
            "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_prefix,
            "IW_ATTEST"
        );
        assert!(cfg
            .honeypot
            .external_handoff
            .attestation_expected_receiver
            .is_empty());
        assert!(!cfg.honeypot.redirect.enabled);
        assert_eq!(cfg.honeypot.redirect.backend, "iptables");
        assert!(!cfg.telegram.enabled);
        assert!(cfg.telegram.bot_token.is_empty());
        assert!(cfg.telegram.chat_id.is_empty());
        assert_eq!(cfg.telegram.min_severity, "high");
        assert!(cfg.telegram.dashboard_url.is_empty());
        assert_eq!(cfg.telegram.approval_ttl_secs, 600);
    }

    #[test]
    fn parses_full_config() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[narrative]
enabled = false
keep_days = 3

[webhook]
enabled = true
url = "https://hooks.example.com/notify"
min_severity = "high"
timeout_secs = 5

[correlation]
enabled = true
window_seconds = 120
max_related_incidents = 4

[telemetry]
enabled = true

[honeypot]
mode = "listener"
bind_addr = "0.0.0.0"
port = 2223
duration_secs = 120
services = ["ssh", "http"]
http_port = 8088
strict_target_only = true
allow_public_listener = true
max_connections = 10
max_payload_bytes = 256
isolation_profile = "standard"
require_high_ports = false
forensics_keep_days = 14
forensics_max_total_mb = 512
transcript_preview_bytes = 192
lock_stale_secs = 600
interaction = "medium"
ssh_max_auth_attempts = 3
http_max_requests = 5

[honeypot.sandbox]
enabled = true
runner_path = "/usr/local/bin/innerwarden-agent"
clear_env = false

[honeypot.pcap_handoff]
enabled = true
timeout_secs = 20
max_packets = 200

[honeypot.containment]
mode = "jail"
require_success = true
namespace_runner = "/usr/bin/unshare"
namespace_args = ["--fork", "--pid", "--mount-proc", "--net"]
jail_runner = "/usr/bin/bwrap"
jail_args = ["--die-with-parent", "--unshare-all"]
jail_profile = "strict"
allow_namespace_fallback = false

[honeypot.external_handoff]
enabled = true
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{{session_id}}", "--metadata", "{{metadata_path}}", "--evidence", "{{evidence_path}}", "--pcap", "{{pcap_path}}"]
timeout_secs = 25
require_success = true
clear_env = false
allowed_commands = ["/usr/local/bin/iw-handoff", "/usr/local/bin/iw-alt"]
enforce_allowlist = true
signature_enabled = true
signature_key_env = "IW_HANDOFF_KEY"
attestation_enabled = true
attestation_key_env = "IW_HANDOFF_ATTEST_KEY"
attestation_prefix = "IW_ATTEST"
attestation_expected_receiver = "receiver-a"

[honeypot.redirect]
enabled = true
backend = "iptables"

[telegram]
enabled = true
bot_token = "1234567890:AAAAAAAAAA"
chat_id = "-1001234567890"
min_severity = "critical"
dashboard_url = "http://my-server:8787"
approval_ttl_secs = 300
"#
        )
        .unwrap();

        let cfg = load(f.path()).unwrap();
        assert!(!cfg.narrative.enabled);
        assert_eq!(cfg.narrative.keep_days, 3);
        assert!(cfg.webhook.enabled);
        assert_eq!(cfg.webhook.url, "https://hooks.example.com/notify");
        assert_eq!(cfg.webhook.parsed_min_severity(), Severity::High);
        assert_eq!(cfg.webhook.timeout_secs, 5);
        assert!(cfg.correlation.enabled);
        assert_eq!(cfg.correlation.window_seconds, 120);
        assert_eq!(cfg.correlation.max_related_incidents, 4);
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.honeypot.mode, "listener");
        assert_eq!(cfg.honeypot.bind_addr, "0.0.0.0");
        assert_eq!(cfg.honeypot.port, 2223);
        assert_eq!(cfg.honeypot.duration_secs, 120);
        assert_eq!(
            cfg.honeypot.services,
            vec!["ssh".to_string(), "http".to_string()]
        );
        assert_eq!(cfg.honeypot.http_port, 8088);
        assert!(cfg.honeypot.strict_target_only);
        assert!(cfg.honeypot.allow_public_listener);
        assert_eq!(cfg.honeypot.max_connections, 10);
        assert_eq!(cfg.honeypot.max_payload_bytes, 256);
        assert_eq!(cfg.honeypot.isolation_profile, "standard");
        assert!(!cfg.honeypot.require_high_ports);
        assert_eq!(cfg.honeypot.forensics_keep_days, 14);
        assert_eq!(cfg.honeypot.forensics_max_total_mb, 512);
        assert_eq!(cfg.honeypot.transcript_preview_bytes, 192);
        assert_eq!(cfg.honeypot.lock_stale_secs, 600);
        assert_eq!(cfg.honeypot.interaction, "medium");
        assert_eq!(cfg.honeypot.ssh_max_auth_attempts, 3);
        assert_eq!(cfg.honeypot.http_max_requests, 5);
        assert!(cfg.honeypot.sandbox.enabled);
        assert_eq!(
            cfg.honeypot.sandbox.runner_path,
            "/usr/local/bin/innerwarden-agent"
        );
        assert!(!cfg.honeypot.sandbox.clear_env);
        assert!(cfg.honeypot.pcap_handoff.enabled);
        assert_eq!(cfg.honeypot.pcap_handoff.timeout_secs, 20);
        assert_eq!(cfg.honeypot.pcap_handoff.max_packets, 200);
        assert_eq!(cfg.honeypot.containment.mode, "jail");
        assert!(cfg.honeypot.containment.require_success);
        assert_eq!(
            cfg.honeypot.containment.namespace_runner,
            "/usr/bin/unshare"
        );
        assert_eq!(
            cfg.honeypot.containment.namespace_args,
            vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string(),
                "--net".to_string()
            ]
        );
        assert_eq!(cfg.honeypot.containment.jail_runner, "/usr/bin/bwrap");
        assert_eq!(
            cfg.honeypot.containment.jail_args,
            vec!["--die-with-parent".to_string(), "--unshare-all".to_string()]
        );
        assert_eq!(cfg.honeypot.containment.jail_profile, "strict");
        assert!(!cfg.honeypot.containment.allow_namespace_fallback);
        assert!(cfg.honeypot.external_handoff.enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.command,
            "/usr/local/bin/iw-handoff"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.args,
            vec![
                "--session-id".to_string(),
                "{session_id}".to_string(),
                "--metadata".to_string(),
                "{metadata_path}".to_string(),
                "--evidence".to_string(),
                "{evidence_path}".to_string(),
                "--pcap".to_string(),
                "{pcap_path}".to_string(),
            ]
        );
        assert_eq!(cfg.honeypot.external_handoff.timeout_secs, 25);
        assert!(cfg.honeypot.external_handoff.require_success);
        assert!(!cfg.honeypot.external_handoff.clear_env);
        assert_eq!(
            cfg.honeypot.external_handoff.allowed_commands,
            vec![
                "/usr/local/bin/iw-handoff".to_string(),
                "/usr/local/bin/iw-alt".to_string()
            ]
        );
        assert!(cfg.honeypot.external_handoff.enforce_allowlist);
        assert!(cfg.honeypot.external_handoff.signature_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.signature_key_env,
            "IW_HANDOFF_KEY"
        );
        assert!(cfg.honeypot.external_handoff.attestation_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_key_env,
            "IW_HANDOFF_ATTEST_KEY"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_prefix,
            "IW_ATTEST"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_expected_receiver,
            "receiver-a"
        );
        assert!(cfg.honeypot.redirect.enabled);
        assert_eq!(cfg.honeypot.redirect.backend, "iptables");
        assert!(cfg.telegram.enabled);
        assert_eq!(cfg.telegram.bot_token, "1234567890:AAAAAAAAAA");
        assert_eq!(cfg.telegram.chat_id, "-1001234567890");
        assert_eq!(cfg.telegram.parsed_min_severity(), Severity::Critical);
        assert_eq!(cfg.telegram.dashboard_url, "http://my-server:8787");
        assert_eq!(cfg.telegram.approval_ttl_secs, 300);
    }

    #[test]
    fn parsed_min_severity_unknown_defaults_to_medium() {
        let cfg = WebhookConfig {
            min_severity: "bogus".into(),
            ..Default::default()
        };
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
    }

    #[test]
    fn telegram_validate_disabled_is_ok() {
        let cfg = TelegramConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn telegram_validate_enabled_missing_token() {
        let cfg = TelegramConfig {
            enabled: true,
            bot_token: String::new(),
            chat_id: "-1001234567890".into(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("bot_token"),
            "error should mention bot_token: {err}"
        );
    }

    #[test]
    fn telegram_validate_enabled_missing_chat_id() {
        let cfg = TelegramConfig {
            enabled: true,
            bot_token: "1234567890:AAAAAAAAAA".into(),
            chat_id: String::new(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("chat_id"),
            "error should mention chat_id: {err}"
        );
    }

    #[test]
    fn telegram_validate_enabled_configured_is_ok() {
        let cfg = TelegramConfig {
            enabled: true,
            bot_token: "1234567890:AAAAAAAAAA".into(),
            chat_id: "-1001234567890".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn telegram_validate_invalid_summary_hour() {
        let cfg = TelegramConfig {
            daily_summary_hour: Some(25),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("daily_summary_hour"),
            "error should mention daily_summary_hour: {err}"
        );
    }

    #[test]
    fn telegram_validate_valid_summary_hour() {
        let cfg = TelegramConfig {
            daily_summary_hour: Some(23),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    // -- AI config tests --

    #[test]
    fn ai_parsed_min_severity_defaults_to_medium() {
        // v0.12.4: default floor lowered from "high" to "medium" so AI
        // triage sees the Medium-severity layer (where most bot campaigns
        // live). Operators can still set "high" in agent.toml explicitly.
        let cfg = AiConfig::default();
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
    }

    #[test]
    fn ai_parsed_min_severity_accepts_all_levels() {
        let mut cfg = AiConfig::default();
        cfg.min_severity = "low".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Low);
        cfg.min_severity = "medium".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
        cfg.min_severity = "high".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
        cfg.min_severity = "critical".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Critical);
    }

    #[test]
    fn ai_parsed_min_severity_unknown_defaults_to_high() {
        let mut cfg = AiConfig::default();
        cfg.min_severity = "galaxy".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
    }

    #[test]
    fn ai_resolved_api_key_prefers_config() {
        let mut cfg = AiConfig::default();
        cfg.api_key = "my-key".into();
        assert_eq!(cfg.resolved_api_key(), "my-key");
    }

    #[test]
    fn ai_resolved_api_key_empty_config_falls_to_env() {
        let cfg = AiConfig::default();
        // Without env var set, returns empty string
        let key = cfg.resolved_api_key();
        // This just checks it doesn't panic; actual value depends on env
        let _ = key;
    }

    #[test]
    fn ai_default_values() {
        let cfg = AiConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.provider, "openai");
        assert!(
            (cfg.confidence_threshold - 0.85).abs() < f32::EPSILON,
            "default threshold should be 0.85"
        );
        assert!(cfg.max_ai_calls_per_tick > 0);
        assert_eq!(cfg.circuit_breaker_threshold, 0); // disabled by default
    }

    // -- Telegram additional tests --

    #[test]
    fn telegram_is_simple_profile_case_insensitive() {
        let mut cfg = TelegramConfig::default();
        cfg.user_profile = "Simple".into();
        assert!(cfg.is_simple_profile());
        cfg.user_profile = "SIMPLE".into();
        assert!(cfg.is_simple_profile());
        cfg.user_profile = "technical".into();
        assert!(!cfg.is_simple_profile());
    }

    #[test]
    fn telegram_parsed_min_severity_all_levels() {
        let mut cfg = TelegramConfig::default();
        cfg.min_severity = "low".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Low);
        cfg.min_severity = "medium".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
        cfg.min_severity = "critical".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Critical);
        cfg.min_severity = "nonsense".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High); // default fallback
    }

    // -- Slack config tests --

    #[test]
    fn slack_parsed_min_severity_defaults_to_high() {
        let cfg = SlackConfig::default();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
    }

    #[test]
    fn slack_parsed_min_severity_unknown_defaults_to_high() {
        let mut cfg = SlackConfig::default();
        cfg.min_severity = "banana".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
    }

    // -- Webhook config tests --

    #[test]
    fn webhook_parsed_min_severity_all_levels() {
        let mut cfg = WebhookConfig::default();
        cfg.min_severity = "debug".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Debug);
        cfg.min_severity = "info".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Info);
        cfg.min_severity = "low".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Low);
        cfg.min_severity = "high".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
        cfg.min_severity = "critical".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Critical);
    }

    // -- Responder defaults --

    #[test]
    fn responder_defaults() {
        let cfg = ResponderConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.dry_run);
        assert!(!cfg.allowed_skills.is_empty());
    }

    // -- Channel notification defaults --

    #[test]
    fn channel_notification_default_is_actionable() {
        let cfg = ChannelNotificationConfig::default();
        assert_eq!(cfg.notification_level, ChannelFilterLevel::Actionable);
    }

    // -- Briefing config defaults --

    #[test]
    fn briefing_defaults() {
        let cfg = BriefingConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.hour, 8);
        assert_eq!(cfg.minute, 0);
        assert!(cfg.telegram);
    }

    #[test]
    fn clamp_confidence_threshold_fixes_unreachable_upper_bound() {
        let mut ai = AiConfig::default();
        ai.confidence_threshold = 1.01;
        ai.clamp_confidence_threshold();
        assert!(
            (ai.confidence_threshold - default_confidence_threshold()).abs() < f32::EPSILON,
            "threshold > 1.0 must be clamped to default"
        );
    }

    #[test]
    fn clamp_confidence_threshold_fixes_negative() {
        let mut ai = AiConfig::default();
        ai.confidence_threshold = -0.5;
        ai.clamp_confidence_threshold();
        assert!(
            (ai.confidence_threshold - default_confidence_threshold()).abs() < f32::EPSILON,
            "negative threshold must be clamped to default"
        );
    }

    #[test]
    fn clamp_confidence_threshold_leaves_valid_values_untouched() {
        for v in [0.0_f32, 0.5, 0.7, 0.85, 0.99, 1.0] {
            let mut ai = AiConfig::default();
            ai.confidence_threshold = v;
            ai.clamp_confidence_threshold();
            assert!(
                (ai.confidence_threshold - v).abs() < f32::EPSILON,
                "valid threshold {v} must not be clamped",
            );
        }
    }

    #[test]
    fn load_clamps_bogus_confidence_threshold() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "[ai]\nconfidence_threshold = 1.01").unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert!(
            (cfg.ai.confidence_threshold - default_confidence_threshold()).abs() < f32::EPSILON,
            "load() must apply clamp so autonomous execution can fire"
        );
    }

    #[test]
    fn shadow_config_default_is_disabled() {
        let s = ShadowConfig::default();
        assert!(!s.enabled);
        assert!(s.provider.is_empty());
        assert!(s.api_key.is_empty());
        assert!(s.model.is_empty());
        assert!(s.base_url.is_empty());
        assert!(s.api_version.is_empty());
        assert_eq!(s.log_path, "/var/lib/innerwarden/shadow-decisions.jsonl");
    }

    #[test]
    fn shadow_config_default_log_path_constant() {
        assert_eq!(
            default_shadow_log_path(),
            "/var/lib/innerwarden/shadow-decisions.jsonl"
        );
    }

    #[test]
    fn shadow_resolved_api_key_field_wins() {
        let mut s = ShadowConfig::default();
        s.api_key = "explicit-key".into();
        s.provider = "openai".into();
        assert_eq!(s.resolved_api_key(), "explicit-key");
    }

    #[test]
    fn shadow_resolved_api_key_matches_each_provider_branch() {
        // Each provider branch must compile + run without panic regardless of
        // the host's env. Function returns String (never errors).
        for provider in ["openai", "anthropic", "ollama", "azure_openai", "unknown"] {
            let mut s = ShadowConfig::default();
            s.provider = provider.into();
            // field empty -> goes into match
            let _ = s.resolved_api_key();
        }
    }

    #[test]
    fn ai_config_default_has_disabled_shadow() {
        let cfg = AiConfig::default();
        assert!(!cfg.shadow.enabled);
        assert!(cfg.api_version.is_empty());
    }

    #[test]
    fn load_parses_shadow_config_block() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai]
provider = "azure_openai"
model = "gpt-5-4-mini"
base_url = "https://example-resource.openai.azure.com"
api_version = "2024-12-01-preview"

[ai.shadow]
enabled = true
provider = "stub"
log_path = "/tmp/shadow.jsonl"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert_eq!(cfg.ai.provider, "azure_openai");
        assert_eq!(cfg.ai.api_version, "2024-12-01-preview");
        assert!(cfg.ai.shadow.enabled);
        assert_eq!(cfg.ai.shadow.provider, "stub");
        assert_eq!(cfg.ai.shadow.log_path, "/tmp/shadow.jsonl");
    }

    #[test]
    fn ai_resolved_api_key_recognises_azure_env() {
        // The AiConfig::resolved_api_key match added "azure_openai" arm.
        // Same coverage guarantee as shadow: hit each branch without panic.
        for provider in ["openai", "anthropic", "ollama", "azure_openai", "unknown"] {
            let mut ai = AiConfig::default();
            ai.provider = provider.into();
            let _ = ai.resolved_api_key();
        }
    }

    // Spec 028-b: incident_flow config defaults keep the flag off and the
    // skip-fase3 list empty so bundled deploy changes nothing about decision
    // behaviour until operator flips the flag explicitly.
    #[test]
    fn incident_flow_defaults_are_conservative() {
        let cfg = IncidentFlowConfig::default();
        assert!(!cfg.escalate_to_decide);
        assert!(cfg.detectors_skip_fase3.is_empty());
    }

    #[test]
    fn load_parses_incident_flow_section() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[incident_flow]
escalate_to_decide = true
detectors_skip_fase3 = ["threat_intel", "sudo_abuse", "suspicious_execution"]
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert!(cfg.incident_flow.escalate_to_decide);
        assert_eq!(cfg.incident_flow.detectors_skip_fase3.len(), 3);
        assert!(cfg
            .incident_flow
            .detectors_skip_fase3
            .iter()
            .any(|d| d == "threat_intel"));
    }

    // Spec 029 PR-C: RoleProviderConfig default is disabled + empty.
    // When both per-role blocks are absent from agent.toml the router
    // falls back to the primary [ai] provider (PR-B back-compat).
    #[test]
    fn role_provider_config_default_is_disabled() {
        let r = RoleProviderConfig::default();
        assert!(!r.enabled);
        assert!(r.provider.is_empty());
        assert!(r.api_key.is_empty());
        assert!(r.model.is_empty());
        assert!(r.base_url.is_empty());
        assert!(r.api_version.is_empty());
    }

    // Spec 029 PR-C: ai_config defaults keep both per-role blocks
    // disabled so pre-029 configs auto-use the primary [ai] block.
    #[test]
    fn ai_config_default_has_disabled_per_role_blocks() {
        let cfg = AiConfig::default();
        assert!(!cfg.classifier.enabled);
        assert!(!cfg.llm.enabled);
    }

    // Spec 029 PR-C: to_ai_config maps the per-role fields into a
    // full AiConfig shell suitable for ai::build_provider. Shared
    // knobs (confidence_threshold, min_severity, etc.) default.
    #[test]
    fn role_provider_to_ai_config_maps_fields() {
        let role = RoleProviderConfig {
            enabled: true,
            provider: "azure_openai".into(),
            api_key: "explicit".into(),
            model: "gpt-5.4-mini".into(),
            base_url: "https://example.openai.azure.com".into(),
            api_version: "2024-12-01-preview".into(),
        };
        let cfg = role.to_ai_config();
        assert!(cfg.enabled);
        assert_eq!(cfg.provider, "azure_openai");
        assert_eq!(cfg.api_key, "explicit");
        assert_eq!(cfg.model, "gpt-5.4-mini");
        assert_eq!(cfg.base_url, "https://example.openai.azure.com");
        assert_eq!(cfg.api_version, "2024-12-01-preview");
        // Shared knobs come from AiConfig::default().
        assert!(!cfg.shadow.enabled);
        assert_eq!(cfg.min_severity, "medium");
    }

    // Spec 029 PR-C: empty api_key on to_ai_config stays empty so
    // the downstream AiConfig::resolved_api_key env-var fallback
    // (OPENAI_API_KEY, AZURE_OPENAI_API_KEY, etc.) fires normally.
    #[test]
    fn role_provider_to_ai_config_preserves_empty_api_key() {
        let role = RoleProviderConfig {
            enabled: true,
            provider: "openai".into(),
            api_key: String::new(),
            ..Default::default()
        };
        let cfg = role.to_ai_config();
        assert!(cfg.api_key.is_empty());
    }

    // Spec 029 PR-C: parses the classifier + llm TOML sections.
    #[test]
    fn load_parses_classifier_and_llm_sections() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai]
enabled = true
provider = "stub"

[ai.classifier]
enabled = true
provider = "local_classifier"
base_url = "/var/lib/innerwarden/models/classifier"

[ai.llm]
enabled = true
provider = "azure_openai"
model = "gpt-5.4-mini"
base_url = "https://example.openai.azure.com"
api_version = "2024-12-01-preview"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();

        assert!(cfg.ai.enabled);
        assert_eq!(cfg.ai.provider, "stub");

        assert!(cfg.ai.classifier.enabled);
        assert_eq!(cfg.ai.classifier.provider, "local_classifier");
        assert_eq!(
            cfg.ai.classifier.base_url,
            "/var/lib/innerwarden/models/classifier"
        );

        assert!(cfg.ai.llm.enabled);
        assert_eq!(cfg.ai.llm.provider, "azure_openai");
        assert_eq!(cfg.ai.llm.model, "gpt-5.4-mini");
        assert_eq!(cfg.ai.llm.api_version, "2024-12-01-preview");
    }

    // Spec 029 PR-C: legacy `[ai]` only config is still parsed with
    // classifier/llm blocks defaulting to disabled. Back-compat gate.
    #[test]
    fn load_without_per_role_sections_leaves_slots_disabled() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai]
enabled = true
provider = "stub"
model = "legacy"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert_eq!(cfg.ai.provider, "stub");
        // Per-role blocks default to disabled so the boot path falls
        // back to the primary [ai] provider for both slots.
        assert!(!cfg.ai.classifier.enabled);
        assert!(!cfg.ai.llm.enabled);
    }
}
