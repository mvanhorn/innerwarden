use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use dialoguer::console::Style;
use dialoguer::{theme::ColorfulTheme, MultiSelect, Select};

use crate::commands::agent::{cmd_agent, parse_selection_indices, resolve_dashboard_url};
use crate::commands::ai::{fetch_models, WIZARD_PROVIDERS};
use crate::commands::capability::cmd_enable_with_deferred_restart;
use crate::commands::notify::{
    cmd_configure_dashboard, cmd_configure_slack, cmd_configure_telegram, cmd_configure_webhook,
};
use crate::{
    am_root, config_editor, load_env_file, mask_secret, prompt, reexec_with_sudo, restart_agent,
    scan, systemd, write_env_key, AgentCommand, CapabilityRegistry, Cli,
};

#[derive(Debug, Clone)]
struct SetupCapabilityPlan {
    id: String,
    params: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct SetupPreconfigPlan {
    essential_capabilities: Vec<SetupCapabilityPlan>,
    set_telegram_min_severity: bool,
    set_webhook_min_severity: bool,
}

#[derive(Debug, Clone)]
enum SetupAiKey {
    None,
    Env { var: String, value: String },
    Config { value: String },
}

#[derive(Debug, Clone)]
struct SetupAiPlan {
    label: String,
    provider: String,
    model: String,
    base_url: Option<String>,
    key: SetupAiKey,
}

#[derive(Debug, Clone, Default)]
struct SetupNotificationPlan {
    telegram: bool,
    slack: bool,
    webhook: bool,
    dashboard: bool,
}

impl SetupNotificationPlan {
    fn label(&self) -> String {
        let mut parts = Vec::new();
        if self.telegram {
            parts.push("Telegram");
        }
        if self.slack {
            parts.push("Slack");
        }
        if self.webhook {
            parts.push("Webhook");
        }
        if self.dashboard {
            parts.push("Dashboard");
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(" + ")
        }
    }

    fn any_selected(&self) -> bool {
        self.telegram || self.slack || self.webhook || self.dashboard
    }
}

#[derive(Debug, Clone, Copy)]
struct SetupResponderPlan {
    dry_run: bool,
}

impl SetupResponderPlan {
    fn label(&self) -> &'static str {
        if self.dry_run {
            "Watch only"
        } else {
            "Auto-protect"
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupMode {
    Basic,
    Advanced,
}

impl SetupMode {
    fn from_str(input: &str) -> Self {
        if input.eq_ignore_ascii_case("advanced") {
            Self::Advanced
        } else {
            Self::Basic
        }
    }

    fn is_advanced(&self) -> bool {
        matches!(self, Self::Advanced)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SetupCheck {
    pub(crate) label: String,
    pub(crate) detail: String,
    pub(crate) ok: bool,
    pub(crate) critical: bool,
}

fn read_agent_doc(path: &Path) -> Option<toml_edit::DocumentMut> {
    std::fs::read_to_string(path).ok()?.parse().ok()
}

fn agent_bool(doc: Option<&toml_edit::DocumentMut>, section: &str, key: &str) -> bool {
    doc.and_then(|d| d.get(section))
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn agent_str(doc: Option<&toml_edit::DocumentMut>, section: &str, key: &str) -> Option<String> {
    doc.and_then(|d| d.get(section))
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}

fn env_has(env_vars: &HashMap<String, String>, key: &str) -> bool {
    env_vars.get(key).is_some_and(|v| !v.trim().is_empty())
        || std::env::var(key).is_ok_and(|v| !v.trim().is_empty())
}

fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool> {
    print!("{label}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() {
        return Ok(default_yes);
    }
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

fn prompt_setup_agent_selection(
    detected_agents: &[innerwarden_agent_guard::detect::DetectedAgent],
) -> Result<Vec<u32>> {
    if detected_agents.is_empty() {
        return Ok(vec![]);
    }

    if detected_agents.len() == 1 {
        let agent = &detected_agents[0];
        let prompt = format!(
            "  Found 1 running AI agent ({} / pid {}). Connect now? [Y/n] ",
            agent.name, agent.pid
        );
        return Ok(if prompt_yes_no(&prompt, true)? {
            vec![agent.pid]
        } else {
            vec![]
        });
    }

    println!("  Found {} running AI agents.", detected_agents.len());
    println!("  {:<4} {:<8} {:<16} TYPE", "NO.", "PID", "NAME");
    println!("  {}", "─".repeat(48));
    for (idx, agent) in detected_agents.iter().enumerate() {
        println!(
            "  {:<4} {:<8} {:<16} {}",
            idx + 1,
            agent.pid,
            agent.name,
            agent.integration
        );
    }
    println!();

    let selection = prompt("  Select agents [ex: 1,3 or all, Enter to skip]")?;
    let trimmed = selection.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    let Some(indices) = parse_selection_indices(trimmed, detected_agents.len()) else {
        println!("  Invalid selection '{trimmed}'. Skipping agent connection.");
        return Ok(vec![]);
    };

    Ok(indices
        .into_iter()
        .map(|idx| detected_agents[idx - 1].pid)
        .collect())
}

fn parse_setup_capability_hint(hint: &str) -> Option<SetupCapabilityPlan> {
    let parts: Vec<&str> = hint.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "innerwarden" || parts[1] != "enable" {
        return None;
    }

    let mut params = HashMap::new();
    let mut i = 3;
    while i < parts.len() {
        if parts[i] == "--param" && i + 1 < parts.len() {
            if let Some((k, v)) = parts[i + 1].split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    Some(SetupCapabilityPlan {
        id: parts[2].to_string(),
        params,
    })
}

fn setup_capability_restart_needs(capability_id: &str) -> (bool, bool) {
    match capability_id {
        // (sensor, agent)
        "ai" => (false, true),
        "block-ip" => (false, true),
        "sudo-protection" => (true, true),
        "shell-audit" => (true, false),
        "search-protection" => (true, true),
        _ => (false, false),
    }
}

fn collect_setup_preconfig_plan(agent_doc: Option<&toml_edit::DocumentMut>) -> SetupPreconfigPlan {
    let probes = scan::run_probes();
    let recs = scan::score_modules(&probes);

    let essential_capabilities = recs
        .iter()
        .filter(|r| matches!(r.tier, scan::Tier::Essential))
        .filter_map(|r| parse_setup_capability_hint(r.enable_hint))
        .collect();

    let set_telegram_min_severity = agent_doc
        .and_then(|d| d.get("telegram"))
        .and_then(|t| t.get("min_severity"))
        .is_none();
    let set_webhook_min_severity = agent_doc
        .and_then(|d| d.get("webhook"))
        .and_then(|t| t.get("min_severity"))
        .is_none();

    SetupPreconfigPlan {
        essential_capabilities,
        set_telegram_min_severity,
        set_webhook_min_severity,
    }
}

pub(crate) fn ai_provider_defaults(provider: &str) -> (String, Option<String>, Option<String>) {
    match provider {
        "openai" => (
            "gpt-4o-mini".to_string(),
            Some("OPENAI_API_KEY".to_string()),
            None,
        ),
        "anthropic" => (
            "claude-haiku-4-5-20251001".to_string(),
            Some("ANTHROPIC_API_KEY".to_string()),
            None,
        ),
        "ollama" => ("llama3.2".to_string(), None, None),
        "groq" => (
            "llama-3.3-70b-versatile".to_string(),
            Some("GROQ_API_KEY".to_string()),
            Some("https://api.groq.com/openai".to_string()),
        ),
        "deepseek" => (
            "deepseek-chat".to_string(),
            Some("DEEPSEEK_API_KEY".to_string()),
            Some("https://api.deepseek.com".to_string()),
        ),
        "together" => (
            "meta-llama/Llama-3.3-70B-Instruct-Turbo".to_string(),
            Some("TOGETHER_API_KEY".to_string()),
            Some("https://api.together.xyz".to_string()),
        ),
        "minimax" => (
            "MiniMax-Text-01".to_string(),
            Some("MINIMAX_API_KEY".to_string()),
            Some("https://api.minimaxi.chat".to_string()),
        ),
        "mistral" => (
            "mistral-small-latest".to_string(),
            Some("MISTRAL_API_KEY".to_string()),
            Some("https://api.mistral.ai".to_string()),
        ),
        "xai" => (
            "grok-3-mini-fast".to_string(),
            Some("XAI_API_KEY".to_string()),
            Some("https://api.x.ai".to_string()),
        ),
        "fireworks" => (
            "accounts/fireworks/models/llama-v3p3-70b-instruct".to_string(),
            Some("FIREWORKS_API_KEY".to_string()),
            Some("https://api.fireworks.ai/inference".to_string()),
        ),
        "openrouter" => (
            "meta-llama/llama-3.3-70b-instruct".to_string(),
            Some("OPENROUTER_API_KEY".to_string()),
            Some("https://openrouter.ai/api".to_string()),
        ),
        "gemini" => (
            "gemini-2.0-flash".to_string(),
            Some("GEMINI_API_KEY".to_string()),
            Some("https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
        ),
        _ => (
            "gpt-4o-mini".to_string(),
            Some(format!("{}_API_KEY", provider.to_uppercase())),
            None,
        ),
    }
}

fn build_setup_ai_plan(
    provider: &str,
    label: &str,
    key: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
) -> SetupAiPlan {
    let (default_model, key_var, default_base_url) = ai_provider_defaults(provider);
    let effective_model = model.unwrap_or(default_model);
    let effective_base_url = base_url.or(default_base_url);
    let key = match key {
        None => SetupAiKey::None,
        Some(value)
            if provider == "ollama"
                && effective_base_url.as_deref() == Some("https://api.ollama.com") =>
        {
            SetupAiKey::Config { value }
        }
        Some(value) => SetupAiKey::Env {
            var: key_var.unwrap_or_else(|| format!("{}_API_KEY", provider.to_uppercase())),
            value,
        },
    };

    SetupAiPlan {
        label: label.to_string(),
        provider: provider.to_string(),
        model: effective_model,
        base_url: effective_base_url,
        key,
    }
}

fn prompt_setup_other_ai_plan() -> Result<Option<SetupAiPlan>> {
    let other_providers = [
        "together",
        "minimax",
        "mistral",
        "xai",
        "fireworks",
        "gemini",
    ];

    println!("  Other provider\n");
    for (idx, provider_name) in other_providers.iter().enumerate() {
        let provider = WIZARD_PROVIDERS
            .iter()
            .find(|p| p.name == *provider_name)
            .expect("wizard provider exists");
        println!("  {}. {}", idx + 1, provider.label);
    }
    let custom_idx = other_providers.len() + 1;
    println!("  {custom_idx}. Custom OpenAI-compatible\n");

    let choice = prompt(&format!("  Choose [1-{custom_idx}]"))?;
    let trimmed = choice.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let idx = trimmed.parse::<usize>().unwrap_or(0);
    if (1..=other_providers.len()).contains(&idx) {
        let provider_name = other_providers[idx - 1];
        let provider = WIZARD_PROVIDERS
            .iter()
            .find(|p| p.name == provider_name)
            .expect("wizard provider exists");
        return prompt_cloud_provider(provider.name, provider.label, provider.signup_url);
    }

    if idx == custom_idx {
        let provider = prompt("  Provider name")?;
        let base_url = prompt("  Base URL")?;
        let key = prompt("  API key")?;
        let model = prompt("  Model")?;

        if provider.is_empty() || base_url.is_empty() || key.is_empty() || model.is_empty() {
            return Ok(None);
        }

        return Ok(Some(build_setup_ai_plan(
            &provider,
            &provider,
            Some(key),
            Some(model),
            Some(base_url),
        )));
    }

    Ok(None)
}

fn prompt_cloud_provider(
    provider: &str,
    label: &str,
    signup_url: &str,
) -> Result<Option<SetupAiPlan>> {
    let (default_model, _, default_base_url) = ai_provider_defaults(provider);
    let api_style = WIZARD_PROVIDERS
        .iter()
        .find(|p| p.name == provider)
        .map(|p| p.api_style)
        .unwrap_or("openai");

    let key = prompt(&format!("  {label} API key ({signup_url})"))?;
    if key.is_empty() {
        return Ok(None);
    }

    let base_url = default_base_url
        .clone()
        .unwrap_or_else(|| format!("https://api.{}.com", provider));

    // Try to fetch available models from the provider
    print!("  Fetching models... ");
    std::io::stdout().flush()?;
    let models = fetch_models(&base_url, &key, api_style);

    if models.is_empty() {
        println!("could not list (using default: {default_model})");
        return Ok(Some(build_setup_ai_plan(
            provider,
            label,
            Some(key),
            None,
            default_base_url,
        )));
    }

    println!("found {} models\n", models.len());

    // Find the default model index
    let default_idx = models
        .iter()
        .position(|m| m == &default_model)
        .map(|i| i + 1)
        .unwrap_or(1);

    let show_count = models.len().min(15);
    for (i, model) in models.iter().take(show_count).enumerate() {
        let tag = if i + 1 == default_idx {
            " (recommended)"
        } else {
            ""
        };
        println!("  {}. {}{}", i + 1, model, tag);
    }
    if models.len() > show_count {
        println!("  ... and {} more", models.len() - show_count);
    }
    println!();

    let model_choice = prompt(&format!(
        "  Model [1-{}, default={}]",
        models.len().min(show_count),
        default_idx
    ))?;
    let idx = model_choice
        .trim()
        .parse::<usize>()
        .unwrap_or(default_idx)
        .saturating_sub(1)
        .min(models.len() - 1);

    Ok(Some(build_setup_ai_plan(
        provider,
        label,
        Some(key),
        Some(models[idx].clone()),
        default_base_url,
    )))
}

fn prompt_setup_ai_plan() -> Result<Option<SetupAiPlan>> {
    println!("  [1/3] AI\n");

    // Auto-detect local Ollama (check if server responds, then list models)
    let ollama_running = ureq::get("http://localhost:11434/api/tags")
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(2)))
        .build()
        .call()
        .is_ok();
    let local_models = if ollama_running {
        fetch_models("http://localhost:11434", "", "ollama")
    } else {
        vec![]
    };

    let ollama_label = if ollama_running && !local_models.is_empty() {
        let model_list: Vec<&str> = local_models.iter().take(3).map(|s| s.as_str()).collect();
        let suffix = if local_models.len() > 3 {
            format!(", +{} more", local_models.len() - 3)
        } else {
            String::new()
        };
        format!(
            "Ollama          {} models: {}{}",
            local_models.len(),
            model_list.join(", "),
            suffix
        )
    } else if ollama_running {
        "Ollama          running, no models yet".to_string()
    } else {
        "Ollama          not installed — https://ollama.com".to_string()
    };

    let items: Vec<String> = vec![
        ollama_label,
        "OpenRouter      400+ models, all providers, one API key".to_string(),
        "OpenAI          gpt-4o-mini".to_string(),
        "Anthropic       claude-haiku-4-5".to_string(),
        "Groq            llama-3.3-70b (fast, free tier)".to_string(),
        "DeepSeek        deepseek-chat".to_string(),
        "Other           Mistral, xAI, Fireworks, Gemini, custom".to_string(),
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("  Use arrows to move, Enter to select")
        .items(&items)
        .default(0)
        .interact()?;

    println!();

    if selection == 0 {
        // Ollama local
        if !ollama_running {
            println!("  Ollama is not installed or not running.\n");
            println!("  1. Install from https://ollama.com");
            println!("  2. Start Ollama");
            println!("  3. Run: ollama pull qwen2.5:3b");
            println!("  4. Re-run: innerwarden setup\n");
            return Ok(None);
        }
        if local_models.is_empty() {
            println!("  Ollama is running but has no models.\n");
            println!("  Run: ollama pull qwen2.5:3b");
            println!("  Then re-run: innerwarden setup\n");
            return Ok(None);
        }

        if local_models.len() == 1 {
            // Single model — auto-select
            println!("  Using: {}\n", local_models[0]);
            return Ok(Some(build_setup_ai_plan(
                "ollama",
                "Ollama",
                None,
                Some(local_models[0].clone()),
                None,
            )));
        }

        for (i, model) in local_models.iter().enumerate() {
            let tag = if model.starts_with("qwen2.5:3b") {
                " (recommended)"
            } else {
                ""
            };
            println!("  {}. {}{}", i + 1, model, tag);
        }

        let default_idx = local_models
            .iter()
            .position(|m| m.starts_with("qwen2.5:3b"))
            .map(|i| i + 1)
            .unwrap_or(1);

        println!();
        let model_choice = prompt(&format!(
            "  Model [1-{}, default={}]",
            local_models.len(),
            default_idx
        ))?;
        let idx = model_choice
            .trim()
            .parse::<usize>()
            .unwrap_or(default_idx)
            .saturating_sub(1)
            .min(local_models.len() - 1);

        Ok(Some(build_setup_ai_plan(
            "ollama",
            "Ollama",
            None,
            Some(local_models[idx].clone()),
            None,
        )))
    } else if selection == 1 {
        prompt_cloud_provider("openrouter", "OpenRouter", "openrouter.ai")
    } else if selection == 2 {
        prompt_cloud_provider("openai", "OpenAI", "platform.openai.com")
    } else if selection == 3 {
        prompt_cloud_provider("anthropic", "Anthropic", "console.anthropic.com")
    } else if selection == 4 {
        prompt_cloud_provider("groq", "Groq", "console.groq.com")
    } else if selection == 5 {
        prompt_cloud_provider("deepseek", "DeepSeek", "platform.deepseek.com")
    } else if selection == 6 {
        prompt_setup_other_ai_plan()
    } else {
        Ok(None)
    }
}

fn apply_setup_ai_plan(cli: &Cli, env_file: &Path, plan: &SetupAiPlan) -> Result<()> {
    match &plan.key {
        SetupAiKey::None => {}
        SetupAiKey::Env { var, value } => write_env_key(env_file, var, value)?,
        SetupAiKey::Config { value } => {
            config_editor::write_str(&cli.agent_config, "ai", "api_key", value)?;
        }
    }

    config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
    config_editor::write_str(&cli.agent_config, "ai", "provider", &plan.provider)?;
    config_editor::write_str(&cli.agent_config, "ai", "model", &plan.model)?;
    if let Some(base_url) = &plan.base_url {
        config_editor::write_str(&cli.agent_config, "ai", "base_url", base_url)?;
    }

    Ok(())
}

fn setup_current_ai_summary(agent_doc: Option<&toml_edit::DocumentMut>) -> String {
    let provider = agent_str(agent_doc, "ai", "provider").unwrap_or_else(|| "configured".into());
    let model = agent_str(agent_doc, "ai", "model").unwrap_or_default();
    if model.is_empty() {
        provider
    } else {
        format!("{provider} ({model})")
    }
}

pub(crate) fn count_failed_setup_checks(checks: &[SetupCheck]) -> usize {
    checks
        .iter()
        .filter(|check| check.critical && !check.ok)
        .count()
}

pub(crate) fn setup_verdict(critical_failures: usize) -> &'static str {
    if critical_failures == 0 {
        "READY"
    } else {
        "READY_WITH_GAPS"
    }
}

pub(crate) fn setup_remediation_command(checks: &[SetupCheck], is_macos: bool) -> Option<String> {
    let failed_critical: Vec<&str> = checks
        .iter()
        .filter(|check| check.critical && !check.ok)
        .map(|check| check.label.as_str())
        .collect();

    if failed_critical.is_empty() {
        return None;
    }

    if failed_critical.len() == 1 && failed_critical[0] == "Agent service" {
        return Some(if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent".to_string()
        } else {
            "sudo systemctl restart innerwarden-agent".to_string()
        });
    }

    Some("innerwarden setup --mode advanced".to_string())
}

fn collect_setup_checks(
    cli: &Cli,
    env_file: &Path,
    notification_plan: &SetupNotificationPlan,
    responder_plan: SetupResponderPlan,
    expect_mesh: bool,
    detected_agents: usize,
) -> Vec<SetupCheck> {
    let agent_doc = read_agent_doc(&cli.agent_config);
    let env_vars = load_env_file(env_file);
    let is_macos = std::env::consts::OS == "macos";
    let dashboard_url = resolve_dashboard_url(cli);
    let dashboard_status_url = format!("{dashboard_url}/api/status");
    let dashboard_reachable = ureq::get(&dashboard_status_url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(2)))
        .build()
        .call()
        .map(|resp| resp.status().as_u16() < 500)
        .unwrap_or(false);
    let agent_running = if is_macos {
        std::process::Command::new("launchctl")
            .args(["list", "com.innerwarden.agent"])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("\"PID\""))
            .unwrap_or(false)
    } else {
        systemd::is_service_active("innerwarden-agent")
    };

    let ai_ready = agent_bool(agent_doc.as_ref(), "ai", "enabled");
    let telegram_ready = env_has(&env_vars, "TELEGRAM_BOT_TOKEN")
        && env_has(&env_vars, "TELEGRAM_CHAT_ID")
        && agent_bool(agent_doc.as_ref(), "telegram", "enabled");
    let slack_ready = env_has(&env_vars, "SLACK_WEBHOOK_URL")
        && agent_bool(agent_doc.as_ref(), "slack", "enabled");
    let webhook_ready =
        env_has(&env_vars, "WEBHOOK_URL") && agent_bool(agent_doc.as_ref(), "webhook", "enabled");
    let responder_ready = agent_bool(agent_doc.as_ref(), "responder", "enabled")
        && agent_bool(agent_doc.as_ref(), "responder", "dry_run") == responder_plan.dry_run;
    let mesh_ready = if expect_mesh {
        agent_bool(agent_doc.as_ref(), "mesh", "enabled")
    } else {
        true
    };

    // At least one selected channel must be ready
    let notifications_ready = if !notification_plan.any_selected() {
        false
    } else {
        let mut any_ready = false;
        if notification_plan.telegram {
            any_ready |= telegram_ready;
        }
        if notification_plan.slack {
            any_ready |= slack_ready;
        }
        if notification_plan.webhook {
            any_ready |= webhook_ready;
        }
        if notification_plan.dashboard {
            any_ready |= dashboard_reachable;
        }
        any_ready
    };

    vec![
        SetupCheck {
            label: "AI".to_string(),
            detail: if ai_ready {
                setup_current_ai_summary(agent_doc.as_ref())
            } else {
                "not configured".to_string()
            },
            ok: ai_ready,
            critical: true,
        },
        SetupCheck {
            label: "Alerts".to_string(),
            detail: if notifications_ready {
                notification_plan.label()
            } else if notification_plan.any_selected() {
                format!("{} not ready", notification_plan.label())
            } else {
                "none selected".to_string()
            },
            ok: notifications_ready,
            critical: true,
        },
        SetupCheck {
            label: "Protection".to_string(),
            detail: responder_plan.label().to_string(),
            ok: responder_ready,
            critical: true,
        },
        SetupCheck {
            label: "Agent service".to_string(),
            detail: if agent_running {
                "running".to_string()
            } else {
                "not running".to_string()
            },
            ok: agent_running,
            critical: true,
        },
        SetupCheck {
            label: "Dashboard".to_string(),
            detail: if dashboard_reachable {
                dashboard_url
            } else {
                "not reachable".to_string()
            },
            ok: dashboard_reachable,
            critical: false,
        },
        SetupCheck {
            label: "Mesh".to_string(),
            detail: if expect_mesh {
                "enabled".to_string()
            } else {
                "not enabled".to_string()
            },
            ok: mesh_ready,
            critical: false,
        },
        SetupCheck {
            label: "AI agents".to_string(),
            detail: if detected_agents == 0 {
                "none detected".to_string()
            } else if detected_agents == 1 {
                "1 detected".to_string()
            } else {
                format!("{detected_agents} detected")
            },
            ok: detected_agents > 0,
            critical: false,
        },
    ]
}

fn prompt_notification_channels(
    telegram_ok: bool,
    slack_ok: bool,
    webhook_ok: bool,
    dashboard_ok: bool,
    env_vars: &HashMap<String, String>,
) -> Result<SetupNotificationPlan> {
    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!("  {}\n", bold.apply_to("[2/3] Notification channels"));

    // Show existing channels with masked secrets
    if telegram_ok || slack_ok || webhook_ok || dashboard_ok {
        println!("  {}", dim.apply_to("Already configured:"));
        if telegram_ok {
            let token = env_vars
                .get("TELEGRAM_BOT_TOKEN")
                .map(|s| mask_secret(s))
                .unwrap_or_default();
            println!(
                "    [ok] Telegram  {}",
                dim.apply_to(format!("token: {token}"))
            );
        }
        if slack_ok {
            let url = env_vars
                .get("SLACK_WEBHOOK_URL")
                .map(|s| mask_secret(s))
                .unwrap_or_default();
            println!(
                "    [ok] Slack     {}",
                dim.apply_to(format!("webhook: {url}"))
            );
        }
        if webhook_ok {
            let url = env_vars
                .get("WEBHOOK_URL")
                .map(|s| mask_secret(s))
                .unwrap_or_default();
            println!("    [ok] Webhook   {}", dim.apply_to(format!("url: {url}")));
        }
        if dashboard_ok {
            let user = env_vars
                .get("INNERWARDEN_DASHBOARD_USER")
                .cloned()
                .unwrap_or_default();
            println!(
                "    [ok] Dashboard {}",
                dim.apply_to(format!("user: {user}"))
            );
        }
        println!();
    }

    let items = &[
        "Telegram    — real-time phone alerts",
        "Slack       — team channel",
        "Webhook     — PagerDuty/Opsgenie/custom",
        "Dashboard   — browser UI",
    ];

    // Default: keep current selection, or Telegram + Dashboard for fresh install
    let defaults = if telegram_ok || slack_ok || webhook_ok || dashboard_ok {
        vec![telegram_ok, slack_ok, webhook_ok, dashboard_ok]
    } else {
        vec![true, false, false, true]
    };

    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("  Use arrows + space to toggle, Enter to confirm")
        .items(items)
        .defaults(&defaults)
        .interact()?;

    println!();

    Ok(SetupNotificationPlan {
        telegram: selections.contains(&0),
        slack: selections.contains(&1),
        webhook: selections.contains(&2),
        dashboard: selections.contains(&3),
    })
}

pub(crate) fn cmd_setup(cli: &Cli, mode: &str) -> Result<()> {
    if !cli.dry_run && !am_root() {
        return reexec_with_sudo();
    }

    let setup_mode = SetupMode::from_str(mode);

    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
    let env_vars = load_env_file(&env_file);
    let agent_doc = read_agent_doc(&cli.agent_config);

    let ai_ok = agent_bool(agent_doc.as_ref(), "ai", "enabled");
    let responder_ok = agent_bool(agent_doc.as_ref(), "responder", "enabled");
    let mesh_ok = agent_bool(agent_doc.as_ref(), "mesh", "enabled");

    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!();
    println!("  {}", bold.apply_to("INNERWARDEN SETUP"));
    println!("  {}", dim.apply_to("─".repeat(40)));
    println!();

    // Safe defaults applied silently during apply (block-ip, alert thresholds, etc.)
    let preconfig_plan = collect_setup_preconfig_plan(agent_doc.as_ref());

    let ai_plan = if ai_ok {
        println!(
            "  [ok] {}  {}",
            bold.apply_to("[1/3] AI"),
            dim.apply_to(setup_current_ai_summary(agent_doc.as_ref()))
        );
        None
    } else {
        let plan = prompt_setup_ai_plan()?;
        if let Some(plan) = &plan {
            println!("\n  [ok] {} ({})", plan.label, dim.apply_to(&plan.model));
        } else {
            println!("  [--] AI not set yet");
        }
        plan
    };

    // ── Detect existing notification channels ──────────────────────────
    let telegram_ok =
        env_has(&env_vars, "TELEGRAM_BOT_TOKEN") && env_has(&env_vars, "TELEGRAM_CHAT_ID");
    let slack_ok = env_has(&env_vars, "SLACK_WEBHOOK_URL")
        && agent_bool(agent_doc.as_ref(), "slack", "enabled");
    let webhook_ok =
        env_has(&env_vars, "WEBHOOK_URL") && agent_bool(agent_doc.as_ref(), "webhook", "enabled");
    let dashboard_ok_existing = env_has(&env_vars, "INNERWARDEN_DASHBOARD_USER")
        && env_has(&env_vars, "INNERWARDEN_DASHBOARD_PASSWORD_HASH");

    let any_channel_configured = telegram_ok || slack_ok || webhook_ok || dashboard_ok_existing;

    println!();
    let notification_plan = if any_channel_configured && !setup_mode.is_advanced() {
        // Show existing channels and offer keep/update
        let mut parts = Vec::new();
        if telegram_ok {
            parts.push("Telegram");
        }
        if slack_ok {
            parts.push("Slack");
        }
        if webhook_ok {
            parts.push("Webhook");
        }
        if dashboard_ok_existing {
            parts.push("Dashboard");
        }
        let summary = parts.join(" + ");
        println!(
            "  [ok] {}  {}",
            bold.apply_to("[2/3] Alerts"),
            dim.apply_to(&summary)
        );
        println!();
        let update = prompt_yes_no("  Update notification channels? [y/N] ", false)?;
        if update {
            prompt_notification_channels(
                telegram_ok,
                slack_ok,
                webhook_ok,
                dashboard_ok_existing,
                &env_vars,
            )?
        } else {
            SetupNotificationPlan {
                telegram: telegram_ok,
                slack: slack_ok,
                webhook: webhook_ok,
                dashboard: dashboard_ok_existing,
            }
        }
    } else {
        prompt_notification_channels(
            telegram_ok,
            slack_ok,
            webhook_ok,
            dashboard_ok_existing,
            &env_vars,
        )?
    };

    let responder_plan = if responder_ok {
        let current = SetupResponderPlan {
            dry_run: agent_bool(agent_doc.as_ref(), "responder", "dry_run"),
        };
        println!(
            "  [ok] {}  {}",
            bold.apply_to("[3/3] Protection"),
            dim.apply_to(current.label())
        );
        current
    } else {
        println!("\n  {}\n", bold.apply_to("[3/3] Protection"));

        let items = &[
            "Watch only (recommended for the first week) — detects and alerts, does not block",
            "Auto-protect — automatically blocks threats, enable after you trust the alerts",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("  Use arrows to move, Enter to select")
            .items(items)
            .default(0)
            .interact()?;

        println!();

        if selection == 1 {
            print!("  Type 'yes' to enable auto-protect: ");
            std::io::stdout().flush()?;
            let mut confirm = String::new();
            std::io::stdin().read_line(&mut confirm)?;
            if confirm.trim() == "yes" {
                SetupResponderPlan { dry_run: false }
            } else {
                SetupResponderPlan { dry_run: true }
            }
        } else {
            SetupResponderPlan { dry_run: true }
        }
    };

    println!();
    let enable_mesh = if mesh_ok {
        println!(
            "  [ok] {}  {}",
            bold.apply_to("Mesh"),
            dim.apply_to("enabled")
        );
        true
    } else if setup_mode.is_advanced() {
        let enabled = prompt_yes_no(
            "  Share threat blocks with your other InnerWarden nodes? [y/N] ",
            false,
        )?;
        println!();
        enabled
    } else {
        false
    };

    let review_ai = ai_plan
        .as_ref()
        .map(|plan| format!("{} ({})", plan.label, plan.model))
        .unwrap_or_else(|| setup_current_ai_summary(agent_doc.as_ref()));

    println!();
    println!("  {}", bold.apply_to("REVIEW"));
    println!("  {}", dim.apply_to("─".repeat(40)));
    println!("  {:<16} {review_ai}", bold.apply_to("AI"));
    println!(
        "  {:<16} {}",
        bold.apply_to("Alerts"),
        notification_plan.label()
    );
    println!(
        "  {:<16} {}",
        bold.apply_to("Protection"),
        responder_plan.label()
    );
    if enable_mesh {
        println!("  {:<16} enabled", bold.apply_to("Mesh"));
    }
    println!(
        "  {:<16} {}",
        bold.apply_to("Config"),
        dim.apply_to(format!(
            "{} + {}",
            cli.agent_config.display(),
            env_file.display()
        ))
    );

    // Show which channels need guided setup after apply
    let mut pending_channels = Vec::new();
    if notification_plan.telegram && !telegram_ok {
        pending_channels.push("Telegram");
    }
    if notification_plan.slack && !slack_ok {
        pending_channels.push("Slack");
    }
    if notification_plan.webhook && !webhook_ok {
        pending_channels.push("Webhook");
    }
    if notification_plan.dashboard && !dashboard_ok_existing {
        pending_channels.push("Dashboard");
    }
    if !pending_channels.is_empty() {
        println!(
            "  {:<16} {} guided setup after apply",
            bold.apply_to("Next"),
            pending_channels.join(", ")
        );
    }
    println!("  {}", dim.apply_to("─".repeat(40)));
    println!();

    if cli.dry_run {
        println!(
            "  {} Setup preview complete. No changes applied.",
            dim.apply_to("[dry-run]")
        );
        return Ok(());
    }

    if !prompt_yes_no("  Apply now? [Y/n] ", true)? {
        println!("\n  Setup cancelled. Nothing changed.");
        return Ok(());
    }

    println!();

    // Apply safe defaults silently (block-ip, alert thresholds, etc.)
    let registry = CapabilityRegistry::default_all();
    let mut restart_sensor_needed = false;
    for capability in &preconfig_plan.essential_capabilities {
        if let Err(err) = cmd_enable_with_deferred_restart(
            cli,
            &registry,
            &capability.id,
            capability.params.clone(),
            true,
            true,
        ) {
            println!("  [warn] Could not enable {}: {err:#}", capability.id);
        } else {
            let (sensor_needed, _agent_needed) = setup_capability_restart_needs(&capability.id);
            restart_sensor_needed |= sensor_needed;
        }
    }
    if preconfig_plan.set_telegram_min_severity {
        let _ = config_editor::write_str(&cli.agent_config, "telegram", "min_severity", "high");
        let _ = config_editor::write_int(&cli.agent_config, "telegram", "daily_summary_hour", 9);
        let _ = config_editor::write_int(&cli.agent_config, "telegram", "daily_budget", 10);
    }
    if preconfig_plan.set_webhook_min_severity {
        let _ = config_editor::write_str(&cli.agent_config, "webhook", "min_severity", "high");
    }

    if let Some(plan) = &ai_plan {
        apply_setup_ai_plan(cli, &env_file, plan)?;
    }

    config_editor::write_bool(&cli.agent_config, "responder", "enabled", true)?;
    config_editor::write_bool(
        &cli.agent_config,
        "responder",
        "dry_run",
        responder_plan.dry_run,
    )?;
    let restart_agent_needed = true;

    if enable_mesh && !mesh_ok {
        config_editor::write_bool(&cli.agent_config, "mesh", "enabled", true)?;
        if agent_doc.as_ref().and_then(|doc| doc.get("mesh")).is_none() {
            config_editor::write_str(&cli.agent_config, "mesh", "bind", "0.0.0.0:8790")?;
            config_editor::write_int(&cli.agent_config, "mesh", "poll_secs", 30)?;
            config_editor::write_bool(&cli.agent_config, "mesh", "auto_broadcast", true)?;
        }
    }

    // ── Channel setup (interactive, writes config, restarts agent) ──────
    let mut channel_restarted_agent = false;

    if notification_plan.telegram && !telegram_ok {
        println!("  Telegram\n");
        if let Err(err) = cmd_configure_telegram(cli, None, None, false) {
            println!("  [warn] Telegram setup did not finish: {err:#}");
        } else {
            channel_restarted_agent = true;
            let _ =
                config_editor::write_int(&cli.agent_config, "telegram", "daily_summary_hour", 9);
            let _ = config_editor::write_int(&cli.agent_config, "telegram", "daily_budget", 10);
        }
    }

    if notification_plan.slack && !slack_ok {
        println!();
        if let Err(err) = cmd_configure_slack(cli, None, "high", false) {
            println!("  [warn] Slack setup did not finish: {err:#}");
        } else {
            channel_restarted_agent = true;
        }
    }

    if notification_plan.webhook && !webhook_ok {
        println!();
        if let Err(err) = cmd_configure_webhook(cli, None, "high", false) {
            println!("  [warn] Webhook setup did not finish: {err:#}");
        } else {
            channel_restarted_agent = true;
        }
    }

    if notification_plan.dashboard && !dashboard_ok_existing {
        println!();
        if let Err(err) = cmd_configure_dashboard(cli, "admin", None) {
            println!("  [warn] Dashboard setup did not finish: {err:#}");
        } else {
            channel_restarted_agent = true;
        }
    }

    if restart_sensor_needed {
        if std::env::consts::OS == "macos" {
            println!("  [warn] innerwarden-sensor restart skipped on macOS.");
        } else if cli.dry_run {
            println!("  [dry-run] would restart innerwarden-sensor");
        } else if let Err(err) = systemd::restart_service("innerwarden-sensor", false) {
            println!("  [warn] Could not restart innerwarden-sensor: {err:#}");
        } else {
            println!("  [ok] innerwarden-sensor restarted");
        }
    }

    if restart_agent_needed && !channel_restarted_agent {
        restart_agent(cli);
    }

    let detected_agents = {
        use innerwarden_agent_guard::detect;
        use innerwarden_agent_guard::signatures::SignatureIndex;

        let index = SignatureIndex::new();
        detect::scan_processes(&index)
    };

    if detected_agents.is_empty() {
        println!();
        println!("  No supported AI agents detected right now.");
    } else {
        println!();
        let selected_agent_pids = prompt_setup_agent_selection(&detected_agents)?;
        if selected_agent_pids.is_empty() {
            println!("  Agent connection skipped.");
        } else {
            for selected_pid in selected_agent_pids {
                let command = AgentCommand::Connect {
                    pid: Some(selected_pid),
                    name: None,
                    label: Some("setup".to_string()),
                };
                let _ = cmd_agent(cli, Some(&command));
            }
        }
    }

    let checks = collect_setup_checks(
        cli,
        &env_file,
        &notification_plan,
        responder_plan,
        enable_mesh,
        detected_agents.len(),
    );
    let critical_failures = count_failed_setup_checks(&checks);
    let verdict = setup_verdict(critical_failures);
    let remediation = setup_remediation_command(&checks, std::env::consts::OS == "macos");

    println!();
    println!("  {verdict}\n");

    for check in &checks {
        let status = if check.ok { "OK" } else { "FIX" };
        println!("  {:<14} {:<4} {}", check.label, status, check.detail);
    }

    println!();
    if critical_failures == 0 {
        println!("  Dashboard: {}", resolve_dashboard_url(cli));
        println!("  Re-run anytime: innerwarden setup");
    } else {
        if critical_failures == 1 {
            println!("  1 critical item needs attention.");
        } else {
            println!("  {critical_failures} critical items need attention.");
        }
        if let Some(command) = remediation {
            println!("  Run this command to close critical gaps:");
            println!("    {command}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_provider_defaults() {
        let (model, key, url) = ai_provider_defaults("openai");
        assert_eq!(model, "gpt-4o-mini");
        assert_eq!(key, Some("OPENAI_API_KEY".to_string()));
        assert_eq!(url, None);

        let (model, key, url) = ai_provider_defaults("groq");
        assert_eq!(model, "llama-3.3-70b-versatile");
        assert_eq!(key, Some("GROQ_API_KEY".to_string()));
        assert_eq!(url, Some("https://api.groq.com/openai".to_string()));

        let (model, key, url) = ai_provider_defaults("ollama");
        assert_eq!(model, "llama3.2");
        assert_eq!(key, None);
        assert_eq!(url, None);

        let (model, key, _url) = ai_provider_defaults("unknown_provider");
        assert_eq!(model, "gpt-4o-mini");
        assert_eq!(key, Some("UNKNOWN_PROVIDER_API_KEY".to_string()));
    }

    #[test]
    fn test_count_failed_setup_checks() {
        let checks = vec![
            SetupCheck {
                label: "1".into(),
                detail: "".into(),
                ok: true,
                critical: true,
            },
            SetupCheck {
                label: "2".into(),
                detail: "".into(),
                ok: false,
                critical: true,
            },
            SetupCheck {
                label: "3".into(),
                detail: "".into(),
                ok: false,
                critical: false,
            },
        ];
        assert_eq!(count_failed_setup_checks(&checks), 1);
    }

    #[test]
    fn test_setup_verdict() {
        assert_eq!(setup_verdict(0), "READY");
        assert_eq!(setup_verdict(1), "READY_WITH_GAPS");
        assert_eq!(setup_verdict(5), "READY_WITH_GAPS");
    }

    #[test]
    fn test_setup_remediation_command() {
        let mut checks = vec![];

        // 0 critical
        assert_eq!(setup_remediation_command(&checks, false), None);

        // 1 critical: Agent service
        checks.push(SetupCheck {
            label: "Agent service".into(),
            detail: "".into(),
            ok: false,
            critical: true,
        });

        let linux_cmd = setup_remediation_command(&checks, false).unwrap();
        assert!(linux_cmd.contains("systemctl restart"));

        let macos_cmd = setup_remediation_command(&checks, true).unwrap();
        assert!(macos_cmd.contains("launchctl kickstart"));

        // More than 1 critical
        checks.push(SetupCheck {
            label: "AI".into(),
            detail: "".into(),
            ok: false,
            critical: true,
        });

        let complex_cmd = setup_remediation_command(&checks, false).unwrap();
        assert_eq!(complex_cmd, "innerwarden setup --mode advanced");
    }
}
