use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tracing::debug;

use super::{AiDecision, AiProvider, DecisionContext};
use super::openai::{build_prompt_pub, parse_decision_pub, system_prompt};

// ---------------------------------------------------------------------------
// Azure OpenAI provider
// ---------------------------------------------------------------------------
//
// Same JSON schema as the OpenAI provider (chat completions with JSON object
// response format). Differences:
//   - Auth header is `api-key: <key>` instead of `Authorization: Bearer ...`
//   - Endpoint is `{base_url}/openai/deployments/{deployment}/chat/completions?api-version={v}`
//     rather than `{base_url}/v1/chat/completions`
//   - `model` is the Azure deployment name, not the underlying model id
//
// Users benefit from the same prompt construction and decision parser that
// the OpenAI provider uses — imported directly from `openai.rs`.

pub struct AzureOpenAiProvider {
    api_key: String,
    deployment: String,
    base_url: String,
    api_version: String,
    client: reqwest::Client,
}

/// Newer Azure-hosted models (gpt-5.x, o1, o3) use `max_completion_tokens`.
/// Older deployments (gpt-4.x, gpt-3.5) use `max_tokens`.
fn uses_new_token_param(deployment: &str) -> bool {
    let m = deployment.to_lowercase();
    m.starts_with("gpt-5") || m.starts_with("o1") || m.starts_with("o3") || m.starts_with("o4")
}

impl AzureOpenAiProvider {
    pub fn new(api_key: String, deployment: String, base_url: String, api_version: String) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("failed to build reqwest client");
        Self {
            api_key,
            deployment,
            base_url,
            api_version,
            client,
        }
    }

    fn chat_url(&self) -> String {
        format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            self.base_url, self.deployment, self.api_version
        )
    }
}

#[async_trait]
impl AiProvider for AzureOpenAiProvider {
    fn name(&self) -> &'static str {
        "azure_openai"
    }

    async fn chat(&self, system_prompt_text: &str, user_message: &str) -> Result<String> {
        if self.api_key.is_empty() {
            bail!(
                "Azure OpenAI API key not configured. Set AZURE_OPENAI_API_KEY env var or [ai].api_key in config."
            );
        }

        debug!(deployment = %self.deployment, "calling Azure OpenAI API for chat");

        let token_key = if uses_new_token_param(&self.deployment) {
            "max_completion_tokens"
        } else {
            "max_tokens"
        };
        let body = json!({
            "messages": [
                { "role": "system", "content": system_prompt_text },
                { "role": "user",   "content": user_message }
            ],
            "temperature": 0.7,
            token_key: 600,
        });

        let resp = self
            .client
            .post(self.chat_url())
            .header("api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .context("Azure OpenAI chat API request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!(
                "Azure OpenAI chat API returned {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }

        let completion: ChatCompletion = resp
            .json()
            .await
            .context("failed to parse Azure OpenAI chat response")?;

        completion
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .context("Azure OpenAI chat returned empty response")
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        if self.api_key.is_empty() {
            bail!(
                "Azure OpenAI API key not configured. Set AZURE_OPENAI_API_KEY env var or [ai].api_key in config."
            );
        }

        let prompt = build_prompt_pub(ctx);
        debug!(deployment = %self.deployment, "calling Azure OpenAI API");

        let token_key = if uses_new_token_param(&self.deployment) {
            "max_completion_tokens"
        } else {
            "max_tokens"
        };
        let body = json!({
            "messages": [
                { "role": "system", "content": system_prompt() },
                { "role": "user",   "content": prompt }
            ],
            "response_format": { "type": "json_object" },
            "temperature": 0.2,
            token_key: 512,
        });

        let resp = self
            .client
            .post(self.chat_url())
            .header("api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .context("Azure OpenAI API request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!(
                "Azure OpenAI API returned {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }

        let completion: ChatCompletion = resp
            .json()
            .await
            .context("failed to parse Azure OpenAI response")?;

        let content = completion
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .context("Azure OpenAI returned empty response")?;

        parse_decision_pub(&content)
    }
}

#[derive(Deserialize)]
struct ChatCompletion {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Deserialize)]
struct Message {
    content: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_url_formats_correctly() {
        let p = AzureOpenAiProvider::new(
            "k".into(),
            "gpt-5-4-mini".into(),
            "https://example-resource.openai.azure.com/".into(),
            "2024-12-01-preview".into(),
        );
        assert_eq!(
            p.chat_url(),
            "https://example-resource.openai.azure.com/openai/deployments/gpt-5-4-mini/chat/completions?api-version=2024-12-01-preview"
        );
    }

    #[test]
    fn uses_max_completion_tokens_for_gpt5() {
        assert!(uses_new_token_param("gpt-5-4-mini"));
        assert!(uses_new_token_param("gpt-5.4"));
        assert!(!uses_new_token_param("gpt-4o-mini"));
        assert!(!uses_new_token_param("gpt-4.1-mini"));
    }
}
