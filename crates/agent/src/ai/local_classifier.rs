//! Local ONNX classifier provider (distilled student of a SecureBERT teacher).
//!
//! Runs inference in-process using `tract-onnx` (pure Rust ONNX runtime) and
//! HuggingFace `tokenizers`. Output: {dismiss, ignore, block_ip, monitor} +
//! confidence.
//!
//! No network calls, no external dependency beyond the crate graph; entire
//! inference happens locally in ~50-200 ms per incident on a typical server
//! CPU.
//!
//! Build with `--features local-classifier`. Requires a `model.onnx` plus
//! `tokenizer.json` on disk. Default path: `/var/lib/innerwarden/models/classifier/`.

#![cfg(feature = "local-classifier")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use innerwarden_core::entities::EntityType;
use tokenizers::Tokenizer;
use tracing::{debug, warn};
use tract_onnx::prelude::*;

use super::{AiAction, AiDecision, AiProvider, DecisionContext};

/// Label order must match the model's training (fine_tune.py LABELS).
const LABELS: [&str; 4] = ["dismiss", "ignore", "block_ip", "monitor"];
const MAX_LEN: usize = 256;

type OnnxModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

pub struct LocalClassifier {
    model: Arc<OnnxModel>,
    tokenizer: Arc<Tokenizer>,
    auto_exec_threshold: f32,
    model_path: PathBuf,
}

impl LocalClassifier {
    pub fn from_dir(dir: &Path, auto_exec_threshold: f32) -> Result<Self> {
        let model_path = dir.join("model.onnx");
        let tokenizer_path = dir.join("tokenizer.json");
        if !model_path.exists() {
            bail!(
                "classifier model.onnx not found at {}",
                model_path.display()
            );
        }
        if !tokenizer_path.exists() {
            bail!(
                "classifier tokenizer.json not found at {}",
                tokenizer_path.display()
            );
        }

        let model = tract_onnx::onnx()
            .model_for_path(&model_path)
            .with_context(|| format!("loading ONNX model {}", model_path.display()))?
            .with_input_fact(
                0,
                InferenceFact::dt_shape(i64::datum_type(), tvec!(1, MAX_LEN)),
            )?
            .with_input_fact(
                1,
                InferenceFact::dt_shape(i64::datum_type(), tvec!(1, MAX_LEN)),
            )?
            .into_optimized()?
            .into_runnable()?;

        let tokenizer =
            Tokenizer::from_file(&tokenizer_path).map_err(|e| anyhow!("loading tokenizer: {e}"))?;

        Ok(Self {
            model: Arc::new(model),
            tokenizer: Arc::new(tokenizer),
            auto_exec_threshold,
            model_path: dir.to_path_buf(),
        })
    }

    fn build_text(ctx: &DecisionContext<'_>) -> String {
        let inc = ctx.incident;
        let detector = inc.incident_id.split(':').next().unwrap_or("unknown");
        let mut parts = vec![
            format!("detector: {}", detector),
            format!("severity: {:?}", inc.severity).to_lowercase(),
            format!("title: {}", truncate(&inc.title, 200)),
        ];
        if !inc.summary.is_empty() {
            parts.push(format!("summary: {}", truncate(&inc.summary, 400)));
        }
        parts.join(" | ")
    }

    fn run_inference(&self, text: &str) -> Result<[f32; 4]> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow!("tokenize: {e}"))?;

        let mut ids: Vec<i64> = encoding.get_ids().iter().map(|&x| x as i64).collect();
        let mut mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&x| x as i64)
            .collect();
        pad_or_truncate(&mut ids, MAX_LEN, 0);
        pad_or_truncate(&mut mask, MAX_LEN, 0);

        let ids_tensor: Tensor = tract_ndarray::Array2::from_shape_vec((1, MAX_LEN), ids)?.into();
        let mask_tensor: Tensor = tract_ndarray::Array2::from_shape_vec((1, MAX_LEN), mask)?.into();

        let outputs = self
            .model
            .run(tvec!(ids_tensor.into(), mask_tensor.into()))?;

        let probs_tensor = outputs
            .first()
            .ok_or_else(|| anyhow!("model produced no outputs"))?;
        let probs_view = probs_tensor.to_array_view::<f32>()?;
        let slice = probs_view
            .as_slice()
            .ok_or_else(|| anyhow!("output not contiguous"))?;
        if slice.len() < LABELS.len() {
            bail!(
                "classifier returned {} probs, expected at least {}",
                slice.len(),
                LABELS.len()
            );
        }
        let mut out = [0.0f32; 4];
        out.copy_from_slice(&slice[..LABELS.len()]);
        Ok(out)
    }

    fn primary_ip(ctx: &DecisionContext<'_>) -> Option<String> {
        ctx.incident
            .entities
            .iter()
            .find(|e| matches!(e.r#type, EntityType::Ip))
            .map(|e| e.value.clone())
    }

    fn clone_handles(&self) -> Self {
        Self {
            model: Arc::clone(&self.model),
            tokenizer: Arc::clone(&self.tokenizer),
            auto_exec_threshold: self.auto_exec_threshold,
            model_path: self.model_path.clone(),
        }
    }
}

#[async_trait]
impl AiProvider for LocalClassifier {
    fn name(&self) -> &'static str {
        "local_classifier"
    }

    /// Spec 029: declare only the capabilities this classifier truly
    /// supports. It cannot generate free-form text (no decoder stage
    /// in MiniLM), cannot explain, cannot simulate a shell. If the
    /// router ever asks this provider for Generate/Explain/SimulateShell
    /// the call is routed elsewhere instead.
    fn capabilities(&self) -> super::capability::AiCapabilities {
        super::capability::AiCapabilities::from_slice(&[
            super::capability::Capability::Decide,
            super::capability::Capability::Classify,
        ])
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        let text = Self::build_text(ctx);
        debug!(
            model = %self.model_path.display(),
            len = text.len(),
            "running local classifier",
        );

        let this = self.clone_handles();
        let probs: [f32; 4] = tokio::task::spawn_blocking(move || this.run_inference(&text))
            .await
            .map_err(|e| anyhow!("inference task join: {e}"))??;

        let (idx, &conf) = probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .ok_or_else(|| anyhow!("empty probs"))?;

        let action_name = LABELS[idx];
        let target_ip = Self::primary_ip(ctx);

        let action = match action_name {
            "block_ip" => match target_ip.clone() {
                Some(ip) => AiAction::BlockIp {
                    ip,
                    skill_id: "block-ip-ufw".to_string(),
                },
                None => {
                    warn!(
                        "classifier predicted block_ip but incident has no IP entity, downgrading to ignore"
                    );
                    AiAction::Ignore {
                        reason: "block_ip predicted but no target IP".to_string(),
                    }
                }
            },
            "monitor" => AiAction::Monitor {
                ip: target_ip.unwrap_or_else(|| "unknown".to_string()),
            },
            "ignore" | "dismiss" => AiAction::Ignore {
                reason: format!("classifier: {} (confidence {:.3})", action_name, conf),
            },
            _ => AiAction::Ignore {
                reason: format!("unknown classifier action: {}", action_name),
            },
        };

        let alternatives: Vec<String> = LABELS
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(i, l)| format!("{} ({:.2})", l, probs[i]))
            .collect();

        let estimated_threat = match conf {
            c if c >= 0.9 => "high",
            c if c >= 0.75 => "medium",
            _ => "low",
        }
        .to_string();

        Ok(AiDecision {
            action,
            confidence: conf,
            auto_execute: conf >= self.auto_exec_threshold,
            reason: format!(
                "Local classifier decided {} with confidence {:.3}. Alternatives: {}.",
                action_name,
                conf,
                alternatives.join(", ")
            ),
            alternatives,
            estimated_threat,
        })
    }

    async fn chat(&self, _system_prompt: &str, _user_message: &str) -> Result<String> {
        bail!("local_classifier does not support free-form chat (classification only)")
    }
}

fn pad_or_truncate(v: &mut Vec<i64>, len: usize, pad: i64) {
    if v.len() > len {
        v.truncate(len);
    } else {
        v.resize(len, pad);
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_shorter() {
        let mut v = vec![1i64, 2, 3];
        pad_or_truncate(&mut v, 8, 0);
        assert_eq!(v, vec![1, 2, 3, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn truncate_longer() {
        let mut v: Vec<i64> = (0..10).collect();
        pad_or_truncate(&mut v, 5, 0);
        assert_eq!(v, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn truncate_handles_utf8() {
        let s = "áéíóú".repeat(10);
        let t = truncate(&s, 12);
        assert!(t.len() <= 12);
    }
}
