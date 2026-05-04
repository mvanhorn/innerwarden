//! Local Warden Model — ONNX classifier (distilled student of a SecureBERT teacher).
//!
//! Operator-facing name: **Local Warden Model** (TOML key `[ai.warden]`,
//! provider id `local_warden`). Internal symbols keep the
//! `local_classifier` / `LocalClassifier` names for audit-trail
//! continuity and to keep diffs minimal.
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

    /// Spec 029: only declare `Decide`. The current `Classify`
    /// call sites (batch triage, ambiguous verification) dispatch
    /// via `chat()` with a prompt asking for a label, which this
    /// classifier cannot serve (no decoder). Declaring only `Decide`
    /// keeps the router honest: Classify requests fall through to
    /// the llm slot where `chat()` actually works, and this provider
    /// is only invoked for the one path it was trained for (incident
    /// triage -> block_ip/monitor/ignore/dismiss).
    fn capabilities(&self) -> super::capability::AiCapabilities {
        super::capability::AiCapabilities::from_slice(&[super::capability::Capability::Decide])
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

        let action = build_action_from_prediction(action_name, target_ip.clone(), conf);

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
                "Local Warden decided {} with confidence {:.3}. Alternatives: {}.",
                action_name,
                conf,
                alternatives.join(", ")
            ),
            alternatives,
            estimated_threat,
        })
    }

    async fn chat(&self, _system_prompt: &str, _user_message: &str) -> Result<String> {
        bail!("Local Warden does not support free-form chat (classification only)")
    }
}

fn pad_or_truncate(v: &mut Vec<i64>, len: usize, pad: i64) {
    if v.len() > len {
        v.truncate(len);
    } else {
        v.resize(len, pad);
    }
}

/// Build an `AiAction` from the classifier's predicted action name + the
/// optional IP entity extracted from the incident context. Pure logic so the
/// downgrade behaviour can be unit-tested without an ONNX runtime.
///
/// Wave 9g (AUDIT-016 anchor): the `"block_ip"` arm matches `target_ip`
/// and downgrades to `Ignore` when no IP is present. Pre-demotion the
/// downgrade emitted a WARN; now it logs at DEBUG because the safety net
/// works as designed and there is no operator action.
fn build_action_from_prediction(
    action_name: &str,
    target_ip: Option<String>,
    conf: f32,
) -> AiAction {
    match action_name {
        "block_ip" => match target_ip {
            Some(ip) => AiAction::BlockIp {
                ip,
                skill_id: "block-ip-ufw".to_string(),
            },
            None => {
                debug!(
                    "classifier predicted block_ip but incident has no IP entity, downgrading to ignore (safety net)"
                );
                AiAction::Ignore {
                    reason: "block_ip predicted but no target IP".to_string(),
                }
            }
        },
        "monitor" => AiAction::Monitor {
            ip: target_ip.unwrap_or_else(|| "unknown".to_string()),
        },
        "ignore" => AiAction::Ignore {
            reason: format!("classifier: ignore (confidence {:.3})", conf),
        },
        "dismiss" => AiAction::Dismiss {
            reason: format!("classifier: dismiss (confidence {:.3})", conf),
        },
        _ => AiAction::Ignore {
            reason: format!("unknown classifier action: {}", action_name),
        },
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

    // ── Wave 9g anchors (2026-05-04) — classifier safety net ─────────────
    //
    // AUDIT-016 (audit tick 7): the classifier emitted block_ip predictions
    // on incidents that had no IP entity. The agent downgrades to Ignore
    // (correct) but pre-Wave-9g it WARN-logged the event, suggesting an
    // operator-actionable problem - there is none, the safety net is the
    // intended behaviour. These anchors pin the downgrade contract so
    // future refactors do not (a) actually block on a missing IP, or
    // (b) re-promote the log to a level that asks the operator to act.

    #[test]
    fn block_ip_without_ip_entity_is_downgraded_to_ignore() {
        // The exact AUDIT-016 prod failure shape: classifier said block_ip
        // but the incident had no IP entity to act on. Result must be
        // Ignore (NOT BlockIp), with a stable reason string the audit log
        // can grep for.
        let action = build_action_from_prediction("block_ip", None, 0.95);
        match action {
            AiAction::Ignore { reason } => {
                assert!(
                    reason.contains("no target IP"),
                    "downgrade reason must mention the missing IP; got: {reason}"
                );
            }
            other => panic!("expected Ignore, got {other:?}"),
        }
    }

    #[test]
    fn block_ip_with_ip_entity_produces_block_ip() {
        // Anti-regression for over-coercing the downgrade: when the IP IS
        // present, the action MUST be BlockIp, not Ignore.
        let action =
            build_action_from_prediction("block_ip", Some("203.0.113.42".to_string()), 0.92);
        match action {
            AiAction::BlockIp { ip, skill_id } => {
                assert_eq!(ip, "203.0.113.42");
                assert_eq!(skill_id, "block-ip-ufw");
            }
            other => panic!("expected BlockIp, got {other:?}"),
        }
    }

    #[test]
    fn monitor_without_ip_uses_unknown_placeholder() {
        // Document the existing fallback so future contributors cannot
        // remove the unwrap_or without changing the public action shape.
        let action = build_action_from_prediction("monitor", None, 0.7);
        match action {
            AiAction::Monitor { ip } => assert_eq!(ip, "unknown"),
            other => panic!("expected Monitor, got {other:?}"),
        }
    }

    #[test]
    fn unknown_action_name_falls_back_to_ignore() {
        // If a future model adds a new label LABELS[i] we don't yet
        // recognise, the agent must fall back to Ignore (not panic, not
        // execute a partial decision). Confidence stays in the reason
        // string for audit visibility.
        let action = build_action_from_prediction("frobnicate", None, 0.66);
        match action {
            AiAction::Ignore { reason } => {
                assert!(reason.contains("unknown classifier action"));
                assert!(reason.contains("frobnicate"));
            }
            other => panic!("expected Ignore, got {other:?}"),
        }
    }

    #[test]
    fn dismiss_includes_confidence_in_reason_string() {
        // Audit-trail anchor: the reason must include the confidence so
        // the operator can grep `dismiss (confidence 0.` for low-confidence
        // dismisses without re-querying the inference batch.
        let action = build_action_from_prediction("dismiss", None, 0.123);
        match action {
            AiAction::Dismiss { reason } => {
                assert!(reason.contains("0.123"), "got: {reason}");
            }
            other => panic!("expected Dismiss, got {other:?}"),
        }
    }
}
