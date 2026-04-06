//! Defender Brain — AlphaZero-trained decision engine.
//!
//! Loads a dual-head neural network (policy + value) trained via adversarial
//! self-play (AlphaZero V4, 6 rounds, 200K+ games). Given the current
//! detection state, suggests the best defensive action with confidence.
//!
//! Architecture: [72 → 256 → 256] trunk → [128 → 30] policy + [64 → 1] value
//! Total params: 137,759 (~550KB binary, ~22KB gzip)
//!
//! Input (72 features): detection counts by severity, composite score,
//! kill chain score, correlation chains, baseline anomalies, active defenses.
//!
//! Output: 30 actions (10 reactive + 10 stance toggles + 10 reserved)
//! with probability distribution + value estimate.

use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Model binary format (IWD1 — InnerWarden Defender v1)
// ---------------------------------------------------------------------------

/// Embedded model weights (AlphaZero V4, 6 rounds, 137K params, 538KB).
/// Always available — no external file needed.
const MODEL_BYTES: &[u8] = include_bytes!("defender-brain.bin");

/// Layer: weights (rows × cols) + biases.
struct Layer {
    weights: Vec<Vec<f32>>,
    biases: Vec<f32>,
}

/// Dual-head network for defender decisions.
pub struct DefenderBrain {
    trunk: Vec<Layer>,
    policy_head: Vec<Layer>,
    value_head: Vec<Layer>,
    loaded: bool,
}

/// Suggested action from the defender brain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BrainSuggestion {
    /// Recommended action index (0-29).
    pub action: usize,
    /// Action name.
    pub action_name: &'static str,
    /// Confidence (probability from policy head).
    pub confidence: f32,
    /// Value estimate (-1 to 1, positive = defender advantage).
    pub value: f32,
    /// Top 3 actions with probabilities.
    pub top_actions: Vec<(usize, &'static str, f32)>,
}

/// A logged brain suggestion with context (for dashboard display + FP audit).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BrainLogEntry {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub incident_id: String,
    pub detector: String,
    pub severity: String,
    pub brain_action: &'static str,
    pub brain_confidence: f32,
    pub brain_value: f32,
    pub brain_top3: Vec<(usize, &'static str, f32)>,
    pub ai_action: String,
    pub ai_confidence: f32,
    /// Whether brain and AI agreed on action type.
    pub agreed: bool,
    /// Operator feedback: None = unreviewed, true = correct, false = FP.
    pub feedback: Option<bool>,
}

/// History of brain suggestions (ring buffer, last N).
#[derive(Debug)]
#[allow(dead_code)]
pub struct BrainHistory {
    entries: std::collections::VecDeque<BrainLogEntry>,
    max_entries: usize,
    pub total_suggestions: u64,
    pub total_agreed: u64,
}

#[allow(dead_code)]
impl BrainHistory {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(max_entries),
            max_entries,
            total_suggestions: 0,
            total_agreed: 0,
        }
    }

    pub fn record(&mut self, entry: BrainLogEntry) {
        self.total_suggestions += 1;
        if entry.agreed {
            self.total_agreed += 1;
        }
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    pub fn recent(&self, limit: usize) -> Vec<&BrainLogEntry> {
        self.entries.iter().rev().take(limit).collect()
    }

    pub fn mark_feedback(&mut self, incident_id: &str, correct: bool) -> bool {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .rev()
            .find(|e| e.incident_id == incident_id)
        {
            entry.feedback = Some(correct);
            true
        } else {
            false
        }
    }

    pub fn agreement_rate(&self) -> f32 {
        if self.total_suggestions == 0 {
            return 0.0;
        }
        self.total_agreed as f32 / self.total_suggestions as f32
    }

    pub fn fp_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.feedback == Some(false))
            .count()
    }

    pub fn tp_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.feedback == Some(true))
            .count()
    }

    pub fn unreviewed_count(&self) -> usize {
        self.entries.iter().filter(|e| e.feedback.is_none()).count()
    }
}

/// Action names matching the gym's defender action space.
const ACTION_NAMES: [&str; 30] = [
    "observe",
    "block_ip",
    "kill_process",
    "suspend_user",
    "deploy_honeypot",
    "capture_forensics",
    "isolate_network",
    "alert",
    "restore_file",
    "escalate",
    // Stances (10-19 in gym, mapped to 20-29 here)
    "enable_waf",
    "enable_ssh_rate_limit",
    "enable_tls_inspection",
    "enable_outbound_monitor",
    "push_cloudflare_edge",
    "enable_correlation",
    "enable_abuseipdb_gate",
    "tighten_ssh",
    "enable_xdp",
    "enable_kernel_monitor",
    // Reserved
    "reserved_20",
    "reserved_21",
    "reserved_22",
    "reserved_23",
    "reserved_24",
    "reserved_25",
    "reserved_26",
    "reserved_27",
    "reserved_28",
    "reserved_29",
];

impl DefenderBrain {
    /// Create an empty (unloaded) brain.
    pub fn new() -> Self {
        Self {
            trunk: Vec::new(),
            policy_head: Vec::new(),
            value_head: Vec::new(),
            loaded: false,
        }
    }

    /// Load from embedded binary (always available, compiled into the agent).
    pub fn load(_path: &str) -> Self {
        if let Some(brain) = Self::from_iwd1(MODEL_BYTES) {
            info!(
                params = brain.param_count(),
                size_kb = MODEL_BYTES.len() / 1024,
                "defender brain loaded (embedded, AlphaZero V4)"
            );
            return brain;
        }
        warn!("defender brain: embedded model failed to parse — running without neural decisions");
        Self::new()
    }

    /// Load from the gym's JSON format (best-def.json). Used in dev/testing.
    #[allow(dead_code)]
    fn load_json(path: &str) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&content).ok()?;

        let trunk = Self::parse_layers(v.get("trunk")?)?;
        let policy_head = Self::parse_layers(v.get("policy_head")?)?;
        let value_head = Self::parse_layers(v.get("value_head")?)?;

        Some(Self {
            trunk,
            policy_head,
            value_head,
            loaded: true,
        })
    }

    #[allow(dead_code)]
    fn parse_layers(v: &serde_json::Value) -> Option<Vec<Layer>> {
        let arr = v.as_array()?;
        let mut layers = Vec::new();
        for layer_val in arr {
            let weights_val = layer_val.get("weights")?.as_array()?;
            let biases_val = layer_val.get("biases")?.as_array()?;

            let weights: Vec<Vec<f32>> = weights_val
                .iter()
                .map(|row| {
                    row.as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|v| v.as_f64().unwrap_or(0.0) as f32)
                        .collect()
                })
                .collect();

            let biases: Vec<f32> = biases_val
                .iter()
                .map(|v| v.as_f64().unwrap_or(0.0) as f32)
                .collect();

            layers.push(Layer { weights, biases });
        }
        Some(layers)
    }

    /// Load from IWD1 binary format.
    #[allow(dead_code)]
    fn from_iwd1(data: &[u8]) -> Option<Self> {
        if data.len() < 8 || &data[0..4] != b"IWD1" {
            return None;
        }
        // Format: "IWD1" + num_sections(u32) + for each section: num_layers(u32) + layers
        // Each layer: rows(u32) + cols(u32) + weights(rows*cols*f32) + biases(rows*f32)
        let mut offset = 4;
        let num_sections = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if num_sections != 3 {
            return None;
        } // trunk, policy, value

        let mut sections = Vec::new();
        for _ in 0..3 {
            let (layers, new_offset) = Self::read_section(data, offset)?;
            sections.push(layers);
            offset = new_offset;
        }

        Some(Self {
            trunk: sections.remove(0),
            policy_head: sections.remove(0),
            value_head: sections.remove(0),
            loaded: true,
        })
    }

    fn read_section(data: &[u8], mut offset: usize) -> Option<(Vec<Layer>, usize)> {
        if offset + 4 > data.len() {
            return None;
        }
        let num_layers = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        let mut layers = Vec::new();
        for _ in 0..num_layers {
            if offset + 8 > data.len() {
                return None;
            }
            let rows = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            let cols = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;
            offset += 8;

            let mut weights = Vec::with_capacity(rows);
            for _ in 0..rows {
                let mut row = Vec::with_capacity(cols);
                for _ in 0..cols {
                    if offset + 4 > data.len() {
                        return None;
                    }
                    let val = f32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]);
                    row.push(val);
                    offset += 4;
                }
                weights.push(row);
            }

            let mut biases = Vec::with_capacity(rows);
            for _ in 0..rows {
                if offset + 4 > data.len() {
                    return None;
                }
                let val = f32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                biases.push(val);
                offset += 4;
            }

            layers.push(Layer { weights, biases });
        }
        Some((layers, offset))
    }

    /// Is the brain loaded and ready?
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Total parameters.
    pub fn param_count(&self) -> usize {
        let count = |layers: &[Layer]| -> usize {
            layers
                .iter()
                .map(|l| l.weights.iter().map(|r| r.len()).sum::<usize>() + l.biases.len())
                .sum()
        };
        count(&self.trunk) + count(&self.policy_head) + count(&self.value_head)
    }

    /// Get the brain's recommendation given the current detection state.
    ///
    /// Features (72-dim):
    /// [0-3] detection counts by severity (low, med, high, crit)
    /// [4] total detections this tick
    /// [5] composite score
    /// [6] kill chain max score
    /// [7] kill chain stage bitmask
    /// [8] correlation chains count
    /// [9] anomaly count
    /// [10] tick normalized
    /// [11] defenses active count
    /// [12-17] per-detector flags (ssh_brute, reverse_shell, privesc, ransomware, log_tamper, web_shell)
    /// [18] blocked
    /// [19-71] reserved
    pub fn suggest(&self, features: &[f32; 72]) -> Option<BrainSuggestion> {
        if !self.loaded {
            return None;
        }

        // Trunk forward (ReLU)
        let mut x = features.to_vec();
        for layer in &self.trunk {
            x = forward_relu(layer, &x);
        }

        // Policy head (ReLU + linear)
        let mut px = x.clone();
        for (i, layer) in self.policy_head.iter().enumerate() {
            if i < self.policy_head.len() - 1 {
                px = forward_relu(layer, &px);
            } else {
                px = forward_linear(layer, &px);
            }
        }
        let policy = softmax(&px);

        // Value head (ReLU + tanh)
        let mut vx = x;
        for (i, layer) in self.value_head.iter().enumerate() {
            if i < self.value_head.len() - 1 {
                vx = forward_relu(layer, &vx);
            } else {
                vx = forward_linear(layer, &vx);
            }
        }
        let value = vx.first().copied().unwrap_or(0.0).tanh();

        // Find best action
        let best_action = policy
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);

        // Top 3
        let mut indexed: Vec<(usize, f32)> =
            policy.iter().enumerate().map(|(i, &p)| (i, p)).collect();
        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let top_actions: Vec<(usize, &str, f32)> = indexed
            .iter()
            .take(3)
            .map(|&(i, p)| (i, ACTION_NAMES.get(i).copied().unwrap_or("unknown"), p))
            .collect();

        Some(BrainSuggestion {
            action: best_action,
            action_name: ACTION_NAMES.get(best_action).copied().unwrap_or("unknown"),
            confidence: policy[best_action],
            value,
            top_actions,
        })
    }
}

/// ReLU forward pass.
fn forward_relu(layer: &Layer, input: &[f32]) -> Vec<f32> {
    layer
        .weights
        .iter()
        .zip(&layer.biases)
        .map(|(w, &b)| {
            let sum: f32 = w.iter().zip(input).map(|(&wi, &xi)| wi * xi).sum::<f32>() + b;
            sum.max(0.0)
        })
        .collect()
}

/// Linear forward pass (no activation).
fn forward_linear(layer: &Layer, input: &[f32]) -> Vec<f32> {
    layer
        .weights
        .iter()
        .zip(&layer.biases)
        .map(|(w, &b)| w.iter().zip(input).map(|(&wi, &xi)| wi * xi).sum::<f32>() + b)
        .collect()
}

/// Softmax.
fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|&l| (l - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum == 0.0 {
        vec![1.0 / logits.len() as f32; logits.len()]
    } else {
        exps.iter().map(|&e| e / sum).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_brain_returns_none() {
        let brain = DefenderBrain::new();
        assert!(!brain.is_loaded());
        assert!(brain.suggest(&[0.0; 72]).is_none());
    }

    #[test]
    fn load_json_model() {
        // Try loading the R6 model if available
        let path = "best-def-r6.json";
        if std::path::Path::new(path).exists() {
            let brain = DefenderBrain::load(path);
            assert!(brain.is_loaded());
            assert_eq!(brain.param_count(), 137759);

            let mut features = [0.0f32; 72];
            features[2] = 0.5; // high severity detection
            features[5] = 0.7; // high composite score
            features[6] = 0.4; // kill chain active

            let suggestion = brain.suggest(&features).unwrap();
            assert!(suggestion.confidence > 0.0);
            assert!(suggestion.value >= -1.0 && suggestion.value <= 1.0);
            assert!(!suggestion.action_name.is_empty());
        }
    }
}
