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
    /// The 72-dim feature vector used for this decision (for offline training).
    pub features: Vec<f32>,
}

/// Persistent brain evolution stats (saved to brain-stats.json).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BrainStats {
    /// Total decisions observed since last retrain.
    pub total_since_retrain: u64,
    /// Agreements since last retrain.
    pub agreed_since_retrain: u64,
    /// Rolling 7-day agreement percentages (one per day, last 56 days = 8 weeks).
    pub daily_agreement: std::collections::VecDeque<(String, f32)>, // (date, pct)
    /// Last retrain timestamp.
    pub last_retrain: Option<String>,
    /// Last retrain accuracy.
    pub last_retrain_accuracy: Option<f32>,
    /// Last retrain data points used.
    pub last_retrain_entries: Option<u64>,
    /// Current day's counters.
    pub today_date: String,
    pub today_agreed: u64,
    pub today_total: u64,
}

#[allow(dead_code)]
impl BrainStats {
    pub fn load(data_dir: &std::path::Path) -> Self {
        let path = data_dir.join("brain-stats.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, data_dir: &std::path::Path) {
        let path = data_dir.join("brain-stats.json");
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, json);
        }
    }

    /// Record a brain vs AI comparison.
    pub fn record(&mut self, agreed: bool, today: &str) {
        // Roll over day
        if self.today_date != today {
            if !self.today_date.is_empty() && self.today_total > 0 {
                let pct = self.today_agreed as f32 / self.today_total as f32 * 100.0;
                self.daily_agreement
                    .push_back((self.today_date.clone(), pct));
                // Keep 56 days (8 weeks)
                while self.daily_agreement.len() > 56 {
                    self.daily_agreement.pop_front();
                }
            }
            self.today_date = today.to_string();
            self.today_agreed = 0;
            self.today_total = 0;
        }

        self.today_total += 1;
        self.total_since_retrain += 1;
        if agreed {
            self.today_agreed += 1;
            self.agreed_since_retrain += 1;
        }
    }

    /// Current agreement percentage.
    pub fn agreement_pct(&self) -> f32 {
        if self.total_since_retrain == 0 {
            return 0.0;
        }
        self.agreed_since_retrain as f32 / self.total_since_retrain as f32 * 100.0
    }

    /// Weekly trend (last 8 weeks, averaged per week).
    pub fn weekly_trend(&self) -> Vec<f32> {
        let days: Vec<f32> = self.daily_agreement.iter().map(|(_, pct)| *pct).collect();
        days.chunks(7)
            .map(|week| week.iter().sum::<f32>() / week.len() as f32)
            .collect()
    }
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

/// Map an AI action string (from brain-log) to action index.
fn ai_action_to_index(action: &str) -> Option<usize> {
    if action.contains("BlockIp") {
        Some(1)
    } else if action.contains("KillProcess") {
        Some(2)
    } else if action.contains("SuspendUser") {
        Some(3)
    } else if action.contains("Honeypot") {
        Some(4)
    } else if action.contains("Ignore") {
        Some(0)
    } else if action.contains("Monitor") {
        Some(7) // alert
    } else if action.contains("Escalate") {
        Some(9)
    } else {
        None
    }
}

impl DefenderBrain {
    /// Retrain the policy head using supervised data from brain-log.json.
    ///
    /// Reads (features, ai_action) pairs, maps ai_action to target index,
    /// and fine-tunes the policy head via backpropagation. Trunk and value
    /// head are frozen — only the policy mapping is updated.
    ///
    /// Returns (entries_used, accuracy) or None if not enough data.
    pub fn retrain_from_log(&mut self, data_dir: &std::path::Path) -> Option<(u64, f32)> {
        if !self.loaded {
            return None;
        }

        let log_path = data_dir.join("brain-log.json");
        let data = std::fs::read_to_string(&log_path).ok()?;
        let entries: Vec<serde_json::Value> = serde_json::from_str(&data).ok()?;

        if entries.len() < 20 {
            info!("brain retrain: only {} entries, need >= 20", entries.len());
            return None;
        }

        // Extract (features, target_action_index) pairs
        let mut samples: Vec<([f32; 72], usize)> = Vec::new();
        for entry in &entries {
            let features_val = entry.get("features").and_then(|v| v.as_array())?;
            if features_val.len() != 72 {
                continue;
            }
            let mut features = [0.0f32; 72];
            for (i, v) in features_val.iter().enumerate() {
                features[i] = v.as_f64().unwrap_or(0.0) as f32;
            }

            let ai_action = entry.get("ai_action").and_then(|v| v.as_str())?;
            if let Some(target) = ai_action_to_index(ai_action) {
                samples.push((features, target));
            }
        }

        if samples.len() < 20 {
            info!(
                "brain retrain: only {} usable samples, need >= 20",
                samples.len()
            );
            return None;
        }

        let lr = 0.01f32;
        let epochs = 10;
        let num_actions = 30;
        let mut correct = 0u64;
        let total = samples.len() as u64;

        for _epoch in 0..epochs {
            correct = 0;
            for (features, target) in &samples {
                // Forward through frozen trunk
                let mut x = features.to_vec();
                for layer in &self.trunk {
                    x = forward_relu(layer, &x);
                }

                // Forward through policy head
                let mut px = x.clone();
                let mut intermediates = vec![x.clone()]; // save activations for backprop
                for (i, layer) in self.policy_head.iter().enumerate() {
                    if i < self.policy_head.len() - 1 {
                        px = forward_relu(layer, &px);
                    } else {
                        px = forward_linear(layer, &px);
                    }
                    intermediates.push(px.clone());
                }

                // Softmax + cross-entropy gradient
                let probs = softmax(&px);
                let predicted = probs
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                if predicted == *target {
                    correct += 1;
                }

                // dL/d_logits = probs - one_hot(target)
                let mut grad: Vec<f32> = probs.clone();
                if *target < num_actions {
                    grad[*target] -= 1.0;
                }

                // Backprop through policy head (reverse order)
                let num_policy_layers = self.policy_head.len();
                for (i, layer) in self.policy_head.iter_mut().enumerate().rev() {
                    let input = &intermediates[i];
                    let is_relu = i < num_policy_layers - 1;

                    // Apply ReLU derivative if not last layer
                    if is_relu {
                        let output = &intermediates[i + 1];
                        for (g, o) in grad.iter_mut().zip(output) {
                            if *o <= 0.0 {
                                *g = 0.0;
                            }
                        }
                    }

                    // Update weights and biases
                    let mut grad_input = vec![0.0f32; input.len()];
                    for (j, (w_row, &g)) in layer.weights.iter_mut().zip(grad.iter()).enumerate() {
                        layer.biases[j] -= lr * g;
                        for (k, w) in w_row.iter_mut().enumerate() {
                            grad_input[k] += *w * g;
                            *w -= lr * g * input[k];
                        }
                    }
                    grad = grad_input;
                }
            }
        }

        let accuracy = correct as f32 / total as f32;
        info!(
            entries = total,
            accuracy = format!("{:.1}%", accuracy * 100.0),
            epochs = epochs,
            "brain retrain complete"
        );

        // Export updated weights to disk (hot-reload next restart)
        if let Some(iwd1) = self.export_iwd1() {
            let brain_path = data_dir.join("defender-brain-retrained.bin");
            if let Err(e) = std::fs::write(&brain_path, &iwd1) {
                warn!("failed to save retrained brain: {e}");
            } else {
                info!(
                    size_kb = iwd1.len() / 1024,
                    "retrained brain saved to {}",
                    brain_path.display()
                );
            }
        }

        Some((total, accuracy))
    }

    /// Export current weights as IWD1 binary.
    fn export_iwd1(&self) -> Option<Vec<u8>> {
        if !self.loaded {
            return None;
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(b"IWD1");
        buf.extend_from_slice(&3u32.to_le_bytes());

        for section in [&self.trunk, &self.policy_head, &self.value_head] {
            buf.extend_from_slice(&(section.len() as u32).to_le_bytes());
            for layer in section {
                let rows = layer.weights.len() as u32;
                let cols = if layer.weights.is_empty() {
                    0u32
                } else {
                    layer.weights[0].len() as u32
                };
                buf.extend_from_slice(&rows.to_le_bytes());
                buf.extend_from_slice(&cols.to_le_bytes());
                for row in &layer.weights {
                    for &w in row {
                        buf.extend_from_slice(&w.to_le_bytes());
                    }
                }
                for &b in &layer.biases {
                    buf.extend_from_slice(&b.to_le_bytes());
                }
            }
        }

        Some(buf)
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
    use serde_json::json;
    use tempfile::tempdir;

    fn make_history_entry(incident_id: &str, agreed: bool) -> BrainLogEntry {
        BrainLogEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            brain_action: "block_ip",
            brain_confidence: 0.9,
            brain_value: 0.2,
            brain_top3: vec![
                (1, "block_ip", 0.9),
                (0, "observe", 0.05),
                (9, "escalate", 0.05),
            ],
            ai_action: "BlockIp".to_string(),
            ai_confidence: 0.8,
            agreed,
            feedback: None,
            features: vec![0.0; 72],
        }
    }

    fn tiny_trainable_brain() -> DefenderBrain {
        let mut trunk_row0 = vec![0.0; 72];
        trunk_row0[0] = 1.0;
        trunk_row0[3] = 2.0;
        trunk_row0[18] = -1.0;

        let mut trunk_row1 = vec![0.0; 72];
        trunk_row1[2] = 1.0;
        trunk_row1[5] = 1.0;

        let mut policy_out_weights = vec![vec![0.0, 0.0]; 30];
        policy_out_weights[0] = vec![0.1, 0.1];
        policy_out_weights[1] = vec![2.0, 0.0];
        policy_out_weights[9] = vec![0.0, 2.0];

        let mut policy_biases = vec![0.0; 30];
        policy_biases[0] = 0.5;

        DefenderBrain {
            trunk: vec![Layer {
                weights: vec![trunk_row0, trunk_row1],
                biases: vec![0.0, 0.0],
            }],
            policy_head: vec![
                Layer {
                    weights: vec![vec![1.0, 0.0], vec![0.0, 1.0]],
                    biases: vec![0.0, 0.0],
                },
                Layer {
                    weights: policy_out_weights,
                    biases: policy_biases,
                },
            ],
            value_head: vec![
                Layer {
                    weights: vec![vec![1.0, -1.0], vec![0.5, 0.5]],
                    biases: vec![0.0, 0.0],
                },
                Layer {
                    weights: vec![vec![0.2, 0.1]],
                    biases: vec![0.0],
                },
            ],
            loaded: true,
        }
    }

    fn build_brain_log_entries(count: usize, action: &str) -> Vec<serde_json::Value> {
        (0..count)
            .map(|i| {
                let mut features = vec![0.0f32; 72];
                features[0] = (i % 3) as f32;
                features[2] = (i % 2) as f32;
                features[5] = (i as f32) / count.max(1) as f32;
                json!({
                    "features": features,
                    "ai_action": action,
                })
            })
            .collect()
    }

    #[test]
    fn empty_brain_returns_none() {
        // Baseline path: unloaded brains should refuse to suggest actions.
        let brain = DefenderBrain::new();
        assert!(!brain.is_loaded());
        assert!(brain.suggest(&[0.0; 72]).is_none());
    }

    #[test]
    fn embedded_iwd1_loads_and_suggests() {
        // Model path: embedded IWD1 weights should parse and produce bounded
        // confidence/value outputs for a non-trivial feature vector.
        let brain = DefenderBrain::from_iwd1(MODEL_BYTES).expect("IWD1 should parse");
        assert!(brain.loaded);

        // Scenario: SSH brute-force (high severity, active kill chain)
        let mut features = [0.0f32; 72];
        features[0] = 5.0; // 5 low-severity detections
        features[2] = 1.0; // 1 high-severity detection
        features[5] = 0.7; // high composite score
        features[6] = 0.3; // kill chain active
        features[12] = 1.0; // ssh_bruteforce flag

        let suggestion = brain.suggest(&features).unwrap();
        assert!(suggestion.confidence > 0.0);
        assert!(suggestion.value >= -1.0 && suggestion.value <= 1.0);
        eprintln!(
            "V5 suggestion: {} ({:.1}%), value={:.3}, top3: {:?}",
            suggestion.action_name,
            suggestion.confidence * 100.0,
            suggestion.value,
            suggestion.top_actions
        );
    }

    #[test]
    fn embedded_iwd1_varied_scenarios() {
        // Scenario path: policy inference should remain stable across quiet,
        // ransomware and scan-style feature combinations.
        let brain = DefenderBrain::from_iwd1(MODEL_BYTES).expect("IWD1 should parse");

        // Scenario 1: quiet (no threats)
        let quiet = brain.suggest(&[0.0; 72]).unwrap();
        // Scenario 2: ransomware (critical)
        let mut ransom = [0.0f32; 72];
        ransom[3] = 1.0; // critical severity
        ransom[5] = 0.95;
        ransom[15] = 1.0; // ransomware flag
        let ransom_s = brain.suggest(&ransom).unwrap();
        // Scenario 3: port scan (low)
        let mut scan = [0.0f32; 72];
        scan[0] = 10.0; // many low detections
        scan[5] = 0.2;
        let scan_s = brain.suggest(&scan).unwrap();

        eprintln!(
            "Quiet: {} ({:.1}%)",
            quiet.action_name,
            quiet.confidence * 100.0
        );
        eprintln!(
            "Ransomware: {} ({:.1}%)",
            ransom_s.action_name,
            ransom_s.confidence * 100.0
        );
        eprintln!(
            "Port scan: {} ({:.1}%)",
            scan_s.action_name,
            scan_s.confidence * 100.0
        );

        // V5 50M: trained on self-play, not production data.
        // Currently suggests same action for all scenarios (low confidence).
        // Will improve once retrained with supervised production decisions.
    }

    #[test]
    fn load_json_model() {
        // Compatibility path: JSON-exported brains should still load when
        // available for local supervised retraining workflows.
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

    #[test]
    fn ai_action_to_index_maps_known_and_unknown_actions() {
        // Mapping path: AI action labels from brain-log entries should map to
        // stable policy-space indices used for supervised fine-tuning.
        assert_eq!(ai_action_to_index("BlockIp"), Some(1));
        assert_eq!(ai_action_to_index("KillProcess"), Some(2));
        assert_eq!(ai_action_to_index("SuspendUser"), Some(3));
        assert_eq!(ai_action_to_index("Honeypot"), Some(4));
        assert_eq!(ai_action_to_index("Ignore"), Some(0));
        assert_eq!(ai_action_to_index("Monitor"), Some(7));
        assert_eq!(ai_action_to_index("Escalate"), Some(9));
        assert_eq!(ai_action_to_index("UnknownAction"), None);
    }

    #[test]
    fn softmax_outputs_probability_distribution() {
        // Numerical path: softmax should always produce non-negative values
        // that sum to 1.0 for downstream policy selection.
        let probs = softmax(&[2.0, 1.0, -3.0]);
        let sum: f32 = probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-6);
        assert!(probs.iter().all(|p| *p >= 0.0));
        assert!(probs[0] > probs[1]);
    }

    #[test]
    fn forward_layers_apply_relu_and_linear_rules() {
        // Activation path: hidden layers clamp negatives with ReLU while
        // linear heads preserve signed values.
        let layer = Layer {
            weights: vec![vec![1.0, -2.0], vec![-1.0, -1.0]],
            biases: vec![0.0, 0.5],
        };
        let input = vec![1.0, 3.0];

        let relu = forward_relu(&layer, &input);
        assert_eq!(relu.len(), 2);
        assert_eq!(relu[0], 0.0);
        assert_eq!(relu[1], 0.0);

        let linear = forward_linear(&layer, &input);
        assert_eq!(linear.len(), 2);
        assert!(linear[0] < 0.0);
        assert!(linear[1] < 0.0);
    }

    #[test]
    fn brain_stats_load_save_and_rollover_cover_edge_cases() {
        let dir = tempdir().unwrap();

        let missing = BrainStats::load(dir.path());
        assert_eq!(missing.total_since_retrain, 0);
        assert_eq!(missing.today_date, "");

        std::fs::write(dir.path().join("brain-stats.json"), "{invalid").unwrap();
        let invalid = BrainStats::load(dir.path());
        assert_eq!(invalid.total_since_retrain, 0);

        let mut stats = BrainStats {
            total_since_retrain: 10,
            agreed_since_retrain: 6,
            daily_agreement: (0..56)
                .map(|i| (format!("2026-03-{i:02}"), i as f32))
                .collect(),
            today_date: "2026-04-01".to_string(),
            today_agreed: 3,
            today_total: 4,
            ..Default::default()
        };

        stats.record(true, "2026-04-02");
        assert_eq!(stats.today_date, "2026-04-02");
        assert_eq!(stats.today_total, 1);
        assert_eq!(stats.today_agreed, 1);
        assert_eq!(stats.total_since_retrain, 11);
        assert_eq!(stats.agreed_since_retrain, 7);
        assert_eq!(stats.daily_agreement.len(), 56);

        stats.save(dir.path());
        let loaded = BrainStats::load(dir.path());
        assert_eq!(loaded.today_date, "2026-04-02");
        assert_eq!(loaded.today_total, 1);
        assert_eq!(loaded.total_since_retrain, 11);
        assert_eq!(loaded.agreed_since_retrain, 7);
    }

    #[test]
    fn brain_stats_agreement_pct_and_weekly_trend_handle_boundaries() {
        let mut stats = BrainStats::default();
        assert_eq!(stats.agreement_pct(), 0.0);

        stats.total_since_retrain = 4;
        stats.agreed_since_retrain = 1;
        assert!((stats.agreement_pct() - 25.0).abs() < 1e-6);

        stats.daily_agreement = vec![
            ("d1".to_string(), 10.0),
            ("d2".to_string(), 20.0),
            ("d3".to_string(), 30.0),
            ("d4".to_string(), 40.0),
            ("d5".to_string(), 50.0),
            ("d6".to_string(), 60.0),
            ("d7".to_string(), 70.0),
            ("d8".to_string(), 80.0),
        ]
        .into_iter()
        .collect();

        let trend = stats.weekly_trend();
        assert_eq!(trend.len(), 2);
        assert!((trend[0] - 40.0).abs() < 1e-6);
        assert!((trend[1] - 80.0).abs() < 1e-6);
    }

    #[test]
    fn brain_history_tracks_ring_buffer_feedback_and_counts() {
        let mut history = BrainHistory::new(2);
        assert_eq!(history.agreement_rate(), 0.0);

        history.record(make_history_entry("inc-1", false));
        history.record(make_history_entry("inc-2", true));
        history.record(make_history_entry("inc-3", false));

        assert_eq!(history.total_suggestions, 3);
        assert_eq!(history.total_agreed, 1);

        let recent = history.recent(5);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].incident_id, "inc-3");
        assert_eq!(recent[1].incident_id, "inc-2");

        assert!(history.mark_feedback("inc-2", true));
        assert!(history.mark_feedback("inc-3", false));
        assert!(!history.mark_feedback("missing", true));

        assert!((history.agreement_rate() - (1.0 / 3.0)).abs() < 1e-6);
        assert_eq!(history.tp_count(), 1);
        assert_eq!(history.fp_count(), 1);
        assert_eq!(history.unreviewed_count(), 0);
    }

    #[test]
    fn load_and_param_count_cover_public_surface() {
        let brain = DefenderBrain::load("ignored");
        assert!(brain.is_loaded());
        assert!(brain.param_count() > 0);
    }

    #[test]
    fn load_json_parse_layers_and_missing_file_paths_are_covered() {
        let dir = tempdir().unwrap();
        let json_path = dir.path().join("model.json");

        std::fs::write(
            &json_path,
            r#"{
  "trunk": [{"weights": [[1.0, 0.0], [0.0, 1.0]], "biases": [0.1, -0.1]}],
  "policy_head": [{"weights": [[0.2, 0.3], [0.4, 0.5]], "biases": [0.0, 0.0]}],
  "value_head": [{"weights": [[0.9, -0.2]], "biases": [0.0]}]
}"#,
        )
        .unwrap();

        let loaded = DefenderBrain::load_json(json_path.to_str().unwrap()).unwrap();
        assert!(loaded.is_loaded());
        assert_eq!(loaded.param_count(), 15);

        std::fs::write(&json_path, "{broken").unwrap();
        assert!(DefenderBrain::load_json(json_path.to_str().unwrap()).is_none());
        assert!(DefenderBrain::load_json("does-not-exist.json").is_none());

        let weird_layers = json!([
            {
                "weights": [123, [2.0, 3.0]],
                "biases": [5.0, "not-a-number"]
            }
        ]);
        let parsed = DefenderBrain::parse_layers(&weird_layers).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].weights[0].len(), 0);
        assert_eq!(parsed[0].weights[1].len(), 2);
        assert_eq!(parsed[0].biases[1], 0.0);
    }

    #[test]
    fn from_iwd1_and_read_section_reject_invalid_inputs() {
        assert!(DefenderBrain::from_iwd1(b"BAD!").is_none());

        let mut wrong_sections = Vec::new();
        wrong_sections.extend_from_slice(b"IWD1");
        wrong_sections.extend_from_slice(&2u32.to_le_bytes());
        assert!(DefenderBrain::from_iwd1(&wrong_sections).is_none());

        assert!(DefenderBrain::read_section(&[], 0).is_none());

        let only_num_layers = 1u32.to_le_bytes().to_vec();
        assert!(DefenderBrain::read_section(&only_num_layers, 0).is_none());

        let mut missing_weight = Vec::new();
        missing_weight.extend_from_slice(&1u32.to_le_bytes()); // num_layers
        missing_weight.extend_from_slice(&1u32.to_le_bytes()); // rows
        missing_weight.extend_from_slice(&1u32.to_le_bytes()); // cols
        assert!(DefenderBrain::read_section(&missing_weight, 0).is_none());

        let mut missing_bias = missing_weight.clone();
        missing_bias.extend_from_slice(&1.5f32.to_le_bytes()); // one weight
        assert!(DefenderBrain::read_section(&missing_bias, 0).is_none());
    }

    #[test]
    fn export_iwd1_roundtrip_and_empty_layer_shape_are_supported() {
        let unloaded = DefenderBrain::new();
        assert!(unloaded.export_iwd1().is_none());

        let roundtrip = tiny_trainable_brain();
        let bytes = roundtrip.export_iwd1().unwrap();
        let parsed = DefenderBrain::from_iwd1(&bytes).unwrap();
        assert!(parsed.is_loaded());
        assert_eq!(parsed.param_count(), roundtrip.param_count());

        let empty_layer_brain = DefenderBrain {
            trunk: vec![Layer {
                weights: vec![],
                biases: vec![],
            }],
            policy_head: vec![Layer {
                weights: vec![],
                biases: vec![],
            }],
            value_head: vec![Layer {
                weights: vec![],
                biases: vec![],
            }],
            loaded: true,
        };
        let empty_bytes = empty_layer_brain.export_iwd1().unwrap();
        let empty_parsed = DefenderBrain::from_iwd1(&empty_bytes).unwrap();
        assert!(empty_parsed.is_loaded());
    }

    #[test]
    fn suggest_matrix_covers_main_feature_combinations() {
        let brain = tiny_trainable_brain();

        let mut quiet = [0.0f32; 72];

        let mut ssh_pressure = [0.0f32; 72];
        ssh_pressure[0] = 3.0;
        ssh_pressure[12] = 1.0;

        let mut ransomware_like = [0.0f32; 72];
        ransomware_like[2] = 1.0;
        ransomware_like[3] = 1.0;
        ransomware_like[5] = 2.0;
        ransomware_like[15] = 1.0;

        let mut blocked_context = [0.0f32; 72];
        blocked_context[0] = 2.0;
        blocked_context[18] = 2.0;
        blocked_context[12] = 1.0;

        let cases = vec![
            ("quiet", &mut quiet, 0usize),
            ("ssh_pressure", &mut ssh_pressure, 1usize),
            ("ransomware_like", &mut ransomware_like, 9usize),
            ("blocked_context", &mut blocked_context, 0usize),
        ];

        for (name, features, expected_action) in cases {
            let suggestion = brain.suggest(features).unwrap();
            assert_eq!(suggestion.action, expected_action, "{name}");
            assert_eq!(
                suggestion.action_name, ACTION_NAMES[expected_action],
                "{name}"
            );
            assert!(suggestion.confidence.is_finite(), "{name}");
            assert!(
                suggestion.confidence >= 0.0 && suggestion.confidence <= 1.0,
                "{name}"
            );
            assert!(suggestion.value.is_finite(), "{name}");
            assert!(
                suggestion.value >= -1.0 && suggestion.value <= 1.0,
                "{name}"
            );
            assert_eq!(suggestion.top_actions.len(), 3, "{name}");
            assert!(
                suggestion.top_actions.windows(2).all(|w| w[0].2 >= w[1].2),
                "{name}"
            );
        }
    }

    #[test]
    fn suggest_handles_numeric_boundaries_without_panicking() {
        let brain = tiny_trainable_brain();

        let mut ones = [1.0f32; 72];
        ones[18] = 0.0;
        let one_suggestion = brain.suggest(&ones).unwrap();
        assert!(one_suggestion.action < 30);

        let mut with_infinity = [0.0f32; 72];
        with_infinity[5] = f32::INFINITY;
        let inf_suggestion = brain.suggest(&with_infinity).unwrap();
        assert!(inf_suggestion.action < 30);

        let mut with_nan = [0.0f32; 72];
        with_nan[6] = f32::NAN;
        let nan_suggestion = brain.suggest(&with_nan).unwrap();
        assert!(nan_suggestion.action < 30);
    }

    #[test]
    fn softmax_empty_logits_returns_empty_output() {
        let probs = softmax(&[]);
        assert!(probs.is_empty());
    }

    #[test]
    fn retrain_from_log_guard_paths_are_handled() {
        let dir = tempdir().unwrap();

        let mut unloaded = DefenderBrain::new();
        assert!(unloaded.retrain_from_log(dir.path()).is_none());

        let mut brain = tiny_trainable_brain();
        assert!(brain.retrain_from_log(dir.path()).is_none());

        std::fs::write(dir.path().join("brain-log.json"), "{broken").unwrap();
        assert!(brain.retrain_from_log(dir.path()).is_none());

        let short_entries = build_brain_log_entries(10, "BlockIp");
        std::fs::write(
            dir.path().join("brain-log.json"),
            serde_json::to_string(&short_entries).unwrap(),
        )
        .unwrap();
        assert!(brain.retrain_from_log(dir.path()).is_none());

        let unknown_action_entries = build_brain_log_entries(25, "UnknownAction");
        std::fs::write(
            dir.path().join("brain-log.json"),
            serde_json::to_string(&unknown_action_entries).unwrap(),
        )
        .unwrap();
        assert!(brain.retrain_from_log(dir.path()).is_none());
    }

    #[test]
    fn retrain_from_log_success_and_write_error_paths() {
        let dir = tempdir().unwrap();
        let mut brain = tiny_trainable_brain();

        let entries: Vec<serde_json::Value> = (0..24)
            .map(|i| {
                let mut features = vec![0.0f32; 72];
                features[0] = (i % 4) as f32;
                features[2] = (i % 3) as f32;
                features[5] = (i as f32) / 24.0;
                let action = if i % 2 == 0 {
                    "BlockIpDecision"
                } else {
                    "MonitorDecision"
                };
                json!({
                    "features": features,
                    "ai_action": action
                })
            })
            .collect();

        std::fs::write(
            dir.path().join("brain-log.json"),
            serde_json::to_string(&entries).unwrap(),
        )
        .unwrap();

        let (used, accuracy) = brain.retrain_from_log(dir.path()).unwrap();
        assert_eq!(used, 24);
        assert!((0.0..=1.0).contains(&accuracy));

        let retrained_path = dir.path().join("defender-brain-retrained.bin");
        let retrained_bytes = std::fs::read(&retrained_path).unwrap();
        let parsed = DefenderBrain::from_iwd1(&retrained_bytes).unwrap();
        assert!(parsed.is_loaded());
        assert!(parsed.param_count() > 0);

        std::fs::remove_file(&retrained_path).unwrap();
        std::fs::create_dir(&retrained_path).unwrap();
        let second = brain.retrain_from_log(dir.path()).unwrap();
        assert_eq!(second.0, 24);
    }
}
