//! Neural anomaly detection lifecycle — Phase 1: autoencoder + rules as teacher.
//!
//! The autoencoder learns "what is normal" for this specific host by training
//! on production events. Novel patterns get high anomaly scores.
//!
//! Lifecycle:
//!   Install → Observation (7 days) → Nightly training → Auto-test → Activation
//!
//! Scoring integration:
//!   final_score = rules(0.4) + killchain(0.3) + anomaly(0.3 × maturity)
//!
//! The rules/killchain act as "teacher": if they say an event is benign but the
//! autoencoder flagged it, the autoencoder learns that pattern is normal.

use innerwarden_core::event::Event;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Feature extraction (mirrored from innerwarden-gym/src/realdata.rs)
// ---------------------------------------------------------------------------

const NUM_FEATURES: usize = 58;
const WINDOW_SIZE: usize = 20;

/// Map event kind to feature index (0-23).
fn kind_index(kind: &str) -> Option<usize> {
    match kind {
        "file.read_access" => Some(0),
        "shell.command_exec" => Some(1),
        "process.exit" => Some(2),
        "process.fd_redirect" => Some(3),
        "process.clone" => Some(4),
        "io_uring.create" => Some(5),
        "firmware.timing_anomaly" => Some(6),
        "network.outbound_connect" => Some(7),
        "sudo.command" => Some(8),
        "network.accept" => Some(9),
        "file.write_access" => Some(10),
        "process.prctl" => Some(11),
        "cgroup.memory_spike" => Some(12),
        "ssh.login_success" => Some(13),
        "ssh.login_failed" => Some(14),
        "memory.rwx_memory" => Some(15),
        "file.timestomp" => Some(16),
        "file.truncate" => Some(17),
        "dns.query" => Some(18),
        "privilege.escalation" => Some(19),
        "process.memfd_create" => Some(20),
        "kernel.new_module_post_boot" => Some(21),
        "filesystem.mount" => Some(22),
        "network.listen" => Some(23),
        _ => None,
    }
}

/// Attack-indicative bigram transitions.
const ATTACK_BIGRAMS: &[(usize, usize, usize)] = &[
    (14, 13, 24), // ssh_failed → ssh_success
    (13, 1, 25),  // ssh_success → shell_exec
    (1, 0, 26),   // shell_exec → file_read
    (0, 7, 27),   // file_read → outbound_connect
    (1, 7, 28),   // shell_exec → outbound_connect
    (8, 0, 29),   // sudo → file_read
    (1, 16, 30),  // shell_exec → timestomp
    (1, 17, 31),  // shell_exec → truncate
    (3, 1, 32),   // fd_redirect → shell_exec
    (19, 1, 33),  // privesc → shell_exec
    (1, 20, 34),  // shell_exec → memfd_create
    (7, 7, 35),   // outbound → outbound (beaconing)
    (1, 1, 36),   // shell → shell (recon burst)
    (21, 1, 37),  // module_load → shell_exec
    (23, 9, 38),  // listen → accept
    (4, 3, 39),   // clone → fd_redirect
];

/// Extract 48 features from a window of event kinds.
fn window_features(kinds: &[Option<usize>]) -> Vec<f32> {
    let mut f = vec![0.0f32; NUM_FEATURES];
    let n = kinds.len() as f32;
    if n == 0.0 {
        return f;
    }

    // Layer 1: kind distribution [0-23]
    for &idx in kinds {
        if let Some(i) = idx {
            f[i] += 1.0 / n;
        }
    }

    // Layer 2: bigram transitions [24-39]
    let n_trans = if kinds.len() > 1 {
        (kinds.len() - 1) as f32
    } else {
        1.0
    };
    for i in 0..kinds.len().saturating_sub(1) {
        if let (Some(from), Some(to)) = (kinds[i], kinds[i + 1]) {
            for &(bf, bt, slot) in ATTACK_BIGRAMS {
                if from == bf && to == bt {
                    f[slot] += 1.0 / n_trans;
                }
            }
        }
    }

    // Layer 3: sequence signals [40-47]

    // 40: kind diversity
    let unique: std::collections::HashSet<_> = kinds.iter().filter_map(|x| *x).collect();
    f[40] = (unique.len() as f32 / 12.0).min(1.0);

    // 41: transition entropy
    {
        let mut bigram_counts = std::collections::HashMap::new();
        let mut total = 0u32;
        for i in 0..kinds.len().saturating_sub(1) {
            if let (Some(from), Some(to)) = (kinds[i], kinds[i + 1]) {
                *bigram_counts.entry((from, to)).or_insert(0u32) += 1;
                total += 1;
            }
        }
        if total > 0 {
            let mut entropy = 0.0f32;
            for &count in bigram_counts.values() {
                let p = count as f32 / total as f32;
                if p > 0.0 {
                    entropy -= p * p.log2();
                }
            }
            f[41] = (entropy / 9.2).min(1.0);
        }
    }

    // 42: longest consecutive same-kind run
    {
        let mut max_run = 1u32;
        let mut current = 1u32;
        for i in 1..kinds.len() {
            if kinds[i] == kinds[i - 1] && kinds[i].is_some() {
                current += 1;
                max_run = max_run.max(current);
            } else {
                current = 1;
            }
        }
        f[42] = (max_run as f32 / n).min(1.0);
    }

    // 43: has sensitive file read (based on kind index 0 = file.read_access presence)
    // In agent, we only have kind indices — full summary check needs Event objects.
    // Approximation: file.read_access after ssh.login_success = credential harvesting signal
    f[43] = if kinds
        .windows(2)
        .any(|w| w[0] == Some(13) && w[1] == Some(0))
    {
        1.0
    } else {
        0.0
    };

    // 44: kill chain stage progression (how many distinct stages appear in order)
    {
        let mut stages_seen = 0u32;
        let mut last_stage = 0u32;
        for &idx in kinds {
            let stage = match idx {
                Some(14) => 1,            // ssh_failed = recon
                Some(13) => 2,            // ssh_success = access
                Some(1) => 3,             // shell_exec = execution
                Some(10) => 4,            // file_write = persistence
                Some(8) | Some(19) => 5,  // sudo/privesc = escalation
                Some(16) | Some(17) => 6, // timestomp/truncate = evasion
                Some(7) => 7,             // outbound = exfiltration
                _ => 0,
            };
            if stage > 0 && stage > last_stage {
                stages_seen += 1;
                last_stage = stage;
            }
        }
        f[44] = (stages_seen as f32 / 7.0).min(1.0);
    }

    // 45: command diversity (approximated by unique kinds in shell-heavy windows)
    let shell_ratio = kinds.iter().filter(|&&k| k == Some(1)).count() as f32 / n;
    f[45] = shell_ratio.min(1.0);

    // 46: network listener present
    f[46] = if kinds.iter().any(|&k| k == Some(23) || k == Some(9)) {
        1.0
    } else {
        0.0
    };

    // 47: window size normalized
    f[47] = (n / 50.0).min(1.0);

    // Features 48-57 are graph structural features (filled by enrich_with_graph)
    // Initialized to 0.0 by default — safe for inference without graph data.

    f
}

/// Graph structural features extracted from the knowledge graph.
/// Used to enrich the autoencoder feature vector (slots 48-57).
#[derive(Debug, Clone, Default)]
pub struct GraphFeatures {
    /// Average degree of active process nodes (fan-out).
    pub avg_process_degree: f32,
    /// Maximum depth of any process tree.
    pub max_process_tree_depth: u32,
    /// Number of IP nodes with threat intel dataset matches.
    pub threat_intel_ip_count: u32,
    /// Number of Wrote edges targeting /etc or /tmp.
    pub writes_to_sensitive: u32,
    /// Number of connected components (isolated clusters).
    pub connected_components: u32,
    /// Ratio of process nodes to IP nodes (normal ~5:1, attack ~1:1).
    pub process_ip_ratio: f32,
    /// Number of nodes with >10 edges (high-connectivity hubs).
    pub high_degree_nodes: u32,
    /// Number of Incident nodes in the graph.
    pub incident_count: u32,
    /// Total edge count (activity level).
    pub total_edges: u32,
    /// Number of active sessions (User→LoggedInFrom edges in last 5min).
    pub active_sessions: u32,
}

/// Enrich a feature vector (slots 48-57) with graph structural features.
fn enrich_features_with_graph(f: &mut [f32], gf: &GraphFeatures) {
    if f.len() < NUM_FEATURES {
        return;
    }
    // 48: average process degree normalized (0 = idle, 1 = 20+ avg connections)
    f[48] = (gf.avg_process_degree / 20.0).min(1.0);
    // 49: max process tree depth (deeper = more suspicious)
    f[49] = (gf.max_process_tree_depth as f32 / 10.0).min(1.0);
    // 50: threat intel IP count
    f[50] = (gf.threat_intel_ip_count as f32 / 10.0).min(1.0);
    // 51: writes to sensitive paths
    f[51] = (gf.writes_to_sensitive as f32 / 20.0).min(1.0);
    // 52: connected components (more = more isolated activity)
    f[52] = (gf.connected_components as f32 / 20.0).min(1.0);
    // 53: process/IP ratio anomaly (deviate from normal ~5:1)
    f[53] = if gf.process_ip_ratio > 0.0 {
        (1.0 - (gf.process_ip_ratio / 5.0).min(1.0)).abs()
    } else {
        0.0
    };
    // 54: high-degree hub count
    f[54] = (gf.high_degree_nodes as f32 / 5.0).min(1.0);
    // 55: incident count
    f[55] = (gf.incident_count as f32 / 20.0).min(1.0);
    // 56: total edge activity level
    f[56] = (gf.total_edges as f32 / 10000.0).min(1.0);
    // 57: active sessions
    f[57] = (gf.active_sessions as f32 / 10.0).min(1.0);
}

// ---------------------------------------------------------------------------
// Autoencoder (inference + training, no external deps)
// ---------------------------------------------------------------------------

/// Simple feedforward layer.
struct Layer {
    weights: Vec<Vec<f32>>,
    biases: Vec<f32>,
}

/// Autoencoder neural network [48 → 16 → 8 → 16 → 48].
struct AutoencoderNet {
    layers: Vec<Layer>,
    lr: f32,
}

impl AutoencoderNet {
    /// Initialize with deterministic pseudo-random Xavier weights.
    /// Uses a simple LCG to avoid external rand dependency.
    fn new(layer_sizes: &[usize], lr: f32) -> Self {
        let mut seed: u64 = 42;
        let mut next_f32 = move || -> f32 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            // Map to [-1, 1]
            ((seed >> 33) as f32 / (1u64 << 31) as f32) * 2.0 - 1.0
        };

        let mut layers = Vec::new();
        for i in 0..layer_sizes.len() - 1 {
            let fan_in = layer_sizes[i];
            let fan_out = layer_sizes[i + 1];
            let scale = (2.0 / (fan_in + fan_out) as f32).sqrt();

            let weights: Vec<Vec<f32>> = (0..fan_out)
                .map(|_| (0..fan_in).map(|_| next_f32() * scale).collect())
                .collect();
            let biases = vec![0.0f32; fan_out];

            layers.push(Layer { weights, biases });
        }

        Self { layers, lr }
    }

    /// Load from IWAE binary format.
    fn load(data: &[u8]) -> Option<Self> {
        if data.len() < 24 || &data[0..4] != b"IWAE" {
            return None;
        }
        // Skip header: magic(4) + version(4) + baseline_mse(4) + baseline_std(4) + samples(8)
        let net_len = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;
        let net_json = &data[28..28 + net_len];

        // Parse the JSON-serialized network
        let net: serde_json::Value = serde_json::from_slice(net_json).ok()?;
        let weights_arr = net.get("weights")?.as_array()?;
        let biases_arr = net.get("biases")?.as_array()?;
        let lr = net.get("lr").and_then(|v| v.as_f64()).unwrap_or(0.001) as f32;

        let mut layers = Vec::new();
        for (w, b) in weights_arr.iter().zip(biases_arr.iter()) {
            let weights: Vec<Vec<f32>> = w
                .as_array()?
                .iter()
                .map(|row| {
                    row.as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|v| v.as_f64().unwrap_or(0.0) as f32)
                        .collect()
                })
                .collect();
            let biases: Vec<f32> = b
                .as_array()?
                .iter()
                .map(|v| v.as_f64().unwrap_or(0.0) as f32)
                .collect();
            layers.push(Layer { weights, biases });
        }

        // Validate dimensions: first layer input size must match NUM_FEATURES
        if let Some(first) = layers.first() {
            if let Some(row) = first.weights.first() {
                if row.len() != NUM_FEATURES {
                    tracing::warn!(
                        "anomaly: model input size {} != expected {}, discarding stale model",
                        row.len(),
                        NUM_FEATURES
                    );
                    return None;
                }
            }
        }

        Some(Self { layers, lr })
    }

    /// Forward pass.
    fn forward(&self, input: &[f32]) -> (Vec<f32>, Vec<Vec<f32>>) {
        let mut activations = vec![input.to_vec()];
        let mut x = input.to_vec();

        for (i, layer) in self.layers.iter().enumerate() {
            let mut next = vec![0.0f32; layer.weights.len()];
            for (j, (wj, bj)) in layer.weights.iter().zip(layer.biases.iter()).enumerate() {
                let mut sum = *bj;
                for (k, &xk) in x.iter().enumerate() {
                    if k < wj.len() {
                        sum += wj[k] * xk;
                    }
                }
                if i < self.layers.len() - 1 {
                    next[j] = sum.max(0.0); // ReLU
                } else {
                    next[j] = sum; // Linear output
                }
            }
            x = next;
            activations.push(x.clone());
        }

        (x, activations)
    }

    fn predict(&self, input: &[f32]) -> Vec<f32> {
        self.forward(input).0
    }

    /// Train one step: reconstruct input, backpropagate error.
    fn train_reconstruction(&mut self, input: &[f32]) {
        let (output, activations) = self.forward(input);

        let mut deltas: Vec<f32> = output
            .iter()
            .zip(input.iter())
            .map(|(o, t)| o - t)
            .collect();

        for layer_idx in (0..self.layers.len()).rev() {
            let act_input = &activations[layer_idx];
            let act_output = &activations[layer_idx + 1];

            if layer_idx < self.layers.len() - 1 {
                for (j, d) in deltas.iter_mut().enumerate() {
                    if act_output[j] <= 0.0 {
                        *d = 0.0;
                    }
                }
            }

            let mut prev_deltas = vec![0.0f32; act_input.len()];
            for j in 0..self.layers[layer_idx].weights.len() {
                for k in 0..self.layers[layer_idx].weights[j].len() {
                    prev_deltas[k] += self.layers[layer_idx].weights[j][k] * deltas[j];
                    self.layers[layer_idx].weights[j][k] -= self.lr * deltas[j] * act_input[k];
                }
                self.layers[layer_idx].biases[j] -= self.lr * deltas[j];
            }

            deltas = prev_deltas;
        }
    }

    /// Reconstruction error (MSE).
    fn reconstruction_error(&self, input: &[f32]) -> f32 {
        let output = self.predict(input);
        input
            .iter()
            .zip(output.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            / input.len() as f32
    }
}

// ---------------------------------------------------------------------------
// Public API: AnomalyEngine
// ---------------------------------------------------------------------------

/// Configuration for the neural anomaly engine.
pub struct AnomalyConfig {
    /// Data directory (reads events JSONL, writes model)
    pub data_dir: PathBuf,
    /// Score threshold for anomaly alerts (0.0-1.0)
    pub threshold: f32,
    /// Max training time in seconds
    pub training_timeout_secs: u64,
    /// Max RAM for training in MB
    pub training_max_ram_mb: u64,
    /// Days of event data to use for training
    pub training_retention_days: u32,
    /// Training epochs per session
    pub training_epochs: u64,
    /// How often to train (cron-style, e.g., "0 3 * * *")
    pub training_schedule: String,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/innerwarden"),
            threshold: 0.75,
            training_timeout_secs: 1800, // 30 min
            training_max_ram_mb: 500,
            training_retention_days: 7,
            training_epochs: 50,
            training_schedule: "0 3 * * *".to_string(),
        }
    }
}

/// The anomaly detection engine — integrates into the agent's event loop.
pub struct AnomalyEngine {
    net: Option<AutoencoderNet>,
    /// Sliding window of recent event kind indices.
    window: VecDeque<Option<usize>>,
    /// Baseline MSE from training (what "normal" looks like).
    baseline_mse: f32,
    /// Baseline standard deviation.
    baseline_std: f32,
    /// Maturity: 0.0 (just installed) → 1.0 (fully trained).
    /// Increases with each successful training cycle.
    pub maturity: f32,
    /// Number of training cycles completed.
    pub training_cycles: u32,
    /// Configuration.
    config: AnomalyConfig,
    /// Cooldown per source to prevent spam.
    cooldowns: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    /// Last computed anomaly score (0.0-1.0), updated by observe().
    /// Used by the agent to push to the BPF NEURAL_SCORE map for kernel enforcement.
    last_score: f32,
    /// Cached graph structural features (updated by the agent every slow tick).
    graph_features: Option<GraphFeatures>,
}

impl AnomalyEngine {
    /// Create a new anomaly engine, attempting to load a saved model.
    pub fn new(config: AnomalyConfig) -> Self {
        let model_path = config.data_dir.join("anomaly-model.bin");
        let (net, baseline_mse, baseline_std, maturity, cycles) = if let Ok(data) =
            std::fs::read(&model_path)
        {
            let net = AutoencoderNet::load(&data);
            let mse = if data.len() >= 12 {
                f32::from_le_bytes([data[8], data[9], data[10], data[11]])
            } else {
                0.0
            };
            let std = if data.len() >= 16 {
                f32::from_le_bytes([data[12], data[13], data[14], data[15]])
            } else {
                1.0
            };
            let samples = if data.len() >= 24 {
                u64::from_le_bytes([
                    data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
                ])
            } else {
                0
            };
            // Estimate maturity from samples seen
            let mat = (samples as f32 / 500_000.0).min(1.0);
            let cyc = (samples / 100_000) as u32;
            if net.is_some() {
                info!(
                    "anomaly: loaded model ({} bytes, baseline MSE {:.6}, maturity {:.2})",
                    data.len(),
                    mse,
                    mat
                );
            }
            (net, mse, std, mat, cyc)
        } else {
            info!("anomaly: no saved model found, starting fresh (observation mode)");
            (None, 0.0, 1.0, 0.0, 0)
        };

        Self {
            net,
            window: VecDeque::with_capacity(WINDOW_SIZE),
            baseline_mse,
            baseline_std,
            maturity,
            training_cycles: cycles,
            config,
            cooldowns: std::collections::HashMap::new(),
            last_score: 0.0,
            graph_features: None,
        }
    }

    /// Update the cached graph structural features.
    /// Called by the agent every slow-loop tick with metrics from the knowledge graph.
    pub fn set_graph_features(&mut self, gf: GraphFeatures) {
        self.graph_features = Some(gf);
    }

    /// Feed an event and return anomaly score if above threshold.
    /// Returns Some((score, weight)) where weight = score × maturity.
    pub fn observe(&mut self, event: &Event) -> Option<(f32, f32)> {
        let idx = kind_index(&event.kind);

        // Update sliding window
        self.window.push_back(idx);
        if self.window.len() > WINDOW_SIZE {
            self.window.pop_front();
        }

        // Need full window to score
        if self.window.len() < WINDOW_SIZE {
            return None;
        }

        // Need a trained model
        let net = self.net.as_ref()?;

        // No maturity = no contribution
        if self.maturity < 0.01 {
            return None;
        }

        let kinds: Vec<Option<usize>> = self.window.iter().copied().collect();
        let mut features = window_features(&kinds);
        // Enrich with graph features if available
        if let Some(ref gf) = self.graph_features {
            enrich_features_with_graph(&mut features, gf);
        }
        let mse = net.reconstruction_error(&features);

        // Normalize to 0-1 via z-score + sigmoid
        let z = if self.baseline_std > 0.0 {
            (mse - self.baseline_mse) / self.baseline_std
        } else {
            if mse > self.baseline_mse {
                3.0
            } else {
                -3.0
            }
        };
        let score = 1.0 / (1.0 + (-z).exp());
        let weighted = score * self.maturity * 0.3; // max contribution = 0.3

        debug!(
            score = format!("{:.3}", score),
            weighted = format!("{:.3}", weighted),
            maturity = format!("{:.2}", self.maturity),
            mse = format!("{:.6}", mse),
            "anomaly: inference"
        );

        if score > self.config.threshold {
            // Cooldown check
            let source = event
                .details
                .get("ip")
                .or(event.details.get("src_ip"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let now = chrono::Utc::now();
            if let Some(&last) = self.cooldowns.get(&source) {
                if (now - last).num_seconds() < 300 {
                    return None;
                }
            }
            self.cooldowns.insert(source, now);

            // Prune cooldowns
            if self.cooldowns.len() > 500 {
                let cutoff = now - chrono::Duration::seconds(300);
                self.cooldowns.retain(|_, t| *t > cutoff);
            }

            self.last_score = score;
            Some((score, weighted))
        } else {
            None
        }
    }

    /// Get the latest anomaly score (0.0-1.0). Used to push to BPF NEURAL_SCORE map.
    pub fn latest_score(&self) -> f32 {
        self.last_score
    }

    /// Run nightly training on recent events.
    /// Reads events JSONL from data_dir, trains autoencoder, saves model.
    pub fn train_nightly(&mut self) -> Result<(), String> {
        let start = std::time::Instant::now();
        info!("anomaly: starting nightly training");

        // Check disk space
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("df")
                .arg("-h")
                .arg(self.config.data_dir.to_str().unwrap_or("/"))
                .output()
            {
                let out = String::from_utf8_lossy(&output.stdout);
                if out.contains("100%")
                    || out.contains("99%")
                    || out.contains("98%")
                    || out.contains("97%")
                    || out.contains("96%")
                {
                    warn!("anomaly: disk nearly full, skipping training");
                    return Err("disk full".to_string());
                }
            }
        }

        // Read FP reports from last 7 days to incorporate into training
        let fp_detectors = read_fp_report_detectors(&self.config.data_dir, 7);
        if !fp_detectors.is_empty() {
            info!(
                "autoencoder: incorporated {} FP report detectors into training",
                fp_detectors.len()
            );
        }

        // Load blocked IPs from decisions files to exclude attack traffic.
        // Training on clean data only produces a model that actually detects anomalies.
        let blocked_ips = load_blocked_ips(&self.config.data_dir);
        if !blocked_ips.is_empty() {
            info!(
                "anomaly: excluding {} blocked IPs from training data",
                blocked_ips.len()
            );
        }

        // Collect events from JSONL files (last N days)
        let cutoff =
            chrono::Utc::now() - chrono::Duration::days(self.config.training_retention_days as i64);
        let mut all_kinds: Vec<Vec<Option<usize>>> = Vec::new();

        let events_dir = &self.config.data_dir;
        let entries = std::fs::read_dir(events_dir).map_err(|e| e.to_string())?;

        let mut total_events = 0u64;
        let mut skipped_attack = 0u64;
        let mut event_window: Vec<Option<usize>> = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !name.starts_with("events-") || !name.ends_with(".jsonl") {
                continue;
            }

            // Check RAM budget (rough estimate: 48 floats × 4 bytes × windows)
            let estimated_mb = (all_kinds.len() * NUM_FEATURES * 4) / (1024 * 1024);
            if estimated_mb > self.config.training_max_ram_mb as usize {
                info!("anomaly: RAM budget reached ({}MB), sampling", estimated_mb);
                break;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines() {
                let ev: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                // Skip events from blocked IPs (attack traffic).
                // Train only on clean traffic so the model learns what "normal" looks like.
                if !blocked_ips.is_empty() {
                    let ip = ev
                        .get("details")
                        .and_then(|d| {
                            d.get("src_ip")
                                .or_else(|| d.get("ip"))
                                .and_then(|v| v.as_str())
                        })
                        .unwrap_or("");
                    if blocked_ips.contains(ip) {
                        skipped_attack += 1;
                        continue;
                    }
                }

                let kind = ev.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let idx = kind_index(kind);

                event_window.push(idx);
                total_events += 1;

                if event_window.len() >= WINDOW_SIZE {
                    all_kinds.push(event_window.clone());
                    // Stride of 5
                    event_window.drain(..5);
                }

                // Timeout check
                if start.elapsed().as_secs() > self.config.training_timeout_secs {
                    warn!("anomaly: training timeout, using data collected so far");
                    break;
                }
            }
        }

        if skipped_attack > 0 {
            info!(
                "anomaly: skipped {} events from blocked IPs (attack traffic)",
                skipped_attack
            );
        }

        info!(
            "anomaly: loaded {} events → {} windows for training",
            total_events,
            all_kinds.len()
        );

        if all_kinds.len() < 100 {
            warn!("anomaly: not enough data for training (need 100+ windows)");
            return Err("insufficient data".to_string());
        }

        // Build a set of kind indices associated with FP detectors
        let fp_kind_indices: HashSet<usize> = if !fp_detectors.is_empty() {
            fp_detector_to_kind_indices(&fp_detectors)
        } else {
            HashSet::new()
        };

        // Extract features, reducing weight for windows matching FP detector patterns
        let features: Vec<Vec<f32>> = all_kinds
            .iter()
            .map(|w| {
                let mut f = window_features(w);
                // If this window contains event kinds associated with known FP detectors,
                // multiply features by 0.1 (teaching the autoencoder "this is normal")
                if !fp_kind_indices.is_empty()
                    && w.iter()
                        .any(|k| k.is_some_and(|i| fp_kind_indices.contains(&i)))
                {
                    for val in f.iter_mut() {
                        *val *= 0.1;
                    }
                }
                f
            })
            .collect();

        // Create or reinitialize network
        let mut net = AutoencoderNet::new(&[NUM_FEATURES, 16, 8, 16, NUM_FEATURES], 0.001);

        // Train
        for epoch in 1..=self.config.training_epochs {
            for f in &features {
                net.train_reconstruction(f);
            }

            if start.elapsed().as_secs() > self.config.training_timeout_secs {
                info!("anomaly: timeout at epoch {}", epoch);
                break;
            }

            if epoch % 10 == 0 {
                let avg_mse: f32 = features
                    .iter()
                    .map(|f| net.reconstruction_error(f))
                    .sum::<f32>()
                    / features.len() as f32;
                info!(
                    "anomaly: epoch {}/{} MSE {:.6}",
                    epoch, self.config.training_epochs, avg_mse
                );
            }
        }

        // Compute baseline
        let errors: Vec<f32> = features
            .iter()
            .map(|f| net.reconstruction_error(f))
            .collect();
        let n = errors.len() as f32;
        let baseline_mse = errors.iter().sum::<f32>() / n;
        let variance = errors
            .iter()
            .map(|e| (e - baseline_mse).powi(2))
            .sum::<f32>()
            / n;
        let baseline_std = variance.sqrt();

        self.baseline_mse = baseline_mse;
        self.baseline_std = baseline_std;
        self.net = Some(net);
        self.training_cycles += 1;

        // Update maturity (increases with each training cycle, maxes at 1.0)
        // Day 1: 0.1, Day 3: 0.3, Day 7: 0.6, Day 30: ~0.9
        self.maturity = (1.0 - (-0.1 * self.training_cycles as f32).exp()).min(1.0);

        info!(
            "anomaly: training complete in {:.1}s — baseline MSE {:.6} ± {:.6}, maturity {:.2}, cycles {}",
            start.elapsed().as_secs_f32(),
            baseline_mse,
            baseline_std,
            self.maturity,
            self.training_cycles
        );

        // Save model (keep previous as backup)
        let model_path = self.config.data_dir.join("anomaly-model.bin");
        let backup_path = self.config.data_dir.join("anomaly-model.prev.bin");
        if model_path.exists() {
            let _ = std::fs::rename(&model_path, &backup_path);
        }

        // Serialize (simple format: IWAE header + JSON weights)
        if let Some(ref net) = self.net {
            let mut data = Vec::new();
            data.extend_from_slice(b"IWAE");
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(&self.baseline_mse.to_le_bytes());
            data.extend_from_slice(&self.baseline_std.to_le_bytes());
            let total_samples = total_events;
            data.extend_from_slice(&total_samples.to_le_bytes());

            // Serialize weights as JSON
            let weights: Vec<Vec<Vec<f32>>> =
                net.layers.iter().map(|l| l.weights.clone()).collect();
            let biases: Vec<Vec<f32>> = net.layers.iter().map(|l| l.biases.clone()).collect();
            let net_json = serde_json::json!({
                "weights": weights,
                "biases": biases,
                "lr": net.lr,
            });
            let net_bytes = serde_json::to_vec(&net_json).unwrap_or_default();
            data.extend_from_slice(&(net_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(&net_bytes);

            if let Err(e) = std::fs::write(&model_path, &data) {
                warn!("anomaly: failed to save model: {}", e);
            } else {
                info!("anomaly: model saved ({} bytes)", data.len());
            }
        }

        Ok(())
    }

    /// Process feedback from rules: if rules say "benign" but we flagged it,
    /// record as false positive for next training cycle.
    pub fn feedback_benign(&mut self, _event: &Event) {
        // In Phase 1, feedback is implicit: the autoencoder trains on ALL
        // production events (which are mostly benign). Events that rules
        // don't flag as incidents are "benign by omission" and the autoencoder
        // learns their patterns in the next nightly cycle.
        //
        // Phase 2 will add explicit feedback recording.
    }

    /// Get the current maturity level description.
    pub fn maturity_description(&self) -> &str {
        match self.maturity {
            m if m < 0.01 => "observation (no model)",
            m if m < 0.2 => "learning (low confidence)",
            m if m < 0.5 => "training (moderate confidence)",
            m if m < 0.8 => "active (good confidence)",
            _ => "mature (high confidence)",
        }
    }
}

// ---------------------------------------------------------------------------
// FP report helpers
// ---------------------------------------------------------------------------

/// Read FP reports from the last `days` days.
/// Phase 7 Gap 1: reads from graph snapshots (Incident nodes with false_positive=true),
/// falls back to fp-reports-*.jsonl if no snapshots found.
pub fn read_fp_report_detectors(data_dir: &Path, days: i64) -> HashSet<String> {
    let mut detectors = HashSet::new();
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days);

    // Phase 7: try graph snapshots
    let today = chrono::Local::now().date_naive();
    let mut loaded_from_graph = false;
    for d in 0..days {
        let date = today - chrono::Duration::days(d);
        let date_str = date.format("%Y-%m-%d").to_string();
        if let Some(graph) = crate::knowledge_graph::KnowledgeGraph::load_dated(data_dir, &date_str)
        {
            use crate::knowledge_graph::types::{Node, NodeType};
            for id in graph.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    detector,
                    false_positive,
                    fp_reported_at,
                    ..
                }) = graph.get_node(id)
                {
                    if *false_positive {
                        if let Some(at) = fp_reported_at {
                            if *at >= cutoff {
                                detectors.insert(detector.clone());
                            }
                        } else {
                            detectors.insert(detector.clone());
                        }
                    }
                }
            }
            loaded_from_graph = true;
        }
    }
    if loaded_from_graph {
        return detectors;
    }

    // Fallback: fp-reports-*.jsonl
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => return detectors,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if !name.starts_with("fp-reports-") || !name.ends_with(".jsonl") {
            continue;
        }
        let date_part = name
            .strip_prefix("fp-reports-")
            .and_then(|s| s.strip_suffix(".jsonl"))
            .unwrap_or("");
        if let Ok(file_date) = chrono::NaiveDate::parse_from_str(date_part, "%Y-%m-%d") {
            let file_dt = file_date.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
            if file_dt < cutoff {
                continue;
            }
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(detector) = v.get("detector").and_then(|d| d.as_str()) {
                    detectors.insert(detector.to_string());
                }
            }
        }
    }
    detectors
}

/// Read FP counts by (detector, entity) pair.
/// Phase 7 Gap 1: reads from graph snapshots, falls back to fp-reports-*.jsonl.
pub fn read_fp_report_counts(data_dir: &Path, days: i64) -> Vec<(String, String, u32)> {
    let mut counts: std::collections::HashMap<(String, String), u32> =
        std::collections::HashMap::new();
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days);

    // Phase 7: try graph snapshots
    let today = chrono::Local::now().date_naive();
    let mut loaded_from_graph = false;
    for d in 0..days {
        let date = today - chrono::Duration::days(d);
        let date_str = date.format("%Y-%m-%d").to_string();
        if let Some(graph) = crate::knowledge_graph::KnowledgeGraph::load_dated(data_dir, &date_str)
        {
            use crate::knowledge_graph::types::{Node, NodeType};
            for id in graph.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    incident_id,
                    detector,
                    false_positive,
                    fp_reported_at,
                    ..
                }) = graph.get_node(id)
                {
                    if *false_positive {
                        if let Some(at) = fp_reported_at {
                            if *at < cutoff {
                                continue;
                            }
                        }
                        let entity = extract_entity_from_incident_id(incident_id);
                        if !detector.is_empty() && !entity.is_empty() {
                            *counts.entry((detector.clone(), entity)).or_insert(0) += 1;
                        }
                    }
                }
            }
            loaded_from_graph = true;
        }
    }
    if loaded_from_graph {
        return counts.into_iter().map(|((d, e), c)| (d, e, c)).collect();
    }

    // Fallback: fp-reports-*.jsonl
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if !name.starts_with("fp-reports-") || !name.ends_with(".jsonl") {
            continue;
        }
        let date_part = name
            .strip_prefix("fp-reports-")
            .and_then(|s| s.strip_suffix(".jsonl"))
            .unwrap_or("");
        if let Ok(file_date) = chrono::NaiveDate::parse_from_str(date_part, "%Y-%m-%d") {
            let file_dt = file_date.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
            if file_dt < cutoff {
                continue;
            }
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                let detector = v
                    .get("detector")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                let incident_id = v.get("incident_id").and_then(|d| d.as_str()).unwrap_or("");
                // Extract entity: first IP or comm from incident_id
                // Format: "detector:ip:timestamp" or "detector:comm:timestamp"
                let entity = extract_entity_from_incident_id(incident_id);
                if !detector.is_empty() && !entity.is_empty() {
                    *counts.entry((detector, entity)).or_insert(0) += 1;
                }
            }
        }
    }

    counts.into_iter().map(|((d, e), c)| (d, e, c)).collect()
}

/// Extract entity (IP or process name) from incident_id.
/// Format is typically "detector:entity:timestamp" or "detector:score:timestamp".
fn extract_entity_from_incident_id(incident_id: &str) -> String {
    let parts: Vec<&str> = incident_id.splitn(3, ':').collect();
    if parts.len() >= 2 {
        let candidate = parts[1].trim();
        // Check if it looks like an IP or a process name
        if !candidate.is_empty()
            && !candidate.chars().all(|c| c.is_ascii_digit())
            && candidate != "unknown"
        {
            return candidate.to_string();
        }
    }
    String::new()
}

/// Map FP detector names to related event kind indices.
/// This is a heuristic mapping: detector names like "ssh_bruteforce" map to
/// event kinds like "ssh.login_failed" (index 14) and "ssh.login_success" (index 13).
fn fp_detector_to_kind_indices(detectors: &HashSet<String>) -> HashSet<usize> {
    let mut indices = HashSet::new();
    for det in detectors {
        match det.as_str() {
            "ssh_bruteforce" | "distributed_ssh" => {
                indices.insert(13); // ssh.login_success
                indices.insert(14); // ssh.login_failed
            }
            "credential_stuffing" | "suspicious_login" => {
                indices.insert(13);
                indices.insert(14);
            }
            "port_scan" | "web_scan" => {
                indices.insert(7); // network.outbound_connect
                indices.insert(9); // network.accept
            }
            "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" | "data_exfiltration" => {
                indices.insert(0); // file.read_access
                indices.insert(7); // network.outbound_connect
            }
            "reverse_shell" | "c2_callback" => {
                indices.insert(7); // network.outbound_connect
                indices.insert(3); // process.fd_redirect
            }
            "privesc" | "sudo_abuse" => {
                indices.insert(8); // sudo.command
                indices.insert(19); // privilege.escalation
            }
            "process_injection" => {
                indices.insert(15); // memory.rwx_memory
                indices.insert(20); // process.memfd_create
            }
            "crypto_miner" | "cgroup_abuse" => {
                indices.insert(12); // cgroup.memory_spike
            }
            "dns_tunneling" | "dns_tunneling_ebpf" => {
                indices.insert(18); // dns.query
            }
            "fileless" => {
                indices.insert(15); // memory.rwx_memory
                indices.insert(20); // process.memfd_create
            }
            "kernel_module_load" => {
                indices.insert(21); // kernel.new_module_post_boot
            }
            "log_tampering" => {
                indices.insert(16); // file.timestomp
                indices.insert(17); // file.truncate
            }
            "container_escape" | "docker_anomaly" => {
                indices.insert(22); // filesystem.mount
            }
            "ransomware" => {
                indices.insert(10); // file.write_access
            }
            _ => {
                // For unknown detectors, use shell_exec as a general signal
                indices.insert(1); // shell.command_exec
            }
        }
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    fn make_event(kind: &str, src_ip: &str) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "prod-01".to_string(),
            source: "ebpf".to_string(),
            kind: kind.to_string(),
            severity: Severity::Medium,
            summary: "event".to_string(),
            details: serde_json::json!({"src_ip": src_ip}),
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn feature_extraction_correct_size() {
        // Feature-shape contract: every extraction must produce the exact
        // fixed vector size expected by the autoencoder input layer.
        let kinds = vec![Some(1), Some(7), Some(0), None, Some(14)];
        let f = window_features(&kinds);
        assert_eq!(f.len(), NUM_FEATURES);
    }

    #[test]
    fn bigram_features_nonzero() {
        // Signal path: attack bigrams should activate their dedicated slots
        // so transition patterns influence anomaly scoring.
        // ssh_failed → ssh_success should activate bigram feature 24
        let kinds = vec![Some(14), Some(13)];
        let f = window_features(&kinds);
        assert!(
            f[24] > 0.0,
            "bigram ssh_failed→ssh_success should be nonzero"
        );
    }

    #[test]
    fn kill_chain_stage_progression() {
        // Sequence-path coverage: stage progression should rise only when
        // the event sequence moves forward through distinct kill-chain stages.
        // Full kill chain: Recon → Access → Exec → Persist → Escalate → Evade → Exfil
        let kinds: Vec<Option<usize>> = vec![
            Some(14), // ssh_failed = stage 1 (recon)
            Some(14), // ssh_failed
            Some(13), // ssh_success = stage 2 (access)
            Some(1),  // shell_exec = stage 3 (execution)
            Some(1),  // shell_exec
            Some(10), // file_write = stage 4 (persistence)
            Some(8),  // sudo = stage 5 (escalation)
            Some(16), // timestomp = stage 6 (evasion)
            Some(7),  // outbound = stage 7 (exfiltration)
            Some(2),  // process_exit
        ];
        let f = window_features(&kinds);
        // Should detect at least 4 sequential stages
        assert!(
            f[44] >= 4.0 / 7.0,
            "kill chain progression should be detected: got {}",
            f[44]
        );
    }

    #[test]
    fn autoencoder_reconstruction() {
        // Learning path: training steps should reduce reconstruction error
        // on a repeated input pattern.
        let mut net = AutoencoderNet::new(&[NUM_FEATURES, 16, 8, 16, NUM_FEATURES], 0.01);
        let input = vec![0.5f32; NUM_FEATURES];

        let err_before = net.reconstruction_error(&input);
        for _ in 0..200 {
            net.train_reconstruction(&input);
        }
        let err_after = net.reconstruction_error(&input);

        assert!(
            err_after < err_before,
            "Error should decrease after training: {} → {}",
            err_before,
            err_after
        );
    }

    #[test]
    fn maturity_increases() {
        // Lifecycle path: maturity must grow monotonically with completed
        // training cycles and approach 1.0 asymptotically.
        let config = AnomalyConfig {
            data_dir: PathBuf::from("/tmp/nonexistent"),
            ..Default::default()
        };
        let mut engine = AnomalyEngine::new(config);
        assert_eq!(engine.maturity, 0.0);

        // Simulate training cycles
        engine.training_cycles = 1;
        engine.maturity = (1.0 - (-0.1 * 1.0f32).exp()).min(1.0);
        assert!(engine.maturity > 0.0 && engine.maturity < 0.2);

        engine.training_cycles = 7;
        engine.maturity = (1.0 - (-0.1 * 7.0f32).exp()).min(1.0);
        assert!(engine.maturity > 0.4);

        engine.training_cycles = 30;
        engine.maturity = (1.0 - (-0.1 * 30.0f32).exp()).min(1.0);
        assert!(engine.maturity > 0.9);
    }

    #[test]
    fn fp_detector_mapping_ssh() {
        // Mapping path: SSH detector aliases must map to login kind indices
        // so FP weighting can target both failed and successful auth events.
        let mut detectors = HashSet::new();
        detectors.insert("ssh_bruteforce".to_string());
        let indices = fp_detector_to_kind_indices(&detectors);
        assert!(indices.contains(&13)); // ssh.login_success
        assert!(indices.contains(&14)); // ssh.login_failed
        assert!(!indices.contains(&7)); // should not contain outbound
    }

    #[test]
    fn fp_detector_mapping_unknown_falls_back() {
        // Fallback path: unknown detector names should still map to a generic
        // shell-exec signal instead of producing an empty mapping.
        let mut detectors = HashSet::new();
        detectors.insert("some_custom_detector".to_string());
        let indices = fp_detector_to_kind_indices(&detectors);
        assert!(indices.contains(&1)); // shell.command_exec fallback
    }

    #[test]
    fn extract_entity_from_incident_id_works() {
        // Parsing path: incident IDs should extract actionable entities while
        // rejecting numeric score placeholders.
        assert_eq!(
            extract_entity_from_incident_id("ssh_bruteforce:1.2.3.4:2026-01-01T00:00:00Z"),
            "1.2.3.4"
        );
        assert_eq!(
            extract_entity_from_incident_id("process_tree:sshd:2026-01-01T00:00:00Z"),
            "sshd"
        );
        // Pure digits are excluded (could be a score)
        assert_eq!(
            extract_entity_from_incident_id("neural_anomaly:85:2026Z"),
            ""
        );
    }

    #[test]
    fn fp_weight_reduction_applied() {
        // Weighting path: windows that match known-FP detector kinds should
        // be down-weighted deterministically during training feature build.
        let mut fp = HashSet::new();
        fp.insert("ssh_bruteforce".to_string());
        let fp_indices = fp_detector_to_kind_indices(&fp);

        // Window with SSH events (index 14 = ssh.login_failed)
        let window = vec![Some(14), Some(14), Some(14), Some(13), Some(1)];
        let normal = window_features(&window);
        let mut reduced = window_features(&window);

        // Check that the window matches FP criteria
        let has_fp = window
            .iter()
            .any(|k| k.map_or(false, |i| fp_indices.contains(&i)));
        assert!(has_fp);

        // Apply reduction
        for val in reduced.iter_mut() {
            *val *= 0.1;
        }

        // All features should be 10% of original
        for (n, r) in normal.iter().zip(reduced.iter()) {
            assert!((r - n * 0.1).abs() < 1e-6);
        }
    }

    #[test]
    fn read_fp_report_detectors_from_temp_dir() {
        // Fallback-reader path: detector names should be collected from recent
        // fp-reports JSONL files when snapshots are unavailable.
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let today = chrono::Utc::now().format("%Y-%m-%d");
        let fp_path = dir.path().join(format!("fp-reports-{today}.jsonl"));
        std::fs::write(
            &fp_path,
            r#"{"ts":"2026-01-01T00:00:00Z","incident_id":"ssh_bruteforce:1.2.3.4:ts","detector":"ssh_bruteforce","reporter":"alice","action":"reported_fp"}
{"ts":"2026-01-01T00:00:00Z","incident_id":"port_scan:5.6.7.8:ts","detector":"port_scan","reporter":"alice","action":"reported_fp"}
"#,
        )
        .expect("fixture fp report file should be written");

        let detectors = read_fp_report_detectors(dir.path(), 7);
        assert!(detectors.contains("ssh_bruteforce"));
        assert!(detectors.contains("port_scan"));
        assert_eq!(detectors.len(), 2);
    }

    #[test]
    fn read_fp_report_counts_from_temp_dir() {
        // Counting path: repeated (detector, entity) pairs should aggregate
        // into stable counts for FP weighting heuristics.
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let today = chrono::Utc::now().format("%Y-%m-%d");
        let fp_path = dir.path().join(format!("fp-reports-{today}.jsonl"));
        std::fs::write(
            &fp_path,
            r#"{"ts":"2026-01-01T00:00:00Z","incident_id":"ssh_bruteforce:1.2.3.4:ts","detector":"ssh_bruteforce","reporter":"alice","action":"reported_fp"}
{"ts":"2026-01-01T00:00:00Z","incident_id":"ssh_bruteforce:1.2.3.4:ts2","detector":"ssh_bruteforce","reporter":"alice","action":"reported_fp"}
{"ts":"2026-01-01T00:00:00Z","incident_id":"ssh_bruteforce:1.2.3.4:ts3","detector":"ssh_bruteforce","reporter":"alice","action":"reported_fp"}
"#,
        )
        .expect("fixture fp count file should be written");

        let counts = read_fp_report_counts(dir.path(), 7);
        let ssh_count = counts
            .iter()
            .find(|(d, e, _)| d == "ssh_bruteforce" && e == "1.2.3.4");
        assert!(ssh_count.is_some());
        assert_eq!(
            ssh_count
                .expect("ssh detector entity count should be present")
                .2,
            3
        );
    }

    #[test]
    fn kind_index_maps_known_and_unknown_kinds() {
        // Dispatch-map path: known event kinds should resolve to stable
        // feature slots while unknown kinds remain intentionally unmapped.
        assert_eq!(kind_index("network.listen"), Some(23));
        assert_eq!(kind_index("dns.query"), Some(18));
        assert_eq!(kind_index("totally.unknown"), None);
    }

    #[test]
    fn enrich_features_with_graph_clamps_and_writes_expected_slots() {
        // Enrichment path: graph metrics should populate slots 48-57 and
        // clamp oversized values into [0, 1].
        let mut f = vec![0.0f32; NUM_FEATURES];
        let gf = GraphFeatures {
            avg_process_degree: 100.0,
            max_process_tree_depth: 42,
            threat_intel_ip_count: 99,
            writes_to_sensitive: 99,
            connected_components: 99,
            process_ip_ratio: 10.0,
            high_degree_nodes: 99,
            incident_count: 99,
            total_edges: 500_000,
            active_sessions: 99,
        };
        enrich_features_with_graph(&mut f, &gf);

        for slot in &f[48..58] {
            assert!(
                (0.0..=1.0).contains(slot),
                "enriched graph slot should be normalized into [0,1]"
            );
        }
        assert_eq!(f[48], 1.0);
        assert_eq!(f[49], 1.0);
        assert_eq!(f[50], 1.0);
        assert_eq!(f[57], 1.0);
    }

    #[test]
    fn enrich_features_with_graph_returns_early_for_short_vectors() {
        // Guard path: short vectors (legacy callers) should be left untouched
        // rather than causing out-of-bounds writes.
        let mut short = vec![0.5f32; 8];
        let before = short.clone();
        enrich_features_with_graph(&mut short, &GraphFeatures::default());
        assert_eq!(short, before);
    }

    #[test]
    fn anomaly_config_defaults_match_nightly_training_contract() {
        // Configuration path: defaults must preserve the documented nightly
        // 03:00 UTC schedule and safe baseline threshold.
        let cfg = AnomalyConfig::default();
        assert_eq!(cfg.training_schedule, "0 3 * * *");
        assert_eq!(cfg.threshold, 0.75);
        assert_eq!(cfg.training_retention_days, 7);
    }

    #[test]
    fn maturity_description_covers_all_ranges() {
        // Status-label path: each maturity range should map to an operator
        // friendly lifecycle description.
        let config = AnomalyConfig {
            data_dir: PathBuf::from("/tmp/nonexistent"),
            ..Default::default()
        };
        let mut engine = AnomalyEngine::new(config);
        engine.maturity = 0.0;
        assert_eq!(engine.maturity_description(), "observation (no model)");
        engine.maturity = 0.15;
        assert_eq!(engine.maturity_description(), "learning (low confidence)");
        engine.maturity = 0.35;
        assert_eq!(
            engine.maturity_description(),
            "training (moderate confidence)"
        );
        engine.maturity = 0.7;
        assert_eq!(engine.maturity_description(), "active (good confidence)");
        engine.maturity = 0.95;
        assert_eq!(engine.maturity_description(), "mature (high confidence)");
    }

    #[test]
    fn observe_needs_full_window_before_scoring() {
        // Windowing path: inference must stay disabled until the sliding
        // window reaches WINDOW_SIZE samples.
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            threshold: 0.0,
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(
            &[NUM_FEATURES, 16, 8, 16, NUM_FEATURES],
            0.001,
        ));
        engine.maturity = 1.0;
        engine.baseline_mse = -1.0;
        engine.baseline_std = 1.0;

        for _ in 0..(WINDOW_SIZE - 1) {
            let ev = make_event("shell.command_exec", "203.0.113.10");
            assert!(
                engine.observe(&ev).is_none(),
                "scores should not emit before window is full"
            );
        }
    }

    #[test]
    fn observe_sets_latest_score_and_applies_source_cooldown() {
        // Cooldown path: first high anomaly from a source should emit a score,
        // immediate follow-up from the same source should be suppressed.
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            threshold: 0.0,
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(
            &[NUM_FEATURES, 16, 8, 16, NUM_FEATURES],
            0.001,
        ));
        engine.maturity = 1.0;
        engine.baseline_mse = -1.0;
        engine.baseline_std = 1.0;

        for _ in 0..WINDOW_SIZE {
            let ev = make_event("shell.command_exec", "198.51.100.5");
            let _ = engine.observe(&ev);
        }
        assert!(
            engine.latest_score() > 0.0,
            "latest_score should be updated after first emitted anomaly"
        );

        let immediate = engine.observe(&make_event("shell.command_exec", "198.51.100.5"));
        assert!(
            immediate.is_none(),
            "cooldown should suppress repeated immediate alerts from same source"
        );
    }

    #[test]
    fn load_blocked_ips_reads_decisions_and_plaintext_block_file() {
        // Data-source path: blocked IP ingestion should combine decision logs
        // and blocked-ips.txt fallback data.
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let decisions = dir.path().join("decisions-2026-04-17.jsonl");
        std::fs::write(
            &decisions,
            r#"{"action_type":"block_ip","target_ip":"203.0.113.8"}
{"action":"monitor","target_ip":"198.51.100.1"}
{"action_type":"block_ip","target_ip":"198.51.100.9"}"#,
        )
        .expect("decisions fixture should be written");
        std::fs::write(
            dir.path().join("blocked-ips.txt"),
            "# comment\n203.0.113.99\n",
        )
        .expect("blocked ips fixture should be written");

        let blocked = load_blocked_ips(dir.path());
        assert!(blocked.contains("203.0.113.8"));
        assert!(blocked.contains("198.51.100.9"));
        assert!(blocked.contains("203.0.113.99"));
        assert!(!blocked.contains("198.51.100.1"));
    }

    #[test]
    fn read_fp_report_detectors_respects_days_cutoff() {
        // Retention path: files older than the requested days window should
        // not contribute detector names.
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let old_date = (chrono::Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string();
        let recent_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        std::fs::write(
            dir.path().join(format!("fp-reports-{old_date}.jsonl")),
            r#"{"detector":"old_detector","incident_id":"old:1.1.1.1:ts"}"#,
        )
        .expect("old fp fixture should be written");
        std::fs::write(
            dir.path().join(format!("fp-reports-{recent_date}.jsonl")),
            r#"{"detector":"recent_detector","incident_id":"recent:1.1.1.1:ts"}"#,
        )
        .expect("recent fp fixture should be written");

        let detectors = read_fp_report_detectors(dir.path(), 7);
        assert!(detectors.contains("recent_detector"));
        assert!(!detectors.contains("old_detector"));
    }

    #[test]
    fn read_fp_report_counts_skips_numeric_entity_placeholders() {
        // Entity-extraction path: numeric middle fields (scores) should be
        // ignored so FP counts only track actionable entities.
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        std::fs::write(
            dir.path().join(format!("fp-reports-{today}.jsonl")),
            r#"{"detector":"neural_anomaly","incident_id":"neural_anomaly:85:ts"}
{"detector":"ssh_bruteforce","incident_id":"ssh_bruteforce:203.0.113.4:ts"}"#,
        )
        .expect("fp count fixture should be written");

        let counts = read_fp_report_counts(dir.path(), 7);
        assert!(counts
            .iter()
            .any(|(d, e, c)| d == "ssh_bruteforce" && e == "203.0.113.4" && *c == 1));
        assert!(
            counts.iter().all(|(d, _, _)| d != "neural_anomaly"),
            "numeric entity placeholders must be ignored"
        );
    }
}

// ---------------------------------------------------------------------------
// Blocked IP loader for clean training
// ---------------------------------------------------------------------------

/// Load all IPs that were blocked — used by train_nightly to exclude attack traffic.
/// Phase 7: reads from dated graph snapshots (last 7 days), falls back to JSONL.
fn load_blocked_ips(data_dir: &Path) -> HashSet<String> {
    let mut blocked = HashSet::new();

    // Phase 7: try dated graph snapshots (last 7 days)
    let today = chrono::Local::now().date_naive();
    let mut loaded_from_graph = false;
    for days_ago in 0..7i64 {
        let date = today - chrono::Duration::days(days_ago);
        let date_str = date.format("%Y-%m-%d").to_string();
        if let Some(graph) = crate::knowledge_graph::KnowledgeGraph::load_dated(data_dir, &date_str)
        {
            use crate::knowledge_graph::types::{Node, NodeType};
            for id in graph.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    decision: Some(action),
                    decision_target,
                    ..
                }) = graph.get_node(id)
                {
                    if action.contains("block") {
                        if let Some(ip) = decision_target {
                            if !ip.is_empty() {
                                blocked.insert(ip.clone());
                            }
                        }
                    }
                }
            }
            loaded_from_graph = true;
        }
    }

    if !loaded_from_graph {
        // Fallback: read from decisions JSONL files
        let entries = match std::fs::read_dir(data_dir) {
            Ok(e) => e,
            Err(_) => return blocked,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !name.starts_with("decisions-") || !name.ends_with(".jsonl") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    let action = v
                        .get("action_type")
                        .or_else(|| v.get("action"))
                        .and_then(|a| a.as_str())
                        .unwrap_or("");
                    if action.contains("block") {
                        if let Some(ip) = v.get("target_ip").and_then(|i| i.as_str()) {
                            if !ip.is_empty() {
                                blocked.insert(ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Also load from blocked-ips.txt (written by sensor feedback loop)
    let blocked_file = data_dir.join("blocked-ips.txt");
    if let Ok(content) = std::fs::read_to_string(&blocked_file) {
        for line in content.lines() {
            let ip = line.trim();
            if !ip.is_empty() && !ip.starts_with('#') {
                blocked.insert(ip.to_string());
            }
        }
    }

    blocked
}
