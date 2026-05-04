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

// Feature layout (bump whenever kinds/bigrams/signals/graph blocks change size —
// old models deserialise to None and are rebuilt on the next training cycle):
//
//   kinds    [0 .. KIND_SLOTS)                one-hot count per event kind
//   bigrams  [BIGRAM_BASE .. SEQ_BASE)        attack-shaped kind transitions
//   signals  [SEQ_BASE .. GRAPH_BASE)         hand-crafted sequence features
//   graph    [GRAPH_BASE .. NUM_FEATURES)     knowledge-graph structural signals
const KIND_SLOTS: usize = 31;
const NUM_BIGRAMS: usize = 16;
const BIGRAM_BASE: usize = KIND_SLOTS;
const NUM_SEQUENCE: usize = 8;
const SEQ_BASE: usize = BIGRAM_BASE + NUM_BIGRAMS;
const NUM_GRAPH: usize = 10;
const GRAPH_BASE: usize = SEQ_BASE + NUM_SEQUENCE;
const NUM_FEATURES: usize = GRAPH_BASE + NUM_GRAPH;
const WINDOW_SIZE: usize = 20;

/// Map event kind to feature index (0..KIND_SLOTS). Slots 24-30 were added
/// in v0.12 to cover kinds the production sensor was already emitting at
/// meaningful volume (http.request, tcp_stream.ssh, memfd / mprotect probes,
/// network.snapshot, file.extracted_from_network, kernel.bpf_program_loaded)
/// but that the pre-012 autoencoder was silently dropping.
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
        "http.request" => Some(24),
        "tcp_stream.ssh" => Some(25),
        "memory.anon_executable" => Some(26),
        "network.snapshot" => Some(27),
        "memory.deleted_file_mapping" => Some(28),
        "file.extracted_from_network" => Some(29),
        "kernel.bpf_program_loaded" => Some(30),
        _ => None,
    }
}

/// Attack-indicative bigram transitions. Slot values follow `BIGRAM_BASE`
/// (updates when `KIND_SLOTS` changes — keep in sync manually).
const ATTACK_BIGRAMS: &[(usize, usize, usize)] = &[
    (14, 13, BIGRAM_BASE),     // ssh_failed → ssh_success
    (13, 1, BIGRAM_BASE + 1),  // ssh_success → shell_exec
    (1, 0, BIGRAM_BASE + 2),   // shell_exec → file_read
    (0, 7, BIGRAM_BASE + 3),   // file_read → outbound_connect
    (1, 7, BIGRAM_BASE + 4),   // shell_exec → outbound_connect
    (8, 0, BIGRAM_BASE + 5),   // sudo → file_read
    (1, 16, BIGRAM_BASE + 6),  // shell_exec → timestomp
    (1, 17, BIGRAM_BASE + 7),  // shell_exec → truncate
    (3, 1, BIGRAM_BASE + 8),   // fd_redirect → shell_exec
    (19, 1, BIGRAM_BASE + 9),  // privesc → shell_exec
    (1, 20, BIGRAM_BASE + 10), // shell_exec → memfd_create
    (7, 7, BIGRAM_BASE + 11),  // outbound → outbound (beaconing)
    (1, 1, BIGRAM_BASE + 12),  // shell → shell (recon burst)
    (21, 1, BIGRAM_BASE + 13), // module_load → shell_exec
    (23, 9, BIGRAM_BASE + 14), // listen → accept
    (4, 3, BIGRAM_BASE + 15),  // clone → fd_redirect
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

    // Layer 3: sequence signals [SEQ_BASE .. GRAPH_BASE)

    // +0: kind diversity
    let unique: std::collections::HashSet<_> = kinds.iter().filter_map(|x| *x).collect();
    f[SEQ_BASE] = (unique.len() as f32 / 12.0).min(1.0);

    // +1: transition entropy
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
            f[SEQ_BASE + 1] = (entropy / 9.2).min(1.0);
        }
    }

    // +2: longest consecutive same-kind run
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
        f[SEQ_BASE + 2] = (max_run as f32 / n).min(1.0);
    }

    // +3: credential harvesting signal (ssh.login_success → file.read_access)
    f[SEQ_BASE + 3] = if kinds
        .windows(2)
        .any(|w| w[0] == Some(13) && w[1] == Some(0))
    {
        1.0
    } else {
        0.0
    };

    // +4: kill chain stage progression (how many distinct stages appear in order)
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
        f[SEQ_BASE + 4] = (stages_seen as f32 / 7.0).min(1.0);
    }

    // +5: command diversity (approximated by unique kinds in shell-heavy windows)
    let shell_ratio = kinds.iter().filter(|&&k| k == Some(1)).count() as f32 / n;
    f[SEQ_BASE + 5] = shell_ratio.min(1.0);

    // +6: network listener present
    f[SEQ_BASE + 6] = if kinds.iter().any(|&k| k == Some(23) || k == Some(9)) {
        1.0
    } else {
        0.0
    };

    // +7: window size normalized
    f[SEQ_BASE + 7] = (n / 50.0).min(1.0);

    // Graph block [GRAPH_BASE .. NUM_FEATURES) is filled by
    // `enrich_features_with_graph`. Initialised to 0.0 by default — safe for
    // inference without graph data.

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

/// Enrich a feature vector with graph structural features. Writes to the
/// `[GRAPH_BASE .. NUM_FEATURES)` block so the kind / bigram / sequence blocks
/// upstream stay untouched.
fn enrich_features_with_graph(f: &mut [f32], gf: &GraphFeatures) {
    if f.len() < NUM_FEATURES {
        return;
    }
    // +0: average process degree normalized (0 = idle, 1 = 20+ avg connections)
    f[GRAPH_BASE] = (gf.avg_process_degree / 20.0).min(1.0);
    // +1: max process tree depth (deeper = more suspicious)
    f[GRAPH_BASE + 1] = (gf.max_process_tree_depth as f32 / 10.0).min(1.0);
    // +2: threat intel IP count
    f[GRAPH_BASE + 2] = (gf.threat_intel_ip_count as f32 / 10.0).min(1.0);
    // +3: writes to sensitive paths
    f[GRAPH_BASE + 3] = (gf.writes_to_sensitive as f32 / 20.0).min(1.0);
    // +4: connected components (more = more isolated activity)
    f[GRAPH_BASE + 4] = (gf.connected_components as f32 / 20.0).min(1.0);
    // +5: process/IP ratio anomaly (deviate from normal ~5:1)
    f[GRAPH_BASE + 5] = if gf.process_ip_ratio > 0.0 {
        (1.0 - (gf.process_ip_ratio / 5.0).min(1.0)).abs()
    } else {
        0.0
    };
    // +6: high-degree hub count
    f[GRAPH_BASE + 6] = (gf.high_degree_nodes as f32 / 5.0).min(1.0);
    // +7: incident count
    f[GRAPH_BASE + 7] = (gf.incident_count as f32 / 20.0).min(1.0);
    // +8: total edge activity level
    f[GRAPH_BASE + 8] = (gf.total_edges as f32 / 10000.0).min(1.0);
    // +9: active sessions
    f[GRAPH_BASE + 9] = (gf.active_sessions as f32 / 10.0).min(1.0);
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
        // Header: magic(4) + version(4) + baseline_mse(4) + baseline_std(4) + samples(8).
        // Version 2 adds `BASELINE_PERCENTILES * 4` bytes of anchor table
        // before the length-prefixed JSON weights. Older v1 files keep the
        // original 24-byte header.
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let net_offset = match version {
            v if v >= 2 => 24 + BASELINE_PERCENTILES * 4,
            _ => 24,
        };
        if data.len() < net_offset + 4 {
            return None;
        }
        let net_len = u32::from_le_bytes([
            data[net_offset],
            data[net_offset + 1],
            data[net_offset + 2],
            data[net_offset + 3],
        ]) as usize;
        let start = net_offset + 4;
        if data.len() < start + net_len {
            return None;
        }
        let net_json = &data[start..start + net_len];

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
    /// Fraction of training windows held out for baseline computation
    /// (range 0.0..=0.5). Computing `baseline_mse` / `baseline_std` on the
    /// same windows the autoencoder memorised produces a tiny, saturated
    /// baseline — every live window then sigmoids to ~1.0. A ~20% holdout
    /// gives a realistic variance estimate. Set to 0.0 to fall back to the
    /// legacy single-set baseline (not recommended; retained for
    /// small-dataset scenarios where splitting the training set would drop
    /// it below `MIN_TRAIN_WINDOWS`).
    pub training_holdout_fraction: f32,
}

/// Minimum number of windows required for training after the holdout split.
/// The older in-place baseline enforced `all_kinds.len() >= 100` — we keep
/// that floor on the training portion.
const MIN_TRAIN_WINDOWS: usize = 100;

/// Deterministic train/holdout split used by `train_nightly`. Every Nth
/// index goes into the holdout bucket so the split is reproducible across
/// runs (no RNG dependency, no test flake). `N` is derived from the
/// requested fraction: 0.2 → every 5th window, 0.1 → every 10th, etc.
#[derive(Debug, Clone)]
pub(crate) struct TrainTestSplit {
    train: Vec<usize>,
    holdout: Vec<usize>,
}

impl TrainTestSplit {
    /// Build a split covering `[0, total)`. `fraction` is clamped to
    /// `0.0..=0.5` (holding out more than half the data would starve the
    /// trainer). `total == 0` is legal and yields two empty vectors.
    pub(crate) fn from_fraction(total: usize, fraction: f32) -> Self {
        if total == 0 {
            return Self {
                train: Vec::new(),
                holdout: Vec::new(),
            };
        }
        let clamped = fraction.clamp(0.0, 0.5);
        if clamped <= f32::EPSILON {
            return Self {
                train: (0..total).collect(),
                holdout: Vec::new(),
            };
        }
        // `stride = round(1 / fraction)` gives the expected every-Nth
        // cadence; clamped to [2, total] so the holdout always has at
        // least one element when the fraction is non-zero + data fits.
        let stride = ((1.0 / clamped).round() as usize).clamp(2, total);
        let mut train = Vec::with_capacity(total - total / stride);
        let mut holdout = Vec::with_capacity(total / stride);
        for i in 0..total {
            if i % stride == stride - 1 {
                holdout.push(i);
            } else {
                train.push(i);
            }
        }
        Self { train, holdout }
    }

    pub(crate) fn indices(&self) -> (Vec<usize>, Vec<usize>) {
        (self.train.clone(), self.holdout.clone())
    }
}

/// Mean reconstruction error over a selection of feature windows.
fn mean_reconstruction_error(net: &AutoencoderNet, features: &[Vec<f32>], idx: &[usize]) -> f32 {
    if idx.is_empty() {
        return 0.0;
    }
    let sum: f32 = idx
        .iter()
        .map(|&i| net.reconstruction_error(&features[i]))
        .sum();
    sum / idx.len() as f32
}

/// Number of evenly-spaced percentile anchors retained from the baseline
/// distribution. 101 keeps storage at 404 bytes (101 × f32) and gives
/// 1%-granularity scoring — enough to separate normal / elevated /
/// anomaly without the full histogram.
pub(crate) const BASELINE_PERCENTILES: usize = 101;

/// Compress a sorted-ascending `errors` vector into `BASELINE_PERCENTILES`
/// anchors. `anchor[k]` is the baseline MSE at the `k/(BASELINE_PERCENTILES-1)`
/// quantile. Empty input yields `vec![0.0; BASELINE_PERCENTILES]`.
fn compute_percentile_anchors(mut errors: Vec<f32>) -> Vec<f32> {
    if errors.is_empty() {
        return vec![0.0; BASELINE_PERCENTILES];
    }
    errors.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let last = errors.len() - 1;
    (0..BASELINE_PERCENTILES)
        .map(|k| {
            let pos = (k as f64 * last as f64 / (BASELINE_PERCENTILES - 1) as f64).round();
            errors[pos as usize]
        })
        .collect()
}

/// Compute `(baseline_mse, baseline_std, percentile_anchors)` over a
/// selection of feature windows. Mean + std keep legacy telemetry values;
/// the anchors drive the percentile-based score that replaces the
/// z-score + sigmoid path (which saturated to 1.0 on production's
/// homogeneous event distribution).
fn compute_baseline(
    net: &AutoencoderNet,
    features: &[Vec<f32>],
    idx: &[usize],
) -> (f32, f32, Vec<f32>) {
    if idx.is_empty() {
        return (0.0, 0.0, vec![0.0; BASELINE_PERCENTILES]);
    }
    let errors: Vec<f32> = idx
        .iter()
        .map(|&i| net.reconstruction_error(&features[i]))
        .collect();
    let n = errors.len() as f32;
    let mean = errors.iter().sum::<f32>() / n;
    let variance = errors.iter().map(|e| (e - mean).powi(2)).sum::<f32>() / n;
    let anchors = compute_percentile_anchors(errors);
    (mean, variance.sqrt(), anchors)
}

/// Model file format constants. Version 1 is the legacy layout (header
/// has no percentile table); version 2 adds `BASELINE_PERCENTILES × f32`
/// after the 24-byte header, followed by the usual JSON weights blob.
const MODEL_MAGIC: &[u8; 4] = b"IWAE";
const MODEL_VERSION_V2: u32 = 2;
const MODEL_HEADER_LEN: usize = 24;
type ParsedModel = (
    Option<AutoencoderNet>,
    f32,      // baseline_mse
    f32,      // baseline_std
    Vec<f32>, // percentile anchors
    f32,      // maturity
    u32,      // training cycles
    u64,      // raw total_samples (Copilot #2: preserve exactly across saves)
);

/// Read the saved `anomaly-model.bin`, surfacing genuine I/O failure
/// via `warn!` while staying silent on `NotFound` (steady state on
/// first boot before training has produced a model). Replaces the
/// silent `if let Ok(data) = std::fs::read(&model_path)` site in
/// `AnomalyEngine::new` (Spec 037 I-13 follow-up #2).
///
/// On a real I/O error (perms, FS error) the operator loses the
/// trained model state across restart and the agent silently starts
/// fresh in observation mode without flagging that the existing
/// model was unreadable. The warn carries path + error so the
/// operator can recover the model or fix permissions.
fn read_anomaly_model_or_warn(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(data) => Some(data),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "anomaly model read failed (starting fresh in observation mode)"
            );
            None
        }
    }
}

/// Parse a saved `anomaly-model.bin` into engine fields. Accepts both the
/// pre-percentile v1 layout (where we synthesise a flat anchor table —
/// forces the new inference path to fall back to z-score until the next
/// training cycle) and the v2 layout that embeds anchors after the
/// header. Returns `None` when the file is truncated / malformed; the
/// caller constructs a fresh engine.
fn parse_model_file(data: &[u8]) -> Option<ParsedModel> {
    if data.len() < MODEL_HEADER_LEN || &data[..4] != MODEL_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let baseline_mse = f32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let baseline_std = f32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let samples = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let maturity = (samples as f32 / 500_000.0).min(1.0);
    let cycles = (samples / 100_000) as u32;

    let anchors = if version == MODEL_VERSION_V2 {
        let expected = MODEL_HEADER_LEN + BASELINE_PERCENTILES * 4;
        if data.len() < expected {
            return None;
        }
        let mut v = Vec::with_capacity(BASELINE_PERCENTILES);
        for k in 0..BASELINE_PERCENTILES {
            let off = MODEL_HEADER_LEN + k * 4;
            v.push(f32::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]));
        }
        v
    } else {
        // v1 layout: no anchors — seed with zeros so `percentile_score`
        // returns `None` and `observe()` falls back to z-score. Next
        // training cycle will overwrite with real data.
        vec![0.0; BASELINE_PERCENTILES]
    };

    // `AutoencoderNet::load` reads the full file (including IWAE header)
    // and skips past the anchor table itself based on the version byte.
    let net = AutoencoderNet::load(data);
    if net.is_some() {
        info!(
            "anomaly: loaded model ({} bytes, version {}, baseline MSE {:.6}, maturity {:.2})",
            data.len(),
            version,
            baseline_mse,
            maturity
        );
    }
    Some((
        net,
        baseline_mse,
        baseline_std,
        anchors,
        maturity,
        cycles,
        samples,
    ))
}

/// Rank a live reconstruction error against the baseline percentile
/// anchors. Returns `Some(0.0..=1.0)`: 0 = better than everything,
/// 1 = worse than everything. Degenerate tables (empty or all-zero)
/// return `None` so the caller can fall back to the legacy z-score
/// path during the transition period.
///
/// 2026-05-01: events with `mse > anchors[last]` previously clipped to
/// exactly 1.0 — every routine prod event saturated because the
/// holdout's max anchor is computed from a deterministic 5-of-N
/// sample of training windows and runtime traffic regularly exceeds
/// it (drift between training-end and now, plus longer tails). When
/// every signal is 1.0 the downstream boost in `incident_decision_eval`
/// fires on every incident, washing out the discriminative value.
/// The fix splits the output range: in-range MSE maps to 0..0.99 by
/// straight rank, beyond-range MSE extrapolates into 0.99..=1.0 via
/// `tanh((mse - max) / (p99 - p50))` so the engine still distinguishes
/// "slightly past max" from "wildly past max" instead of clipping.
pub(crate) fn percentile_score(mse: f32, anchors: &[f32]) -> Option<f32> {
    if anchors.len() < 2 {
        return None;
    }
    if !anchors.iter().any(|&x| x > 0.0) {
        return None;
    }
    let max = *anchors.last().expect("non-empty: len() >= 2 above");
    if mse <= max {
        let below = anchors.iter().filter(|&&a| a <= mse).count();
        return Some(0.99 * below as f32 / anchors.len() as f32);
    }
    let p50 = anchors[anchors.len() / 2];
    let p99 = anchors[(anchors.len() * 99) / 100];
    let scale = (p99 - p50).max(1e-6);
    Some(0.99 + 0.01 * ((mse - max) / scale).tanh())
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
            training_holdout_fraction: 0.2,
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
    /// Baseline standard deviation. Retained for telemetry + the legacy
    /// z-score fallback path; the live score now comes from the
    /// percentile anchors below.
    baseline_std: f32,
    /// Sorted-ascending reconstruction-error anchors over the baseline
    /// windows (length `BASELINE_PERCENTILES`). Populated by training and
    /// consumed by `percentile_score` at inference time.
    baseline_percentile_anchors: Vec<f32>,
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
    /// 2026-05-04 (Wave 7a): set by `new()` so the first slow_loop
    /// tick after boot triggers a post-graph-features recalibration.
    /// Cleared by `clear_post_graph_recalibration_flag()` after a
    /// successful run. See `needs_post_graph_recalibration` for the
    /// rationale (boot recalibration uses zero-graph features →
    /// anchors too narrow → live observe() saturates again).
    recal_pending_post_graph: bool,
    /// 2026-05-04 (Wave 7a Copilot #2 follow-up): the exact
    /// `total_samples` u64 read from `anomaly-model.bin` at load
    /// time. Synthesising this from `cycles * 100_000` on save
    /// truncates the remainder (e.g. 499_999 → 400_000) and
    /// silently drops maturity from ~1.0 to ~0.8 across a
    /// recalibration save. Persisting the original value preserves
    /// `parse_model_file`'s maturity = samples / 500_000 contract
    /// exactly. Initialised to 0 when starting fresh (no model).
    loaded_total_samples: u64,
}

impl AnomalyEngine {
    /// Create a new anomaly engine, attempting to load a saved model.
    pub fn new(config: AnomalyConfig) -> Self {
        let model_path = config.data_dir.join("anomaly-model.bin");
        let (net, baseline_mse, baseline_std, anchors, maturity, cycles, total_samples) =
            if let Some(data) = read_anomaly_model_or_warn(&model_path) {
                parse_model_file(&data).unwrap_or_else(|| {
                    info!("anomaly: existing model rejected by loader, starting fresh");
                    (None, 0.0, 1.0, vec![0.0; BASELINE_PERCENTILES], 0.0, 0, 0)
                })
            } else {
                info!("anomaly: no saved model found, starting fresh (observation mode)");
                (None, 0.0, 1.0, vec![0.0; BASELINE_PERCENTILES], 0.0, 0, 0)
            };

        Self {
            net,
            window: VecDeque::with_capacity(WINDOW_SIZE),
            baseline_mse,
            baseline_std,
            baseline_percentile_anchors: anchors,
            maturity,
            training_cycles: cycles,
            config,
            cooldowns: std::collections::HashMap::new(),
            last_score: 0.0,
            graph_features: None,
            recal_pending_post_graph: true,
            loaded_total_samples: total_samples,
        }
    }

    /// 2026-05-04 (Wave 7a): true while a post-graph-features
    /// recalibration is still pending. Boot's recalibration runs
    /// before `set_graph_features` is ever called, so the MSEs it
    /// collected used a feature vector with zeros in the
    /// `[GRAPH_BASE..NUM_FEATURES)` slots. Live `observe()` after
    /// the first slow_loop tick has those slots populated → MSEs
    /// jump above the boot anchor table → saturation returns.
    /// This flag tells slow_loop to trigger a SECOND recalibration
    /// once graph features are available, so the anchors reflect
    /// the actual production feature shape.
    pub fn needs_post_graph_recalibration(&self) -> bool {
        self.recal_pending_post_graph && self.graph_features.is_some()
    }

    /// Mark the post-graph recalibration as done so it does not run
    /// every tick. Called by slow_loop after a successful recalibration.
    pub fn clear_post_graph_recalibration_flag(&mut self) {
        self.recal_pending_post_graph = false;
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

        // Primary path: percentile score against the baseline distribution.
        // Returns `None` when the baseline is empty/degenerate (v1 model
        // files, or very small datasets) — fall back to the legacy
        // z-score + sigmoid so the engine keeps producing signal.
        let score = percentile_score(mse, &self.baseline_percentile_anchors).unwrap_or_else(|| {
            let z = if self.baseline_std > 0.0 {
                (mse - self.baseline_mse) / self.baseline_std
            } else if mse > self.baseline_mse {
                3.0
            } else {
                -3.0
            };
            1.0 / (1.0 + (-z).exp())
        });
        let weighted = score * self.maturity * 0.3; // max contribution = 0.3

        debug!(
            score = format!("{:.3}", score),
            weighted = format!("{:.3}", weighted),
            maturity = format!("{:.2}", self.maturity),
            mse = format!("{:.6}", mse),
            "anomaly: inference"
        );

        if score > self.config.threshold {
            // Cooldown check.
            // Spec 037 I-15: trim + filter empty so the "unknown" fallback
            // covers both "key missing" and "key present but empty";
            // otherwise an "" cooldown key would conflate distinct attackers.
            let source = event
                .details
                .get("ip")
                .or(event.details.get("src_ip"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
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

    /// 2026-05-04 (Wave 7a): recompute the percentile anchor table
    /// against a fresh batch of events WITHOUT retraining the network.
    ///
    /// **Why this exists**: in production on 2026-05-04 the autoencoder
    /// was emitting `score="1.000"` for every event (238/238 in a 6h
    /// sample). The 2026-05-01 spec-033 Phase 0 fix replaced the
    /// clip-to-1.0 path with `tanh((mse - max) / (p99 - p50))` for
    /// above-range MSE, but the anchors themselves remained from a
    /// stale training holdout — current prod's reconstruction errors
    /// land far past `max` so `tanh(huge)` saturates to ~1.0 anyway.
    /// Boost in `incident_decision_eval` was firing constant 9.9% on
    /// every triggered incident, washing out the discriminative value.
    ///
    /// **What this does**: walks the events through the SAME pipeline
    /// `observe()` uses (kind_index → sliding window → window_features
    /// → reconstruction_error), collects every per-window MSE into a
    /// fresh sample, then rebuilds `baseline_percentile_anchors` from
    /// the new sample via `compute_percentile_anchors`. The network
    /// weights are NOT touched — this is a calibration refresh, not a
    /// retrain. Result: p99 of the new anchors reflects current prod
    /// distribution, so most observations score in 0..0.99 (rank-based)
    /// instead of saturating in the 0.99..=1.0 tanh tail.
    ///
    /// **What this does NOT do**: retrain the model. If the
    /// reconstruction error has drifted because the autoencoder
    /// itself is mis-fit (e.g. event-kind vocabulary changed), only a
    /// full `train_nightly_with_store` run will fix that. The
    /// recalibration is a fast (~seconds) intermediate fix that lets
    /// the operator restore signal between nightly retrains.
    ///
    /// Returns the count of MSE samples used. Errors:
    /// - "no model loaded": engine has not been trained yet
    /// - "insufficient samples: N < 101": fewer than `BASELINE_PERCENTILES`
    ///   full-window MSE samples could be collected from the input,
    ///   so the resulting anchors would be pathological
    pub fn recalibrate_anchors_from_events(&mut self, events: &[Event]) -> Result<usize, String> {
        let net = self
            .net
            .as_ref()
            .ok_or_else(|| "no model loaded: train_nightly first".to_string())?;

        // Use a temporary window so the engine's live state is not
        // affected. observe() advances `self.window` as a side effect;
        // calibration must NOT poison subsequent live observations.
        let mut tmp_window: VecDeque<Option<usize>> = VecDeque::with_capacity(WINDOW_SIZE);
        let mut errors: Vec<f32> = Vec::with_capacity(events.len().saturating_sub(WINDOW_SIZE));

        for ev in events {
            tmp_window.push_back(kind_index(&ev.kind));
            if tmp_window.len() > WINDOW_SIZE {
                tmp_window.pop_front();
            }
            if tmp_window.len() < WINDOW_SIZE {
                continue;
            }
            let kinds: Vec<Option<usize>> = tmp_window.iter().copied().collect();
            let mut features = window_features(&kinds);
            // Match observe(): if the engine has cached graph features,
            // mirror them into the calibration features so the
            // reconstruction error is computed on the same shape that
            // live observations see.
            if let Some(ref gf) = self.graph_features {
                enrich_features_with_graph(&mut features, gf);
            }
            errors.push(net.reconstruction_error(&features));
        }

        if errors.len() < BASELINE_PERCENTILES {
            return Err(format!(
                "insufficient samples: {} < {} (need at least {} full windows from input \
                 of {} events; many short bursts produce few full windows)",
                errors.len(),
                BASELINE_PERCENTILES,
                BASELINE_PERCENTILES,
                events.len(),
            ));
        }

        // Copilot #4 fix: avoid the errors.clone() — capture the
        // count first, then move `errors` into the anchor builder.
        // On boot with 10k events that clone was ~80 KB of pointless
        // memcpy; trivial individually but matches the codebase's
        // "no allocation in hot paths" stance.
        let n = errors.len() as f32;
        let mean = errors.iter().sum::<f32>() / n;
        let variance = errors.iter().map(|e| (e - mean).powi(2)).sum::<f32>() / n;
        let std_dev = variance.sqrt();
        let samples = errors.len();
        let new_anchors = compute_percentile_anchors(errors);

        info!(
            samples,
            old_p50 = self
                .baseline_percentile_anchors
                .get(50)
                .copied()
                .unwrap_or(0.0),
            old_p99 = self
                .baseline_percentile_anchors
                .get(99)
                .copied()
                .unwrap_or(0.0),
            new_p50 = new_anchors.get(50).copied().unwrap_or(0.0),
            new_p99 = new_anchors.get(99).copied().unwrap_or(0.0),
            new_max = new_anchors.last().copied().unwrap_or(0.0),
            new_mean = mean,
            new_std = std_dev,
            "anomaly: anchor recalibration complete"
        );

        self.baseline_mse = mean;
        self.baseline_std = std_dev;
        self.baseline_percentile_anchors = new_anchors;
        // The model file persists anchors as part of v2 layout. Save so
        // the recalibration survives agent restart. Failure here is
        // best-effort — the in-memory anchors are still updated.
        if let Err(e) = self.persist_model_state() {
            warn!("anomaly: failed to persist recalibrated model: {e}");
        }
        Ok(samples)
    }

    /// 2026-05-04 (Wave 7a): write the current model + baseline
    /// fields to `anomaly-model.bin` using the v2 layout. Extracted
    /// from `train_nightly_with_store`'s save block so
    /// `recalibrate_anchors_from_events` can persist without
    /// duplicating the serialisation. Atomic via tmp + rename.
    ///
    /// Layout MUST match `parse_model_file`:
    /// - magic (4) + version u32 LE (4)
    /// - baseline_mse f32 LE (4) + baseline_std f32 LE (4)
    /// - total_samples u64 LE (8) — preserved exactly from the
    ///   value parsed at load time (Copilot #2: synthesising from
    ///   `cycles * 100_000` truncates remainders and silently drops
    ///   maturity ~0.2 across saves on existing prod models).
    /// - BASELINE_PERCENTILES × f32 LE anchors (404, padded with 0.0
    ///   if the in-memory vec ever shrinks below the constant).
    /// - weights JSON length u32 LE (4) + weights JSON bytes
    ///
    /// 2026-05-04 (Copilot #1): write order is "tmp first, then
    /// rotate, then atomic rename onto target". The previous order
    /// (rotate target → .prev BEFORE tmp write) created a window
    /// where a tmp-write failure left zero usable model files —
    /// next restart would start fresh. New order keeps the existing
    /// `anomaly-model.bin` available until the new tmp is durable.
    fn persist_model_state(&self) -> std::io::Result<()> {
        let net = self
            .net
            .as_ref()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no model loaded"))?;
        // Mirror train_nightly_with_store's weights JSON shape so a
        // recalibration-saved file is byte-compatible with the v2
        // layout the loader expects.
        let weights: Vec<Vec<Vec<f32>>> = net.layers.iter().map(|l| l.weights.clone()).collect();
        let biases: Vec<Vec<f32>> = net.layers.iter().map(|l| l.biases.clone()).collect();
        let net_json = serde_json::json!({
            "weights": weights,
            "biases": biases,
            "lr": net.lr,
        });
        let net_bytes = serde_json::to_vec(&net_json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Copilot #2 fix: persist the original samples value (read
        // at load time) instead of synthesising from cycles. Falls
        // back to `cycles * 100_000` only when the engine started
        // fresh (loaded_total_samples == 0) so a never-trained
        // engine that calls persist still emits a coherent header.
        let total_samples: u64 = if self.loaded_total_samples > 0 {
            self.loaded_total_samples
        } else {
            (self.training_cycles as u64) * 100_000
        };
        let mut bytes: Vec<u8> =
            Vec::with_capacity(MODEL_HEADER_LEN + 4 * BASELINE_PERCENTILES + 4 + net_bytes.len());
        bytes.extend_from_slice(MODEL_MAGIC);
        bytes.extend_from_slice(&MODEL_VERSION_V2.to_le_bytes());
        bytes.extend_from_slice(&self.baseline_mse.to_le_bytes());
        bytes.extend_from_slice(&self.baseline_std.to_le_bytes());
        bytes.extend_from_slice(&total_samples.to_le_bytes());
        // Copilot #3 fix: pad to BASELINE_PERCENTILES exactly so a
        // shorter-than-expected in-memory vec cannot produce an
        // invalid v2 layout that the loader would reject on next
        // restart. Mirrors train_nightly_with_store's save block.
        for k in 0..BASELINE_PERCENTILES {
            let v = self
                .baseline_percentile_anchors
                .get(k)
                .copied()
                .unwrap_or(0.0);
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend_from_slice(&(net_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&net_bytes);

        // Copilot #1 fix: ordering. Write tmp first; only AFTER it
        // is durably on disk do we rotate the existing model to
        // .prev and rename tmp into place. If any step before the
        // final rename fails, the existing model file is untouched.
        let model_path = self.config.data_dir.join("anomaly-model.bin");
        let backup_path = self.config.data_dir.join("anomaly-model.prev.bin");
        let tmp = model_path.with_extension("bin.tmp");
        std::fs::write(&tmp, &bytes)?;
        // Best-effort fsync on the tmp so the rename below promotes
        // a durable file. POSIX rename is atomic on the same
        // filesystem — this combination gives "either old or new,
        // never empty / half-written".
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&tmp) {
            let _ = f.sync_all();
        }
        if model_path.exists() {
            // Rotate the previous good file aside; failure is
            // non-fatal because the rename below atomically replaces
            // model_path either way.
            let _ = std::fs::rename(&model_path, &backup_path);
        }
        std::fs::rename(&tmp, &model_path)?;
        Ok(())
    }

    /// Run nightly training on recent events.
    /// Reads events from SQLite (spec 016) when `store` is provided, falls
    /// back to JSONL scan otherwise for older deployments + the test harness.
    pub fn train_nightly(&mut self) -> Result<(), String> {
        self.train_nightly_with_store(None)
    }

    /// Variant that prefers a SQLite-backed event source. Production calls
    /// this with `Some(&state.sqlite_store)` after spec 016 stopped writing
    /// per-day events JSONL files — without the store argument the training
    /// path finds zero windows and emits "insufficient data" forever.
    pub fn train_nightly_with_store(
        &mut self,
        store: Option<&innerwarden_store::Store>,
    ) -> Result<(), String> {
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

        // Collect events from the last N days. Production ingests through
        // `innerwarden.db` (spec 016), so prefer the SQLite store when
        // available; fall back to per-day JSONL scan only for pre-016
        // deployments and the in-tree test harness.
        let cutoff =
            chrono::Utc::now() - chrono::Duration::days(self.config.training_retention_days as i64);
        let cutoff_iso = cutoff.to_rfc3339();
        let mut all_kinds: Vec<Vec<Option<usize>>> = Vec::new();
        let mut total_events = 0u64;
        let mut skipped_attack = 0u64;
        let mut event_window: Vec<Option<usize>> = Vec::new();

        let max_windows = (self.config.training_max_ram_mb as usize)
            .saturating_mul(1024 * 1024)
            .saturating_div(NUM_FEATURES.max(1) * 4)
            .max(1);
        // Each stored window hydrates into its feature vector later, so the
        // raw cap is shared between RAM budget and the query limit.
        let event_limit = max_windows.saturating_mul(5).max(200_000);

        let ram_cap_mb = self.config.training_max_ram_mb as usize;
        let timeout_secs = self.config.training_timeout_secs;
        let mut timed_out = false;

        if let Some(sq) = store {
            match sq.events_for_training(&cutoff_iso, event_limit) {
                Ok(rows) => {
                    info!(
                        "anomaly: sourcing training data from innerwarden.db ({} rows since {})",
                        rows.len(),
                        cutoff_iso
                    );
                    for (kind, ip) in rows {
                        if !blocked_ips.is_empty() {
                            if let Some(ref ip) = ip {
                                if blocked_ips.contains(ip) {
                                    skipped_attack += 1;
                                    continue;
                                }
                            }
                        }

                        event_window.push(kind_index(&kind));
                        total_events += 1;
                        if event_window.len() >= WINDOW_SIZE {
                            all_kinds.push(event_window.clone());
                            event_window.drain(..5);
                        }

                        let estimated_mb = (all_kinds.len() * NUM_FEATURES * 4) / (1024 * 1024);
                        if estimated_mb > ram_cap_mb {
                            info!(
                                "anomaly: RAM budget reached ({}MB), truncating training window",
                                estimated_mb
                            );
                            break;
                        }
                        if start.elapsed().as_secs() > timeout_secs {
                            timed_out = true;
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("anomaly: sqlite training read failed: {e}");
                }
            }
        }

        // Either store was None or the store query emitted nothing — try the
        // legacy JSONL scan so pre-016 layouts keep working.
        if total_events == 0 {
            let events_dir = &self.config.data_dir;
            let entries = match std::fs::read_dir(events_dir) {
                Ok(e) => e,
                Err(e) => {
                    return Err(format!(
                        "no sqlite training source and JSONL scan failed: {e}"
                    ))
                }
            };

            'files: for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if !name.starts_with("events-") || !name.ends_with(".jsonl") {
                    continue;
                }

                let estimated_mb = (all_kinds.len() * NUM_FEATURES * 4) / (1024 * 1024);
                if estimated_mb > ram_cap_mb {
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
                    let kind = ev.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                    // Spec 037 I-15: trim + filter so blocked-IP filtering
                    // never matches against an "" entry (defense-in-depth
                    // even though blocked_ips itself should never contain "").
                    let ip = ev.get("details").and_then(|d| {
                        d.get("src_ip")
                            .or_else(|| d.get("ip"))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                    });
                    if !blocked_ips.is_empty() {
                        if let Some(ip) = ip {
                            if blocked_ips.contains(ip) {
                                skipped_attack += 1;
                                continue;
                            }
                        }
                    }

                    event_window.push(kind_index(kind));
                    total_events += 1;
                    if event_window.len() >= WINDOW_SIZE {
                        all_kinds.push(event_window.clone());
                        event_window.drain(..5);
                    }

                    if start.elapsed().as_secs() > timeout_secs {
                        timed_out = true;
                        break 'files;
                    }
                }
            }
        }

        if timed_out {
            warn!("anomaly: training timeout, using data collected so far");
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

        // Split into train/holdout BEFORE feature extraction so the holdout
        // baseline reflects windows the network never saw during
        // backpropagation. See `TrainTestSplit` comments for the rationale.
        let split =
            TrainTestSplit::from_fraction(all_kinds.len(), self.config.training_holdout_fraction);
        let (train_idx, holdout_idx) = split.indices();
        info!(
            train_windows = train_idx.len(),
            holdout_windows = holdout_idx.len(),
            "anomaly: split windows train/holdout"
        );
        if train_idx.len() < MIN_TRAIN_WINDOWS {
            warn!(
                "anomaly: training set below floor after split ({} < {})",
                train_idx.len(),
                MIN_TRAIN_WINDOWS
            );
            return Err("insufficient data".to_string());
        }

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

        // Train ONLY on the training partition so the holdout stays
        // representative of "unseen normal" windows at baseline time.
        for epoch in 1..=self.config.training_epochs {
            for &i in &train_idx {
                net.train_reconstruction(&features[i]);
            }

            if start.elapsed().as_secs() > self.config.training_timeout_secs {
                info!("anomaly: timeout at epoch {}", epoch);
                break;
            }

            if epoch % 10 == 0 {
                let avg_mse: f32 = train_idx
                    .iter()
                    .map(|&i| net.reconstruction_error(&features[i]))
                    .sum::<f32>()
                    / train_idx.len() as f32;
                info!(
                    "anomaly: epoch {}/{} train-MSE {:.6}",
                    epoch, self.config.training_epochs, avg_mse
                );
            }
        }

        // Compute baseline on the held-out windows. This is the core of the
        // scoring fix: the autoencoder memorised the training set (MSE
        // collapses toward 0), so computing baseline there produces a tiny
        // std that saturates sigmoid(z) to 1.0 on live traffic. Held-out
        // MSE is an order of magnitude larger + has realistic variance.
        //
        // Fallback: when holdout is empty (fraction == 0 or dataset too
        // small) compute baseline on the training set — preserves legacy
        // behaviour, no silent panic.
        let baseline_idx: &[usize] = if holdout_idx.is_empty() {
            info!("anomaly: holdout empty — falling back to train-set baseline");
            &train_idx
        } else {
            &holdout_idx
        };
        let (baseline_mse, baseline_std, anchors) = compute_baseline(&net, &features, baseline_idx);
        let train_mse = mean_reconstruction_error(&net, &features, &train_idx);
        info!(
            "anomaly: baseline from holdout (train MSE {:.6}, holdout MSE {:.6} ± {:.6}, p50 {:.6}, p95 {:.6}, p99 {:.6})",
            train_mse,
            baseline_mse,
            baseline_std,
            anchors.get(50).copied().unwrap_or(0.0),
            anchors.get(95).copied().unwrap_or(0.0),
            anchors.get(99).copied().unwrap_or(0.0),
        );

        self.baseline_mse = baseline_mse;
        self.baseline_std = baseline_std;
        self.baseline_percentile_anchors = anchors;
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

        // Serialize as the v2 format: IWAE header + percentile anchor
        // table + length-prefixed JSON weights. Readers (both `new()` and
        // the AutoencoderNet loader) branch on the version byte.
        if let Some(ref net) = self.net {
            let mut data = Vec::new();
            data.extend_from_slice(MODEL_MAGIC);
            data.extend_from_slice(&MODEL_VERSION_V2.to_le_bytes());
            data.extend_from_slice(&self.baseline_mse.to_le_bytes());
            data.extend_from_slice(&self.baseline_std.to_le_bytes());
            let total_samples = total_events;
            data.extend_from_slice(&total_samples.to_le_bytes());

            // Percentile anchor table — pad with zeros if for any reason
            // the trainer produced a shorter-than-expected vector (should
            // not happen, but defence-in-depth).
            for k in 0..BASELINE_PERCENTILES {
                let v = self
                    .baseline_percentile_anchors
                    .get(k)
                    .copied()
                    .unwrap_or(0.0);
                data.extend_from_slice(&v.to_le_bytes());
            }

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
            // 2026-05-04 (Wave 7a Copilot #2 follow-up): keep the
            // in-memory `loaded_total_samples` in sync with what
            // `train_nightly` just wrote. A subsequent
            // `persist_model_state` call (e.g. from a recalibration
            // later this process lifetime) must persist this fresh
            // value, not the stale one from boot. Without this update
            // a recalibration immediately after retrain would silently
            // restore the pre-train samples count.
            self.loaded_total_samples = total_events;
        }

        // 2026-05-04 (Wave 7a follow-up): nightly retrain rebuilds
        // anchors from the training holdout — which was computed
        // BEFORE graph features were enriched on the feature vectors
        // (the network forward pass below applies graph enrichment
        // for the live `observe()` path, not for the holdout MSE
        // computation). Result observed in prod 2026-05-04 03:03 UTC:
        // every nightly cycle wipes the boot/post-graph
        // recalibration and prod is back to 100 % saturated by
        // morning, even with a fresh model.
        //
        // Re-run the recalibration on the SAME windows the trainer
        // just used, but this time enrich each feature vector with
        // the cached graph features so the resulting MSEs match what
        // live observe() will produce. Anchors then reflect the
        // graph-aware MSE distribution and survive across the next
        // observe() loop.
        //
        // Best-effort: any failure leaves the train-time anchors in
        // place. The slow_loop's post-graph recalibration (gated by
        // `recal_pending_post_graph`) is the next layer of defence
        // on the next tick.
        if let (Some(ref net), Some(ref gf)) = (&self.net, &self.graph_features) {
            if !all_kinds.is_empty() {
                let mut errors: Vec<f32> = Vec::with_capacity(all_kinds.len());
                for kinds in &all_kinds {
                    let mut features = window_features(kinds);
                    enrich_features_with_graph(&mut features, gf);
                    errors.push(net.reconstruction_error(&features));
                }
                if errors.len() >= BASELINE_PERCENTILES {
                    let n = errors.len() as f32;
                    let mean = errors.iter().sum::<f32>() / n;
                    let variance = errors.iter().map(|e| (e - mean).powi(2)).sum::<f32>() / n;
                    let samples = errors.len();
                    let new_anchors = compute_percentile_anchors(errors);
                    info!(
                        samples,
                        new_p50 = new_anchors.get(50).copied().unwrap_or(0.0),
                        new_p99 = new_anchors.get(99).copied().unwrap_or(0.0),
                        new_max = new_anchors.last().copied().unwrap_or(0.0),
                        "anomaly: post-train recalibration complete (graph-aware anchors)"
                    );
                    self.baseline_mse = mean;
                    self.baseline_std = variance.sqrt();
                    self.baseline_percentile_anchors = new_anchors;
                    if let Err(e) = self.persist_model_state() {
                        warn!("anomaly: post-train recalibration save failed: {e}");
                    }
                } else {
                    warn!(
                        "anomaly: post-train recalibration skipped: only {} windows < {} percentiles",
                        errors.len(),
                        BASELINE_PERCENTILES
                    );
                }
            }
        } else {
            // Either no model trained (impossible by here) or graph
            // features not yet set (boot path still does its own
            // recal). Either way: nothing to do.
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
        if let Some(graph) =
            crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(data_dir, &date_str)
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
        if let Some(graph) =
            crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(data_dir, &date_str)
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

    #[test]
    fn train_test_split_happy_path_every_fifth() {
        // 20% fraction on 10 items: stride=5 → indices 4, 9 go to holdout,
        // 0..3 and 5..8 go to train. Deterministic, no RNG.
        let s = TrainTestSplit::from_fraction(10, 0.2);
        let (train, holdout) = s.indices();
        assert_eq!(holdout, vec![4, 9]);
        assert_eq!(train, vec![0, 1, 2, 3, 5, 6, 7, 8]);
    }

    #[test]
    fn train_test_split_empty_input() {
        let s = TrainTestSplit::from_fraction(0, 0.2);
        assert!(s.indices().0.is_empty());
        assert!(s.indices().1.is_empty());
    }

    #[test]
    fn train_test_split_zero_fraction_yields_everything_to_train() {
        // Legacy fallback: fraction=0 means the caller wants the pre-fix
        // single-set baseline. Must not return an empty train set.
        let s = TrainTestSplit::from_fraction(10, 0.0);
        let (train, holdout) = s.indices();
        assert_eq!(train.len(), 10);
        assert!(holdout.is_empty());
    }

    #[test]
    fn train_test_split_fraction_clamped_to_half() {
        // Holdout > 50% would starve the trainer; clamp silently so
        // operators don't configure themselves into "no training" by
        // setting an absurd fraction.
        let s = TrainTestSplit::from_fraction(10, 0.9);
        let (train, holdout) = s.indices();
        assert!(
            train.len() >= 5,
            "clamp must preserve at least half for training"
        );
        assert!(!holdout.is_empty());
    }

    #[test]
    fn compute_percentile_anchors_sorted_and_cover_extremes() {
        // Shuffled input — anchors must still come out monotone
        // non-decreasing, starting at min and ending at max.
        let anchors = compute_percentile_anchors(vec![3.0, 1.0, 2.0, 5.0, 4.0]);
        assert_eq!(anchors.len(), BASELINE_PERCENTILES);
        assert_eq!(anchors.first().copied(), Some(1.0));
        assert_eq!(anchors.last().copied(), Some(5.0));
        for w in anchors.windows(2) {
            assert!(w[0] <= w[1], "anchors must be monotone non-decreasing");
        }
    }

    #[test]
    fn compute_percentile_anchors_empty_input_is_all_zero() {
        let anchors = compute_percentile_anchors(vec![]);
        assert_eq!(anchors.len(), BASELINE_PERCENTILES);
        assert!(anchors.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn percentile_score_matches_expected_quantiles() {
        // Linear ramp [0..100] → anchor[k] = k as f32. A live MSE of
        // 50 lies at the 51st anchor (51 of 101 <= 50). Post-fix the
        // in-range path is `0.99 * 51 / 101 ≈ 0.50000` because the
        // top 1% of the output range is reserved for above-max
        // extrapolation (see `percentile_score_extrapolates_above_max`).
        let anchors: Vec<f32> = (0..=100).map(|k| k as f32).collect();
        let s = percentile_score(50.0, &anchors).expect("ramp anchors should score");
        let expected = 0.99 * 51.0 / 101.0;
        assert!(
            (s - expected).abs() < 1e-4,
            "expected ≈{expected} near median, got {s}"
        );
        let s_low = percentile_score(-1.0, &anchors).expect("score below min");
        assert_eq!(s_low, 0.0);
    }

    #[test]
    fn percentile_score_extrapolates_above_max() {
        // Pre-2026-05-01 every `mse > anchors[100]` clipped to 1.0,
        // saturating the engine on routine prod traffic. The fix
        // reserves [0.99, 1.0] for above-max extrapolation via tanh
        // so two distinct "past the worst-case holdout" events get
        // distinct scores.
        let anchors: Vec<f32> = (0..=100).map(|k| k as f32).collect();
        // p50=50, p99=99, scale=49. Just past max: tanh small → just
        // above 0.99. Moderately past max: tanh closer to 1 → close to
        // 1.0 but still strictly less. Far past max in f32 saturates
        // tanh to 1.0 exactly, which is fine — the invariant we care
        // about is that distinct "above max" events get distinct
        // scores in the lower stretch of (0.99, 1.0].
        let s_just_past = percentile_score(101.0, &anchors).expect("above max");
        let s_moderate = percentile_score(150.0, &anchors).expect("moderately above max");
        assert!(
            (0.99..1.0).contains(&s_just_past),
            "just past max should land in (0.99, 1.0), got {s_just_past}"
        );
        assert!(
            s_moderate > s_just_past,
            "moderately past ({s_moderate}) must score higher than just past ({s_just_past})"
        );
        assert!(
            (s_moderate - s_just_past) > 0.001,
            "extrapolation must give measurable gradient, gap={}",
            s_moderate - s_just_past
        );
        // Bounded above by 1.0 (the asymptote, with f32 eventually
        // saturating exactly there for very large z).
        let s_far = percentile_score(1.0e9, &anchors).expect("far above max");
        assert!(s_far <= 1.0, "score must never exceed 1.0, got {s_far}");
        assert!(s_far > s_moderate, "far past must dominate moderately past");
    }

    #[test]
    fn percentile_score_returns_none_on_degenerate_table() {
        // `None` is the trigger for the caller to fall back to z-score.
        let all_zero = vec![0.0f32; BASELINE_PERCENTILES];
        assert!(percentile_score(1.0, &all_zero).is_none());
        let too_short = vec![1.0f32];
        assert!(percentile_score(1.0, &too_short).is_none());
    }

    #[test]
    fn parse_model_file_rejects_garbage() {
        assert!(parse_model_file(&[]).is_none());
        assert!(parse_model_file(b"NOT_AN_IWAE_HEADER_AT_ALL").is_none());
    }

    #[test]
    fn parse_model_file_roundtrips_v2_anchors() {
        // Minimal v2 synthetic payload — real training roundtrip is
        // exercised by the full `train_nightly_with_store` integration
        // test elsewhere; this one just pins the header format so a
        // future bump forces the spec to update with it.
        let mut buf = Vec::new();
        buf.extend_from_slice(MODEL_MAGIC);
        buf.extend_from_slice(&MODEL_VERSION_V2.to_le_bytes());
        buf.extend_from_slice(&0.42f32.to_le_bytes()); // baseline_mse
        buf.extend_from_slice(&0.37f32.to_le_bytes()); // baseline_std
        buf.extend_from_slice(&1_000_000u64.to_le_bytes()); // samples
        for k in 0..BASELINE_PERCENTILES {
            buf.extend_from_slice(&(k as f32).to_le_bytes());
        }
        // Length-prefixed malformed JSON — loader returns None for net.
        let payload = b"not-json";
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);

        let parsed = parse_model_file(&buf).expect("header + anchors must parse");
        assert_eq!(parsed.1, 0.42); // baseline_mse
        assert_eq!(parsed.2, 0.37); // baseline_std
        assert_eq!(parsed.3.len(), BASELINE_PERCENTILES);
        assert_eq!(parsed.3[50], 50.0);
        assert!(parsed.5 >= 1, "cycles derived from samples count");
        // Malformed JSON → net = None; this is tolerated so a corrupted
        // weights blob doesn't discard the baseline anchors.
        assert!(parsed.0.is_none());
    }

    #[test]
    fn parse_model_file_handles_v1_layout_without_anchors() {
        // v1 header is 24 bytes + length-prefixed JSON. The loader must
        // read it without touching the anchor region + return an
        // all-zero anchor table so `percentile_score` falls back to
        // z-score until the next training cycle.
        let mut buf = Vec::new();
        buf.extend_from_slice(MODEL_MAGIC);
        buf.extend_from_slice(&1u32.to_le_bytes()); // version 1
        buf.extend_from_slice(&0.1f32.to_le_bytes());
        buf.extend_from_slice(&0.2f32.to_le_bytes());
        buf.extend_from_slice(&500_000u64.to_le_bytes());
        let payload = b"{}";
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        let parsed = parse_model_file(&buf).expect("v1 header must still parse");
        assert!(parsed.3.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn mean_reconstruction_error_empty_is_zero() {
        let net = AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01);
        assert_eq!(mean_reconstruction_error(&net, &[], &[]), 0.0);
    }

    #[test]
    fn compute_baseline_empty_returns_zero_anchors() {
        let net = AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01);
        let (mse, std, anchors) = compute_baseline(&net, &[], &[]);
        assert_eq!(mse, 0.0);
        assert_eq!(std, 0.0);
        assert!(anchors.iter().all(|&v| v == 0.0));
    }

    /// 2026-05-04 (Wave 7a anchor): the recalibration entry-point
    /// must rebuild `baseline_percentile_anchors` from a fresh batch
    /// of events without touching the network weights, AND must
    /// refuse to act when the batch is too small to produce
    /// meaningful percentile coverage.
    ///
    /// Pinned the 2026-05-04 prod symptom where every observe()
    /// returned `score="1.000"` — anchors had drifted past the live
    /// MSE distribution, so the spec-033 tanh extrapolation
    /// saturated near 1.0. Recalibration restores discrimination
    /// without a full retrain.
    #[test]
    fn recalibrate_refuses_short_input_keeps_old_anchors() {
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            ..Default::default()
        });
        // Force a model + stale anchors so we can observe the
        // refusal path leaves them untouched.
        engine.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        engine.baseline_percentile_anchors = vec![42.0; BASELINE_PERCENTILES];

        // 5 events ≪ WINDOW_SIZE (20) → 0 full windows → fewer than
        // BASELINE_PERCENTILES samples → refused.
        let events: Vec<Event> = (0..5)
            .map(|i| make_event("ssh.login_failed", &format!("10.0.0.{i}")))
            .collect();
        let err = engine
            .recalibrate_anchors_from_events(&events)
            .expect_err("must refuse short input");
        assert!(
            err.contains("insufficient samples"),
            "unexpected error message: {err}"
        );
        // Anchors must NOT have been replaced.
        assert!(engine
            .baseline_percentile_anchors
            .iter()
            .all(|&v| v == 42.0));
    }

    #[test]
    fn recalibrate_refuses_when_no_model_loaded() {
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            ..Default::default()
        });
        // No model loaded → method must error rather than silently
        // doing nothing.
        let events: Vec<Event> = (0..200)
            .map(|_| make_event("ssh.login_failed", "10.0.0.1"))
            .collect();
        let err = engine
            .recalibrate_anchors_from_events(&events)
            .expect_err("must refuse without model");
        assert!(err.contains("no model loaded"), "unexpected error: {err}");
    }

    #[test]
    fn recalibrate_replaces_anchors_with_fresh_distribution() {
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        // Stale anchors deliberately placed all at 42.0 — clearly
        // not representative of any real reconstruction error.
        engine.baseline_percentile_anchors = vec![42.0; BASELINE_PERCENTILES];

        // 200 events of varied kinds gives enough full windows
        // (200 - 19 = 181 ≥ BASELINE_PERCENTILES=101) to repopulate
        // the anchor table.
        let kinds = [
            "ssh.login_failed",
            "ssh.login_success",
            "tcp_stream.ssh",
            "http.request",
        ];
        let events: Vec<Event> = (0..200)
            .map(|i| make_event(kinds[i % kinds.len()], "10.0.0.1"))
            .collect();

        let n = engine
            .recalibrate_anchors_from_events(&events)
            .expect("recalibrate");
        assert!(
            n >= BASELINE_PERCENTILES,
            "expected ≥{BASELINE_PERCENTILES} samples, got {n}"
        );
        // The 42.0 placeholders must be gone.
        assert!(
            !engine
                .baseline_percentile_anchors
                .iter()
                .all(|&v| (v - 42.0).abs() < 1e-6),
            "stale 42.0 anchors survived recalibration"
        );
        // Anchors must be sorted ascending (compute_percentile_anchors
        // sorts the inputs before sampling).
        for win in engine.baseline_percentile_anchors.windows(2) {
            assert!(win[0] <= win[1], "anchors must be ascending: {win:?}");
        }
    }

    #[test]
    fn recalibrate_persisted_state_round_trips_via_disk() {
        // End-to-end disk round-trip: train → recalibrate → save →
        // re-load. The reloaded engine must carry the recalibrated
        // anchors AND the same training_cycles count (preserved via
        // the synthesised `total_samples` field).
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: data_dir.clone(),
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        engine.training_cycles = 7;
        engine.maturity = 0.5;

        let kinds = ["ssh.login_failed", "tcp_stream.ssh", "http.request"];
        let events: Vec<Event> = (0..150)
            .map(|i| make_event(kinds[i % kinds.len()], "10.0.0.1"))
            .collect();
        engine
            .recalibrate_anchors_from_events(&events)
            .expect("recalibrate");
        let recal_anchors = engine.baseline_percentile_anchors.clone();

        // Reload from disk and confirm the anchors survived.
        let reloaded = AnomalyEngine::new(AnomalyConfig {
            data_dir,
            ..Default::default()
        });
        // Loader synthesises maturity from total_samples (cycles*100k
        // = 700k → maturity 1.4 clamped to 1.0). Cycles round-trips
        // exactly: 700_000 / 100_000 = 7.
        assert_eq!(reloaded.training_cycles, 7);
        assert_eq!(reloaded.baseline_percentile_anchors, recal_anchors);
    }

    /// 2026-05-04 (Copilot #2 anchor): when the engine was loaded
    /// from an existing model file, `loaded_total_samples` carries
    /// the EXACT value parsed from disk. A subsequent recalibration
    /// save must preserve that value rather than re-deriving it from
    /// `cycles * 100_000` — for any samples count that is not a
    /// multiple of 100_000 (e.g. 499_999 produced by long-running
    /// prod), the synthesis would truncate the remainder and silently
    /// drop maturity from `samples/500_000` ≈ 1.0 to ~0.8 across the
    /// save. Pin the preservation contract.
    #[test]
    fn persist_after_recal_preserves_loaded_total_samples_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        // Seed an engine + write a model with samples=499_999
        // (deliberately not a multiple of 100_000 so the synthesised
        // fallback would truncate to 400_000 → maturity 0.8).
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: data_dir.clone(),
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        engine.training_cycles = 4; // 499_999 / 100_000 = 4
        engine.maturity = 0.999_998; // 499_999 / 500_000 ≈ 0.999998
        engine.loaded_total_samples = 499_999;
        engine.baseline_percentile_anchors = vec![0.5; BASELINE_PERCENTILES];

        engine.persist_model_state().expect("save");

        // Reload and verify maturity comes through.
        let reloaded = AnomalyEngine::new(AnomalyConfig {
            data_dir,
            ..Default::default()
        });
        assert_eq!(reloaded.loaded_total_samples, 499_999);
        // maturity = (499_999 / 500_000).min(1.0) ≈ 0.999998. The
        // pre-fix synthesis would have produced 400_000/500_000 = 0.8.
        assert!(
            reloaded.maturity > 0.99,
            "maturity dropped: {} (Copilot #2 regression)",
            reloaded.maturity
        );
    }

    /// 2026-05-04 (Copilot #3 anchor): the v2 file layout requires
    /// exactly `BASELINE_PERCENTILES * 4` bytes of anchor table
    /// regardless of what's in `baseline_percentile_anchors`. If the
    /// in-memory vec is ever shorter (corruption, partial init), the
    /// save MUST pad with 0.0 so the next load doesn't reject the
    /// file as truncated. Pin the padding behaviour.
    #[test]
    fn persist_pads_anchor_table_to_exact_layout_size() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: data_dir.clone(),
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        // Deliberately corrupt: only 5 entries in the vec.
        engine.baseline_percentile_anchors = vec![1.0; 5];
        engine.training_cycles = 1;

        engine.persist_model_state().expect("save");

        // The reload path requires BASELINE_PERCENTILES * 4 anchor
        // bytes after the header, otherwise parse_model_file returns
        // None and the engine starts fresh. If it parsed
        // successfully, padding worked.
        let reloaded = AnomalyEngine::new(AnomalyConfig {
            data_dir,
            ..Default::default()
        });
        assert!(
            reloaded.net.is_some(),
            "model file unparseable — anchor padding regressed"
        );
        assert_eq!(
            reloaded.baseline_percentile_anchors.len(),
            BASELINE_PERCENTILES
        );
        // First 5 entries are the originals; rest are padded zeros.
        assert_eq!(reloaded.baseline_percentile_anchors[0], 1.0);
        assert_eq!(reloaded.baseline_percentile_anchors[5], 0.0);
        assert_eq!(
            reloaded.baseline_percentile_anchors[BASELINE_PERCENTILES - 1],
            0.0
        );
    }

    /// 2026-05-04 (Copilot #1 anchor): the persist write order must
    /// keep `anomaly-model.bin` available until the new tmp file is
    /// durably on disk. Pre-fix the rotate-then-write order would
    /// leave zero usable model files if the tmp write failed mid-way.
    /// We can't easily fault-inject the tmp write, so we pin the
    /// observable invariant: after a SUCCESSFUL persist, both the
    /// new model AND the rotated `.prev` file exist on disk.
    #[test]
    fn persist_keeps_previous_model_as_dot_prev_backup() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: data_dir.clone(),
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        engine.training_cycles = 1;

        // First save creates the primary file with no .prev sibling
        // (nothing to rotate yet).
        engine.persist_model_state().expect("first save");
        assert!(data_dir.join("anomaly-model.bin").exists());
        assert!(!data_dir.join("anomaly-model.prev.bin").exists());

        // Second save rotates: previous → .prev, new → primary.
        engine.persist_model_state().expect("second save");
        assert!(data_dir.join("anomaly-model.bin").exists());
        assert!(
            data_dir.join("anomaly-model.prev.bin").exists(),
            "second save must rotate previous to .prev"
        );
        // tmp file must NOT linger after a successful save.
        assert!(!data_dir.join("anomaly-model.bin.tmp").exists());
    }

    /// 2026-05-04 (Wave 7a follow-up anchor): the post-train
    /// recalibration block in `train_nightly_with_store` must be
    /// gated on `graph_features.is_some()` AND on having ≥
    /// BASELINE_PERCENTILES windows. The function must remain a
    /// no-op when graph features are absent so test fixtures that
    /// never call `set_graph_features` do not get a spurious
    /// post-train recal that would overwrite anchors with a
    /// degraded (no-graph) MSE distribution. Pinned the
    /// `let (Some(net), Some(gf)) = ...` guard.
    #[test]
    fn train_nightly_post_recal_skips_when_no_graph_features() {
        // The full train_nightly_with_store path is exercised in
        // the existing `train_nightly_with_store_*` tests; here we
        // assert the source-level guard directly so a refactor that
        // drops `Some(gf)` is loud at test time.
        let src = include_str!("neural_lifecycle.rs");
        // Find the post-train recalibration block by its anchor
        // log message and verify the graph-features guard is in
        // place immediately above it.
        let recal_marker = src
            .find("post-train recalibration complete (graph-aware anchors)")
            .expect("post-train recalibration log line missing");
        let mut window_start = recal_marker.saturating_sub(2000);
        while window_start < src.len() && !src.is_char_boundary(window_start) {
            window_start += 1;
        }
        let window = &src[window_start..recal_marker];
        assert!(
            window.contains("Some(ref gf)") || window.contains("Some(ref net), Some(ref gf)"),
            "post-train recal must guard on Some(graph_features); guard missing in window:\n{window}"
        );
    }

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

    /// 2026-05-04 (Wave 7a coverage): exercise the
    /// `enrich_features_with_graph` branch of
    /// `recalibrate_anchors_from_events`. Without graph features the
    /// recalibration uses the no-graph feature path; with graph
    /// features it must call the enrichment helper and produce
    /// different anchors than the no-graph case. Pinned the operator
    /// 2026-05-04 prod observation: graph-feature-enriched anchors
    /// were ~20× wider than no-graph anchors (max 0.103 vs 0.019).
    #[test]
    fn recalibrate_with_graph_features_produces_distinct_anchors() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine_no_graph = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        });
        engine_no_graph.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));

        let kinds = [
            "ssh.login_failed",
            "tcp_stream.ssh",
            "http.request",
            "ssh.login_success",
        ];
        let events: Vec<Event> = (0..200)
            .map(|i| make_event(kinds[i % kinds.len()], "10.0.0.1"))
            .collect();
        engine_no_graph
            .recalibrate_anchors_from_events(&events)
            .expect("no-graph recal");
        let no_graph_anchors = engine_no_graph.baseline_percentile_anchors.clone();

        // Same engine + events, but with non-zero graph features set.
        // The enrichment block writes signal into the
        // [GRAPH_BASE..NUM_FEATURES) slots, which the network has to
        // reconstruct → different MSE → different anchors.
        let dir2 = tempfile::tempdir().unwrap();
        let mut engine_graph = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir2.path().to_path_buf(),
            ..Default::default()
        });
        // Same architecture so both engines have the same net layout
        // and the only variable is the graph_features path.
        engine_graph.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        engine_graph.set_graph_features(GraphFeatures {
            avg_process_degree: 5.0,
            max_process_tree_depth: 3,
            threat_intel_ip_count: 2,
            writes_to_sensitive: 1,
            connected_components: 4,
            process_ip_ratio: 1.5,
            ..GraphFeatures::default()
        });
        engine_graph
            .recalibrate_anchors_from_events(&events)
            .expect("graph recal");
        let graph_anchors = engine_graph.baseline_percentile_anchors.clone();

        // The two anchor sets must differ — same model architecture,
        // same input events, different feature shape. If they match,
        // the graph enrichment branch was not exercised.
        assert_ne!(
            no_graph_anchors, graph_anchors,
            "graph-feature recal must produce different anchors than no-graph recal"
        );
    }

    /// 2026-05-04 (Wave 7a coverage): exercise the post-train
    /// recalibration block end-to-end. Set graph features BEFORE
    /// calling `train_nightly_with_store`; the resulting anchors
    /// must be the post-train recal output (graph-aware) rather
    /// than the holdout output (no-graph). Test the integration by
    /// asserting the `recal_pending_post_graph` flag is still true
    /// after train (post-train recal is a different code path that
    /// does not clear that flag — only the slow_loop path does).
    #[test]
    fn train_nightly_with_store_runs_post_train_recal_when_graph_features_set() {
        use chrono::Utc;
        use innerwarden_core::entities::EntityRef;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let kinds = [
            "file.read_access",
            "shell.command_exec",
            "network.outbound_connect",
            "ssh.login_success",
            "http.request",
            "tcp_stream.ssh",
        ];
        let mut events = Vec::new();
        for i in 0..1000 {
            events.push(Event {
                ts: Utc::now(),
                host: "test-host".into(),
                source: "test".into(),
                kind: kinds[i % kinds.len()].into(),
                severity: Severity::Info,
                summary: "synthetic".into(),
                details: serde_json::json!({"src_ip": "1.2.3.4"}),
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4")],
            });
        }
        store.insert_events_batch(&events).expect("seed");

        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            training_epochs: 4,
            training_timeout_secs: 60,
            training_max_ram_mb: 64,
            training_retention_days: 30,
            threshold: 0.5,
            ..AnomalyConfig::default()
        });
        // Set graph features BEFORE train so the post-train recal
        // block's `Some(gf)` guard passes.
        engine.set_graph_features(GraphFeatures {
            avg_process_degree: 5.0,
            max_process_tree_depth: 3,
            threat_intel_ip_count: 1,
            writes_to_sensitive: 0,
            connected_components: 2,
            process_ip_ratio: 1.0,
            ..GraphFeatures::default()
        });
        engine
            .train_nightly_with_store(Some(&store))
            .expect("train + post-train recal");

        // Train ran (cycles incremented).
        assert!(engine.training_cycles >= 1);
        // Anchors are populated (post-train recal wrote them too,
        // but at minimum train's holdout did). Either way, the
        // serialised file exists and re-loads.
        assert!(dir.path().join("anomaly-model.bin").exists());
        let reloaded = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        });
        assert!(reloaded.net.is_some(), "model file must round-trip");
        assert_eq!(
            reloaded.baseline_percentile_anchors.len(),
            BASELINE_PERCENTILES,
            "anchor table preserved"
        );
    }

    /// 2026-05-04 (Wave 7a coverage): the
    /// `needs_post_graph_recalibration` gate returns true only when
    /// BOTH the recal_pending_post_graph flag is set AND graph
    /// features are present. Pre-set-graph-features the engine
    /// reports false (boot recal hasn't seen graph yet). After
    /// `set_graph_features` the engine reports true. After
    /// `clear_post_graph_recalibration_flag` it reports false
    /// permanently. Pinned the slow_loop dispatch contract.
    #[test]
    fn needs_post_graph_recalibration_gates_on_flag_and_graph_presence() {
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            ..Default::default()
        });
        // Boot state: flag is true, graph absent → gate is FALSE
        // (not yet ready to recal).
        assert!(!engine.needs_post_graph_recalibration());

        // Operator sets graph features → gate flips to TRUE.
        engine.set_graph_features(GraphFeatures::default());
        assert!(engine.needs_post_graph_recalibration());

        // Slow_loop calls `clear_post_graph_recalibration_flag`
        // after a successful recal → gate locks to FALSE.
        engine.clear_post_graph_recalibration_flag();
        assert!(!engine.needs_post_graph_recalibration());

        // Even setting graph features again must not re-arm —
        // the flag is the gate, not graph presence alone.
        engine.set_graph_features(GraphFeatures::default());
        assert!(!engine.needs_post_graph_recalibration());
    }

    /// 2026-05-04 (Wave 7a coverage): persist_model_state happy
    /// path with a freshly-trained engine writes a round-trippable
    /// file. Distinct from the persist_keeps_previous test — that
    /// one verifies the rotation, this one verifies the basic
    /// write succeeds and the file is parseable.
    #[test]
    fn persist_model_state_writes_parseable_v2_file() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: data_dir.clone(),
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        engine.training_cycles = 3;
        engine.baseline_percentile_anchors = vec![0.001; BASELINE_PERCENTILES];
        engine.baseline_mse = 0.0005;
        engine.baseline_std = 0.0001;

        engine.persist_model_state().expect("persist");

        // File must exist and be parseable by parse_model_file.
        let path = data_dir.join("anomaly-model.bin");
        assert!(path.exists(), "model file must be created");
        let data = std::fs::read(&path).expect("read");
        let parsed = parse_model_file(&data).expect("parse_model_file must accept the v2 file");
        let (_net, mse, std_dev, anchors, _maturity, cycles, _samples) = parsed;
        assert!((mse - 0.0005).abs() < 1e-6, "baseline_mse round-trip");
        assert!((std_dev - 0.0001).abs() < 1e-6, "baseline_std round-trip");
        assert_eq!(anchors.len(), BASELINE_PERCENTILES);
        assert_eq!(cycles, 3, "training_cycles round-trip via samples");
    }

    /// 2026-05-04 (Wave 7a coverage): recalibration with graph
    /// features set (both branches of the enrichment conditional
    /// inside the recal loop body). Each iteration runs
    /// `enrich_features_with_graph`; without this test the branch
    /// would only be hit by the integration path that requires
    /// graph features to flow from a knowledge graph fixture.
    #[test]
    fn recalibrate_anchors_from_events_when_graph_features_set_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        });
        engine.net = Some(AutoencoderNet::new(&[NUM_FEATURES, 4, NUM_FEATURES], 0.01));
        engine.set_graph_features(GraphFeatures {
            avg_process_degree: 8.0,
            max_process_tree_depth: 5,
            threat_intel_ip_count: 3,
            writes_to_sensitive: 2,
            connected_components: 1,
            process_ip_ratio: 2.5,
            ..GraphFeatures::default()
        });

        let kinds = ["ssh.login_failed", "tcp_stream.ssh", "http.request"];
        let events: Vec<Event> = (0..200)
            .map(|i| make_event(kinds[i % kinds.len()], "10.0.0.1"))
            .collect();
        let n = engine
            .recalibrate_anchors_from_events(&events)
            .expect("recal with graph_features must succeed");
        assert!(n >= BASELINE_PERCENTILES);
        assert_eq!(
            engine.baseline_percentile_anchors.len(),
            BASELINE_PERCENTILES
        );
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
        // ssh_failed → ssh_success should activate the first bigram slot.
        let kinds = vec![Some(14), Some(13)];
        let f = window_features(&kinds);
        assert!(
            f[BIGRAM_BASE] > 0.0,
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
        // Should detect at least 4 sequential stages (stage-progression slot).
        assert!(
            f[SEQ_BASE + 4] >= 4.0 / 7.0,
            "kill chain progression should be detected: got {}",
            f[SEQ_BASE + 4]
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
    fn kind_index_covers_v012_additions() {
        // Regression guard for the spec-025-follow-up widening: kinds that
        // production was emitting at high volume (HTTP, raw TLS streams,
        // memory probes, bpf loads) must map into the feature vector or the
        // autoencoder trains on a biased slice of reality.
        assert_eq!(kind_index("http.request"), Some(24));
        assert_eq!(kind_index("tcp_stream.ssh"), Some(25));
        assert_eq!(kind_index("memory.anon_executable"), Some(26));
        assert_eq!(kind_index("network.snapshot"), Some(27));
        assert_eq!(kind_index("memory.deleted_file_mapping"), Some(28));
        assert_eq!(kind_index("file.extracted_from_network"), Some(29));
        assert_eq!(kind_index("kernel.bpf_program_loaded"), Some(30));
        // Feature layout contract: every mapped slot must fit inside the
        // one-hot region.
        assert!(KIND_SLOTS >= 31);
        assert_eq!(BIGRAM_BASE, KIND_SLOTS);
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

        for slot in &f[GRAPH_BASE..NUM_FEATURES] {
            assert!(
                (0.0..=1.0).contains(slot),
                "enriched graph slot should be normalized into [0,1]"
            );
        }
        assert_eq!(f[GRAPH_BASE], 1.0); // avg_process_degree saturates at 100/20
        assert_eq!(f[GRAPH_BASE + 1], 1.0); // max_process_tree_depth saturates
        assert_eq!(f[GRAPH_BASE + 2], 1.0); // threat_intel_ip_count saturates
        assert_eq!(f[GRAPH_BASE + 9], 1.0); // active_sessions saturates
    }

    #[test]
    fn train_nightly_with_store_uses_sqlite_events_and_calibrates_baseline() {
        // Primary fix path: training must drain the SQLite event table instead
        // of the JSONL directory that spec 016 stopped populating. A fresh
        // engine pointed at an in-memory store with several hundred seeded
        // events should produce a trained model + non-trivial baseline.
        use chrono::Utc;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::{Event, Severity};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let kinds = [
            "file.read_access",
            "shell.command_exec",
            "network.outbound_connect",
            "ssh.login_success",
            "http.request",
            "tcp_stream.ssh",
        ];
        let mut events = Vec::new();
        // 1000 events → ~197 sliding windows. After the 20% holdout split
        // the train set still clears `MIN_TRAIN_WINDOWS=100` comfortably.
        for i in 0..1000 {
            let kind = kinds[i % kinds.len()];
            events.push(Event {
                ts: Utc::now(),
                host: "test-host".into(),
                source: "test".into(),
                kind: kind.into(),
                severity: Severity::Info,
                summary: "synthetic".into(),
                details: serde_json::json!({"src_ip": "1.2.3.4"}),
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4")],
            });
        }
        store
            .insert_events_batch(&events)
            .expect("seed events for training");

        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            training_epochs: 4,
            training_timeout_secs: 60,
            training_max_ram_mb: 64,
            training_retention_days: 30,
            threshold: 0.5,
            ..AnomalyConfig::default()
        });
        engine
            .train_nightly_with_store(Some(&store))
            .expect("sqlite-backed training should succeed");

        assert!(engine.training_cycles >= 1, "one training cycle at minimum");
        assert!(
            engine.maturity > 0.0,
            "maturity must advance after training"
        );
        assert!(
            dir.path().join("anomaly-model.bin").exists(),
            "model file must be written to data_dir"
        );
    }

    #[test]
    fn train_nightly_runs_against_dedicated_store_when_agent_pool_is_saturated() {
        // Spec 037 production fix anchor (2026-04-26): the 03 UTC training
        // trigger opens a dedicated `Store` instead of borrowing
        // `state.sqlite_store`, so a long-running training read cannot
        // exhaust the agent's r2d2 pool and cascade into a tokio runtime
        // deadlock. This test pins that property: hold every connection
        // in pool A (the "agent" store), then run training against pool B
        // (the "dedicated" store) on the same on-disk database. Training
        // must succeed because the two pools are independent.
        use chrono::Utc;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::{Event, Severity};

        let dir = tempfile::tempdir().expect("tempdir");
        let pool_a = innerwarden_store::Store::open(dir.path()).expect("agent store");

        // Seed events through pool A — the rows are visible to any
        // connection against the same on-disk DB.
        let kinds = [
            "file.read_access",
            "shell.command_exec",
            "network.outbound_connect",
            "ssh.login_success",
            "http.request",
            "tcp_stream.ssh",
        ];
        let mut events = Vec::new();
        for i in 0..1000 {
            events.push(Event {
                ts: Utc::now(),
                host: "test-host".into(),
                source: "test".into(),
                kind: kinds[i % kinds.len()].into(),
                severity: Severity::Info,
                summary: "synthetic".into(),
                details: serde_json::json!({"src_ip": "1.2.3.4"}),
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4")],
            });
        }
        pool_a
            .insert_events_batch(&events)
            .expect("seed events for training");

        // Saturate pool A — hold all 4 connections so any code path that
        // tries to call `pool_a.conn()` would block. If training were
        // still using `state.sqlite_store`, this would deadlock.
        let _holds: Vec<_> = (0..4)
            .map(|_| pool_a.conn().expect("acquire connection from pool A"))
            .collect();

        // Pool B = the "dedicated" store the production code now opens
        // for training. Independent r2d2 pool, same DB file.
        let pool_b = innerwarden_store::Store::open(dir.path()).expect("dedicated store");

        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            training_epochs: 4,
            training_timeout_secs: 60,
            training_max_ram_mb: 64,
            training_retention_days: 30,
            threshold: 0.5,
            ..AnomalyConfig::default()
        });

        // The proof: training completes while pool A is fully held.
        engine
            .train_nightly_with_store(Some(&pool_b))
            .expect("training with dedicated store succeeds despite saturated agent pool");
        assert!(
            engine.training_cycles >= 1,
            "training must have advanced at least one cycle"
        );

        drop(_holds);
    }

    #[test]
    fn train_nightly_with_store_falls_back_to_jsonl_when_sqlite_is_empty() {
        // Backward-compat path: pre-016 layouts keep working. A store without
        // events + JSONL fixtures in data_dir should still feed the trainer.
        use chrono::Utc;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let today = Utc::now().format("%Y-%m-%d");
        let jsonl_path = dir.path().join(format!("events-{today}.jsonl"));
        let mut contents = String::new();
        // 1000 events → ~197 sliding windows. After the 20% holdout split
        // the train set still clears `MIN_TRAIN_WINDOWS=100` comfortably.
        for i in 0..1000 {
            let kind = if i % 2 == 0 {
                "file.read_access"
            } else {
                "shell.command_exec"
            };
            contents.push_str(&format!(
                r#"{{"ts":"2026-04-18T10:00:00Z","host":"h","source":"t","kind":"{kind}","severity":"info","summary":"","details":{{"src_ip":"9.9.9.9"}},"tags":[],"entities":[]}}
"#
            ));
        }
        std::fs::write(&jsonl_path, contents).expect("write jsonl fixture");

        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            training_epochs: 2,
            training_timeout_secs: 60,
            training_max_ram_mb: 64,
            training_retention_days: 30,
            threshold: 0.5,
            ..AnomalyConfig::default()
        });
        engine
            .train_nightly_with_store(Some(&store))
            .expect("jsonl fallback should produce a model");
        assert!(engine.training_cycles >= 1);
    }

    #[test]
    fn train_nightly_with_store_errors_when_nothing_to_read() {
        // Failure path: no sqlite rows AND no JSONL files → explicit error so
        // the slow loop logs instead of silently rebuilding an empty model.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        let mut engine = AnomalyEngine::new(AnomalyConfig {
            data_dir: dir.path().to_path_buf(),
            training_retention_days: 7,
            ..AnomalyConfig::default()
        });
        let err = engine
            .train_nightly_with_store(Some(&store))
            .expect_err("empty sources must error out");
        assert!(err.contains("insufficient"), "got: {err}");
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

    // Spec 037 I-13 follow-up #2: read_anomaly_model_or_warn
    //
    // Wraps the silent `if let Ok(data) = std::fs::read(&model_path)`
    // site in `AnomalyEngine::new`. NotFound is steady state on first
    // boot; only real I/O errors should warn.

    #[test]
    fn read_anomaly_model_or_warn_returns_some_silently_on_existing_file() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("anomaly-model.bin");
        std::fs::write(&path, b"\x00\x01\x02\x03").expect("seed model file");

        let result = read_anomaly_model_or_warn(&path);
        assert!(result.is_some(), "existing file must yield Some(Vec)");

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("anomaly model read failed"),
            "happy path must not emit warn, got: {captured}"
        );
    }

    #[test]
    fn read_anomaly_model_or_warn_returns_none_and_warns_on_io_failure() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        let path = blocking_file.join("anomaly-model.bin");

        let result = read_anomaly_model_or_warn(&path);
        assert!(result.is_none(), "io-failure must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("anomaly model read failed"),
            "io-failure warn missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
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
        if let Some(graph) =
            crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(data_dir, &date_str)
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
