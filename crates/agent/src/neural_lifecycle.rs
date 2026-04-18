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
);

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
    Some((net, baseline_mse, baseline_std, anchors, maturity, cycles))
}

/// Rank a live reconstruction error against the baseline percentile
/// anchors. Returns `Some(0.0..=1.0)`: 0 = better than everything,
/// 1 = worse than everything. Degenerate tables (empty or all-zero)
/// return `None` so the caller can fall back to the legacy z-score
/// path during the transition period.
pub(crate) fn percentile_score(mse: f32, anchors: &[f32]) -> Option<f32> {
    if anchors.len() < 2 {
        return None;
    }
    if !anchors.iter().any(|&x| x > 0.0) {
        return None;
    }
    let below = anchors.iter().filter(|&&a| a <= mse).count();
    Some(below as f32 / anchors.len() as f32)
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
}

impl AnomalyEngine {
    /// Create a new anomaly engine, attempting to load a saved model.
    pub fn new(config: AnomalyConfig) -> Self {
        let model_path = config.data_dir.join("anomaly-model.bin");
        let (net, baseline_mse, baseline_std, anchors, maturity, cycles) =
            if let Ok(data) = std::fs::read(&model_path) {
                parse_model_file(&data).unwrap_or_else(|| {
                    info!("anomaly: existing model rejected by loader, starting fresh");
                    (None, 0.0, 1.0, vec![0.0; BASELINE_PERCENTILES], 0.0, 0)
                })
            } else {
                info!("anomaly: no saved model found, starting fresh (observation mode)");
                (None, 0.0, 1.0, vec![0.0; BASELINE_PERCENTILES], 0.0, 0)
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
                    let ip = ev.get("details").and_then(|d| {
                        d.get("src_ip")
                            .or_else(|| d.get("ip"))
                            .and_then(|v| v.as_str())
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
        // Linear ramp [0..100] → anchor[k] = k as f32. A live MSE of 50
        // lies at the 51st anchor (51 of 101 <= 50) → score ≈ 0.505.
        let anchors: Vec<f32> = (0..=100).map(|k| k as f32).collect();
        let s = percentile_score(50.0, &anchors).expect("ramp anchors should score");
        assert!(
            (s - 0.505).abs() < 1e-4,
            "expected ≈0.505 at median, got {s}"
        );
        let s_low = percentile_score(-1.0, &anchors).expect("score below min");
        assert_eq!(s_low, 0.0);
        let s_high = percentile_score(200.0, &anchors).expect("score above max");
        assert_eq!(s_high, 1.0);
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
