//! Trace of the Times — rootkit detection through kernel function timing anomalies.
//!
//! Based on: Landauer et al. (2025), arXiv:2503.02402, 98.7% F1 score.
//!
//! Rootkits hook kernel functions (filldir64, iterate_dir, tcp4_seq_show).
//! Hooks add code → code takes time → execution time distribution shifts.
//! By measuring function execution times and comparing against a baseline,
//! we detect the timing shift with high confidence.
//!
//! # Detection Method
//!
//! 1. Collect N timing samples per kernel function (entry→return delta)
//! 2. Compute quantile distribution (9 equidistant quantiles: 0.11→0.89)
//! 3. Compare against baseline using Mahalanobis distance
//! 4. Convert to p-value via chi-squared test
//! 5. p-value < threshold → anomaly (rootkit hook detected)
//!
//! The key insight: we don't compare means (too noisy). We compare the
//! SHAPE of the distribution via quantiles. A rootkit shifts the entire
//! distribution right, which changes multiple quantiles simultaneously.

use crate::{confidence, CheckResult, CheckStatus};

/// Number of quantiles to extract from each distribution.
/// Paper uses 9 (equidistant from 0.11 to 0.89).
pub const NUM_QUANTILES: usize = 9;

/// Quantile positions (avoid 0.0 and 1.0 for robustness against outliers).
pub const QUANTILE_POSITIONS: [f64; NUM_QUANTILES] =
    [0.11, 0.22, 0.33, 0.44, 0.56, 0.67, 0.78, 0.89, 0.95];

/// Default p-value threshold for anomaly detection.
/// Paper found 10^-10 optimal. We use 10^-8 for slightly more sensitivity.
pub const DEFAULT_THRESHOLD: f64 = 1e-8;

/// Minimum samples needed for reliable statistical analysis.
pub const MIN_SAMPLES: usize = 100;

/// A batch of timing measurements for a single kernel function.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimingBatch {
    /// Kernel function name (e.g., "filldir64", "iterate_dir").
    pub function: String,
    /// Delta times in nanoseconds (entry→return for each call).
    pub deltas_ns: Vec<u64>,
}

/// Quantile profile extracted from a timing batch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantileProfile {
    pub function: String,
    /// Quantile values at the standard positions.
    pub quantiles: [f64; NUM_QUANTILES],
    /// Number of samples used.
    pub sample_count: usize,
}

/// Baseline model — mean quantile profile + covariance for each function.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimingModel {
    /// When the model was built.
    pub built_at: String,
    /// Per-function baseline profiles.
    pub functions: Vec<FunctionModel>,
}

/// Baseline model for a single kernel function.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionModel {
    pub function: String,
    /// Mean quantile values (from training batches).
    pub mean_quantiles: [f64; NUM_QUANTILES],
    /// Inverse covariance matrix (flattened NUM_QUANTILES x NUM_QUANTILES).
    /// Used for Mahalanobis distance. None if only 1 training batch.
    pub inv_covariance: Option<Vec<f64>>,
    /// Number of training batches used.
    pub training_batches: usize,
    /// Variance of each quantile (diagonal of covariance, for fallback detection).
    pub quantile_variances: [f64; NUM_QUANTILES],
}

/// Result of analyzing a timing batch against the model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimingAnalysis {
    pub function: String,
    /// Mahalanobis distance (higher = more anomalous).
    pub mahalanobis_d2: f64,
    /// p-value from chi-squared test (lower = more anomalous).
    pub p_value: f64,
    /// Whether this is flagged as anomalous.
    pub anomalous: bool,
    /// Per-quantile z-scores (how many stddevs from baseline).
    pub quantile_z_scores: [f64; NUM_QUANTILES],
    /// Maximum z-score across quantiles.
    pub max_z_score: f64,
}

// ── Quantile extraction ─────────────────────────────────────────────────

/// Extract quantile profile from a batch of timing deltas.
pub fn extract_quantiles(batch: &TimingBatch) -> Option<QuantileProfile> {
    if batch.deltas_ns.len() < MIN_SAMPLES {
        return None;
    }

    let mut sorted: Vec<f64> = batch.deltas_ns.iter().map(|&d| d as f64).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = sorted.len();
    let mut quantiles = [0.0f64; NUM_QUANTILES];
    for (i, &pos) in QUANTILE_POSITIONS.iter().enumerate() {
        let idx = ((n as f64) * pos) as usize;
        quantiles[i] = sorted[idx.min(n - 1)];
    }

    Some(QuantileProfile {
        function: batch.function.clone(),
        quantiles,
        sample_count: n,
    })
}

// ── Model building ──────────────────────────────────────────────────────

/// Build a timing model from multiple training batches.
pub fn build_model(training_batches: &[Vec<TimingBatch>]) -> TimingModel {
    // Group batches by function name.
    let mut by_function: std::collections::BTreeMap<String, Vec<QuantileProfile>> =
        std::collections::BTreeMap::new();

    for batch_set in training_batches {
        for batch in batch_set {
            if let Some(profile) = extract_quantiles(batch) {
                by_function
                    .entry(profile.function.clone())
                    .or_default()
                    .push(profile);
            }
        }
    }

    let mut functions = Vec::new();
    for (func_name, profiles) in &by_function {
        let n = profiles.len();
        if n == 0 {
            continue;
        }

        // Compute mean quantiles.
        let mut mean = [0.0f64; NUM_QUANTILES];
        for p in profiles {
            for i in 0..NUM_QUANTILES {
                mean[i] += p.quantiles[i];
            }
        }
        for m in &mut mean {
            *m /= n as f64;
        }

        // Compute variance per quantile (diagonal of covariance).
        let mut variance = [0.0f64; NUM_QUANTILES];
        if n > 1 {
            for p in profiles {
                for i in 0..NUM_QUANTILES {
                    let diff = p.quantiles[i] - mean[i];
                    variance[i] += diff * diff;
                }
            }
            for v in &mut variance {
                *v /= (n - 1) as f64;
                // Prevent zero variance (would cause division by zero).
                if *v < 1.0 {
                    *v = 1.0;
                }
            }
        } else {
            // Single batch: use 10% of mean as default variance.
            for i in 0..NUM_QUANTILES {
                variance[i] = (mean[i] * 0.1).max(1.0);
            }
        }

        // Full covariance matrix (for Mahalanobis distance).
        let inv_cov = if n >= NUM_QUANTILES + 1 {
            compute_inv_covariance(profiles)
        } else {
            None
        };

        functions.push(FunctionModel {
            function: func_name.clone(),
            mean_quantiles: mean,
            inv_covariance: inv_cov,
            training_batches: n,
            quantile_variances: variance,
        });
    }

    TimingModel {
        built_at: ::chrono::Utc::now().to_rfc3339(),
        functions,
    }
}

/// Compute inverse covariance matrix from quantile profiles.
/// Returns None if matrix is singular or not enough data.
fn compute_inv_covariance(profiles: &[QuantileProfile]) -> Option<Vec<f64>> {
    let n = profiles.len();
    let q = NUM_QUANTILES;

    if n < q + 1 {
        return None; // need more samples than dimensions
    }

    // Compute mean.
    let mut mean = [0.0f64; NUM_QUANTILES];
    for p in profiles {
        for i in 0..q {
            mean[i] += p.quantiles[i];
        }
    }
    for m in &mut mean {
        *m /= n as f64;
    }

    // Compute covariance matrix (q x q, stored as flat Vec).
    let mut cov = vec![0.0f64; q * q];
    for p in profiles {
        for i in 0..q {
            for j in 0..q {
                cov[i * q + j] += (p.quantiles[i] - mean[i]) * (p.quantiles[j] - mean[j]);
            }
        }
    }
    for c in &mut cov {
        *c /= (n - 1) as f64;
    }

    // Add regularization to prevent singularity.
    for i in 0..q {
        cov[i * q + i] += 1.0; // ridge regularization
    }

    // Invert via Gauss-Jordan elimination (small 9x9 matrix).
    invert_matrix(&cov, q)
}

/// Gauss-Jordan matrix inversion for small matrices.
fn invert_matrix(mat: &[f64], n: usize) -> Option<Vec<f64>> {
    let mut aug = vec![0.0f64; n * 2 * n];

    // Build augmented matrix [mat | I].
    for i in 0..n {
        for j in 0..n {
            aug[i * 2 * n + j] = mat[i * n + j];
        }
        aug[i * 2 * n + n + i] = 1.0;
    }

    // Forward elimination.
    for col in 0..n {
        // Find pivot.
        let mut max_row = col;
        let mut max_val = aug[col * 2 * n + col].abs();
        for row in (col + 1)..n {
            let val = aug[row * 2 * n + col].abs();
            if val > max_val {
                max_val = val;
                max_row = row;
            }
        }
        if max_val < 1e-12 {
            return None; // singular
        }

        // Swap rows.
        if max_row != col {
            for j in 0..(2 * n) {
                let tmp = aug[col * 2 * n + j];
                aug[col * 2 * n + j] = aug[max_row * 2 * n + j];
                aug[max_row * 2 * n + j] = tmp;
            }
        }

        // Scale pivot row.
        let pivot = aug[col * 2 * n + col];
        for j in 0..(2 * n) {
            aug[col * 2 * n + j] /= pivot;
        }

        // Eliminate column.
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = aug[row * 2 * n + col];
            for j in 0..(2 * n) {
                aug[row * 2 * n + j] -= factor * aug[col * 2 * n + j];
            }
        }
    }

    // Extract inverse from right half.
    let mut inv = vec![0.0f64; n * n];
    for i in 0..n {
        for j in 0..n {
            inv[i * n + j] = aug[i * 2 * n + n + j];
        }
    }

    Some(inv)
}

// ── Anomaly detection ───────────────────────────────────────────────────

/// Analyze a timing batch against the model.
pub fn detect_anomaly(
    batch: &TimingBatch,
    model: &FunctionModel,
    threshold: f64,
) -> Option<TimingAnalysis> {
    let profile = extract_quantiles(batch)?;

    // Compute per-quantile z-scores (simple fallback).
    let mut z_scores = [0.0f64; NUM_QUANTILES];
    for i in 0..NUM_QUANTILES {
        let diff = profile.quantiles[i] - model.mean_quantiles[i];
        let stddev = model.quantile_variances[i].sqrt();
        z_scores[i] = if stddev > 0.0 { diff / stddev } else { 0.0 };
    }
    let max_z = z_scores.iter().fold(0.0f64, |a, &b| a.max(b.abs()));

    // Compute Mahalanobis distance.
    let (d2, p_value) = if let Some(ref inv_cov) = model.inv_covariance {
        mahalanobis_d2(&profile.quantiles, &model.mean_quantiles, inv_cov)
    } else {
        // Fallback: sum of squared z-scores (diagonal Mahalanobis).
        let d2: f64 = z_scores.iter().map(|z| z * z).sum();
        let p = chi_squared_p_value(d2, NUM_QUANTILES);
        (d2, p)
    };

    let anomalous = p_value < threshold;

    Some(TimingAnalysis {
        function: batch.function.clone(),
        mahalanobis_d2: d2,
        p_value,
        anomalous,
        quantile_z_scores: z_scores,
        max_z_score: max_z,
    })
}

/// Compute squared Mahalanobis distance.
fn mahalanobis_d2(
    x: &[f64; NUM_QUANTILES],
    mean: &[f64; NUM_QUANTILES],
    inv_cov: &[f64],
) -> (f64, f64) {
    let q = NUM_QUANTILES;
    let mut diff = [0.0f64; NUM_QUANTILES];
    for i in 0..q {
        diff[i] = x[i] - mean[i];
    }

    // D² = diff^T * inv_cov * diff
    let mut d2 = 0.0f64;
    for i in 0..q {
        let mut row_sum = 0.0;
        for j in 0..q {
            row_sum += inv_cov[i * q + j] * diff[j];
        }
        d2 += diff[i] * row_sum;
    }

    let p = chi_squared_p_value(d2, q);
    (d2, p)
}

/// Approximate p-value from chi-squared distribution.
/// Uses Wilson-Hilferty approximation for the chi-squared CDF.
fn chi_squared_p_value(x: f64, k: usize) -> f64 {
    if x <= 0.0 || k == 0 {
        return 1.0;
    }
    let k_f = k as f64;

    // Wilson-Hilferty approximation: transform chi-squared to ~N(0,1).
    let z = ((x / k_f).powf(1.0 / 3.0) - (1.0 - 2.0 / (9.0 * k_f))) / (2.0 / (9.0 * k_f)).sqrt();

    // Standard normal survival function (1 - CDF) via error function approximation.
    let p = 0.5 * erfc(z / core::f64::consts::SQRT_2);
    p.clamp(0.0, 1.0)
}

/// Complementary error function approximation (Abramowitz & Stegun 7.1.26).
fn erfc(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.3275911 * x.abs());
    let poly = t
        * (0.254829592
            + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    let result = poly * (-x * x).exp();
    if x >= 0.0 {
        result
    } else {
        2.0 - result
    }
}

// ── Kernel functions to probe ───────────────────────────────────────────

/// Functions commonly hooked by rootkits (targets for timing probes).
pub const ROOTKIT_TARGET_FUNCTIONS: &[(&str, &str)] = &[
    ("iterate_dir", "file hiding (getdents)"),
    ("filldir64", "directory entry filtering"),
    ("tcp4_seq_show", "network connection hiding (/proc/net/tcp)"),
    ("tcp6_seq_show", "IPv6 connection hiding"),
    ("find_task_by_vpid", "process hiding (kill, /proc)"),
    ("proc_pid_readdir", "process listing manipulation"),
    ("vfs_statx", "file stat manipulation"),
    ("do_sys_openat2", "file open interception"),
];

// ── Check function ──────────────────────────────────────────────────────

/// Analyze timing data from kernel probes.
/// Takes pre-collected batches and a model, returns check result.
pub fn check_timing_traces(
    batches: &[TimingBatch],
    model: &TimingModel,
    threshold: f64,
) -> CheckResult {
    if batches.is_empty() {
        return CheckResult {
            id: "TOT-001",
            name: "Trace of the Times",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "no timing data available (need eBPF kprobe/kretprobe pairs)".into(),
        };
    }

    let mut anomalies = Vec::new();
    let mut analyzed = 0;

    for batch in batches {
        let func_model = model
            .functions
            .iter()
            .find(|f| f.function == batch.function);
        let Some(fm) = func_model else {
            continue; // no baseline for this function
        };

        if let Some(analysis) = detect_anomaly(batch, fm, threshold) {
            analyzed += 1;
            if analysis.anomalous {
                anomalies.push(analysis);
            }
        }
    }

    if analyzed == 0 {
        return CheckResult {
            id: "TOT-001",
            name: "Trace of the Times",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "insufficient timing data for analysis (need >= 100 samples per function)"
                .into(),
        };
    }

    if !anomalies.is_empty() {
        let funcs: Vec<String> = anomalies
            .iter()
            .map(|a| {
                format!(
                    "{} (z={:.1}, p={:.2e})",
                    a.function, a.max_z_score, a.p_value
                )
            })
            .collect();

        CheckResult {
            id: "TOT-001",
            name: "Trace of the Times",
            status: CheckStatus::Critical,
            confidence: confidence(0.95, 0.85),
            detail: format!(
                "TIMING ANOMALY in {} function(s): {}. \
                 Execution time distribution shifted from baseline. \
                 Consistent with kernel function hooking (ftrace/kprobe rootkit).",
                anomalies.len(),
                funcs.join("; "),
            ),
        }
    } else {
        CheckResult {
            id: "TOT-001",
            name: "Trace of the Times",
            status: CheckStatus::Secure,
            confidence: confidence(0.85, 0.8),
            detail: format!(
                "{analyzed} function(s) analyzed, all within baseline timing. \
                 No kernel function hooking detected."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_batch(func: &str, base: u64, jitter: u64, count: usize) -> TimingBatch {
        let mut deltas = Vec::with_capacity(count);
        for i in 0..count {
            // Simulate normal distribution around base with small jitter.
            let delta = base + (i as u64 % jitter);
            deltas.push(delta);
        }
        TimingBatch {
            function: func.to_string(),
            deltas_ns: deltas,
        }
    }

    #[test]
    fn extract_quantiles_basic() {
        let batch = make_batch("filldir64", 1000, 100, 200);
        let profile = extract_quantiles(&batch).unwrap();
        assert_eq!(profile.function, "filldir64");
        assert_eq!(profile.sample_count, 200);
        // Quantiles should be monotonically increasing.
        for i in 1..NUM_QUANTILES {
            assert!(profile.quantiles[i] >= profile.quantiles[i - 1]);
        }
    }

    #[test]
    fn extract_quantiles_too_few_samples() {
        let batch = TimingBatch {
            function: "test".into(),
            deltas_ns: vec![100; 10], // less than MIN_SAMPLES
        };
        assert!(extract_quantiles(&batch).is_none());
    }

    #[test]
    fn build_model_single_batch() {
        let batch = make_batch("filldir64", 1000, 100, 200);
        let model = build_model(&[vec![batch]]);
        assert_eq!(model.functions.len(), 1);
        assert_eq!(model.functions[0].function, "filldir64");
        assert_eq!(model.functions[0].training_batches, 1);
    }

    #[test]
    fn build_model_multiple_batches() {
        let batches: Vec<Vec<TimingBatch>> = (0..20)
            .map(|_| vec![make_batch("filldir64", 1000, 100, 200)])
            .collect();
        let model = build_model(&batches);
        assert_eq!(model.functions[0].training_batches, 20);
        // With 20 batches, inverse covariance should be computed.
        assert!(model.functions[0].inv_covariance.is_some());
    }

    #[test]
    fn detect_normal_batch() {
        // Build model from normal data.
        let training: Vec<Vec<TimingBatch>> = (0..20)
            .map(|_| vec![make_batch("filldir64", 1000, 100, 200)])
            .collect();
        let model = build_model(&training);

        // Test with similar normal data.
        let test = make_batch("filldir64", 1000, 100, 200);
        let analysis = detect_anomaly(&test, &model.functions[0], DEFAULT_THRESHOLD).unwrap();

        assert!(
            !analysis.anomalous,
            "normal data should not be flagged. p={}, d2={}",
            analysis.p_value, analysis.mahalanobis_d2,
        );
    }

    #[test]
    fn detect_hooked_batch() {
        // Build model from normal data (fast execution: ~1000ns).
        let training: Vec<Vec<TimingBatch>> = (0..20)
            .map(|_| vec![make_batch("filldir64", 1000, 50, 200)])
            .collect();
        let model = build_model(&training);

        // Simulate rootkit: execution takes 3x longer.
        let hooked = make_batch("filldir64", 3000, 50, 200);
        let analysis = detect_anomaly(&hooked, &model.functions[0], DEFAULT_THRESHOLD).unwrap();

        assert!(
            analysis.anomalous,
            "hooked function (3x slower) should be detected. p={}, d2={}, max_z={}",
            analysis.p_value, analysis.mahalanobis_d2, analysis.max_z_score,
        );
    }

    #[test]
    fn detect_subtle_hook() {
        // Build model from normal data.
        let training: Vec<Vec<TimingBatch>> = (0..20)
            .map(|_| vec![make_batch("filldir64", 1000, 50, 200)])
            .collect();
        let model = build_model(&training);

        // Subtle hook: only 20% slower (rootkit doing minimal work).
        let subtle = make_batch("filldir64", 1200, 50, 200);
        let analysis = detect_anomaly(&subtle, &model.functions[0], DEFAULT_THRESHOLD).unwrap();

        // 20% shift should still be detectable with enough samples.
        assert!(
            analysis.max_z_score > 2.0,
            "20% timing shift should produce significant z-score: {}",
            analysis.max_z_score,
        );
    }

    #[test]
    fn chi_squared_p_value_basic() {
        // Known values: chi2(0, k) should give p ≈ 1.0
        assert!((chi_squared_p_value(0.0, 9) - 1.0).abs() < 0.01);
        // Very large chi2 should give p ≈ 0.0
        assert!(chi_squared_p_value(100.0, 9) < 0.001);
    }

    #[test]
    fn erfc_basic() {
        assert!((erfc(0.0) - 1.0).abs() < 0.001);
        assert!(erfc(3.0) < 0.001); // erfc(3) ≈ 0.000022
        assert!((erfc(-3.0) - 2.0).abs() < 0.001);
    }

    #[test]
    fn matrix_inversion() {
        // 2x2 identity should invert to identity.
        let mat = vec![1.0, 0.0, 0.0, 1.0];
        let inv = invert_matrix(&mat, 2).unwrap();
        assert!((inv[0] - 1.0).abs() < 1e-10);
        assert!((inv[3] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn check_no_data() {
        let model = TimingModel {
            built_at: "test".into(),
            functions: vec![],
        };
        let result = check_timing_traces(&[], &model, DEFAULT_THRESHOLD);
        assert_eq!(result.status, CheckStatus::Unavailable);
    }
}
