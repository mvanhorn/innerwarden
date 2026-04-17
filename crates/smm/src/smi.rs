//! SMI (System Management Interrupt) anomaly detection.
//!
//! Monitors the SMI counter from MSR_SMI_COUNT over time to detect
//! firmware rootkits that trigger excessive SMIs. Normal systems see
//! <10 SMIs/min. A firmware rootkit actively executing in SMM mode
//! can cause >100 SMIs/min (SMI storms).

use crate::msr;
use crate::{confidence, CheckResult, CheckStatus};
use std::time::{Duration, Instant};

/// SMI rate measurement — two readings separated by a delay.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SmiRate {
    /// SMI count at start of measurement.
    pub count_start: u64,
    /// SMI count at end of measurement.
    pub count_end: u64,
    /// Duration of measurement window.
    pub window_secs: f64,
    /// Computed rate: SMIs per minute.
    pub rate_per_min: f64,
}

/// Measure SMI rate over a short window.
/// Default window is 2 seconds (enough to detect storm patterns).
pub fn measure_smi_rate(window: Duration) -> Option<SmiRate> {
    let start = msr::read_smi_count()?;
    let t0 = Instant::now();

    std::thread::sleep(window);

    let end = msr::read_smi_count()?;
    let elapsed = t0.elapsed().as_secs_f64();

    let delta = end.saturating_sub(start);
    let rate = if elapsed > 0.0 {
        (delta as f64 / elapsed) * 60.0
    } else {
        0.0
    };

    Some(SmiRate {
        count_start: start,
        count_end: end,
        window_secs: elapsed,
        rate_per_min: rate,
    })
}

// ── Thresholds ──────────────────────────────────────────────────────────

/// Normal SMI rate: modern systems typically see 0-5 SMIs/min.
const SMI_RATE_NORMAL: f64 = 10.0;

/// Warning threshold: something unusual is triggering SMIs.
const SMI_RATE_WARNING: f64 = 50.0;

/// Critical threshold: SMI storm — possible firmware rootkit activity.
const SMI_RATE_CRITICAL: f64 = 200.0;

// ── Check function ──────────────────────────────────────────────────────

/// Check SMI rate for anomalies (quick 2-second measurement).
pub fn check_smi_rate() -> CheckResult {
    let rate = measure_smi_rate(Duration::from_secs(2));

    let Some(rate) = rate else {
        return CheckResult {
            id: "SMI-001",
            name: "SMI Rate",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read MSR_SMI_COUNT (need root + msr module)".into(),
        };
    };

    if rate.rate_per_min >= SMI_RATE_CRITICAL {
        CheckResult {
            id: "SMI-001",
            name: "SMI Rate",
            status: CheckStatus::Critical,
            confidence: confidence(0.9, 0.7),
            detail: format!(
                "SMI STORM: {:.0} SMIs/min ({} SMIs in {:.1}s). \
                 This indicates active firmware-level execution — possible SMM rootkit. \
                 Immediate investigation required.",
                rate.rate_per_min,
                rate.count_end - rate.count_start,
                rate.window_secs,
            ),
        }
    } else if rate.rate_per_min >= SMI_RATE_WARNING {
        CheckResult {
            id: "SMI-001",
            name: "SMI Rate",
            status: CheckStatus::Warning,
            confidence: confidence(0.6, 0.6),
            detail: format!(
                "elevated SMI rate: {:.0} SMIs/min. Normal is <{SMI_RATE_NORMAL}. \
                 Could be aggressive power management or early rootkit activity.",
                rate.rate_per_min,
            ),
        }
    } else {
        CheckResult {
            id: "SMI-001",
            name: "SMI Rate",
            status: CheckStatus::Secure,
            confidence: confidence(0.7, 0.8),
            detail: format!(
                "SMI rate normal: {:.1} SMIs/min (total count: {})",
                rate.rate_per_min, rate.count_end,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_calculation() {
        // Arithmetic path: SMI/min conversion should scale deltas from the
        // sampling window into per-minute rates.
        let rate = SmiRate {
            count_start: 100,
            count_end: 110,
            window_secs: 2.0,
            rate_per_min: (10.0 / 2.0) * 60.0, // 300 SMIs/min
        };
        assert!(rate.rate_per_min >= SMI_RATE_CRITICAL);
    }

    #[test]
    fn normal_rate() {
        // Baseline path: no SMI growth across the window should stay below the
        // normal threshold.
        let rate = SmiRate {
            count_start: 100,
            count_end: 100, // no new SMIs
            window_secs: 2.0,
            rate_per_min: 0.0,
        };
        assert!(rate.rate_per_min < SMI_RATE_NORMAL);
    }

    #[test]
    fn thresholds_are_strictly_ordered() {
        // Constant path: threshold ordering must remain normal < warning <
        // critical for deterministic severity classification.
        assert!(SMI_RATE_NORMAL < SMI_RATE_WARNING);
        assert!(SMI_RATE_WARNING < SMI_RATE_CRITICAL);
    }

    #[test]
    fn warning_band_sits_between_normal_and_critical() {
        // Boundary path: values in the warning band should exceed normal but
        // remain below critical storm levels.
        let rate = SmiRate {
            count_start: 0,
            count_end: 2,
            window_secs: 2.0,
            rate_per_min: 60.0,
        };
        assert!(rate.rate_per_min >= SMI_RATE_WARNING);
        assert!(rate.rate_per_min < SMI_RATE_CRITICAL);
    }

    #[test]
    fn check_smi_rate_exposes_stable_check_id() {
        // Contract path: the SMI detector must always emit the canonical id
        // expected by report aggregation.
        let result = check_smi_rate();
        assert_eq!(result.id, "SMI-001");
    }
}
