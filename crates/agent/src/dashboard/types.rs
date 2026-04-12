#[cfg(test)]
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::telemetry::TelemetrySnapshot;

#[derive(Clone, Debug)]
pub struct AdvisoryEntry {
    pub advisory_id: String,
    pub command_hash: String,
    pub command_preview: String,
    pub risk_score: u32,
    pub recommendation: String,
    pub signals: Vec<String>,
    pub ts: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// D3 - action request / response structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct BlockIpRequest {
    /// Target IP address to block.
    pub(super) ip: String,
    /// Operator-supplied reason (mandatory - becomes the audit trail entry).
    pub(super) reason: String,
    /// Optional incident ID to associate this action with.
    pub(super) incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SuspendUserRequest {
    /// Linux username to suspend from sudo.
    pub(super) user: String,
    /// Operator-supplied reason (mandatory).
    pub(super) reason: String,
    /// How long to suspend (seconds). Defaults to 3600 (1 hour).
    pub(super) duration_secs: Option<u64>,
    /// Optional incident ID to associate this action with.
    pub(super) incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HoneypotTestRequest {
    /// Operator-supplied reason (mandatory).
    pub(super) reason: String,
    /// Duration in seconds for the honeypot session (default: 120).
    pub(super) duration_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ActionResponse {
    pub(super) success: bool,
    pub(super) dry_run: bool,
    pub(super) message: String,
    /// Echoes back the skill ID that was invoked (or would have been).
    pub(super) skill_id: String,
}

// ---------------------------------------------------------------------------
// Query structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    pub(super) limit: Option<usize>,
    pub(super) date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // severity_min/detector accepted for API forward-compat; graph filters land in spec 016
pub(crate) struct EntitiesQuery {
    pub(super) limit: Option<usize>,
    pub(super) date: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    pub(super) group_by: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // severity_min/detector accepted for API forward-compat; graph filters land in spec 016
pub(crate) struct JourneyQuery {
    pub(super) subject_type: Option<String>,
    pub(super) subject: Option<String>,
    // Backward compatibility with D2.1 clients
    pub(super) ip: Option<String>,
    pub(super) date: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    pub(super) window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AiExplainQuery {
    pub(super) r#type: Option<String>,
    pub(super) value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // severity_min/detector accepted for API forward-compat; graph filters land in spec 016
pub(crate) struct ClusterQuery {
    pub(super) limit: Option<usize>,
    pub(super) date: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    pub(super) window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExportQuery {
    pub(super) date: Option<String>,
    pub(super) format: Option<String>,
    pub(super) subject_type: Option<String>,
    pub(super) subject: Option<String>,
    // Backward compatibility with D2.1 clients
    pub(super) ip: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    pub(super) group_by: Option<String>,
    pub(super) limit: Option<usize>,
    pub(super) window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReportQuery {
    /// Optional specific date (YYYY-MM-DD). Defaults to latest available.
    pub(super) date: Option<String>,
}

// ---------------------------------------------------------------------------
// Response structs - existing
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct OverviewResponse {
    pub(super) date: String,
    pub(super) events_count: usize,
    pub(super) incidents_count: usize,
    pub(super) decisions_count: usize,
    /// Incidents where AI decided to act (block, kill, honeypot, monitor).
    /// This is the "real threat" count. incidents_count - confirmed = noise/ignored.
    pub(super) ai_confirmed: usize,
    /// Incidents where AI executed a response action (block_ip, kill_process, etc).
    pub(super) ai_responded: usize,
    /// Incidents where AI decided to ignore (false positive or low risk).
    pub(super) ai_ignored: usize,
    /// Incidents with no decision yet — need human attention.
    pub(super) unresolved_count: usize,
    /// Incidents safely resolved (blocked, killed, contained, monitored, honeypot).
    pub(super) safely_resolved: usize,
    /// Breakdown by severity level: {"critical": N, "high": N, ...}
    pub(super) severity_breakdown: std::collections::HashMap<String, usize>,
    /// Incidents from allowlisted IPs/users (can be hidden in dashboard).
    pub(super) allowlisted_count: usize,
    pub(super) top_detectors: Vec<DetectorCount>,
    pub(super) latest_telemetry: Option<TelemetrySnapshot>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DetectorCount {
    pub(super) detector: String,
    pub(super) count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct IncidentListResponse {
    pub(super) date: String,
    pub(super) total: usize,
    pub(super) items: Vec<IncidentView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DecisionListResponse {
    pub(super) date: String,
    pub(super) total: usize,
    pub(super) items: Vec<DecisionView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IncidentView {
    pub(super) ts: chrono::DateTime<Utc>,
    pub(super) incident_id: String,
    pub(super) severity: String,
    /// Effective severity after considering outcome: blocked critical → medium, ignored → info.
    pub(super) effective_severity: String,
    pub(super) title: String,
    pub(super) summary: String,
    pub(super) entities: Vec<String>,
    pub(super) tags: Vec<String>,
    /// Resolution status: "blocked", "suspended", "monitored", "ignored", or "open"
    pub(super) outcome: String,
    /// What action was taken (e.g. "block-ip-ufw", "fail2ban:sshd")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) action_taken: Option<String>,
    /// AI decision confidence (0.0 - 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) confidence: Option<f32>,
    /// True if the source entity is in the allowlist.
    pub(super) is_allowlisted: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct DecisionView {
    pub(super) ts: chrono::DateTime<Utc>,
    pub(super) incident_id: String,
    pub(super) action_type: String,
    pub(super) target_ip: Option<String>,
    pub(super) skill_id: Option<String>,
    pub(super) confidence: f32,
    pub(super) auto_executed: bool,
    pub(super) dry_run: bool,
    pub(super) reason: String,
    pub(super) execution_result: String,
}

// ---------------------------------------------------------------------------
// Response structs - D2 journey
// ---------------------------------------------------------------------------

/// Summarizes an attacker (IP with at least one incident) for the left panel.
#[derive(Debug, Serialize)]
pub(crate) struct AttackerSummary {
    pub(super) ip: String,
    pub(super) first_seen: chrono::DateTime<Utc>,
    pub(super) last_seen: chrono::DateTime<Utc>,
    pub(super) max_severity: String,
    pub(super) detectors: Vec<String>,
    /// "blocked" | "monitoring" | "honeypot" | "active" | "unknown"
    pub(super) outcome: String,
    pub(super) incident_count: usize,
    pub(super) event_count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct EntitiesResponse {
    pub(super) date: String,
    pub(super) attackers: Vec<AttackerSummary>,
}

/// One timestamped entry in an attacker's journey timeline.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyEntry {
    pub(super) ts: chrono::DateTime<Utc>,
    /// "event" | "incident" | "decision" | "honeypot_ssh" | "honeypot_http" | "honeypot_banner"
    pub(super) kind: String,
    pub(super) data: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct JourneySummary {
    pub(super) total_entries: usize,
    pub(super) events_count: usize,
    pub(super) incidents_count: usize,
    pub(super) decisions_count: usize,
    pub(super) honeypot_count: usize,
    pub(super) first_event: Option<chrono::DateTime<Utc>>,
    pub(super) first_incident: Option<chrono::DateTime<Utc>>,
    pub(super) first_decision: Option<chrono::DateTime<Utc>>,
    pub(super) first_honeypot: Option<chrono::DateTime<Utc>>,
    pub(super) pivot_shortcuts: Vec<String>,
    pub(super) hints: Vec<String>,
}

/// D5 - High-level attack assessment derived from the journey entries.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyVerdict {
    /// Detected attack vector: "ssh_bruteforce" | "credential_stuffing" |
    /// "port_scan" | "sudo_abuse" | "unknown"
    pub(super) entry_vector: String,
    /// "no_evidence_of_success" | "likely_success" | "confirmed_success" | "inconclusive"
    pub(super) access_status: String,
    /// "no_evidence" | "attempted" | "confirmed" | "inconclusive"
    pub(super) privilege_status: String,
    /// "blocked" | "monitored" | "honeypot" | "active" | "unknown"
    pub(super) containment_status: String,
    /// "engaged" | "diverted" | "not_engaged"
    pub(super) honeypot_status: String,
    /// "high" | "medium" | "low"
    pub(super) confidence: String,
}

/// D5 - A logical phase of the attack story derived from consecutive entries.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyChapter {
    /// Stage label: "reconnaissance" | "initial_access_attempt" | "access_success" |
    /// "privilege_abuse" | "response" | "containment" | "honeypot_interaction" | "unknown"
    pub(super) stage: String,
    pub(super) title: String,
    pub(super) summary: String,
    pub(super) start_ts: chrono::DateTime<Utc>,
    pub(super) end_ts: chrono::DateTime<Utc>,
    pub(super) entry_count: usize,
    /// Key facts / evidence highlights (usernames, ports, credentials, etc.)
    pub(super) evidence_highlights: Vec<String>,
    /// Indices into the parent `entries` array for drill-down
    pub(super) entry_indices: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct JourneyResponse {
    pub(super) subject_type: String,
    pub(super) subject: String,
    pub(super) date: String,
    pub(super) first_seen: Option<chrono::DateTime<Utc>>,
    pub(super) last_seen: Option<chrono::DateTime<Utc>>,
    pub(super) outcome: String,
    pub(super) summary: JourneySummary,
    /// D5 - high-level attack assessment
    pub(super) verdict: JourneyVerdict,
    /// D5 - logical attack chapters derived from entries
    pub(super) chapters: Vec<JourneyChapter>,
    pub(super) entries: Vec<JourneyEntry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PivotItem {
    pub(super) group_by: String,
    pub(super) value: String,
    pub(super) first_seen: chrono::DateTime<Utc>,
    pub(super) last_seen: chrono::DateTime<Utc>,
    pub(super) max_severity: String,
    pub(super) incident_count: usize,
    pub(super) event_count: usize,
    pub(super) outcome: String,
    pub(super) detectors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PivotResponse {
    pub(super) date: String,
    pub(super) group_by: String,
    pub(super) total: usize,
    pub(super) items: Vec<PivotItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterItem {
    pub(super) cluster_id: String,
    pub(super) pivot: String,
    pub(super) pivot_type: String,
    pub(super) pivot_value: String,
    pub(super) start_ts: DateTime<Utc>,
    pub(super) end_ts: DateTime<Utc>,
    pub(super) incident_count: usize,
    pub(super) detector_kinds: Vec<String>,
    pub(super) incident_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterResponse {
    pub(super) date: String,
    pub(super) total: usize,
    pub(super) items: Vec<ClusterItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InvestigationExport {
    pub(super) generated_at: DateTime<Utc>,
    pub(super) date: String,
    pub(super) filters: serde_json::Value,
    pub(super) group_by: String,
    pub(super) subject_type: Option<String>,
    pub(super) subject: Option<String>,
    pub(super) overview: OverviewResponse,
    pub(super) pivots: Vec<PivotItem>,
    pub(super) clusters: Vec<ClusterItem>,
    pub(super) journey: Option<JourneyResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PivotKind {
    Ip,
    User,
    Detector,
}

impl PivotKind {
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        match raw.unwrap_or("ip").trim().to_ascii_lowercase().as_str() {
            "user" => Self::User,
            "detector" => Self::Detector,
            _ => Self::Ip,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::User => "user",
            Self::Detector => "detector",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // fields consumed by `#[cfg(test)]` legacy JSONL helpers until spec 016
pub(crate) struct InvestigationFilters {
    pub(super) severity_min: Option<u8>,
    pub(super) detector: Option<String>,
}

impl InvestigationFilters {
    pub(crate) fn from_query(severity_min: Option<&str>, detector: Option<&str>) -> Self {
        let severity_min = severity_min
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| severity_order(v.to_ascii_lowercase().as_str()));
        let severity_min = match severity_min {
            Some(0) | None => None,
            other => other,
        };

        let detector = detector
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_ascii_lowercase());

        Self {
            severity_min,
            detector,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal accumulator for grouping events/incidents by IP
// ---------------------------------------------------------------------------

#[cfg(test)]
#[derive(Default)]
pub(crate) struct IpAccumulator {
    pub(super) first_seen: Option<chrono::DateTime<Utc>>,
    pub(super) last_seen: Option<chrono::DateTime<Utc>>,
    pub(super) max_severity: u8,
    pub(super) max_severity_str: String,
    pub(super) detectors: BTreeSet<String>,
    pub(super) ips: BTreeSet<String>,
    pub(super) incident_count: usize,
    pub(super) event_count: usize,
}

#[cfg(test)]
impl IpAccumulator {
    pub(crate) fn update_time(&mut self, ts: chrono::DateTime<Utc>) {
        if self.first_seen.is_none_or(|existing| ts < existing) {
            self.first_seen = Some(ts);
        }
        if self.last_seen.is_none_or(|existing| ts > existing) {
            self.last_seen = Some(ts);
        }
    }
}

pub(crate) fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}
