//! Monthly Threat Report generation.
//!
//! Scans all JSONL files for a given month and produces a comprehensive
//! report: executive summary, top attackers, campaign detection, MITRE
//! heatmap, geographic distribution, honeypot intel, mesh summary, and
//! weekly trends. Output as JSON + publishable Markdown.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use tracing::warn;

/// Open a monthly incidents JSONL file for the threat-report scan,
/// surfacing genuine I/O failure via `warn!` while staying silent on
/// `NotFound` (steady state for dates with no incidents recorded;
/// the call site already guards with `path.exists()` but keeps
/// NotFound silent for the rare TOCTOU race). Replaces the silent
/// `if let Ok(file) = File::open(&incidents_path)` site
/// (Spec 037 I-13 follow-up #2).
///
/// On a real I/O error the operator loses every incident from that
/// day in the monthly executive report. The warn carries path +
/// error so the operator can recover the file or fix permissions.
fn open_monthly_incident_jsonl_or_warn(path: &Path) -> Option<std::fs::File> {
    match std::fs::File::open(path) {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "monthly incident JSONL open failed (one day of incidents lost from threat report)"
            );
            None
        }
    }
}

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::Serialize;

use crate::attacker_intel::{self, AttackerProfile, CampaignCluster};
use crate::decisions::DecisionEntry;
use crate::mitre;

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct MonthlyThreatReport {
    pub generated_at: DateTime<Utc>,
    pub month: String,
    pub executive_summary: ExecutiveSummary,
    pub top_attackers: Vec<AttackerSummaryCompact>,
    pub campaigns: Vec<CampaignCluster>,
    pub mitre_coverage: MitreCoverage,
    pub geographic_distribution: GeoDistribution,
    pub honeypot_intelligence: HoneypotIntel,
    pub mesh_network: MeshSummary,
    pub weekly_trends: Vec<WeeklyBucket>,
}

#[derive(Debug, Serialize)]
pub struct ExecutiveSummary {
    pub total_events: u64,
    pub total_incidents: u64,
    pub total_decisions: u64,
    pub total_blocks: u64,
    pub unique_attackers: u64,
    pub unique_countries: u64,
    pub top_detector: String,
    pub top_mitre_technique: String,
    pub avg_incidents_per_day: f64,
    pub days_with_data: u32,
}

#[derive(Debug, Serialize)]
pub struct AttackerSummaryCompact {
    pub ip: String,
    pub risk_score: u8,
    pub country: String,
    pub total_incidents: u32,
    pub detectors: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub action_taken: String,
    pub dna_hash: String,
    pub pattern_class: String,
}

#[derive(Debug, Serialize)]
pub struct MitreCoverage {
    pub techniques_seen: Vec<MitreTechniqueSeen>,
    pub tactics_counts: BTreeMap<String, u64>,
    pub total_unique_techniques: usize,
}

#[derive(Debug, Serialize)]
pub struct MitreTechniqueSeen {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub incident_count: u64,
    pub attacker_count: u64,
}

#[derive(Debug, Serialize)]
pub struct GeoDistribution {
    pub by_country: Vec<CountryStats>,
}

#[derive(Debug, Serialize)]
pub struct CountryStats {
    pub country_code: String,
    pub country: String,
    pub attacker_count: u64,
    pub incident_count: u64,
}

#[derive(Debug, Serialize)]
pub struct HoneypotIntel {
    pub total_sessions: u64,
    pub unique_ips: u64,
    pub top_credentials: Vec<(String, String, u64)>,
    pub top_commands: Vec<(String, u64)>,
    pub tool_signatures: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MeshSummary {
    pub threats_shared: u64,
    pub threats_received: u64,
    pub peer_count: u64,
}

#[derive(Debug, Serialize)]
pub struct WeeklyBucket {
    pub week_label: String,
    pub date_range: String,
    pub events: u64,
    pub incidents: u64,
    pub decisions: u64,
    pub blocks: u64,
    pub unique_attackers: u64,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate that a month string is exactly YYYY-MM format with no path traversal.
/// Prevents CWE-22 when month is used in file paths.
fn validate_month(month: &str) -> Option<&str> {
    // Must be exactly 7 chars: YYYY-MM
    if month.len() != 7 {
        return None;
    }
    // Must not contain path separators or dots
    if month.contains('/') || month.contains('\\') || month.contains("..") {
        return None;
    }
    // Must parse as valid year-month
    let parts: Vec<&str> = month.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let year: u32 = parts[0].parse().ok()?;
    let mon: u32 = parts[1].parse().ok()?;
    if !(2000..=2100).contains(&year) || !(1..=12).contains(&mon) {
        return None;
    }
    Some(month)
}

/// Check if a monthly report already exists for the given month (YYYY-MM).
pub fn report_exists(data_dir: &Path, month: &str) -> bool {
    let month = match validate_month(month) {
        Some(m) => m,
        None => return false,
    };
    data_dir
        .join(format!("monthly-report-{month}.json"))
        .exists()
}

/// Validate and canonicalize a directory path.
///
/// Returns `Some(canonical_path)` only if the path resolves to an existing
/// absolute directory. This is a sanitizer function for CWE-22 prevention.
fn validate_directory(dir: &Path) -> Option<std::path::PathBuf> {
    let canonical = dir.canonicalize().ok()?;
    if canonical.is_dir() && canonical.is_absolute() {
        Some(canonical)
    } else {
        None
    }
}

/// List available months that have report files or data.
///
/// Scans filenames in the data directory for monthly report and incident
/// files. Only extracts basenames — never constructs paths from the names.
pub fn available_months(data_dir: &Path) -> Vec<String> {
    let mut months = HashSet::new();

    let safe_dir = match validate_directory(data_dir) {
        Some(d) => d,
        None => return Vec::new(),
    };

    if let Ok(entries) = std::fs::read_dir(safe_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(month) = name
                .strip_prefix("monthly-report-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                months.insert(month.to_string());
            }
            // Also detect months with incident data
            if let Some(date) = name
                .strip_prefix("incidents-")
                .and_then(|s| s.strip_suffix(".jsonl"))
            {
                // Validate YYYY-MM-DD format (reject incidents-graph-*, incidents-trigger-*, etc.)
                if date.len() >= 7
                    && date.as_bytes().get(4) == Some(&b'-')
                    && date[..4].chars().all(|c| c.is_ascii_digit())
                    && date[5..7].chars().all(|c| c.is_ascii_digit())
                {
                    months.insert(date[..7].to_string());
                }
            }
        }
    }

    let mut sorted: Vec<_> = months.into_iter().collect();
    sorted.sort();
    sorted.reverse();
    sorted
}

/// Generate the monthly report for a given month (YYYY-MM).
pub fn generate_monthly(
    data_dir: &Path,
    month: &str,
    profiles: &HashMap<String, AttackerProfile>,
) -> Result<MonthlyThreatReport> {
    let month = validate_month(month).context("invalid month format (expected YYYY-MM)")?;
    let month_start =
        NaiveDate::parse_from_str(&format!("{month}-01"), "%Y-%m-%d").context("invalid month")?;
    let next_month = if month_start.month() == 12 {
        NaiveDate::from_ymd_opt(month_start.year() + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(month_start.year(), month_start.month() + 1, 1)
    }
    .unwrap_or(month_start);
    let days_in_month = (next_month - month_start).num_days() as u32;

    // Scan all data files for the month
    let mut total_events: u64 = 0;
    let mut total_incidents: u64 = 0;
    let mut total_decisions: u64 = 0;
    let mut total_blocks: u64 = 0;
    let mut incidents_by_detector: BTreeMap<String, u64> = BTreeMap::new();
    let mut attacker_ips: HashSet<String> = HashSet::new();
    let mut days_with_data: u32 = 0;

    // Weekly buckets
    let mut weekly: Vec<WeeklyBucket> = (0..4)
        .map(|w| {
            let start = month_start + chrono::Duration::days(w * 7);
            let end =
                (start + chrono::Duration::days(6)).min(next_month - chrono::Duration::days(1));
            WeeklyBucket {
                week_label: format!("W{}", w + 1),
                date_range: format!("{} — {}", start.format("%b %d"), end.format("%b %d")),
                events: 0,
                incidents: 0,
                decisions: 0,
                blocks: 0,
                unique_attackers: 0,
            }
        })
        .collect();
    let mut weekly_ips: Vec<HashSet<String>> = vec![HashSet::new(); 4];

    // Phase 7 Gap 4: use dated graph snapshots for monthly aggregation.
    // Falls back to JSONL for days without a snapshot.
    tracing::info!(
        month = %month,
        days = days_in_month,
        "threat_report: aggregating monthly data from graph snapshots"
    );

    for day_offset in 0..days_in_month {
        let date = month_start + chrono::Duration::days(day_offset as i64);
        let date_str = date.format("%Y-%m-%d").to_string();
        let week_idx = (day_offset / 7).min(3) as usize;

        // Try graph snapshot first (SQLite canonical, JSON fallback).
        if let Some(graph) =
            crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(data_dir, &date_str)
        {
            use crate::knowledge_graph::types::{Node, NodeType, Relation};
            let event_count = graph.edge_count() as u64; // approximate: edges ≈ events
            total_events += event_count;
            weekly[week_idx].events += event_count;
            if event_count > 0 {
                days_with_data += 1;
            }

            for id in graph.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    incident_id: _,
                    detector,
                    decision,
                    ..
                }) = graph.get_node(id)
                {
                    total_incidents += 1;
                    weekly[week_idx].incidents += 1;
                    *incidents_by_detector.entry(detector.clone()).or_default() += 1;

                    // Extract attacker IPs from TriggeredBy edges
                    for edge in graph.outgoing_edges(id) {
                        if edge.relation == Relation::TriggeredBy {
                            if let Some(Node::Ip { addr, .. }) = graph.get_node(edge.to) {
                                attacker_ips.insert(addr.clone());
                                weekly_ips[week_idx].insert(addr.clone());
                            }
                        }
                    }

                    if let Some(action) = decision {
                        total_decisions += 1;
                        weekly[week_idx].decisions += 1;
                        if action == "block_ip" {
                            total_blocks += 1;
                            weekly[week_idx].blocks += 1;
                        }
                    }
                }
            }
            continue;
        }

        // Fallback: JSONL
        let events_path = data_dir.join(format!("events-{date_str}.jsonl"));
        if events_path.exists() {
            let count = count_jsonl_lines(&events_path);
            total_events += count;
            weekly[week_idx].events += count;
            if count > 0 {
                days_with_data += 1;
            }
        }

        let incidents_path = data_dir.join(format!("incidents-{date_str}.jsonl"));
        if incidents_path.exists() {
            if let Some(file) = open_monthly_incident_jsonl_or_warn(&incidents_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                        total_incidents += 1;
                        weekly[week_idx].incidents += 1;
                        if let Some(iid) = val["incident_id"].as_str() {
                            let detector = mitre::detector_from_incident_id(iid);
                            *incidents_by_detector
                                .entry(detector.to_string())
                                .or_default() += 1;
                        }
                        if let Some(entities) = val["entities"].as_array() {
                            for entity in entities {
                                if entity["type"].as_str() == Some("ip") {
                                    if let Some(ip) = entity["value"].as_str() {
                                        attacker_ips.insert(ip.to_string());
                                        weekly_ips[week_idx].insert(ip.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let decisions_path = data_dir.join(format!("decisions-{date_str}.jsonl"));
        if decisions_path.exists() {
            if let Ok(file) = std::fs::File::open(&decisions_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    if let Ok(entry) = serde_json::from_str::<DecisionEntry>(&line) {
                        total_decisions += 1;
                        weekly[week_idx].decisions += 1;
                        if entry.action_type == "block_ip" {
                            total_blocks += 1;
                            weekly[week_idx].blocks += 1;
                        }
                    }
                }
            }
        }
    }

    // Fill weekly unique attackers
    for (i, ips) in weekly_ips.iter().enumerate() {
        weekly[i].unique_attackers = ips.len() as u64;
    }

    // Top detector
    let top_detector = incidents_by_detector
        .iter()
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| k.clone())
        .unwrap_or_else(|| "none".to_string());

    // MITRE coverage
    let mitre_coverage = build_mitre_coverage(&incidents_by_detector, profiles);

    let top_mitre_technique = mitre_coverage
        .techniques_seen
        .first()
        .map(|t| format!("{} ({})", t.technique_id, t.technique_name))
        .unwrap_or_else(|| "none".to_string());

    // Build top attackers from profiles
    let mut month_profiles: Vec<&AttackerProfile> = profiles
        .values()
        .filter(|p| p.visit_dates.iter().any(|d| d.starts_with(month)))
        .collect();
    month_profiles.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    let top_attackers: Vec<AttackerSummaryCompact> = month_profiles
        .iter()
        .take(20)
        .map(|p| {
            let action = if p.total_blocks > 0 {
                "blocked"
            } else if p.total_honeypot_diversions > 0 {
                "honeypot"
            } else if p.total_monitors > 0 {
                "monitoring"
            } else {
                "observed"
            };
            AttackerSummaryCompact {
                ip: p.ip.clone(),
                risk_score: p.risk_score,
                country: p
                    .geo
                    .as_ref()
                    .map(|g| g.country_code.clone())
                    .unwrap_or_default(),
                total_incidents: p.total_incidents,
                detectors: p.detectors_triggered.iter().cloned().collect(),
                mitre_techniques: p.mitre_techniques.iter().cloned().collect(),
                action_taken: action.to_string(),
                dna_hash: p.dna.hash.chars().take(12).collect(),
                pattern_class: p.dna.pattern_class.clone(),
            }
        })
        .collect();

    // Geographic distribution
    let geo = build_geo_distribution(&month_profiles);

    // Unique countries
    let unique_countries = geo.by_country.len() as u64;

    // Honeypot intelligence
    let honeypot = build_honeypot_intel(&month_profiles);

    // Campaign detection (DNA + IOC correlation from attacker_intel engine)
    let month_profiles_map: HashMap<String, AttackerProfile> = month_profiles
        .iter()
        .map(|p| (p.ip.clone(), (*p).clone()))
        .collect();
    let campaigns = attacker_intel::detect_campaigns(&month_profiles_map);

    // Mesh summary (from profiles)
    let mesh = MeshSummary {
        threats_shared: month_profiles
            .iter()
            .map(|p| p.mesh_peer_confirmations as u64)
            .sum(),
        threats_received: month_profiles
            .iter()
            .map(|p| p.mesh_signals_received as u64)
            .sum(),
        peer_count: 0, // would need live mesh state
    };

    let avg_incidents_per_day = if days_with_data > 0 {
        total_incidents as f64 / days_with_data as f64
    } else {
        0.0
    };

    Ok(MonthlyThreatReport {
        generated_at: Utc::now(),
        month: month.to_string(),
        executive_summary: ExecutiveSummary {
            total_events,
            total_incidents,
            total_decisions,
            total_blocks,
            unique_attackers: attacker_ips.len() as u64,
            unique_countries,
            top_detector,
            top_mitre_technique,
            avg_incidents_per_day,
            days_with_data,
        },
        top_attackers,
        campaigns,
        mitre_coverage,
        geographic_distribution: geo,
        honeypot_intelligence: honeypot,
        mesh_network: mesh,
        weekly_trends: weekly,
    })
}

/// Write report as JSON and Markdown to the data directory.
pub fn write_report(report: &MonthlyThreatReport, data_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let json_path = data_dir.join(format!("monthly-report-{}.json", report.month));
    let md_path = data_dir.join(format!("monthly-report-{}.md", report.month));

    let json = serde_json::to_string_pretty(report).context("serialize report")?;
    std::fs::write(&json_path, json).context("write JSON report")?;

    let md = render_markdown(report);
    std::fs::write(&md_path, md).context("write Markdown report")?;

    Ok((json_path, md_path))
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

fn render_markdown(r: &MonthlyThreatReport) -> String {
    let mut md = String::with_capacity(8192);
    let s = &r.executive_summary;

    md.push_str(&format!("# InnerWarden Threat Report — {}\n\n", r.month));
    md.push_str(&format!(
        "*Generated: {}*\n\n",
        r.generated_at.format("%Y-%m-%d %H:%M UTC")
    ));

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str("| Metric | Value |\n|--------|-------|\n");
    md.push_str(&format!("| Total Events | {} |\n", s.total_events));
    md.push_str(&format!("| Total Incidents | {} |\n", s.total_incidents));
    md.push_str(&format!("| Total Decisions | {} |\n", s.total_decisions));
    md.push_str(&format!("| Total Blocks | {} |\n", s.total_blocks));
    md.push_str(&format!("| Unique Attackers | {} |\n", s.unique_attackers));
    md.push_str(&format!("| Unique Countries | {} |\n", s.unique_countries));
    md.push_str(&format!("| Top Detector | {} |\n", s.top_detector));
    md.push_str(&format!(
        "| Top MITRE Technique | {} |\n",
        s.top_mitre_technique
    ));
    md.push_str(&format!(
        "| Avg Incidents/Day | {:.1} |\n",
        s.avg_incidents_per_day
    ));
    md.push_str(&format!("| Days with Data | {} |\n\n", s.days_with_data));

    // Top Attackers
    if !r.top_attackers.is_empty() {
        md.push_str("## Top Attackers\n\n");
        md.push_str("| # | IP | Risk | Country | Incidents | Pattern | Action |\n");
        md.push_str("|---|-----|------|---------|-----------|---------|--------|\n");
        for (i, a) in r.top_attackers.iter().enumerate() {
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | {} | {} |\n",
                i + 1,
                a.ip,
                a.risk_score,
                a.country,
                a.total_incidents,
                a.pattern_class,
                a.action_taken
            ));
        }
        md.push('\n');
    }

    // MITRE ATT&CK Coverage
    if !r.mitre_coverage.techniques_seen.is_empty() {
        md.push_str("## MITRE ATT&CK Coverage\n\n");
        md.push_str("| Technique | Tactic | Incidents | Attackers |\n");
        md.push_str("|-----------|--------|-----------|----------|\n");
        for t in &r.mitre_coverage.techniques_seen {
            md.push_str(&format!(
                "| {} ({}) | {} | {} | {} |\n",
                t.technique_id, t.technique_name, t.tactic, t.incident_count, t.attacker_count
            ));
        }
        md.push('\n');
    }

    // Geographic Distribution
    if !r.geographic_distribution.by_country.is_empty() {
        md.push_str("## Geographic Distribution\n\n");
        md.push_str("| Country | Attackers | Incidents |\n");
        md.push_str("|---------|-----------|----------|\n");
        for c in r.geographic_distribution.by_country.iter().take(15) {
            md.push_str(&format!(
                "| {} ({}) | {} | {} |\n",
                c.country, c.country_code, c.attacker_count, c.incident_count
            ));
        }
        md.push('\n');
    }

    // Campaigns
    if !r.campaigns.is_empty() {
        md.push_str("## Detected Campaigns\n\n");
        for c in &r.campaigns {
            md.push_str(&format!(
                "### {} — {} (confidence: {})\n\n",
                c.campaign_id, c.correlation_type, c.confidence
            ));
            md.push_str(&format!("- **Summary:** {}\n", c.summary));
            md.push_str(&format!(
                "- **IPs ({}):** {}\n",
                c.member_ips.len(),
                c.member_ips.join(", ")
            ));
            if !c.shared_dna_signature.is_empty() {
                md.push_str(&format!(
                    "- **DNA Signature:** `{}`\n",
                    c.shared_dna_signature
                ));
            }
            if !c.shared_iocs.is_empty() {
                md.push_str(&format!(
                    "- **Shared IOCs:** {}\n",
                    c.shared_iocs.join(", ")
                ));
            }
            if !c.shared_detectors.is_empty() {
                md.push_str(&format!(
                    "- **Detectors:** {}\n",
                    c.shared_detectors.join(", ")
                ));
            }
            md.push('\n');
        }
    }

    // Honeypot Intelligence
    if r.honeypot_intelligence.total_sessions > 0 {
        md.push_str("## Honeypot Intelligence\n\n");
        md.push_str(&format!(
            "- **Sessions:** {} from {} unique IPs\n",
            r.honeypot_intelligence.total_sessions, r.honeypot_intelligence.unique_ips
        ));
        if !r.honeypot_intelligence.top_credentials.is_empty() {
            md.push_str("\n**Top Credentials:**\n\n");
            md.push_str("| Username | Password | Count |\n");
            md.push_str("|----------|----------|-------|\n");
            for (u, p, c) in r.honeypot_intelligence.top_credentials.iter().take(10) {
                md.push_str(&format!("| `{}` | `{}` | {} |\n", u, p, c));
            }
        }
        if !r.honeypot_intelligence.top_commands.is_empty() {
            md.push_str("\n**Top Commands:**\n\n");
            for (cmd, count) in r.honeypot_intelligence.top_commands.iter().take(10) {
                md.push_str(&format!("- `{}` ({}x)\n", cmd, count));
            }
        }
        md.push('\n');
    }

    // Weekly Trends
    if !r.weekly_trends.is_empty() {
        md.push_str("## Weekly Trends\n\n");
        md.push_str("| Week | Date Range | Events | Incidents | Blocks | Attackers |\n");
        md.push_str("|------|-----------|--------|-----------|--------|----------|\n");
        for w in &r.weekly_trends {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                w.week_label, w.date_range, w.events, w.incidents, w.blocks, w.unique_attackers
            ));
        }
        md.push('\n');
    }

    md.push_str("---\n\n*Report generated by InnerWarden.*\n");
    md
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn count_jsonl_lines(path: &Path) -> u64 {
    std::fs::File::open(path)
        .map(|f| BufReader::new(f).lines().count() as u64)
        .unwrap_or(0)
}

fn build_mitre_coverage(
    incidents_by_detector: &BTreeMap<String, u64>,
    profiles: &HashMap<String, AttackerProfile>,
) -> MitreCoverage {
    let mut techniques: BTreeMap<String, (String, String, String, u64, HashSet<String>)> =
        BTreeMap::new();
    let mut tactics_counts: BTreeMap<String, u64> = BTreeMap::new();

    for (detector, count) in incidents_by_detector {
        if let Some(mapping) = mitre::map_detector(detector) {
            let key = mapping.technique_id.to_string();
            let entry = techniques.entry(key.clone()).or_insert_with(|| {
                (
                    mapping.technique_id.to_string(),
                    mapping.technique_name.to_string(),
                    mapping.tactic.to_string(),
                    0,
                    HashSet::new(),
                )
            });
            entry.3 += count;
            *tactics_counts
                .entry(mapping.tactic.to_string())
                .or_default() += count;
        }
    }

    // Count attackers per technique from profiles
    for profile in profiles.values() {
        for tech in &profile.mitre_techniques {
            // tech format: "T1110 (Brute Force)"
            if let Some(tid) = tech.split(' ').next() {
                if let Some(entry) = techniques.get_mut(tid) {
                    entry.4.insert(profile.ip.clone());
                }
            }
        }
    }

    let mut seen: Vec<MitreTechniqueSeen> = techniques
        .into_values()
        .map(|(tid, name, tactic, count, attackers)| MitreTechniqueSeen {
            technique_id: tid,
            technique_name: name,
            tactic,
            incident_count: count,
            attacker_count: attackers.len() as u64,
        })
        .collect();
    seen.sort_by(|a, b| b.incident_count.cmp(&a.incident_count));

    let total = seen.len();
    MitreCoverage {
        techniques_seen: seen,
        tactics_counts,
        total_unique_techniques: total,
    }
}

fn build_geo_distribution(profiles: &[&AttackerProfile]) -> GeoDistribution {
    let mut by_country: BTreeMap<String, (String, u64, u64)> = BTreeMap::new();

    for p in profiles {
        if let Some(geo) = &p.geo {
            if !geo.country_code.is_empty() {
                let entry = by_country
                    .entry(geo.country_code.clone())
                    .or_insert_with(|| (geo.country.clone(), 0, 0));
                entry.1 += 1;
                entry.2 += p.total_incidents as u64;
            }
        }
    }

    let mut stats: Vec<CountryStats> = by_country
        .into_iter()
        .map(|(code, (name, attackers, incidents))| CountryStats {
            country_code: code,
            country: name,
            attacker_count: attackers,
            incident_count: incidents,
        })
        .collect();
    stats.sort_by(|a, b| b.attacker_count.cmp(&a.attacker_count));

    GeoDistribution { by_country: stats }
}

fn build_honeypot_intel(profiles: &[&AttackerProfile]) -> HoneypotIntel {
    let mut total_sessions: u64 = 0;
    let mut unique_ips: HashSet<String> = HashSet::new();
    let mut cred_counts: HashMap<(String, String), u64> = HashMap::new();
    let mut cmd_counts: HashMap<String, u64> = HashMap::new();
    let mut tools: HashSet<String> = HashSet::new();

    for p in profiles {
        if p.honeypot_sessions > 0 {
            total_sessions += p.honeypot_sessions as u64;
            unique_ips.insert(p.ip.clone());

            for (user, pass) in &p.credentials_attempted {
                *cred_counts.entry((user.clone(), pass.clone())).or_default() += 1;
            }
            for cmd in &p.commands_executed {
                *cmd_counts.entry(cmd.clone()).or_default() += 1;
            }
            for tool in &p.dna.tool_signatures {
                tools.insert(tool.clone());
            }
        }
    }

    let mut top_credentials: Vec<(String, String, u64)> = cred_counts
        .into_iter()
        .map(|((u, p), c)| (u, p, c))
        .collect();
    top_credentials.sort_by(|a, b| b.2.cmp(&a.2));
    top_credentials.truncate(15);

    let mut top_commands: Vec<(String, u64)> = cmd_counts.into_iter().collect();
    top_commands.sort_by(|a, b| b.1.cmp(&a.1));
    top_commands.truncate(15);

    HoneypotIntel {
        total_sessions,
        unique_ips: unique_ips.len() as u64,
        top_credentials,
        top_commands,
        tool_signatures: tools.into_iter().collect(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attacker_intel::{self, GeoIdentity};
    use crate::decisions::DecisionEntry;

    fn write_jsonl(path: &Path, lines: &[String]) {
        let mut content = lines.join("\n");
        content.push('\n');
        std::fs::write(path, content).unwrap();
    }

    fn incident_line(incident_id: &str, ip: Option<&str>) -> String {
        let entities = ip
            .map(|addr| vec![serde_json::json!({"type": "ip", "value": addr})])
            .unwrap_or_default();
        serde_json::json!({
            "incident_id": incident_id,
            "entities": entities
        })
        .to_string()
    }

    fn decision_line(action_type: &str) -> String {
        serde_json::to_string(&DecisionEntry {
            ts: Utc::now(),
            incident_id: "inc-1".to_string(),
            host: "host-a".to_string(),
            ai_provider: "stub".to_string(),
            action_type: action_type.to_string(),
            target_ip: Some("10.0.0.1".to_string()),
            target_user: None,
            skill_id: Some("skill.test".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "test".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        })
        .unwrap()
    }

    fn make_profile(ip: &str, risk: u8, detectors: &[&str]) -> AttackerProfile {
        let mut p = attacker_intel::new_profile(ip, Utc::now());
        p.risk_score = risk;
        p.total_incidents = risk as u32; // ensure non-zero for campaign detection
        for d in detectors {
            p.detectors_triggered.insert(d.to_string());
        }
        p.visit_dates.push("2026-03-15".to_string());
        p
    }

    fn make_profile_with_geo(
        ip: &str,
        risk: u8,
        detectors: &[&str],
        country: &str,
        country_code: &str,
    ) -> AttackerProfile {
        let mut p = make_profile(ip, risk, detectors);
        p.geo = Some(GeoIdentity {
            country: country.to_string(),
            country_code: country_code.to_string(),
            city: "City".to_string(),
            isp: "ISP".to_string(),
            asn: "AS123".to_string(),
        });
        p.mitre_techniques
            .insert("T1110.001 (Brute Force: Password Guessing)".to_string());
        p
    }

    #[test]
    fn report_exists_returns_false_for_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!report_exists(dir.path(), "2026-03"));
    }

    #[test]
    fn available_months_finds_reports() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("monthly-report-2026-03.json"), "{}").unwrap();
        let months = available_months(dir.path());
        assert!(months.contains(&"2026-03".to_string()));
    }

    #[test]
    fn campaign_detection_uses_dna_engine() {
        let mut profiles = HashMap::new();
        let p1 = make_profile(
            "1.1.1.1",
            80,
            &["ssh_bruteforce", "port_scan", "credential_stuffing"],
        );
        let p2 = make_profile(
            "2.2.2.2",
            70,
            &["ssh_bruteforce", "port_scan", "credential_stuffing"],
        );
        let p3 = make_profile("3.3.3.3", 50, &["web_scan"]);
        profiles.insert("1.1.1.1".into(), p1);
        profiles.insert("2.2.2.2".into(), p2);
        profiles.insert("3.3.3.3".into(), p3);

        let campaigns = attacker_intel::detect_campaigns(&profiles);
        // p1 and p2 share DNA signature (same detectors)
        assert!(!campaigns.is_empty());
        let camp = &campaigns[0];
        assert_eq!(camp.member_ips.len(), 2);
    }

    #[test]
    fn empty_profiles_no_campaigns() {
        let profiles = HashMap::new();
        let campaigns = attacker_intel::detect_campaigns(&profiles);
        assert!(campaigns.is_empty());
    }

    #[test]
    fn generate_monthly_empty_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let profiles = HashMap::new();
        let report = generate_monthly(dir.path(), "2026-03", &profiles).unwrap();
        assert_eq!(report.executive_summary.total_events, 0);
        assert_eq!(report.month, "2026-03");
    }

    // The three tests below + `incident_count_boundaries_one_and_thousand_are_handled`
    // open a real `redb` store via `generate_monthly`, which pulls in
    // `scheduled-thread-pool` for background WAL compaction. On macOS GitHub
    // Actions runners that thread-pool deterministically hits
    // `pthread_create` EAGAIN (errno 35) — runner thread budget is tight
    // and the cumulative test run blows it.
    //
    // Linux release builds (the only target we ship today; nightmare codename)
    // run all four tests in `release.yml` + scenario-qa + replay-qa. Skipping
    // them on macOS loses zero meaningful coverage and stops the
    // `Build and publish (macOS)` job in release.yml from blocking tags.
    // Re-enable if we add a macOS shipping target (Phantom codename) AND
    // the upstream thread-pool dep is replaced or its thread count capped.

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn markdown_renders_without_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let profiles = HashMap::new();
        let report = generate_monthly(dir.path(), "2026-03", &profiles).unwrap();
        let md = render_markdown(&report);
        assert!(md.contains("# InnerWarden Threat Report"));
        assert!(md.contains("2026-03"));
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn write_report_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let profiles = HashMap::new();
        let report = generate_monthly(dir.path(), "2026-03", &profiles).unwrap();
        let (json_path, md_path) = write_report(&report, dir.path()).unwrap();
        assert!(json_path.exists());
        assert!(md_path.exists());
    }

    #[test]
    fn month_validation_and_directory_sanitization_reject_bad_inputs() {
        let dir = tempfile::TempDir::new().unwrap();
        for bad_month in [
            "2026-3",
            "202603",
            "2026/03",
            "2026\\03",
            "../2026-03",
            "1999-12",
            "2101-01",
            "2026-13",
        ] {
            assert!(!report_exists(dir.path(), bad_month), "{bad_month}");
        }

        assert!(generate_monthly(dir.path(), "2026-13", &HashMap::new()).is_err());
        assert!(available_months(Path::new("/definitely/missing/path")).is_empty());

        let file_path = dir.path().join("not_a_dir.txt");
        std::fs::write(&file_path, "x").unwrap();
        assert!(available_months(&file_path).is_empty());
    }

    #[test]
    fn available_months_detects_reports_and_incidents_and_sorts_desc() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("monthly-report-2026-01.json"), "{}").unwrap();
        std::fs::write(dir.path().join("monthly-report-2026-03.json"), "{}").unwrap();
        std::fs::write(dir.path().join("incidents-2026-02-15.jsonl"), "{}\n").unwrap();
        std::fs::write(dir.path().join("incidents-graph-2026-03-01.jsonl"), "{}\n").unwrap();
        std::fs::write(dir.path().join("incidents-2026-AA-01.jsonl"), "{}\n").unwrap();

        let months = available_months(dir.path());
        assert_eq!(months.first().map(String::as_str), Some("2026-03"));
        assert!(months.contains(&"2026-02".to_string()));
        assert!(months.contains(&"2026-01".to_string()));
        assert!(!months.contains(&"2026-AA".to_string()));
    }

    #[test]
    fn count_jsonl_lines_handles_existing_and_missing_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sample.jsonl");
        std::fs::write(&path, "a\nb\nc\n").unwrap();
        assert_eq!(count_jsonl_lines(&path), 3);
        assert_eq!(count_jsonl_lines(&dir.path().join("absent.jsonl")), 0);
    }

    #[test]
    fn helper_aggregations_cover_mitre_geo_and_honeypot_paths() {
        let mut by_detector = BTreeMap::new();
        by_detector.insert("ssh_bruteforce".to_string(), 3);
        by_detector.insert("unknown_detector".to_string(), 10);

        let mut p1 = make_profile_with_geo(
            "10.0.0.1",
            80,
            &["ssh_bruteforce", "credential_stuffing"],
            "United States",
            "US",
        );
        p1.honeypot_sessions = 3;
        p1.credentials_attempted
            .push(("root".to_string(), "toor".to_string()));
        p1.commands_executed.push("wget http://evil".to_string());
        p1.dna.tool_signatures.push("wget".to_string());

        let mut p2 =
            make_profile_with_geo("10.0.0.2", 60, &["ssh_bruteforce"], "United States", "US");
        p2.honeypot_sessions = 1;
        p2.credentials_attempted
            .push(("admin".to_string(), "admin".to_string()));
        p2.commands_executed.push("curl http://evil".to_string());
        p2.dna.tool_signatures.push("curl".to_string());
        p2.mitre_techniques
            .insert("T1110 (Brute Force)".to_string());

        let mut profiles_map = HashMap::new();
        profiles_map.insert(p1.ip.clone(), p1.clone());
        profiles_map.insert(p2.ip.clone(), p2.clone());

        let mitre = build_mitre_coverage(&by_detector, &profiles_map);
        assert!(mitre.total_unique_techniques >= 1);
        assert!(!mitre.tactics_counts.is_empty());
        assert!(mitre
            .techniques_seen
            .iter()
            .any(|t| t.attacker_count >= 1 && t.incident_count >= 1));

        let no_geo = make_profile("10.0.0.3", 40, &["web_scan"]);
        let geo = build_geo_distribution(&[&p1, &p2, &no_geo]);
        assert_eq!(geo.by_country.len(), 1);
        assert_eq!(geo.by_country[0].country_code, "US");
        assert_eq!(geo.by_country[0].attacker_count, 2);

        let hp = build_honeypot_intel(&[&p1, &p2, &no_geo]);
        assert_eq!(hp.total_sessions, 4);
        assert_eq!(hp.unique_ips, 2);
        assert!(!hp.top_credentials.is_empty());
        assert!(!hp.top_commands.is_empty());
        assert!(!hp.tool_signatures.is_empty());
    }

    #[test]
    fn generate_monthly_parses_jsonl_skips_corrupt_and_aggregates_weekly_metrics() {
        let dir = tempfile::TempDir::new().unwrap();
        let date = "2026-03-15";
        write_jsonl(
            &dir.path().join(format!("events-{date}.jsonl")),
            &["e1".to_string(), "e2".to_string(), "e3".to_string()],
        );
        write_jsonl(
            &dir.path().join(format!("incidents-{date}.jsonl")),
            &[
                incident_line("ssh_bruteforce:001", Some("10.10.10.1")),
                "{bad-json".to_string(),
                incident_line("ssh_bruteforce:002", Some("10.10.10.2")),
            ],
        );
        write_jsonl(
            &dir.path().join(format!("decisions-{date}.jsonl")),
            &[
                decision_line("block_ip"),
                "not-json".to_string(),
                decision_line("observe"),
            ],
        );

        let profiles = HashMap::new();
        let report = generate_monthly(dir.path(), "2026-03", &profiles).unwrap();

        assert_eq!(report.executive_summary.total_events, 3);
        assert_eq!(report.executive_summary.total_incidents, 2);
        assert_eq!(report.executive_summary.total_decisions, 2);
        assert_eq!(report.executive_summary.total_blocks, 1);
        assert_eq!(report.executive_summary.unique_attackers, 2);
        assert_eq!(report.executive_summary.days_with_data, 1);
        assert_eq!(report.executive_summary.top_detector, "ssh_bruteforce");

        let week = &report.weekly_trends[2]; // day 15 is week index 2
        assert_eq!(week.events, 3);
        assert_eq!(week.incidents, 2);
        assert_eq!(week.decisions, 2);
        assert_eq!(week.blocks, 1);
        assert_eq!(week.unique_attackers, 2);
    }

    #[test]
    fn generate_monthly_top20_json_markdown_and_private_field_contract() {
        let dir = tempfile::TempDir::new().unwrap();
        let date = "2026-03-05";
        write_jsonl(
            &dir.path().join(format!("events-{date}.jsonl")),
            &["ev".to_string()],
        );
        write_jsonl(
            &dir.path().join(format!("incidents-{date}.jsonl")),
            &[
                incident_line("ssh_bruteforce:1", Some("20.0.0.1")),
                incident_line("ransomware:2", Some("20.0.0.2")),
            ],
        );
        write_jsonl(
            &dir.path().join(format!("decisions-{date}.jsonl")),
            &[decision_line("block_ip")],
        );

        let mut profiles = HashMap::new();
        for i in 0..25u8 {
            let ip = format!("20.0.0.{}", i + 1);
            let mut p = make_profile_with_geo(
                &ip,
                100u8.saturating_sub(i),
                &["ssh_bruteforce", "credential_stuffing", "port_scan"],
                "United States",
                "US",
            );
            p.visit_dates.push("2026-03-05".to_string());
            p.total_incidents = (i as u32) + 1;
            p.iocs.urls.push("http://evil.shared/payload".to_string());
            p.honeypot_sessions = 1;
            p.credentials_attempted
                .push(("root".to_string(), "toor".to_string()));
            p.commands_executed.push("cat /etc/passwd".to_string());
            p.dna.tool_signatures.push("busybox".to_string());
            p.mesh_peer_confirmations = 2;
            p.mesh_signals_received = 3;

            if i == 0 {
                p.total_blocks = 3;
            } else if i == 1 {
                p.total_honeypot_diversions = 2;
            } else if i == 2 {
                p.total_monitors = 4;
            }
            profiles.insert(ip, p);
        }

        let report = generate_monthly(dir.path(), "2026-03", &profiles).unwrap();
        assert_eq!(report.top_attackers.len(), 20);
        assert!(report.top_attackers[0].risk_score >= report.top_attackers[1].risk_score);
        let actions: std::collections::HashSet<&str> = report
            .top_attackers
            .iter()
            .map(|a| a.action_taken.as_str())
            .collect();
        assert!(actions.contains("blocked"));
        assert!(actions.contains("honeypot"));
        assert!(actions.contains("monitoring"));
        assert!(actions.contains("observed"));

        assert!(!report.mitre_coverage.techniques_seen.is_empty());
        assert!(!report.geographic_distribution.by_country.is_empty());
        assert!(report.honeypot_intelligence.total_sessions > 0);
        assert!(!report.honeypot_intelligence.top_credentials.is_empty());
        assert!(!report.campaigns.is_empty());
        assert!(!report.weekly_trends.is_empty());

        let (json_path, md_path) = write_report(&report, dir.path()).unwrap();
        let json_text = std::fs::read_to_string(json_path).unwrap();
        let json_val: serde_json::Value = serde_json::from_str(&json_text).unwrap();
        assert!(json_val.get("generated_at").is_some());
        assert!(json_val.get("executive_summary").is_some());
        assert!(json_val.get("top_attackers").is_some());
        assert!(json_val.get("campaigns").is_some());
        assert!(json_val.get("weekly_trends").is_some());
        assert!(!json_text.contains("credentials_attempted"));
        assert!(!json_text.contains("hour_distribution"));
        assert!(!json_text.contains("mesh_peer_confirmations"));

        let md = std::fs::read_to_string(md_path).unwrap();
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("## Top Attackers"));
        assert!(md.contains("## MITRE ATT&CK Coverage"));
        assert!(md.contains("## Geographic Distribution"));
        assert!(md.contains("## Detected Campaigns"));
        assert!(md.contains("## Honeypot Intelligence"));
        assert!(md.contains("## Weekly Trends"));
    }

    #[test]
    fn campaign_detection_ioc_overlap_and_no_overlap_cases() {
        let dir = tempfile::TempDir::new().unwrap();

        let mut overlap_profiles = HashMap::new();
        let mut a = make_profile("30.0.0.1", 80, &["port_scan"]);
        a.iocs.urls.push("http://shared.c2/payload".to_string());
        let mut b = make_profile("30.0.0.2", 70, &["ssh_bruteforce"]);
        b.iocs.urls.push("http://shared.c2/payload".to_string());
        overlap_profiles.insert(a.ip.clone(), a);
        overlap_profiles.insert(b.ip.clone(), b);

        let overlap_report = generate_monthly(dir.path(), "2026-03", &overlap_profiles).unwrap();
        assert_eq!(overlap_report.campaigns.len(), 1);
        assert!(overlap_report.campaigns[0].correlation_type.contains("ioc"));

        let mut no_overlap_profiles = HashMap::new();
        let p1 = make_profile("31.0.0.1", 60, &["ssh_bruteforce"]);
        let p2 = make_profile("31.0.0.2", 55, &["web_scan"]);
        no_overlap_profiles.insert(p1.ip.clone(), p1);
        no_overlap_profiles.insert(p2.ip.clone(), p2);

        let no_overlap_report =
            generate_monthly(dir.path(), "2026-03", &no_overlap_profiles).unwrap();
        assert!(no_overlap_report.campaigns.is_empty());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn incident_count_boundaries_one_and_thousand_are_handled() {
        let dir = tempfile::TempDir::new().unwrap();

        write_jsonl(
            &dir.path().join("incidents-2026-03-02.jsonl"),
            &[incident_line("ssh_bruteforce:1", Some("40.0.0.1"))],
        );
        let one = generate_monthly(dir.path(), "2026-03", &HashMap::new()).unwrap();
        assert_eq!(one.executive_summary.total_incidents, 1);

        let mut thousand_lines = Vec::with_capacity(1000);
        for i in 0..1000 {
            thousand_lines.push(incident_line(
                &format!("ssh_bruteforce:{i}"),
                Some("40.0.0.2"),
            ));
        }
        write_jsonl(
            &dir.path().join("incidents-2026-03-03.jsonl"),
            &thousand_lines,
        );
        let thousand = generate_monthly(dir.path(), "2026-03", &HashMap::new()).unwrap();
        assert_eq!(thousand.executive_summary.total_incidents, 1001);
    }

    // Spec 037 I-13 follow-up #2: open_monthly_incident_jsonl_or_warn

    #[test]
    fn open_monthly_incident_jsonl_or_warn_returns_some_silently_on_existing_file() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("incidents-2026-04-01.jsonl");
        std::fs::write(&path, b"{}\n").expect("seed file");

        let result = open_monthly_incident_jsonl_or_warn(&path);
        assert!(result.is_some(), "existing file must yield Some");

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("monthly incident JSONL"),
            "happy path must not emit warn, got: {captured}"
        );
    }

    #[test]
    fn open_monthly_incident_jsonl_or_warn_returns_none_and_warns_on_io_failure() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        let path = blocking_file.join("incidents-2026-04-01.jsonl");

        let result = open_monthly_incident_jsonl_or_warn(&path);
        assert!(result.is_none(), "io-failure must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("monthly incident JSONL open failed"),
            "io-failure warn missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
        );
    }
}
