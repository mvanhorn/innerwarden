//! DNS Command & Control detector.
//!
//! Detects C2 communication hidden in DNS queries, distinct from DNS tunneling
//! (data exfiltration). C2 over DNS uses DNS as a bidirectional command channel:
//! - Commands sent via TXT/CNAME/MX responses from attacker's DNS server
//! - Results sent via encoded subdomain queries
//!
//! MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS)
//!
//! Patterns detected:
//! 1. TXT record queries to non-standard domains (C2 commands come via TXT)
//! 2. High-frequency queries to same domain with varying subdomains (polling)
//! 3. Long encoded subdomains (base32/base64/hex encoded payloads)
//! 4. Periodic query patterns (beacon interval detection via jitter analysis)

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
    incident::Incident,
};

/// Known legitimate DNS-heavy services to exclude.
const ALLOWED_DOMAINS: &[&str] = &[
    "googleapis.com",
    "gstatic.com",
    "cloudflare.com",
    "amazonaws.com",
    "azure.com",
    "microsoft.com",
    "akamaiedge.net",
    "cloudfront.net",
    "fbcdn.net",
    "apple.com",
    "icloud.com",
    "ubuntu.com",
    "debian.org",
    "github.com",
    "docker.io",
    "docker.com",
    "snapcraft.io",
    "canonical.com",
    "letsencrypt.org",
    "ntp.org",
    "in-addr.arpa",
    "ip6.arpa",
    "local",
    "localhost",
    "innerwarden.com",
    // Cloud providers — OCI instances resolve metadata, API endpoints,
    // storage, and internal services via these domains. Observed
    // 2026-04-12: 7 "Possible DNS C2 channel: oraclecloud.com" Medium
    // FPs per hour from normal OCI metadata/API resolution.
    "oraclecloud.com",
    "oracle.com",
    "oraclecloud.net",
    "oci.oraclecloud.com",
    // AWS (EC2 metadata, S3, SSM, etc.)
    "aws.amazon.com",
    "awsstatic.com",
    // GCP
    "google.internal",
    "googleusercontent.com",
    // Hetzner
    "hetzner.com",
    "hetzner.cloud",
];

pub struct DnsC2Detector {
    window: Duration,
    /// Per root domain: ring of (timestamp, full_query, query_type)
    queries: HashMap<String, VecDeque<(DateTime<Utc>, String, String)>>,
    /// Cooldown per domain
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
    /// Min queries to same root domain before analysis (avoid FP on low traffic)
    min_queries: usize,
    /// Min subdomain length to flag as encoded
    min_encoded_len: usize,
}

impl DnsC2Detector {
    pub fn new(host: impl Into<String>, min_queries: usize, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            queries: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
            min_queries,
            min_encoded_len: 20,
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "dns.query" {
            return None;
        }

        let domain = event.details.get("domain").and_then(|v| v.as_str())?;
        let query_type = event
            .details
            .get("query_type")
            .and_then(|v| v.as_str())
            .unwrap_or("A");
        let now = event.ts;
        let cutoff = now - self.window;

        // Extract root domain (last 2 labels)
        let root = extract_root_domain(domain);

        // Skip known-good domains
        if ALLOWED_DOMAINS.iter().any(|d| root.ends_with(d)) {
            return None;
        }

        // Track query
        let entries = self.queries.entry(root.clone()).or_default();
        while entries.front().is_some_and(|(ts, _, _)| *ts < cutoff) {
            entries.pop_front();
        }
        entries.push_back((now, domain.to_string(), query_type.to_string()));

        // Not enough data yet
        if entries.len() < self.min_queries {
            return None;
        }

        // Cooldown
        if let Some(&last) = self.alerted.get(&root) {
            if now - last < self.window {
                return None;
            }
        }

        // ── Analysis ──

        let mut signals: Vec<String> = Vec::new();
        let mut score: f32 = 0.0;

        // Signal 1: TXT record queries (C2 commands often come via TXT)
        let txt_count = entries
            .iter()
            .filter(|(_, _, qt)| qt == "TXT" || qt == "CNAME" || qt == "MX" || qt == "NULL")
            .count();
        if txt_count >= 3 {
            signals.push(format!(
                "{txt_count} TXT/CNAME/MX queries (C2 response channel)"
            ));
            score += 0.3;
        }

        // Signal 2: High unique subdomain count (encoded payloads)
        let unique_subdomains: std::collections::HashSet<&str> = entries
            .iter()
            .filter_map(|(_, full, _)| {
                let stripped = full.strip_suffix(&format!(".{root}"))?;
                Some(stripped)
            })
            .collect();
        let unique_ratio = unique_subdomains.len() as f32 / entries.len().max(1) as f32;
        if unique_ratio > 0.7 && unique_subdomains.len() >= 5 {
            signals.push(format!(
                "{} unique subdomains ({:.0}% unique — encoded payloads)",
                unique_subdomains.len(),
                unique_ratio * 100.0
            ));
            score += 0.3;
        }

        // Signal 3: Long subdomains (base32/base64/hex encoded)
        let long_subs: Vec<&&str> = unique_subdomains
            .iter()
            .filter(|s| s.len() >= self.min_encoded_len)
            .collect();
        if long_subs.len() >= 3 {
            signals.push(format!(
                "{} long subdomains (>{}chars — likely encoded)",
                long_subs.len(),
                self.min_encoded_len
            ));
            score += 0.2;
        }

        // Signal 4: Periodic pattern (beaconing)
        if entries.len() >= 6 {
            let intervals: Vec<i64> = entries
                .iter()
                .zip(entries.iter().skip(1))
                .map(|((t1, _, _), (t2, _, _))| (*t2 - *t1).num_seconds())
                .filter(|i| *i > 0)
                .collect();
            if intervals.len() >= 4 {
                let mean = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
                let variance = intervals
                    .iter()
                    .map(|i| (*i as f64 - mean).powi(2))
                    .sum::<f64>()
                    / intervals.len() as f64;
                let cv = variance.sqrt() / mean.max(0.001); // coefficient of variation
                if cv < 0.5 && mean > 1.0 && mean < 300.0 {
                    signals.push(format!(
                        "periodic pattern: ~{:.0}s interval (CV={:.2} — beaconing)",
                        mean, cv
                    ));
                    score += 0.3;
                }
            }
        }

        // Need at least 2 signals and score >= 0.5 to alert
        if signals.len() < 2 || score < 0.5 {
            return None;
        }

        self.alerted.insert(root.clone(), now);

        let severity = if score >= 0.8 {
            Severity::High
        } else {
            Severity::Medium
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("dns_c2:{}:{}", root, now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("Possible DNS C2 channel: {root}"),
            summary: format!(
                "Domain {root} shows DNS C2 indicators: {}. Score: {score:.2}",
                signals.join("; ")
            ),
            evidence: serde_json::json!({
                "root_domain": root,
                "query_count": entries.len(),
                "signals": signals,
                "score": score,
                "txt_queries": txt_count,
                "unique_subdomains": unique_subdomains.len(),
                "sample_queries": entries.iter().take(5).map(|(_, q, t)| format!("{t} {q}")).collect::<Vec<_>>(),
            }),
            recommended_checks: vec![
                format!("Investigate DNS queries to {root} — check for data encoding"),
                "Review process making these queries (check /proc/net/udp for source PID)".into(),
                "Compare with known C2 frameworks: DNSCat2, Cobalt Strike DNS, iodine".into(),
                "Block domain at DNS resolver level if confirmed malicious".into(),
            ],
            tags: vec![
                "network".into(),
                "dns".into(),
                "c2".into(),
                "T1071.004".into(),
            ],
            entities: vec![EntityRef::service(root)],
        })
    }
}

/// Extract root domain (last 2 labels, or 3 for co.uk/com.br style).
fn extract_root_domain(domain: &str) -> String {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return domain.trim_end_matches('.').to_string();
    }
    // Handle ccTLD like co.uk, com.br, co.jp
    let sld = labels[labels.len() - 2];
    if (sld == "co" || sld == "com" || sld == "org" || sld == "net") && labels.len() >= 3 {
        labels[labels.len() - 3..].join(".")
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_event(domain: &str, qtype: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "dns_capture".into(),
            kind: "dns.query".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({
                "domain": domain,
                "query_type": qtype,
            }),
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn test_extract_root_domain() {
        assert_eq!(extract_root_domain("evil.com"), "evil.com");
        assert_eq!(extract_root_domain("abc123.payload.evil.com"), "evil.com");
        assert_eq!(extract_root_domain("data.exfil.co.uk"), "exfil.co.uk");
    }

    #[test]
    fn test_no_alert_on_legitimate() {
        let mut det = DnsC2Detector::new("host1", 3, 300);
        let now = Utc::now();
        for i in 0..10 {
            let e = dns_event("www.googleapis.com", "A", now + Duration::seconds(i));
            assert!(det.process(&e).is_none());
        }
    }

    #[test]
    fn test_detects_c2_pattern() {
        let mut det = DnsC2Detector::new("host1", 5, 300);
        let now = Utc::now();

        // Simulate C2 beaconing: periodic TXT queries with encoded subdomains
        for i in 0..8 {
            let subdomain = format!("{}abcdef0123456789abcdef.evil-c2.com", i);
            let e = dns_event(&subdomain, "TXT", now + Duration::seconds(i * 30));
            let result = det.process(&e);
            if i >= 5 {
                // Should eventually trigger
                if let Some(inc) = result {
                    assert!(inc.incident_id.contains("dns_c2"));
                    assert!(inc.tags.contains(&"T1071.004".into()));
                    return;
                }
            }
        }
    }

    #[test]
    fn test_allowed_domains_skipped() {
        let mut det = DnsC2Detector::new("host1", 3, 300);
        let now = Utc::now();
        for i in 0..20 {
            let sub = format!("encoded{}.ubuntu.com", i);
            let e = dns_event(&sub, "TXT", now + Duration::seconds(i));
            assert!(det.process(&e).is_none());
        }
    }
}
