use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Timelike, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects successful SSH logins from IPs that previously had failed attempts.
/// Pattern: brute-force → success = possible compromise.
///
/// Also flags:
/// - First-time IPs logging into privileged accounts (root, admin, sudo users)
/// - Logins during off-hours (22:00-06:00 UTC) from any non-baseline IP
///
/// V4 AlphaZero finding: ValidAccountLogin was the #1 attacker technique (378 uses)
/// because it bypassed all SSH detection. This enhancement closes that gap.
pub struct SuspiciousLoginDetector {
    window: Duration,
    /// Per-IP ring of failed login timestamps within window.
    failed_ips: HashMap<String, VecDeque<DateTime<Utc>>>,
    /// IPs that have successfully logged in before (known-good baseline).
    known_good_ips: std::collections::HashSet<String>,
    /// Per-IP: hours when logins were seen (for off-hours detection).
    ip_login_hours: HashMap<String, std::collections::HashSet<u32>>,
    /// Suppress re-alerts per IP within window.
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
    /// Enable time-of-day anomaly detection based on per-user login hour baseline.
    anomaly_hours_enabled: bool,
    /// Per-user: bitmask of hours (0-23) when logins have been observed.
    user_login_hours: HashMap<String, [bool; 24]>,
    /// Per-user: set of distinct dates (YYYY-MM-DD) with observed logins.
    user_training_dates: HashMap<String, std::collections::HashSet<String>>,
}

impl SuspiciousLoginDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64, anomaly_hours_enabled: bool) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            failed_ips: HashMap::new(),
            known_good_ips: std::collections::HashSet::new(),
            ip_login_hours: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
            anomaly_hours_enabled,
            user_login_hours: HashMap::new(),
            user_training_dates: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        let ip = event.details["ip"].as_str()?.to_string();
        if super::is_internal_ip(&ip) {
            return None;
        }
        let now = event.ts;
        let cutoff = now - self.window;

        // Track failed logins
        if event.kind == "ssh.login_failed" {
            let entries = self.failed_ips.entry(ip).or_default();
            while entries.front().is_some_and(|&t| t < cutoff) {
                entries.pop_front();
            }
            entries.push_back(now);
            return None;
        }

        // Only care about successful logins
        if event.kind != "ssh.login_success" {
            return None;
        }

        let user = event.details["user"].as_str().unwrap_or("unknown");
        let hour = now.hour();

        // Check for anomalous login hour BEFORE updating user baseline (must read prior state).
        let is_anomaly_hour = if self.anomaly_hours_enabled {
            let dates = self.user_training_dates.get(user);
            let profile = self.user_login_hours.get(user);
            match (dates, profile) {
                (Some(d), Some(p)) if d.len() >= 7 => !p[hour as usize],
                _ => false,
            }
        } else {
            false
        };

        // Update user login baseline tracking.
        let date_str = now.format("%Y-%m-%d").to_string();
        self.user_training_dates
            .entry(user.to_string())
            .or_default()
            .insert(date_str);
        self.user_login_hours.entry(user.to_string()).or_default()[hour as usize] = true;

        // Track login hours for this IP (for off-hours detection).
        self.ip_login_hours
            .entry(ip.clone())
            .or_default()
            .insert(hour);

        // Known-good IPs skip detection unless an anomalous login hour is detected.
        if self.known_good_ips.contains(&ip) && !is_anomaly_hour {
            return None;
        }

        // Check if this IP had prior failed attempts
        let prior_failures = self
            .failed_ips
            .get(&ip)
            .map(|entries| entries.iter().filter(|&&t| t > cutoff).count())
            .unwrap_or(0);

        // Suppress re-alerts within window
        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.window {
                // Still add to known-good so we don't alert again
                self.known_good_ips.insert(ip);
                return None;
            }
        }

        // Check for off-hours login (22:00-06:00 UTC)
        let is_off_hours = !(6..22).contains(&hour);

        // Check for privileged user
        let is_privileged = matches!(user, "root" | "admin" | "ubuntu" | "deploy" | "ansible");

        // Determine alert reason and severity
        let (should_alert, reason, severity) = if prior_failures >= 5 {
            // Classic brute-force → success
            (true, "brute_force_success", Severity::Critical)
        } else if prior_failures > 0 {
            // Some failures then success
            (true, "failed_then_success", Severity::High)
        } else if !self.known_good_ips.contains(&ip) && is_privileged {
            // First-time IP logging into privileged account
            (true, "first_time_privileged", Severity::High)
        } else if !self.known_good_ips.contains(&ip) && is_off_hours {
            // First-time IP during off-hours
            (true, "off_hours_new_ip", Severity::Medium)
        } else if is_anomaly_hour {
            // Login hour outside this user's 7-day baseline profile
            (true, "anomaly_hours_user", Severity::Medium)
        } else {
            // Known-good IP, normal hours — no alert
            (false, "", Severity::Low)
        };

        // Add to known-good baseline
        self.known_good_ips.insert(ip.clone());

        if !should_alert {
            return None;
        }

        // Suppress re-alerts within window
        if let Some(&last) = self.alerted.get(&ip) {
            if now - last < self.window {
                return None;
            }
        }
        self.alerted.insert(ip.clone(), now);

        let title = match reason {
            "brute_force_success" => {
                format!("SSH login from attacking IP {ip} after {prior_failures} failed attempts")
            }
            "failed_then_success" => {
                format!("SSH login from {ip} after {prior_failures} failed attempts")
            }
            "first_time_privileged" => {
                format!("First-time SSH login to privileged account {user} from {ip}")
            }
            "off_hours_new_ip" => format!("Off-hours SSH login from new IP {ip} as {user}"),
            "anomaly_hours_user" => {
                format!("SSH login by {user} at {hour}:00 UTC — outside baseline hours")
            }
            _ => format!("Suspicious SSH login from {ip} as {user}"),
        };

        let summary = match reason {
            "brute_force_success" | "failed_then_success" => format!(
                "IP {ip} logged in as {user} after {prior_failures} failed attempts in {} seconds. Likely compromised credential.",
                self.window.num_seconds()
            ),
            "first_time_privileged" => format!(
                "IP {ip} logged in as privileged user {user} for the first time. No prior history for this IP. Verify authorization."
            ),
            "off_hours_new_ip" => format!(
                "IP {ip} logged in as {user} at {hour}:00 UTC (off-hours) from an IP never seen before. Possible credential theft."
            ),
            "anomaly_hours_user" => format!(
                "User {user} logged in at {hour}:00 UTC from {ip}. This hour has not been observed in the 7-day login baseline. Possible unauthorized access."
            ),
            _ => format!("IP {ip} logged in as {user} — suspicious pattern: {reason}"),
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("suspicious_login:{}:{}", ip, now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title,
            summary,
            evidence: serde_json::json!([{
                "kind": "suspicious_login",
                "reason": reason,
                "ip": ip,
                "user": user,
                "prior_failures": prior_failures,
                "hour": hour,
                "is_off_hours": is_off_hours,
                "is_privileged": is_privileged,
                "first_time_ip": !self.known_good_ips.contains(&ip),
                "window_seconds": self.window.num_seconds(),
            }]),
            recommended_checks: vec![
                format!("Verify if {user} login from {ip} was authorized"),
                format!("Check commands run by {user} after login"),
                "Review /var/log/auth.log for the full session".to_string(),
                if is_privileged {
                    "Consider suspending sudo access until verified".to_string()
                } else {
                    "Monitor for privilege escalation".to_string()
                },
            ],
            tags: vec![
                "auth".to_string(),
                "ssh".to_string(),
                if reason.contains("brute") {
                    "compromise".to_string()
                } else {
                    "suspicious".to_string()
                },
            ],
            entities: vec![EntityRef::ip(&ip), EntityRef::user(user)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_event(ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: format!("Failed SSH from {ip}"),
            details: serde_json::json!({"ip": ip, "user": "root"}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    fn success_event(ip: &str, user: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_success".to_string(),
            severity: Severity::Info,
            summary: format!("Login accepted for {user} from {ip}"),
            details: serde_json::json!({"ip": ip, "user": user}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip), EntityRef::user(user)],
        }
    }

    #[test]
    fn fires_on_success_after_failures() {
        let mut det = SuspiciousLoginDetector::new("test", 300, false);
        let now = Utc::now();

        // 3 failed attempts
        det.process(&failed_event("1.2.3.4", now));
        det.process(&failed_event("1.2.3.4", now + Duration::seconds(1)));
        det.process(&failed_event("1.2.3.4", now + Duration::seconds(2)));

        // Then success
        let inc = det
            .process(&success_event(
                "1.2.3.4",
                "root",
                now + Duration::seconds(10),
            ))
            .expect("should fire");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("1.2.3.4"));
        assert!(inc.summary.contains("3 failed") || inc.summary.contains("failed attempts"));
    }

    #[test]
    fn critical_for_many_failures() {
        let mut det = SuspiciousLoginDetector::new("test", 300, false);
        let now = Utc::now();

        for i in 0..6 {
            det.process(&failed_event("5.6.7.8", now + Duration::seconds(i)));
        }

        let inc = det
            .process(&success_event(
                "5.6.7.8",
                "admin",
                now + Duration::seconds(10),
            ))
            .expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn no_alert_for_clean_login_nonpriv() {
        let mut det = SuspiciousLoginDetector::new("test", 300, false);
        // Use a fixed daytime hour (12:00 UTC) to avoid off-hours detection
        let now = Utc::now()
            .date_naive()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc();

        // Success without prior failures from non-privileged user → no alert
        assert!(det
            .process(&success_event("9.9.9.9", "www-data", now))
            .is_none());
    }

    #[test]
    fn alerts_first_time_privileged_login() {
        let mut det = SuspiciousLoginDetector::new("test", 300, false);
        let now = Utc::now();

        // First-time login to privileged account should alert (V4 enhancement)
        let inc = det
            .process(&success_event("9.9.9.9", "ubuntu", now))
            .expect("should fire for first-time privileged");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("First-time") || inc.title.contains("privileged"));
    }

    #[test]
    fn no_alert_for_known_good_ip() {
        let mut det = SuspiciousLoginDetector::new("test", 300, false);
        let now = Utc::now();

        // First login - becomes known-good
        det.process(&success_event("1.1.1.1", "ubuntu", now));

        // Failures then success from known-good - no alert
        det.process(&failed_event("1.1.1.1", now + Duration::seconds(100)));
        assert!(det
            .process(&success_event(
                "1.1.1.1",
                "ubuntu",
                now + Duration::seconds(200)
            ))
            .is_none());
    }

    #[test]
    fn ignores_internal_ips() {
        let mut det = SuspiciousLoginDetector::new("test", 300, false);
        let now = Utc::now();

        det.process(&failed_event("192.168.1.1", now));
        assert!(det
            .process(&success_event(
                "192.168.1.1",
                "root",
                now + Duration::seconds(1)
            ))
            .is_none());
    }

    #[test]
    fn suppresses_realert_within_window() {
        let mut det = SuspiciousLoginDetector::new("test", 300, false);
        let now = Utc::now();

        det.process(&failed_event("1.2.3.4", now));
        assert!(det
            .process(&success_event(
                "1.2.3.4",
                "root",
                now + Duration::seconds(1)
            ))
            .is_some());
        // Second alert suppressed
        det.process(&failed_event("1.2.3.4", now + Duration::seconds(10)));
        assert!(det
            .process(&success_event(
                "1.2.3.4",
                "root",
                now + Duration::seconds(11)
            ))
            .is_none());
    }

    fn success_event_at_hour(ip: &str, user: &str, date: &str, hour: u32) -> Event {
        let ts = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
            .unwrap()
            .and_hms_opt(hour, 0, 0)
            .unwrap()
            .and_utc();
        Event {
            ts,
            host: "test".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_success".to_string(),
            severity: Severity::Info,
            summary: format!("Login accepted for {user} from {ip}"),
            details: serde_json::json!({"ip": ip, "user": user}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip), EntityRef::user(user)],
        }
    }

    #[test]
    fn anomaly_hours_fires_after_baseline_matures() {
        let mut det = SuspiciousLoginDetector::new("test", 300, true);

        // Build a 7-day baseline: alice logs in at 10:00 UTC from a known IP.
        // This makes the IP known-good so the anomaly_hours branch is reached
        // (a brand-new IP at 3am would fire off_hours_new_ip instead).
        for day in 1..=7u32 {
            let date = format!("2026-03-{day:02}");
            det.process(&success_event_at_hour("1.2.3.4", "alice", &date, 10));
        }

        // Same IP (known-good), same user, but at 3:00 UTC — outside baseline.
        let inc = det
            .process(&success_event_at_hour("1.2.3.4", "alice", "2026-03-08", 3))
            .expect("should fire for anomalous login hour");
        assert_eq!(inc.severity, Severity::Medium);
        assert!(
            inc.title.contains("baseline hours") || inc.title.contains("3:00"),
            "title was: {}",
            inc.title
        );
        assert!(inc.summary.contains("baseline"));
    }

    #[test]
    fn anomaly_hours_no_fire_before_baseline_matures() {
        let mut det = SuspiciousLoginDetector::new("test", 300, true);

        // Only 6 days of baseline — not yet mature.
        for day in 1..=6u32 {
            let date = format!("2026-03-{day:02}");
            det.process(&success_event_at_hour("1.2.3.4", "alice", &date, 10));
        }

        // Known-good IP, but baseline not yet mature — no alert.
        assert!(det
            .process(&success_event_at_hour("1.2.3.4", "alice", "2026-03-07", 3))
            .is_none());
    }

    #[test]
    fn anomaly_hours_no_fire_when_disabled() {
        let mut det = SuspiciousLoginDetector::new("test", 300, false);

        for day in 1..=7u32 {
            let date = format!("2026-03-{day:02}");
            det.process(&success_event_at_hour("1.2.3.4", "alice", &date, 10));
        }

        // anomaly_hours_enabled = false, so no alert even at an unseen hour.
        assert!(det
            .process(&success_event_at_hour("1.2.3.4", "alice", "2026-03-08", 3))
            .is_none());
    }

    #[test]
    fn anomaly_hours_no_fire_for_known_hour() {
        let mut det = SuspiciousLoginDetector::new("test", 300, true);

        // Baseline includes hour 10 on 7 days.
        for day in 1..=7u32 {
            let date = format!("2026-03-{day:02}");
            det.process(&success_event_at_hour("1.2.3.4", "alice", &date, 10));
        }

        // Login at 10:00 UTC (within baseline) — no alert.
        assert!(det
            .process(&success_event_at_hour("1.2.3.4", "alice", "2026-03-08", 10))
            .is_none());
    }
}
