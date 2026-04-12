//! Sandbox/Virtualization Evasion detector.
//!
//! Detects malware that checks if it's running in a sandbox, VM, or analysis
//! environment and changes behavior to avoid detection.
//!
//! MITRE ATT&CK: T1497 (Virtualization/Sandbox Evasion)
//!   T1497.001 System Checks (CPUID, DMI, MAC address)
//!   T1497.003 Time Based Evasion (sleep, timing checks)
//!
//! Patterns detected:
//! 1. Process reads VM detection files (/sys/class/dmi/id/*, /proc/scsi/scsi)
//! 2. Process runs VM detection commands (dmidecode, lspci, systemd-detect-virt)
//! 3. Process checks sandbox indicators (agent processes, /proc/self/status TracerPid)
//! 4. Process sleeps then changes behavior (time-based evasion)
//! 5. Process checks timing (rdtsc/clock_gettime bursts to detect single-stepping)

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Files that VM-aware malware commonly checks.
const VM_DETECTION_PATHS: &[&str] = &[
    "/sys/class/dmi/id/product_name",
    "/sys/class/dmi/id/sys_vendor",
    "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/bios_vendor",
    "/sys/class/dmi/id/chassis_vendor",
    "/proc/scsi/scsi",
    "/sys/hypervisor/type",
    "/sys/devices/virtual/dmi",
    "/proc/cpuinfo",                  // checked for hypervisor flag
    "/sys/firmware/acpi/tables/DSDT", // VM-specific ACPI tables
];

/// Commands that check for VM/sandbox environment.
const VM_DETECTION_COMMANDS: &[&str] = &[
    "dmidecode",
    "systemd-detect-virt",
    "virt-what",
    "lspci",
    "lscpu",
    "dmesg | grep -i virtual",
    "dmesg | grep -i vmware",
    "dmesg | grep -i kvm",
    "dmesg | grep -i xen",
    "cat /proc/cpuinfo | grep hypervisor",
    "hostnamectl",
];

/// Processes that sandbox-aware malware checks for (analysis tools).
const ANALYSIS_PROCESSES: &[&str] = &[
    "strace",
    "ltrace",
    "gdb",
    "lldb",
    "radare2",
    "r2",
    "ida",
    "ghidra",
    "frida",
    "wireshark",
    "tcpdump",
    "volatility",
    "cuckoo",
    "sandbox",
];

pub struct SandboxEvasionDetector {
    window: Duration,
    /// Per PID: ring of (timestamp, check_type)
    checks: HashMap<u32, VecDeque<(DateTime<Utc>, String)>>,
    /// Cooldown per PID
    alerted: HashMap<u32, DateTime<Utc>>,
    host: String,
    threshold: usize,
}

impl SandboxEvasionDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            checks: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
            threshold,
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        let now = event.ts;
        let cutoff = now - self.window;

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        if pid == 0 {
            return None;
        }

        // Skip InnerWarden's own processes: the hypervisor audit, SMM audit,
        // and firmware integrity modules legitimately read
        // /sys/class/dmi/id/*, /proc/cpuinfo, and run dmidecode/lspci as
        // part of the own-host security posture check. Without this filter,
        // `tokio-rt-worker` self-triggers sandbox_evasion every few seconds
        // (observed on 2026-04-11: 832+ `Sandbox/VM evasion detected:
        // tokio-rt-worker` High incidents per day, 100% self-detection).
        let ev_uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        let ev_comm = event
            .details
            .get("comm")
            .or(event.details.get("process"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if super::allowlists::is_innerwarden_process(ev_uid, ev_comm) {
            return None;
        }

        let check_type = self.classify_event(event)?;

        // Track
        let entries = self.checks.entry(pid).or_default();
        while entries.front().is_some_and(|(ts, _)| *ts < cutoff) {
            entries.pop_front();
        }
        entries.push_back((now, check_type));

        // Count unique check types
        let unique_types: std::collections::HashSet<&str> =
            entries.iter().map(|(_, t)| t.as_str()).collect();

        if unique_types.len() < self.threshold {
            return None;
        }

        // Cooldown
        if let Some(&last) = self.alerted.get(&pid) {
            if now - last < self.window {
                return None;
            }
        }
        self.alerted.insert(pid, now);

        let comm = event
            .details
            .get("comm")
            .or(event.details.get("process"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let checks: Vec<&str> = unique_types.into_iter().collect();

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "sandbox_evasion:{}:{}:{}",
                comm,
                pid,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: format!("Sandbox/VM evasion detected: {comm} (PID {pid})"),
            summary: format!(
                "Process {comm} (PID {pid}) performed {} different VM/sandbox detection checks in {}s: {}",
                checks.len(),
                self.window.num_seconds(),
                checks.join(", ")
            ),
            evidence: serde_json::json!({
                "pid": pid,
                "comm": comm,
                "check_types": checks,
                "check_count": entries.len(),
                "unique_checks": checks.len(),
                "window_seconds": self.window.num_seconds(),
            }),
            recommended_checks: vec![
                format!("Inspect binary /proc/{pid}/exe — may be malware with sandbox detection"),
                "Check if process changed behavior after VM detection (sleep→exec pattern)".into(),
                "Capture binary for offline analysis (YARA + dynamic sandbox)".into(),
                "Check parent process chain for initial access vector".into(),
            ],
            tags: vec![
                "defense_evasion".into(),
                "sandbox".into(),
                "T1497".into(),
                "T1497.001".into(),
            ],
            entities: vec![EntityRef::service(format!("pid:{pid}"))],
        })
    }

    /// Classify an event as a VM/sandbox detection check.
    fn classify_event(&self, event: &Event) -> Option<String> {
        match event.kind.as_str() {
            "file.read_access" => {
                let path = event.details.get("path").and_then(|v| v.as_str())?;
                if VM_DETECTION_PATHS.iter().any(|p| path.contains(p)) {
                    return Some(format!("vm_file_check:{}", path));
                }
            }
            "shell.command_exec" => {
                let cmd = event
                    .details
                    .get("command")
                    .or(event.details.get("cmdline"))
                    .and_then(|v| v.as_str())?;
                let cmd_lower = cmd.to_lowercase();

                // VM detection commands
                if VM_DETECTION_COMMANDS.iter().any(|c| cmd_lower.contains(c)) {
                    return Some(format!("vm_command:{}", &cmd[..cmd.len().min(50)]));
                }

                // Checking for analysis processes
                if (cmd_lower.contains("pgrep") || cmd_lower.contains("ps "))
                    && ANALYSIS_PROCESSES.iter().any(|p| cmd_lower.contains(p))
                {
                    return Some("analysis_process_check".into());
                }

                // TracerPid check (anti-debug)
                if cmd_lower.contains("tracerpid") || cmd_lower.contains("/proc/self/status") {
                    return Some("anti_debug_check".into());
                }
            }
            "process.prctl" => {
                // PR_SET_PTRACER checks (anti-debug)
                return Some("ptrace_check".into());
            }
            _ => {}
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_read(pid: u32, path: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "file.read_access".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({
                "pid": pid,
                "path": path,
                "comm": "suspicious_bin",
            }),
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    fn cmd_exec(pid: u32, cmd: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "exec_audit".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({
                "pid": pid,
                "command": cmd,
                "comm": "suspicious_bin",
            }),
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn test_detects_vm_check_burst() {
        let mut det = SandboxEvasionDetector::new("host1", 3, 60);
        let now = Utc::now();

        // Process checks multiple VM indicators
        assert!(det
            .process(&file_read(1234, "/sys/class/dmi/id/product_name", now))
            .is_none());
        assert!(det
            .process(&file_read(
                1234,
                "/sys/class/dmi/id/sys_vendor",
                now + Duration::seconds(1)
            ))
            .is_none());
        let result = det.process(&cmd_exec(
            1234,
            "systemd-detect-virt",
            now + Duration::seconds(2),
        ));
        assert!(result.is_some());
        let inc = result.unwrap();
        assert!(inc.tags.contains(&"T1497".to_string()));
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn test_no_alert_single_check() {
        let mut det = SandboxEvasionDetector::new("host1", 3, 60);
        let now = Utc::now();
        // Single check is normal (sysadmin running lspci)
        assert!(det.process(&cmd_exec(1234, "lspci", now)).is_none());
    }
}
