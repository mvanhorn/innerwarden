//! Cross-Layer Correlation Engine.
//!
//! Correlates events across all layers (firmware, kernel/eBPF, userspace,
//! network, honeypot) to detect multi-stage attack chains that no single
//! detector can see. Uses a rule-based pattern matching engine with entity
//! pivoting and configurable time windows.
//!
//! Example chain: CL-004 MSR Write → Process Injection → Log Tampering
//! Each stage produces an event in a different layer; the engine connects
//! them via shared entities (PID, IP, user) within a time window.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use innerwarden_core::entities::{EntityRef, EntityType};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

use crate::knowledge_graph::intern::intern;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Which system layer produced this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Firmware,
    Hypervisor,
    Kernel,
    Userspace,
    Network,
    Honeypot,
}

/// A normalized event for cross-layer correlation.
///
/// Wave 6 (AUDIT-WAVE6-INTERN, 2026-05-05): `source` and `kind` are
/// `Arc<str>` interned at insert time so the 10 000-entry
/// `event_window` (and any `AttackChain.events` clones it produces)
/// shares one allocation per distinct value. Pre-Wave-6 each entry
/// held an independent `String`, so a window full of
/// `kind = "ssh.login_failed"` paid 10 000 × (24-byte header + heap
/// chars). On the prod jeprof baseline saved 2026-05-05 these two
/// fields drove ~1 MB of duplicated heap inside the correlation
/// engine alone.
///
/// Pinned by
/// `correlation_engine::tests::correlation_event_source_and_kind_share_arc_allocations`.
///
/// `incident_id` stays `String` because it is unique per incident — no
/// dedup possible. `details` stays `serde_json::Value` (Wave 7 target).
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationEvent {
    pub ts: DateTime<Utc>,
    pub layer: Layer,
    pub source: Arc<str>,
    pub kind: Arc<str>,
    pub severity: Severity,
    pub entities: Vec<EntityRef>,
    pub details: serde_json::Value,
    /// Phase 014-C: incident_id when the event originated from an Incident
    /// (set by classify_incident). Empty for raw events.
    #[serde(default)]
    pub incident_id: String,
}

/// A detected multi-stage attack chain.
#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    pub chain_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub start_ts: DateTime<Utc>,
    pub last_ts: DateTime<Utc>,
    pub events: Vec<CorrelationEvent>,
    pub stages_matched: usize,
    pub stages_total: usize,
    pub confidence: f32,
    pub layers_involved: Vec<Layer>,
    pub severity: Severity,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

/// A correlation rule defines a multi-stage pattern to detect.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub stages: Vec<RuleStage>,
    /// Maximum seconds between first and last stage event.
    pub window_secs: u64,
    /// Minimum confidence to emit the chain as an incident.
    pub min_confidence: f32,
    /// Override severity when chain is detected.
    pub severity: Severity,
}

/// One stage in a correlation rule.
#[derive(Debug, Clone)]
pub struct RuleStage {
    /// Required layer (None = any layer).
    pub layer: Option<Layer>,
    /// Event kind patterns to match (glob-style: "firmware.*", "ssh_bruteforce").
    pub kind_patterns: Vec<String>,
    /// If true, this stage must share at least one entity with the previous stage.
    pub entity_must_match: bool,
}

/// Tracks an in-progress chain match.
#[derive(Debug, Clone)]
struct PendingChain {
    rule_id: String,
    matched_events: Vec<CorrelationEvent>,
    matched_entities: HashSet<String>,
    next_stage: usize,
    started_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The cross-layer correlation engine.
pub struct CorrelationEngine {
    /// Sliding window of recent events (all layers).
    event_window: VecDeque<CorrelationEvent>,
    /// Maximum events to retain in the window.
    max_window_size: usize,
    /// In-progress chain matches.
    pending_chains: Vec<PendingChain>,
    /// Completed chains (drained by the caller).
    completed_chains: Vec<AttackChain>,
    /// Correlation rules.
    rules: Vec<CorrelationRule>,
    /// Cooldown: avoid re-emitting the same chain within N seconds.
    chain_cooldowns: HashMap<String, DateTime<Utc>>,
    /// Chain ID counter.
    next_chain_id: u64,
}

impl CorrelationEngine {
    /// Create a new engine with the built-in rule set.
    pub fn new() -> Self {
        Self {
            event_window: VecDeque::with_capacity(10_000),
            max_window_size: 10_000,
            pending_chains: Vec::new(),
            completed_chains: Vec::new(),
            rules: builtin_rules(),
            chain_cooldowns: HashMap::new(),
            next_chain_id: 1,
        }
    }

    /// Feed a new event into the engine.
    ///
    /// Checks all pending chains and starts new chains if the event matches
    /// the first stage of any rule.
    pub fn observe(&mut self, event: CorrelationEvent) {
        let now = event.ts;

        // Expire old pending chains
        self.pending_chains.retain(|pc| pc.expires_at > now);

        // Expire old cooldowns
        self.chain_cooldowns.retain(|_, expires| *expires > now);

        // Try to advance existing pending chains
        let mut newly_completed = Vec::new();
        for pc in &mut self.pending_chains {
            let rule = match self.rules.iter().find(|r| r.id == pc.rule_id) {
                Some(r) => r,
                None => continue,
            };

            if pc.next_stage >= rule.stages.len() {
                continue;
            }

            let stage = &rule.stages[pc.next_stage];

            if matches_stage(stage, &event, &pc.matched_entities, &pc.rule_id) {
                pc.matched_events.push(event.clone());
                // Add all entity values to the set for next-stage matching
                for entity in &event.entities {
                    pc.matched_entities.insert(format!(
                        "{}:{}",
                        entity_type_str(&entity.r#type),
                        entity.value
                    ));
                }
                pc.next_stage += 1;

                // Check if chain is complete
                if pc.next_stage >= rule.stages.len() {
                    newly_completed.push(pc.clone());
                }
            }
        }

        // Emit completed chains
        for mut pc in newly_completed {
            let rule = match self.rules.iter().find(|r| r.id == pc.rule_id) {
                Some(r) => r,
                None => continue,
            };

            // Cooldown check: same rule + same primary entity
            let cooldown_key = format!(
                "{}:{}",
                pc.rule_id,
                pc.matched_entities.iter().next().unwrap_or(&String::new())
            );
            if self.chain_cooldowns.contains_key(&cooldown_key) {
                continue;
            }

            let chain_id = format!("CHAIN-{:04}", self.next_chain_id);
            self.next_chain_id += 1;

            let layers: Vec<Layer> = pc
                .matched_events
                .iter()
                .map(|e| e.layer)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            let confidence = if layers.len() >= 3 {
                0.95
            } else if layers.len() >= 2 {
                0.85
            } else {
                0.70
            };

            // 2026-05-08 (fix/chains-tab-honesty-bundle): sort by
            // event timestamp before computing start/last so the
            // duration in the chain summary can never go negative.
            // Operator's prod 2026-05-08 dashboard showed multiple
            // chains with summaries like
            // `"...: 2 stages across 1 layers in -2s"` — that
            // happened when the second stage's event arrived in
            // the matched_events vec earlier than the first stage
            // (rule order independence + event-delivery race).
            // `.first()` / `.last()` walked vec order, not time
            // order — sorting here pins the contract that duration
            // is the actual chronological window.
            pc.matched_events.sort_by_key(|e| e.ts);
            let start_ts = pc.matched_events.first().map(|e| e.ts).unwrap_or(now);
            let last_ts = pc.matched_events.last().map(|e| e.ts).unwrap_or(now);

            let summary = format!(
                "{}: {} stages across {} layers in {}s",
                rule.name,
                pc.matched_events.len(),
                layers.len(),
                (last_ts - start_ts).num_seconds()
            );

            info!(
                chain_id = %chain_id,
                rule = %rule.id,
                stages = pc.matched_events.len(),
                layers = layers.len(),
                "attack chain detected: {}",
                rule.name
            );

            self.completed_chains.push(AttackChain {
                chain_id,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                start_ts,
                last_ts,
                events: pc.matched_events,
                stages_matched: rule.stages.len(),
                stages_total: rule.stages.len(),
                confidence,
                layers_involved: layers,
                severity: rule.severity.clone(),
                summary,
            });

            // Set cooldown (10 minutes for same rule + entity)
            self.chain_cooldowns
                .insert(cooldown_key, now + chrono::Duration::seconds(600));

            // Remove the completed pending chain
            self.pending_chains
                .retain(|p| p.rule_id != pc.rule_id || p.started_at != pc.started_at);
        }

        // Try to start new chains (event matches first stage of a rule)
        for rule in &self.rules {
            let first_stage = &rule.stages[0];
            if matches_stage(first_stage, &event, &HashSet::new(), &rule.id) {
                let mut entities = HashSet::new();
                for entity in &event.entities {
                    entities.insert(format!(
                        "{}:{}",
                        entity_type_str(&entity.r#type),
                        entity.value
                    ));
                }

                self.pending_chains.push(PendingChain {
                    rule_id: rule.id.clone(),
                    matched_events: vec![event.clone()],
                    matched_entities: entities,
                    next_stage: 1,
                    started_at: now,
                    expires_at: now + chrono::Duration::seconds(rule.window_secs as i64),
                });
            }
        }

        // Add to event window
        self.event_window.push_back(event);
        while self.event_window.len() > self.max_window_size {
            self.event_window.pop_front();
        }
    }

    /// Drain completed attack chains. Caller should convert these to incidents.
    pub fn drain_completed(&mut self) -> Vec<AttackChain> {
        std::mem::take(&mut self.completed_chains)
    }

    /// Number of pending (in-progress) chains.
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.pending_chains.len()
    }

    /// Number of rules loaded.
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Convert an Event from the sensor into a CorrelationEvent.
    pub fn classify_event(event: &innerwarden_core::event::Event) -> CorrelationEvent {
        let layer = classify_layer(&event.source, &event.kind);
        CorrelationEvent {
            ts: event.ts,
            layer,
            source: intern(&event.source),
            kind: intern(&event.kind),
            severity: event.severity.clone(),
            entities: event.entities.clone(),
            details: event.details.clone(),
            incident_id: String::new(),
        }
    }

    /// Convert an Incident into a CorrelationEvent (using the detector kind).
    pub fn classify_incident(incident: &Incident) -> CorrelationEvent {
        let detector = crate::mitre::detector_from_incident_id(&incident.incident_id);
        let layer = classify_layer("detector", detector);
        CorrelationEvent {
            ts: incident.ts,
            layer,
            source: intern("detector"),
            kind: intern(detector),
            severity: incident.severity.clone(),
            entities: incident.entities.clone(),
            details: incident.evidence.clone(),
            incident_id: incident.incident_id.clone(),
        }
    }

    /// Create a CorrelationEvent from SMM firmware scan results.
    /// Called from `firmware_tick::process_firmware_tick` for each
    /// Critical/Warning check and each correlated threat, so CL-043
    /// (Ring -2 + Ring -1 deep compromise) can match against real
    /// firmware signal alongside hypervisor and kernel events.
    pub fn firmware_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Firmware,
            source: intern("smm"),
            kind: intern(kind),
            severity: Severity::High,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from hypervisor audit results.
    pub fn hypervisor_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Hypervisor,
            source: intern("hypervisor"),
            kind: intern(kind),
            severity: Severity::High,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from kill chain detection.
    pub fn killchain_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Kernel,
            source: intern("killchain"),
            kind: intern(kind),
            severity: Severity::Critical,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from threat DNA analysis.
    pub fn dna_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Userspace,
            source: intern("dna"),
            kind: intern(kind),
            severity: Severity::Medium,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from baseline anomaly detection.
    pub fn baseline_event(
        kind: &str,
        severity: Severity,
        entities: Vec<EntityRef>,
        details: serde_json::Value,
    ) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Userspace,
            source: intern("baseline"),
            kind: intern(kind),
            severity,
            entities,
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from autoencoder neural anomaly.
    pub fn neural_event(
        score: f32,
        entities: Vec<EntityRef>,
        details: serde_json::Value,
    ) -> CorrelationEvent {
        let severity = if score > 0.9 {
            Severity::High
        } else if score > 0.7 {
            Severity::Medium
        } else {
            Severity::Low
        };
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Userspace,
            source: intern("autoencoder"),
            kind: intern("neural.anomaly"),
            severity,
            entities,
            details,
            incident_id: String::new(),
        }
    }

    /// Create a CorrelationEvent from shield escalation.
    pub fn shield_event(kind: &str, details: serde_json::Value) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer: Layer::Network,
            source: intern("shield"),
            kind: intern(kind),
            severity: Severity::High,
            entities: vec![],
            details,
            incident_id: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Matching logic
// ---------------------------------------------------------------------------

fn matches_stage(
    stage: &RuleStage,
    event: &CorrelationEvent,
    previous_entities: &HashSet<String>,
    rule_id: &str,
) -> bool {
    // Layer check
    if let Some(required_layer) = stage.layer {
        if event.layer != required_layer {
            return false;
        }
    }

    // Kind pattern check (any pattern matching = success)
    let kind_match = stage.kind_patterns.iter().any(|pattern| {
        if pattern.contains('*') {
            // Glob match: "firmware.*" matches "firmware.msr_write"
            let prefix = pattern.trim_end_matches('*');
            event.kind.starts_with(prefix)
        } else if pattern.contains('|') {
            // OR match: "ssh_bruteforce|credential_stuffing"
            // Wave 6: event.kind is `Arc<str>` so we deref via `&*`
            // to get a `&str` PartialEq with the trimmed pattern.
            pattern.split('|').any(|p| &*event.kind == p.trim())
        } else {
            // `*event.kind` derefs `Arc<str>` to `str`; matched against
            // `*pattern` (also `str`). The clippy `op_ref` lint flags
            // `&*event.kind` in this position so we deref directly.
            *event.kind == *pattern
        }
    });

    if !kind_match {
        return false;
    }

    // Entity matching (if required and previous entities exist)
    if stage.entity_must_match && !previous_entities.is_empty() {
        let current_entities: HashSet<String> = event
            .entities
            .iter()
            .map(|e| format!("{}:{}", entity_type_str(&e.r#type), e.value))
            .collect();

        if current_entities.is_disjoint(previous_entities) {
            return false;
        }
    }

    // Wave 8a (2026-05-04): per-rule comm suppression.
    // Suppresses chains where the originating process is a known package
    // manager / system-update tool. Without this CL-008 was blocking
    // Ubuntu mirrors, GitHub Pages, Telegram, etc. during apt upgrades
    // (the agent's own notification infra in Telegram's case).
    if event_comm_is_suppressed(rule_id, event) {
        return false;
    }

    true
}

/// Does `event.details.comm` match a suppression list? Three distinct
/// policies share this gate:
///
/// 1. **InnerWarden binary self-traffic** (Wave 8a + PR ε; rule-agnostic,
///    every rule). The originating process is one of our binaries
///    (`innerwarden-age` truncated, `innerwarden-sen`, `innerwarden-ctl`,
///    `innerwarden-watc`). These names are unambiguous - no third-party
///    process produces them - so we suppress regardless of which chain
///    wants to claim the event.
///
/// 2. **CL-008-only Tokio worker carve-out** (PR ε; CL-008 only).
///    `tokio-rt-worker` is the thread name Tokio gives every runtime
///    worker on every Tokio-based process, which means a malicious
///    Tokio app could legitimately execute under that comm. We do NOT
///    suppress it rule-agnostically, but for CL-008 specifically (the
///    "file.read + outbound connect" data-exfil chain) the false-
///    positive rate from the agent's own outbound traffic is high
///    enough to warrant suppression there. Other chains
///    (`lateral_movement`, `credential_theft`, etc.) still fire on
///    `tokio-rt-worker` if their own kind patterns match.
///
/// 3. **Per-rule package manager** (Wave 8a; opt-in by `rule_id`,
///    currently only CL-008). Apt/dpkg/dnf/etc. running upgrades
///    naturally trigger CL-008's two stages. Operators may want
///    package-manager suppression for some chains and not others, so
///    this stays per-rule via [`rule_comm_suppressions`].
///
/// Returns false when the event has no `comm` field or when no list
/// matches.
pub(crate) fn event_comm_is_suppressed(rule_id: &str, event: &CorrelationEvent) -> bool {
    let Some(comm) = event.details.get("comm").and_then(|v| v.as_str()) else {
        return false;
    };
    // PR ε: rule-agnostic InnerWarden binary suppression. Pinned by
    // `innerwarden_binary_self_traffic_suppression_is_rule_agnostic`.
    if INNERWARDEN_SELF_COMMS.contains(&comm) {
        return true;
    }
    // PR ε: CL-008-only `tokio-rt-worker` carve-out. The thread name
    // is generic (every Tokio app uses it), so we deliberately do NOT
    // promote it to the rule-agnostic list - that would create a
    // blind spot for a malicious Tokio-based attacker tool. We only
    // suppress it for the rule whose FP rate makes it operationally
    // necessary. Pinned by both `cl008_suppressed_..._tokio_rt_worker`
    // and `tokio_rt_worker_only_suppressed_on_cl008_not_other_rules`.
    if rule_id == "CL-008" && comm == "tokio-rt-worker" {
        return true;
    }
    // Wave 8a: per-rule package-manager suppression.
    rule_comm_suppressions(rule_id).contains(&comm)
}

/// Wave 8a (2026-05-04): per-rule list of `comm` values whose events
/// should NOT participate in chain matching. Returning `&[]` (the
/// default) means no suppression — events match by kind/layer/entity
/// only, as before.
///
/// Currently only CL-008 (Data Exfiltration via eBPF Sequence) opts in,
/// because that rule's two stages (sensitive file read + outbound
/// connect) trigger every package-manager run on every distro. Other
/// rules can opt in by adding a match arm here.
fn rule_comm_suppressions(rule_id: &str) -> &'static [&'static str] {
    match rule_id {
        "CL-008" => PACKAGE_MANAGER_COMMS,
        _ => &[],
    }
}

/// Wave 8a (2026-05-04): comm names of package managers and related
/// system-update tooling across the major Linux distros (and macOS
/// Homebrew, since the agent runs there too).
///
/// All entries match `event.details.comm` exactly. Linux truncates
/// `comm` to 15 characters (TASK_COMM_LEN - 1), so long names are
/// pre-truncated here (e.g. `unattended-upgrade` → `unattended-upgr`,
/// `dpkg-statoverride` → `dpkg-statoverri`). Distro-agnostic by design:
/// covers apt, dpkg, snap, dnf/yum, rpm, zypper, pacman, apk, emerge,
/// xbps, flatpak, brew, PackageKit.
const PACKAGE_MANAGER_COMMS: &[&str] = &[
    // Debian / Ubuntu — apt family
    "apt",
    "apt-get",
    "apt-cache",
    "apt-config",
    "aptitude",
    "apt-listchanges",
    "apt-listbugs",
    // Debian / Ubuntu — dpkg family (truncated forms first where >15 chars)
    "dpkg",
    "dpkg-deb",
    "dpkg-query",
    "dpkg-divert",
    "dpkg-statoverri", // dpkg-statoverride truncated
    "dpkg-trigger",
    // Debian / Ubuntu — auto-update + restart helpers
    "unattended-upgr", // unattended-upgrade truncated
    "needrestart",
    // Snap (cross-distro)
    "snap",
    "snapd",
    "snap-update-ns",
    "snap-confine",
    "snap-mgmt",
    // RHEL / Fedora / Rocky / Alma — yum / dnf family
    "yum",
    "dnf",
    "dnf5",
    "microdnf",
    "yumdownloader",
    "rpm",
    "rpm-ostree",
    // SUSE
    "zypper",
    // Arch
    "pacman",
    "pacstrap",
    "makepkg",
    "yay",
    "paru",
    // Alpine
    "apk",
    "abuild",
    // Gentoo
    "emerge",
    "ebuild",
    "portageq",
    // Void
    "xbps-install",
    "xbps-remove",
    "xbps-query",
    // Cross-distro app distribution
    "flatpak",
    // macOS
    "brew",
    // Cross-distro service-style package backends
    "PackageKit",
    "packagekitd",
];

/// PR ε (2026-05-04): comm names of InnerWarden's own binaries.
/// Correlation chains whose originating event has one of these comms
/// are agent self-traffic and must NOT be classified as attacker
/// activity regardless of the rule that wants to claim them.
///
/// Linux truncates `comm` to 15 characters (TASK_COMM_LEN - 1), so
/// `innerwarden-agent` (17 chars) appears as `innerwarden-age` in
/// `/proc/<pid>/comm` and in eBPF events. We pre-truncate here so
/// the exact-match comparison works against what the kernel actually
/// produces - the full untruncated names would never match.
///
/// **Deliberately excludes `tokio-rt-worker`**: that thread name is
/// emitted by every Tokio-based process, not just ours. Including it
/// here would let a malicious Tokio app bypass every correlation
/// rule. The CL-008-specific carve-out for `tokio-rt-worker` lives
/// inline in `event_comm_is_suppressed` instead, so it only relaxes
/// the one rule with a documented FP rate from the agent's own
/// outbound calls.
///
/// Distinct from the existing graph-level
/// [`crate::knowledge_graph::ingestion::is_self_traffic_incident`]
/// (which catches incidents AFTER they have been ingested into the
/// knowledge graph): this list short-circuits the chain at correlation
/// time so the chain is never CREATED to begin with.
///
/// AUDIT-CL008-SELF (2026-05-04 prod): pre-fix CL-008 fired 72x in
/// 30 min on prod, blocking outbound to 208.95.112.1 (an external
/// dependency the agent reaches), to Telegram, and to the host's
/// own cloud provider. All of these had `comm = tokio-rt-worker`
/// from the agent's outbound connect path; this list + the
/// CL-008 carve-out together stop them upstream of the chain.
const INNERWARDEN_SELF_COMMS: &[&str] = &[
    "innerwarden-age",  // innerwarden-agent (17 chars truncated)
    "innerwarden-sen",  // innerwarden-sensor (18 chars truncated)
    "innerwarden-ctl",  // 15 chars - exact
    "innerwarden-watc", // innerwarden-watchdog (20 chars truncated)
];

fn entity_type_str(et: &EntityType) -> &'static str {
    match et {
        EntityType::Ip => "ip",
        EntityType::User => "user",
        EntityType::Container => "container",
        EntityType::Path => "path",
        EntityType::Service => "service",
    }
}

fn classify_layer(source: &str, kind: &str) -> Layer {
    // Check hypervisor (Ring -1)
    if source == "hypervisor"
        || kind.starts_with("hypervisor.")
        || kind.contains("cpuid")
        || kind.contains("vmexit")
        || kind.contains("blue_pill")
    {
        Layer::Hypervisor
    // Check firmware (Ring -2)
    } else if source == "smm"
        || kind.starts_with("firmware.")
        || kind.contains("msr")
        || kind.contains("acpi")
        || kind.contains("uefi")
        || kind.contains("tpm")
        || kind.contains("spi")
    {
        Layer::Firmware
    // Network before Kernel (eBPF can produce network events)
    } else if kind.starts_with("network.")
        || kind.starts_with("dns.")
        || kind.contains("outbound")
        || kind.contains("bind_listen")
    {
        Layer::Network
    } else if kind.starts_with("honeypot") {
        Layer::Honeypot
    } else if source == "ebpf"
        || source == "killchain"
        || kind.starts_with("killchain.")
        || kind.starts_with("privilege.")
        || kind.starts_with("lsm.")
        || kind == "kernel_module_load"
        || kind.starts_with("dup.")
        || kind == "mprotect"
    {
        Layer::Kernel
    } else {
        Layer::Userspace
    }
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------

fn builtin_rules() -> Vec<CorrelationRule> {
    vec![
        // CL-001: Firmware → Privilege Escalation → Rootkit Module
        CorrelationRule {
            id: "CL-001".into(),
            name: "Firmware to Rootkit Chain".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Firmware),
                    kind_patterns: vec!["firmware.*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["kernel_module_load".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-002: Recon → Access → Exfil
        CorrelationRule {
            id: "CL-002".into(),
            name: "Recon to Exfiltration Chain".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["port_scan".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["ssh_bruteforce|credential_stuffing".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["data_exfiltration|outbound_anomaly".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-003: Honeypot → Real Attack
        CorrelationRule {
            id: "CL-003".into(),
            name: "Honeypot to Real Attack".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Honeypot),
                    kind_patterns: vec!["honeypot*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "ssh.*".into(),
                        "network.*".into(),
                        "ssh_bruteforce".into(),
                        "credential_stuffing".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.7,
            severity: Severity::High,
        },
        // CL-004: MSR Write → Injection → Log Tampering
        CorrelationRule {
            id: "CL-004".into(),
            name: "MSR Write to Log Tampering".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Firmware),
                    kind_patterns: vec!["firmware.msr*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into(), "process_injection".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["log_tampering".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.8,
            severity: Severity::Critical,
        },
        // CL-005: Container Escape → Host Execution → Privesc
        CorrelationRule {
            id: "CL-005".into(),
            name: "Container Escape to Host".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["container_drift".into(), "container_escape".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["shell.command_exec".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-006: Fileless Attack
        CorrelationRule {
            id: "CL-006".into(),
            name: "Fileless Malware Chain".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["fileless".into(), "memfd_create".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["mprotect".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 300,
            min_confidence: 0.8,
            severity: Severity::Critical,
        },
        // CL-007: Reverse Shell via eBPF sequence
        CorrelationRule {
            id: "CL-007".into(),
            name: "Reverse Shell (eBPF Sequence)".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["dup.redirect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 10,
            min_confidence: 0.9,
            severity: Severity::Critical,
        },
        // CL-008: Data Exfiltration via eBPF sequence.
        // Wave 8a (2026-05-04): this rule opts into per-rule comm
        // suppression via PACKAGE_MANAGER_COMMS, because both stages
        // (sensitive file read + outbound connect) trigger on every
        // package-manager run on every distro. Without the carve-out
        // CL-008 was blocking Ubuntu mirrors, GitHub, and Telegram
        // (the agent's OWN notification infra) during apt upgrades.
        // See `rule_comm_suppressions` and the anchor tests
        // `cl008_*` in this file.
        CorrelationRule {
            id: "CL-008".into(),
            name: "Data Exfiltration (eBPF Sequence)".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["file.read_access".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 60,
            min_confidence: 0.7,
            severity: Severity::High,
        },
        // CL-009: Silence After Compromise
        // Note: this rule is special — handled by the silence detector
        // in baseline.rs, not by the stage-matching engine.
        // Placeholder here for documentation.
        CorrelationRule {
            id: "CL-009".into(),
            name: "Silence After Compromise".into(),
            stages: vec![RuleStage {
                layer: None,
                kind_patterns: vec!["__silence_placeholder__".into()],
                entity_must_match: false,
            }],
            window_secs: 300,
            min_confidence: 0.6,
            severity: Severity::High,
        },
        // CL-010: Multi-Low Elevation
        // Also special — handled by custom logic below, not stage matching.
        CorrelationRule {
            id: "CL-010".into(),
            name: "Multi-Low Severity Elevation".into(),
            stages: vec![RuleStage {
                layer: None,
                kind_patterns: vec!["__multi_low_placeholder__".into()],
                entity_must_match: false,
            }],
            window_secs: 600,
            min_confidence: 0.6,
            severity: Severity::High,
        },
        // ── Additional rules (CL-011 to CL-023) ──────────────────────

        // CL-011: Credential theft → Lateral movement
        CorrelationRule {
            id: "CL-011".into(),
            name: "Credential Theft to Lateral Movement".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["credential_harvest".into(), "file.read_access".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["lateral_movement".into(), "ssh_key_injection".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-012: Persistence installation chain
        CorrelationRule {
            id: "CL-012".into(),
            name: "Multi-Persistence Installation".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["crontab_persistence".into(), "systemd_persistence".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["ssh_key_injection".into(), "user_creation".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-013: Web shell deployment chain
        CorrelationRule {
            id: "CL-013".into(),
            name: "Web Shell Deployment".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["web_scan".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["file.write_access".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["web_shell".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-014: Cryptominer deployment
        //
        // Requires entity match on BOTH stages so that the CPU abuse
        // comes from the SAME process/container that made the outbound
        // connection. Without this, any unrelated CPU spike (cargo
        // build, snap refresh) + any outbound connect (CrowdSec polling,
        // Telegram notification) would fire "Cryptominer Deployment
        // Chain". Observed 2026-04-12: 21 false Cryptominer chains per
        // day from CrowdSec CAPI polling + cargo build CPU spike.
        CorrelationRule {
            id: "CL-014".into(),
            name: "Cryptominer Deployment Chain".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "shell.command_exec".into(),
                        "network.outbound_connect".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["crypto_miner".into(), "cgroup.cpu_abuse".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.7,
            severity: Severity::High,
        },
        // CL-015: Log tampering after compromise
        CorrelationRule {
            id: "CL-015".into(),
            name: "Post-Compromise Log Tampering".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "privilege.escalation".into(),
                        "reverse_shell".into(),
                        "ssh_bruteforce".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["log_tampering".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.8,
            severity: Severity::Critical,
        },
        // CL-016: TPM measurement failure → later attack
        CorrelationRule {
            id: "CL-016".into(),
            name: "TPM Integrity Failure Followed by Attack".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Firmware),
                    kind_patterns: vec!["firmware.efivar*".into(), "firmware.acpi*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "ransomware".into(),
                        "rootkit".into(),
                        "reverse_shell".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 172800, // 48 hours
            min_confidence: 0.6,
            severity: Severity::Critical,
        },
        // CL-017: io_uring evasion (high io_uring with low visible I/O)
        CorrelationRule {
            id: "CL-017".into(),
            name: "io_uring Evasion Detection".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["io_uring*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 60,
            min_confidence: 0.6,
            severity: Severity::High,
        },
        // CL-018: eBPF weaponization chain
        CorrelationRule {
            id: "CL-018".into(),
            name: "eBPF Program Weaponization".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["kernel.bpf_program_loaded".into(), "lsm.bpf*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["privilege.escalation".into(), "process_injection".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 300,
            min_confidence: 0.8,
            severity: Severity::Critical,
        },
        // CL-019: Memory injection chain (RWX + connect)
        CorrelationRule {
            id: "CL-019".into(),
            name: "Memory Injection to C2".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["memory.rwx*".into(), "memory.anon*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 120,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // CL-020: Docker image pull → lateral movement
        CorrelationRule {
            id: "CL-020".into(),
            name: "Container as Lateral Movement Vector".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["docker*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["shell.command_exec".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 300,
            min_confidence: 0.6,
            severity: Severity::High,
        },
        // CL-021: Ransomware chain (encryption detection + file burst)
        CorrelationRule {
            id: "CL-021".into(),
            name: "Ransomware Encryption Chain".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "file.encrypted_write".into(),
                        "file.ransomware_burst".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["file.realtime_modified".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 60,
            min_confidence: 0.9,
            severity: Severity::Critical,
        },
        // CL-022: YARA match → network callback
        CorrelationRule {
            id: "CL-022".into(),
            name: "Malware Execution with C2 Callback".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["yara_scan".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["network.outbound_connect".into(), "c2_callback".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 300,
            min_confidence: 0.9,
            severity: Severity::Critical,
        },
        // CL-023: Sigma rule match + privilege escalation
        CorrelationRule {
            id: "CL-023".into(),
            name: "Sigma Alert Escalated by Privilege Change".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["sigma".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.7,
            severity: Severity::Critical,
        },
        // -----------------------------------------------------------------
        // Gym-discovered rules (adversarial RL training insights)
        // -----------------------------------------------------------------
        // CL-024: Fast recon→exploit→exfil chain (gym top pattern)
        // Attacker learned: web exploit is faster than SSH brute force,
        // and short chains (3-5 steps) succeed most often.
        CorrelationRule {
            id: "CL-024".into(),
            name: "Gym: Fast Web Exploit to Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "port_scan".into(),
                        "web_scan".into(),
                        "user_agent_scanner".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["web_shell".into(), "web_scan".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "data_exfiltration".into(),
                        "outbound_anomaly".into(),
                        "dns_tunneling".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 300, // 5 min — gym showed short chains are most dangerous
            min_confidence: 0.95,
            severity: Severity::Critical,
        },
        // CL-025: Service enumeration → exploit (gym: ServiceEnum passes undetected 72%)
        // Catches nmap -sV → vulnerability exploitation pattern
        CorrelationRule {
            id: "CL-025".into(),
            name: "Gym: Service Enumeration to Exploitation".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["port_scan".into(), "user_agent_scanner".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "web_shell".into(),
                        "reverse_shell".into(),
                        "ssh_bruteforce".into(),
                        "credential_stuffing".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.85,
            severity: Severity::High,
        },
        // CL-026: DNS recon → exfiltration (gym: DnsRecon 73% undetected)
        // Attacker uses DNS for both recon and data exfiltration
        CorrelationRule {
            id: "CL-026".into(),
            name: "Gym: DNS Recon to Data Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["dns_tunneling".into(), "port_scan".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["data_exfiltration".into(), "data_exfil_ebpf".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 900,
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-027: Multi-vector initial access (gym: attacker tries web + SSH simultaneously)
        // Same IP attempts both web exploit and SSH brute force
        CorrelationRule {
            id: "CL-027".into(),
            name: "Gym: Multi-Vector Initial Access Attempt".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["ssh_bruteforce".into(), "credential_stuffing".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "web_scan".into(),
                        "web_shell".into(),
                        "user_agent_scanner".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.85,
            severity: Severity::High,
        },
        // -----------------------------------------------------------------
        // Red team gap rules (Phase 3 atomic testing insights)
        // -----------------------------------------------------------------
        // CL-028: Discovery burst → credential access (red team gap #1)
        // 6 discovery techniques pass undetected, but combined with
        // credential access = attack in progress
        CorrelationRule {
            id: "CL-028".into(),
            name: "Red Team: Discovery Burst to Credential Access".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "process_discovery".into(),
                        "network_discovery".into(),
                        "file_discovery".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "credential_harvest".into(),
                        "data_exfiltration".into(),
                        "sensitive_write".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 300,
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-029: Persistence chain (red team gap #2)
        // ShellRc + crontab + systemd persistence attempts
        CorrelationRule {
            id: "CL-029".into(),
            name: "Red Team: Multi-Persistence Attempt".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "crontab_persistence".into(),
                        "systemd_persistence".into(),
                        "sensitive_write".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "ssh_key_injection".into(),
                        "sensitive_write".into(),
                        "crontab_persistence".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-030: Defense evasion + exfiltration (red team gap #3)
        // Log tampering or timestomp followed by data exfil
        CorrelationRule {
            id: "CL-030".into(),
            name: "Red Team: Evasion to Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["log_tampering".into(), "sensitive_write".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "data_exfiltration".into(),
                        "outbound_anomaly".into(),
                        "dns_tunneling".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // -----------------------------------------------------------------
        // Self-play v2/v3 discoveries (2026-04-05)
        // -----------------------------------------------------------------
        // CL-031: Web shell upload + outbound connection (v1 chain #1, #5, #12)
        // Attacker learned: upload web shell to non-standard path, then exfil.
        // WebShellUpload passed undetected in 38% of chains.
        CorrelationRule {
            id: "CL-031".into(),
            name: "Selfplay: Web Shell Upload to Outbound Connection".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "file.write_access".into(),
                        "web_shell".into(),
                        "sensitive_write".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "network.outbound_connect".into(),
                        "data_exfiltration".into(),
                        "data_exfil_ebpf".into(),
                        "outbound_anomaly".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 60,
            min_confidence: 0.90,
            severity: Severity::Critical,
        },
        // CL-032: Sensitive file read + high-entropy DNS (v1 chains #1, #5, #6)
        // Attacker prefers DNS exfil over HTTP — dns_tunneling detector misses
        // correlation with prior file read.
        CorrelationRule {
            id: "CL-032".into(),
            name: "Selfplay: File Read to DNS Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "file.read_access".into(),
                        "credential_harvest".into(),
                        "data_exfil_ebpf".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["dns_tunneling".into(), "dns.query".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 30,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-033: Repeated web exploit + encrypted exfil (v2 convergence pattern)
        // Attacker learned to spam WebExploit (even detected) because ExfilEncrypted
        // is invisible. 3+ web attacks from same entity + any TLS outbound = critical.
        CorrelationRule {
            id: "CL-033".into(),
            name: "Selfplay: Persistent Web Exploit to Encrypted Exfil".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "web_scan".into(),
                        "web_shell".into(),
                        "user_agent_scanner".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["web_scan".into(), "web_shell".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "outbound_anomaly".into(),
                        "data_exfiltration".into(),
                        "data_exfil_ebpf".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.90,
            severity: Severity::Critical,
        },
        // CL-034: Trust exploit / lateral movement (v1 chain #2)
        // TrustExploit never detected — new internal SSH from IP that brute-forced
        // another host + rapid command execution = lateral movement.
        CorrelationRule {
            id: "CL-034".into(),
            name: "Selfplay: Lateral Movement via Trust Exploitation".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "ssh_bruteforce".into(),
                        "credential_stuffing".into(),
                        "ssh.login_success".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "lateral_movement".into(),
                        "ssh_key_injection".into(),
                        "suspicious_execution".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 300,
            min_confidence: 0.85,
            severity: Severity::High,
        },
        // CL-035: DNS recon burst + encrypted exfil (v3 combined convergence pattern)
        // Attacker discovered DnsRecon is NEVER detected. Spams 50+ DNS queries
        // then exfiltrates via encrypted channel. This was the 8% attacker win strategy.
        CorrelationRule {
            id: "CL-035".into(),
            name: "Selfplay: DNS Recon Burst to Encrypted Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "dns_tunneling".into(),
                        "dns.query".into(),
                        "outbound_anomaly".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "data_exfiltration".into(),
                        "data_exfil_ebpf".into(),
                        "outbound_anomaly".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.90,
            severity: Severity::Critical,
        },
        // -----------------------------------------------------------------
        // AlphaZero V4 discoveries (2026-04-06, round 2)
        // -----------------------------------------------------------------
        // CL-036: Security tool disable → Impact chain
        // V4 attacker discovered: disable innerwarden first, then destroy/exfil.
        // DisableSecurityTools had 100% success rate in round 2.
        CorrelationRule {
            id: "CL-036".into(),
            name: "V4: Security Tool Disable to Impact".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["sudo_abuse".into(), "sensitive_write".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "data_exfiltration".into(),
                        "data_exfil_ebpf".into(),
                        "ransomware".into(),
                        "log_tampering".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 300,
            min_confidence: 0.90,
            severity: Severity::Critical,
        },
        // CL-037: io_uring evasion → exfiltration chain
        // V4 attacker learned: io_uring bypasses syscall monitoring for network I/O.
        // IoUringEvasion had 100% success rate — invisible to eBPF tracepoints.
        CorrelationRule {
            id: "CL-037".into(),
            name: "V4: io_uring Evasion to Data Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["io_uring*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec![
                        "data_exfiltration".into(),
                        "outbound_anomaly".into(),
                        "dns_tunneling".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 120,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-038: Valid account login (off-hours) → data destruction
        // V4 attacker: uses valid credentials at unusual hours then immediately impacts.
        // ValidAccountLogin bypasses SSH brute force detection entirely.
        CorrelationRule {
            id: "CL-038".into(),
            name: "V4: Off-Hours Login to Destructive Action".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["suspicious_login".into(), "ssh.login_success".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "sudo_abuse".into(),
                        "sensitive_write".into(),
                        "log_tampering".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 600,
            min_confidence: 0.80,
            severity: Severity::Critical,
        },
        // CL-039: Distributed SSH + web exploit (multi-vector initial access)
        // V4 attacker: simultaneously brute force SSH from multiple IPs and probe web.
        // DistributedSshBrute was top 4 technique (214 uses in analysis).
        CorrelationRule {
            id: "CL-039".into(),
            name: "V4: Multi-Vector Initial Access".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["distributed_ssh".into(), "ssh_bruteforce".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "web_shell".into(),
                        "web_scan".into(),
                        "credential_harvest".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.85,
            severity: Severity::High,
        },
        // CL-040: Process injection → reverse shell → DNS exfil
        // V4 attacker: inject into process, spawn reverse shell, exfil via DNS.
        // ProcessInjection + ReverseShell + ExfilDns all had 100% success.
        CorrelationRule {
            id: "CL-040".into(),
            name: "V4: Process Injection to DNS Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["process_injection".into(), "fileless".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["reverse_shell".into(), "shell.command_exec".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["dns_tunneling".into(), "data_exfiltration".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 300,
            min_confidence: 0.90,
            severity: Severity::Critical,
        },
        // CL-041: Blue Pill — stealth hypervisor installation detected
        // Environment drifts from bare metal to VM + CPUID inconsistency + timing anomaly.
        CorrelationRule {
            id: "CL-041".into(),
            name: "Blue Pill Rootkit Detection".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Hypervisor),
                    kind_patterns: vec!["hypervisor.environment_drift".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Hypervisor),
                    kind_patterns: vec!["hypervisor.hv_*".into(), "hypervisor.cpuid_*".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 600,
            min_confidence: 0.95,
            severity: Severity::Critical,
        },
        // CL-042: VM Escape Chain — hypervisor anomaly + privilege escalation + lateral movement.
        CorrelationRule {
            id: "CL-042".into(),
            name: "VM Escape Attack Chain".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Hypervisor),
                    kind_patterns: vec!["hypervisor.vmexit_*".into(), "hypervisor.hv_*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec!["privilege.escalation".into(), "kernel_module_load".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["lateral_movement".into(), "data_exfiltration".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-043: Firmware + Hypervisor Compromise — deep persistent threat across Ring -2 and -1.
        CorrelationRule {
            id: "CL-043".into(),
            name: "Deep Ring Compromise (Firmware + Hypervisor)".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Firmware),
                    kind_patterns: vec!["firmware.*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Hypervisor),
                    kind_patterns: vec!["hypervisor.*".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Kernel),
                    kind_patterns: vec![
                        "kernel_module_load".into(),
                        "privilege.escalation".into(),
                        "rootkit".into(),
                    ],
                    entity_must_match: false,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.90,
            severity: Severity::Critical,
        },
        // CL-044: Silence After Compromise — baseline detects silence after a confirmed attack.
        CorrelationRule {
            id: "CL-044".into(),
            name: "Silence After Compromise".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "reverse_shell".into(),
                        "privesc".into(),
                        "rootkit".into(),
                        "log_tampering".into(),
                        "process_injection".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["baseline.silence".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 7200, // 2 hours
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-045: Coordinated Volume Attack — baseline rate spike + shield escalation.
        CorrelationRule {
            id: "CL-045".into(),
            name: "Coordinated Volume Attack".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["baseline.rate_spike".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Network),
                    kind_patterns: vec!["shield.escalation.*".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 300, // 5 minutes
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-046: Neural-Confirmed Attack — autoencoder anomaly + detector in same window.
        CorrelationRule {
            id: "CL-046".into(),
            name: "Neural-Confirmed Attack".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["neural.anomaly".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None, // any layer
                    kind_patterns: vec![
                        "reverse_shell".into(),
                        "c2_callback".into(),
                        "data_exfiltration".into(),
                        "lateral_movement".into(),
                        "container_escape".into(),
                        "process_injection".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 120, // 2 minutes
            min_confidence: 0.90,
            severity: Severity::High,
        },
        // CL-047: Attacker IP Rotation — same behavioral DNA from a new IP + any attack.
        CorrelationRule {
            id: "CL-047".into(),
            name: "Attacker IP Rotation Detected".into(),
            stages: vec![RuleStage {
                layer: Some(Layer::Userspace),
                kind_patterns: vec!["dna.ip_rotation".into()],
                entity_must_match: false,
            }],
            window_secs: 1, // single event is enough
            min_confidence: 0.95,
            severity: Severity::Critical,
        },
        // ─── spec 050-PR7 — Cross-tactic chain rules (CL-051 → CL-070) ─────
        // Wire PR1-6 detectors into MITRE-shaped attack chains. Each rule
        // pivots on a shared entity (IP / user) across stages where it
        // helps; uses entity_must_match=false where the chain stages
        // canonically rotate identity (e.g. wiper precursors).

        // CL-051: Discovery → Privesc — recon-then-elevate.
        // (T1018 / T1083 / T1046 → T1548.001 / T1548.005 / T1068)
        CorrelationRule {
            id: "CL-051".into(),
            name: "Discovery → Privilege Escalation".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "nmap_scan|wordlist_scan|discovery_anomaly|discovery_burst|port_scan"
                            .into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "setuid_exploit_pattern|capabilities_abuse|privesc|sudo_abuse".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-052: Privesc → Lateral Movement — elevate-then-pivot.
        // (T1548 / T1068 → T1021.004 / T1570)
        CorrelationRule {
            id: "CL-052".into(),
            name: "Privilege Escalation → Lateral Movement".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "setuid_exploit_pattern|capabilities_abuse|privesc".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "lateral_egress_ssh|lateral_egress_scp_rsync|lateral_movement".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-053: Collection → Exfiltration — stage-then-push.
        // (T1119 / T1115 / T1056.001 → T1048 / T1041)
        //
        // Wave 2026-05-17 post-Caldera tuning: added legacy-name
        // variants `data_archive` / `suspicious_archive` to stage 1
        // and `data_exfil_cmd` to stage 2. The detectors that fired
        // in the 2026-05-17 Caldera run emit those names but the
        // original PR7 rule only carried the new PR1-6 detector
        // kinds. Without these the chain never matched.
        CorrelationRule {
            id: "CL-053".into(),
            name: "Collection → Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "clipboard_read|screen_capture|keylogger_bash_trap|automated_file_collection|archive_pwd_protected|data_archive|suspicious_archive".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "lateral_egress_scp_rsync|data_exfiltration|data_exfil_ebpf|data_exfil_cmd".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-054: Web Shell → C2 — foothold establishes attacker channel.
        // (T1505.003 → T1572 / T1090 / T1571)
        CorrelationRule {
            id: "CL-054".into(),
            name: "Web Shell → C2 Channel".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["web_shell".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "c2_web_tunnel|c2_protocol_tunneling|c2_non_standard_port|c2_callback".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-055: Persistence → Defense Evasion — establish-then-blind.
        // (T1556 / T1037 → T1562.001)
        CorrelationRule {
            id: "CL-055".into(),
            name: "Persistence → Defense Evasion".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "pam_module_change|startup_script_persistence|systemd_persistence|crontab_persistence|ssh_key_injection".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "auditd_disable|selinux_apparmor_disable|log_tampering".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-056: Defense Evasion → Impact — blind-then-wipe (wiper pattern).
        // (T1562.001 → T1485 / T1561.001 / T1486)
        CorrelationRule {
            id: "CL-056".into(),
            name: "Defense Evasion → Impact (wiper shape)".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "auditd_disable|selinux_apparmor_disable|log_tampering".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["data_destruction_pattern|ransomware".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.90,
            severity: Severity::Critical,
        },
        // CL-057: Discovery Burst → Collection — map-then-grab.
        // (T1083 / T1018 → T1119)
        // Wave 2026-05-17: legacy collection variants added.
        CorrelationRule {
            id: "CL-057".into(),
            name: "Discovery Burst → Collection".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "discovery_burst|discovery_anomaly|nmap_scan|wordlist_scan".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "archive_pwd_protected|automated_file_collection|data_archive|suspicious_archive".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-058: Initial Access → Foothold — exploit-lands-shell.
        // (T1190 / T1110 / T1078 → T1059)
        CorrelationRule {
            id: "CL-058".into(),
            name: "Initial Access → Foothold".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "web_scan|ssh_bruteforce|credential_stuffing|user_agent_scanner".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["web_shell|reverse_shell".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-059: Foothold → Persistence — survive-the-reboot.
        // (T1059 → T1037 / T1556 / T1543.002)
        CorrelationRule {
            id: "CL-059".into(),
            name: "Foothold → Persistence".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["reverse_shell|web_shell".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "pam_module_change|startup_script_persistence|systemd_persistence|crontab_persistence|ssh_key_injection".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-060: C2 → Discovery — beaconing-then-mapping.
        // (T1572 / T1571 → T1018 / T1046)
        CorrelationRule {
            id: "CL-060".into(),
            name: "C2 → Internal Discovery".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "c2_callback|c2_web_tunnel|c2_protocol_tunneling|c2_non_standard_port".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "nmap_scan|wordlist_scan|discovery_anomaly|discovery_burst|port_scan".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::High,
        },
        // CL-061: Discovery → C2 — recon-then-callout (precursor shape).
        CorrelationRule {
            id: "CL-061".into(),
            name: "Discovery → C2 Callout".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "nmap_scan|wordlist_scan|discovery_anomaly|discovery_burst|port_scan".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "c2_callback|c2_web_tunnel|c2_protocol_tunneling|c2_non_standard_port".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-062: Reverse Shell → Privesc — get-shell-then-go-root.
        // (T1059 → T1548)
        CorrelationRule {
            id: "CL-062".into(),
            name: "Reverse Shell → Privilege Escalation".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["reverse_shell|web_shell".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "setuid_exploit_pattern|capabilities_abuse|privesc|sudo_abuse".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-063: Privesc → Persistence — root-then-pin.
        // (T1548 → T1037 / T1556)
        CorrelationRule {
            id: "CL-063".into(),
            name: "Privilege Escalation → Persistence".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "setuid_exploit_pattern|capabilities_abuse|privesc".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "pam_module_change|systemd_persistence|startup_script_persistence|crontab_persistence|ssh_key_injection".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-064: Persistence → Lateral Movement — pinned-then-pivot.
        // (T1037 / T1556 → T1021)
        CorrelationRule {
            id: "CL-064".into(),
            name: "Persistence → Lateral Movement".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "pam_module_change|systemd_persistence|startup_script_persistence|crontab_persistence|ssh_key_injection".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["lateral_egress_ssh|lateral_egress_scp_rsync".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-065: Lateral → Collection — pivot-then-stage on remote.
        CorrelationRule {
            id: "CL-065".into(),
            name: "Lateral → Collection".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["lateral_egress_ssh".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "archive_pwd_protected|automated_file_collection|clipboard_read".into(),
                    ],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-066: Collection → Lateral Exfil — stage-then-push (T1048.001).
        // Wave 2026-05-17: legacy variants added to both stages.
        CorrelationRule {
            id: "CL-066".into(),
            name: "Collection → Lateral Exfiltration".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "archive_pwd_protected|automated_file_collection|clipboard_read|data_archive|suspicious_archive".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["lateral_egress_scp_rsync|data_exfil_cmd".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-067: Full kill chain — Initial Access → Foothold → Persistence
        // → Defense Evasion → Impact. The complete picture.
        CorrelationRule {
            id: "CL-067".into(),
            name: "Full Kill Chain (5-stage)".into(),
            stages: vec![
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "web_scan|ssh_bruteforce|credential_stuffing".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["web_shell|reverse_shell".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "pam_module_change|startup_script_persistence|systemd_persistence|crontab_persistence".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec![
                        "auditd_disable|selinux_apparmor_disable|log_tampering".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["data_destruction_pattern|ransomware".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 7200, // 2 hours
            min_confidence: 0.95,
            severity: Severity::Critical,
        },
        // CL-068: Wiper Precursor — blind-then-map-then-wipe.
        // Distinct from CL-056 by inserting a discovery burst between
        // evasion and impact (the textbook nation-state wiper shape).
        CorrelationRule {
            id: "CL-068".into(),
            name: "Wiper Precursor (evasion + discovery + impact)".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "auditd_disable|selinux_apparmor_disable".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "nmap_scan|wordlist_scan|discovery_anomaly|discovery_burst".into(),
                    ],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["data_destruction_pattern".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 1800,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
        // CL-069: Insider Exfil — interactive shell + collection +
        // lateral_egress_scp_rsync. Entity-pivoted on shared IP/uid.
        // Wave 2026-05-17: legacy variants added to stages 2 + 3.
        CorrelationRule {
            id: "CL-069".into(),
            name: "Insider Exfiltration Pattern".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["shell.command_exec".into()],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec![
                        "archive_pwd_protected|automated_file_collection|data_archive|suspicious_archive".into(),
                    ],
                    entity_must_match: true,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["lateral_egress_scp_rsync|data_exfil_cmd".into()],
                    entity_must_match: true,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.80,
            severity: Severity::High,
        },
        // CL-070: PAM Credential Theft Chain — PAM tamper + subsequent
        // successful auth + outbound ssh pivot. Identity rotates between
        // PAM-write (attacker uid) and login-success (victim creds), so
        // entity_must_match=false on cross-stage hops.
        CorrelationRule {
            id: "CL-070".into(),
            name: "PAM Credential Theft → Lateral Pivot".into(),
            stages: vec![
                RuleStage {
                    layer: Some(Layer::Userspace),
                    kind_patterns: vec!["pam_module_change".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["ssh.login_success|suspicious_login".into()],
                    entity_must_match: false,
                },
                RuleStage {
                    layer: None,
                    kind_patterns: vec!["lateral_egress_ssh".into()],
                    entity_must_match: false,
                },
            ],
            window_secs: 3600,
            min_confidence: 0.85,
            severity: Severity::Critical,
        },
    ]
}

impl CorrelationEngine {
    /// Check for Multi-Low elevation: 3+ different Low detectors for the same
    /// IP within 600 seconds should elevate to High.
    ///
    /// Called after observe(). Returns an AttackChain if the threshold is met.
    pub fn check_multi_low_elevation(&mut self) -> Option<AttackChain> {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(600);

        // Group recent low-severity events by IP
        let mut ip_detectors: HashMap<String, Vec<CorrelationEvent>> = HashMap::new();
        for event in &self.event_window {
            if event.ts < cutoff {
                continue;
            }
            if event.severity != Severity::Low {
                continue;
            }
            for entity in &event.entities {
                if entity.r#type == EntityType::Ip {
                    ip_detectors
                        .entry(entity.value.clone())
                        .or_default()
                        .push(event.clone());
                }
            }
        }

        for (ip, events) in &ip_detectors {
            // Wave 6: e.kind is `Arc<str>` so deref via `&*` to get `&str`.
            // Avoids the unstable `Arc<str>::as_str` (Rust feature gate
            // `str_as_str`).
            let unique_kinds: HashSet<&str> = events.iter().map(|e| &*e.kind).collect();
            if unique_kinds.len() >= 3 {
                let cooldown_key = format!("CL-010:ip:{ip}");
                if self.chain_cooldowns.contains_key(&cooldown_key) {
                    continue;
                }

                let chain_id = format!("CHAIN-{:04}", self.next_chain_id);
                self.next_chain_id += 1;

                let summary = format!(
                    "Multi-vector reconnaissance from {}: {} different low-severity detectors in 10 minutes ({})",
                    ip,
                    unique_kinds.len(),
                    unique_kinds.into_iter().collect::<Vec<_>>().join(", ")
                );

                info!(chain_id = %chain_id, ip = %ip, "CL-010 multi-low elevation");

                self.chain_cooldowns
                    .insert(cooldown_key, now + chrono::Duration::seconds(600));

                return Some(AttackChain {
                    chain_id,
                    rule_id: "CL-010".into(),
                    rule_name: "Multi-Low Severity Elevation".into(),
                    start_ts: events.first().map(|e| e.ts).unwrap_or(now),
                    last_ts: events.last().map(|e| e.ts).unwrap_or(now),
                    events: events.clone(),
                    stages_matched: events.len(),
                    stages_total: events.len(),
                    confidence: 0.75,
                    layers_involved: events
                        .iter()
                        .map(|e| e.layer)
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect(),
                    severity: Severity::High,
                    summary,
                });
            }
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Event;

    /// Wave 6 (AUDIT-WAVE6-INTERN) anchor: pushing 10 000 events that
    /// share `source`/`kind` strings into a `CorrelationEngine`'s
    /// `event_window` must produce one Arc<str> per distinct value,
    /// not 10 000 independent String allocations. Verified by
    /// pointer-equality on the resulting `Arc<str>` fields.
    ///
    /// Pre-Wave-6 the type was `String`, so `event_window` of length
    /// 10 000 with kind="ssh.login_failed" paid ~250 KB just for that
    /// one repeated string. With `Arc<str>` interning the same window
    /// pays one 24-byte Arc + one 16-byte heap allocation, full stop.
    #[test]
    fn correlation_event_source_and_kind_share_arc_allocations() {
        // Build N CorrelationEvents from raw `Event` shapes that share
        // source/kind. The CorrelationEvent::From<Event> impl is the
        // production interning point.
        let mut engine = CorrelationEngine::new();
        for _ in 0..1000 {
            let raw_event = Event {
                ts: Utc::now(),
                host: "h".into(),
                source: "auth_log".into(),
                kind: "ssh.login_failed".into(),
                severity: Severity::Medium,
                summary: "s".into(),
                details: serde_json::json!({}),
                tags: vec![],
                entities: vec![EntityRef::ip("1.2.3.4")],
            };
            let ce = CorrelationEngine::classify_event(&raw_event);
            engine.event_window.push_back(ce);
        }
        assert_eq!(engine.event_window.len(), 1000);
        // Pointer-equality on every entry's source — they MUST share
        // the same Arc<str> backing allocation. If the impl ever
        // regresses to `String`, this fails: two `String` instances
        // never share heap memory even when their content matches.
        let first_source = engine.event_window[0].source.clone();
        let first_kind = engine.event_window[0].kind.clone();
        for (i, ce) in engine.event_window.iter().enumerate() {
            assert!(
                std::sync::Arc::ptr_eq(&ce.source, &first_source),
                "event[{i}].source should share Arc with event[0].source — \
                 the interner deduplicates 'auth_log' across the window"
            );
            assert!(
                std::sync::Arc::ptr_eq(&ce.kind, &first_kind),
                "event[{i}].kind should share Arc with event[0].kind — \
                 the interner deduplicates 'ssh.login_failed' across the window"
            );
        }
    }

    fn make_event(layer: Layer, kind: &str, ip: &str) -> CorrelationEvent {
        CorrelationEvent {
            ts: Utc::now(),
            layer,
            source: intern("test"),
            kind: intern(kind),
            severity: Severity::Medium,
            entities: vec![EntityRef::ip(ip)],
            details: serde_json::json!({}),
            incident_id: String::new(),
        }
    }

    fn make_event_at(layer: Layer, kind: &str, ip: &str, ts: DateTime<Utc>) -> CorrelationEvent {
        CorrelationEvent {
            ts,
            layer,
            source: intern("test"),
            kind: intern(kind),
            severity: Severity::Medium,
            entities: vec![EntityRef::ip(ip)],
            details: serde_json::json!({}),
            incident_id: String::new(),
        }
    }

    #[test]
    fn engine_starts_empty() {
        let engine = CorrelationEngine::new();
        // 47 original (CL-001 → CL-047) + 20 spec 050-PR7 (CL-051 → CL-070).
        assert_eq!(engine.rule_count(), 67);
        assert_eq!(engine.pending_count(), 0);
    }

    #[test]
    fn single_event_starts_pending_chain() {
        let mut engine = CorrelationEngine::new();
        let ev = make_event(Layer::Firmware, "firmware.msr_write", "10.0.0.1");
        engine.observe(ev);

        // Should have started CL-001 and CL-004 (both start with firmware.*)
        assert!(engine.pending_count() >= 1);
        assert!(engine.drain_completed().is_empty());
    }

    /// 2026-05-08 anchor (fix/chains-tab-honesty-bundle): when the
    /// engine completes a chain whose stage events arrived in the
    /// `matched_events` vec out of chronological order (rule order
    /// independence + event-delivery race), the duration in the
    /// summary string MUST NOT go negative. Operator's prod
    /// 2026-05-08 dashboard had multiple chains with summaries like
    /// `"...: 2 stages across 1 layers in -2s"`. The fix sorts
    /// `matched_events` by `ts` before computing `start_ts` and
    /// `last_ts` so the duration is the actual chronological window.
    #[test]
    fn complete_chain_summary_duration_is_nonnegative_with_out_of_order_stage_events() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";
        let later = Utc::now();
        let earlier = later - chrono::Duration::seconds(10);

        // Feed stage 2's event FIRST (earlier in time), then stage 1
        // arriving LATER but with an EARLIER timestamp. The ordering
        // here mimics what happens when events of the same logical
        // attack arrive on parallel channels and the second one to
        // be observed has the earlier wall-clock ts.
        let mut e2 = make_event_at(Layer::Userspace, "ssh_bruteforce", ip, later);
        e2.severity = Severity::High;
        engine.observe(make_event_at(Layer::Network, "port_scan", ip, later));
        let _ = engine.drain_completed();
        engine.observe(make_event_at(
            Layer::Network,
            "data_exfiltration",
            ip,
            earlier,
        ));

        for chain in engine.drain_completed() {
            let secs = (chain.last_ts - chain.start_ts).num_seconds();
            assert!(
                secs >= 0,
                "chain duration MUST NOT go negative — got {} seconds for rule {} \
                 (summary: {:?})",
                secs,
                chain.rule_id,
                chain.summary
            );
            // Summary string must also reflect the non-negative duration.
            assert!(
                !chain.summary.contains("in -"),
                "chain summary must not contain a negative duration token: {:?}",
                chain.summary
            );
        }
    }

    #[test]
    fn complete_chain_cl002_recon_to_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Stage 1: port_scan
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        let _ = engine.drain_completed(); // may trigger partial matches

        // Stage 2: ssh_bruteforce (same IP)
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        let _ = engine.drain_completed(); // CL-025 may trigger here

        // Stage 3: data_exfiltration (same IP)
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));

        let chains = engine.drain_completed();
        assert!(
            chains.iter().any(|c| c.rule_id == "CL-002"),
            "expected CL-002 in {:?}",
            chains.iter().map(|c| &c.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn chain_requires_entity_match() {
        let mut engine = CorrelationEngine::new();

        // Stage 1: port_scan from IP A
        engine.observe(make_event(Layer::Network, "port_scan", "10.0.0.1"));

        // Stage 2: ssh_bruteforce from IP B (different IP — should NOT advance CL-002)
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", "10.0.0.2"));

        // Stage 3: data_exfiltration from IP B
        engine.observe(make_event(Layer::Network, "data_exfiltration", "10.0.0.2"));

        // CL-002 should NOT complete (IP mismatch between stage 1 and 2)
        let chains = engine.drain_completed();
        assert!(chains.iter().all(|c| c.rule_id != "CL-002"));
    }

    #[test]
    fn chain_expires_after_window() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";
        let now = Utc::now();

        // Stage 1 at T=0
        engine.observe(make_event_at(Layer::Network, "port_scan", ip, now));

        // Stage 2 at T=2000s (beyond CL-002 window of 1800s)
        let later = now + chrono::Duration::seconds(2000);
        engine.observe(make_event_at(Layer::Userspace, "ssh_bruteforce", ip, later));

        // Pending chain should have expired
        // New chain started from stage 2, but stage 3 not met
        let chains = engine.drain_completed();
        assert!(chains.is_empty());
    }

    #[test]
    fn multi_low_elevation() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // 3 different low-severity detectors for the same IP
        let mut ev1 = make_event(Layer::Network, "port_scan", ip);
        ev1.severity = Severity::Low;
        engine.observe(ev1);

        let mut ev2 = make_event(Layer::Userspace, "user_agent_scanner", ip);
        ev2.severity = Severity::Low;
        engine.observe(ev2);

        let mut ev3 = make_event(Layer::Network, "web_scan", ip);
        ev3.severity = Severity::Low;
        engine.observe(ev3);

        let chain = engine.check_multi_low_elevation();
        assert!(chain.is_some());
        let chain = chain.unwrap();
        assert_eq!(chain.rule_id, "CL-010");
        assert_eq!(chain.severity, Severity::High);
    }

    #[test]
    fn multi_low_needs_3_different_kinds() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Same kind twice + one different = only 2 unique kinds
        let mut ev1 = make_event(Layer::Network, "port_scan", ip);
        ev1.severity = Severity::Low;
        engine.observe(ev1);

        let mut ev2 = make_event(Layer::Network, "port_scan", ip);
        ev2.severity = Severity::Low;
        engine.observe(ev2);

        let mut ev3 = make_event(Layer::Userspace, "web_scan", ip);
        ev3.severity = Severity::Low;
        engine.observe(ev3);

        let chain = engine.check_multi_low_elevation();
        assert!(chain.is_none());
    }

    #[test]
    fn classify_layer_firmware() {
        assert_eq!(classify_layer("smm", "firmware.check"), Layer::Firmware);
        assert_eq!(
            classify_layer("sensor", "firmware.msr_write"),
            Layer::Firmware
        );
    }

    #[test]
    fn classify_layer_kernel() {
        assert_eq!(
            classify_layer("ebpf", "privilege.escalation"),
            Layer::Kernel
        );
    }

    #[test]
    fn classify_layer_network() {
        assert_eq!(
            classify_layer("ebpf", "network.outbound_connect"),
            Layer::Network
        );
    }

    #[test]
    fn classify_layer_honeypot() {
        assert_eq!(classify_layer("honeypot", "honeypot_ssh"), Layer::Honeypot);
    }

    #[test]
    fn cooldown_prevents_duplicate_chains() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.1";

        // Complete CL-002 first time (may also trigger CL-025)
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));
        let chains = engine.drain_completed();
        assert!(!chains.is_empty(), "expected at least CL-002");
        assert!(chains.iter().any(|c| c.rule_id == "CL-002"));

        // Try same sequence again — should be suppressed by cooldown
        engine.observe(make_event(Layer::Network, "port_scan", ip));
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Network, "data_exfiltration", ip));
        assert_eq!(engine.drain_completed().len(), 0);
    }

    #[test]
    fn glob_pattern_matching() {
        let stage = RuleStage {
            layer: None,
            kind_patterns: vec!["firmware.*".into()],
            entity_must_match: false,
        };
        let ev = make_event(Layer::Firmware, "firmware.msr_write", "10.0.0.1");
        assert!(matches_stage(&stage, &ev, &HashSet::new(), "test"));

        let ev2 = make_event(Layer::Kernel, "privilege.escalation", "10.0.0.1");
        assert!(!matches_stage(&stage, &ev2, &HashSet::new(), "test"));
    }

    #[test]
    fn or_pattern_matching() {
        let stage = RuleStage {
            layer: None,
            kind_patterns: vec!["ssh_bruteforce|credential_stuffing".into()],
            entity_must_match: false,
        };
        let ev1 = make_event(Layer::Userspace, "ssh_bruteforce", "10.0.0.1");
        assert!(matches_stage(&stage, &ev1, &HashSet::new(), "test"));

        let ev2 = make_event(Layer::Userspace, "credential_stuffing", "10.0.0.1");
        assert!(matches_stage(&stage, &ev2, &HashSet::new(), "test"));

        let ev3 = make_event(Layer::Userspace, "port_scan", "10.0.0.1");
        assert!(!matches_stage(&stage, &ev3, &HashSet::new(), "test"));
    }

    // Wave 8a anchor (2026-05-04): operator-hit prod bug — CL-008
    // (Data Exfiltration via eBPF Sequence) blocked Ubuntu archive
    // mirrors, GitHub Pages CDN, Telegram (the agent's own notification
    // infra) and Oracle Cloud during a routine `apt upgrade` on
    // 2026-05-04 (32 critical incidents in one day, all auto-block via
    // UFW with dry_run=false). Root cause: the rule's stages
    // (file.read_access + network.outbound_connect) trigger on every
    // package-manager run that opens /etc/* and connects to a mirror.
    // This anchor pins the per-rule comm suppression that makes
    // CL-008 ignore events whose `details.comm` is a known package
    // manager. It is distro-agnostic (covers apt/dpkg/snap/dnf/yum/
    // rpm/zypper/pacman/apk/emerge/xbps/flatpak/brew/PackageKit).
    #[test]
    fn cl008_does_not_match_when_originating_process_is_a_package_manager() {
        // Ubuntu apt upgrade reading /var/cache/apt files and connecting
        // to archive.ubuntu.com (91.189.91.46 = real prod block).
        let mut ev_read = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev_read.details =
            serde_json::json!({"pid": 1234, "comm": "apt-get", "path": "/etc/apt/sources.list"});
        let mut ev_connect = make_event(Layer::Network, "network.outbound_connect", "91.189.91.46");
        ev_connect.details = serde_json::json!({"pid": 1234, "comm": "apt-get", "dst_ip": "91.189.91.46", "dst_port": 80});

        let stages = &[
            RuleStage {
                layer: None,
                kind_patterns: vec!["file.read_access".into()],
                entity_must_match: false,
            },
            RuleStage {
                layer: Some(Layer::Network),
                kind_patterns: vec!["network.outbound_connect".into()],
                entity_must_match: true,
            },
        ];

        // CL-008 must reject both stages when comm is apt-get (suppression active).
        assert!(
            !matches_stage(&stages[0], &ev_read, &HashSet::new(), "CL-008"),
            "CL-008 stage 1 must NOT match apt-get reading /etc/apt — \
             that's a package upgrade, not exfil. Pinned by Wave 8a after \
             the 2026-05-04 prod incident where 32 critical chains fired \
             during apt upgrade and blocked Ubuntu mirrors via UFW."
        );

        let mut entities: HashSet<String> = HashSet::new();
        entities.insert("ip:91.189.91.46".to_string());
        assert!(
            !matches_stage(&stages[1], &ev_connect, &entities, "CL-008"),
            "CL-008 stage 2 must NOT match apt-get connecting to a \
             repository mirror. See ANCHOR_TESTS.md Wave 8a entry."
        );
    }

    #[test]
    fn cl008_still_matches_for_non_package_manager_processes() {
        // Same shape as the test above but the comm is a generic shell —
        // the rule MUST still fire here; suppression is a tight allowlist,
        // not a hole that disables the chain.
        let mut ev_read = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev_read.details = serde_json::json!({"pid": 999, "comm": "bash", "path": "/etc/shadow"});
        let mut ev_connect = make_event(Layer::Network, "network.outbound_connect", "203.0.113.7");
        ev_connect.details = serde_json::json!({"pid": 999, "comm": "bash", "dst_ip": "203.0.113.7", "dst_port": 4444});

        let stage1 = RuleStage {
            layer: None,
            kind_patterns: vec!["file.read_access".into()],
            entity_must_match: false,
        };
        let stage2 = RuleStage {
            layer: Some(Layer::Network),
            kind_patterns: vec!["network.outbound_connect".into()],
            entity_must_match: true,
        };

        assert!(matches_stage(&stage1, &ev_read, &HashSet::new(), "CL-008"));

        let mut entities: HashSet<String> = HashSet::new();
        entities.insert("ip:203.0.113.7".to_string());
        assert!(matches_stage(&stage2, &ev_connect, &entities, "CL-008"));
    }

    // Wave 8a (2026-05-04): unattended-upgrade and dpkg-statoverride
    // are both >15 chars. Linux truncates `comm` at TASK_COMM_LEN-1 = 15.
    // The suppression list MUST contain the truncated forms or the bug
    // returns silently for anyone running unattended-upgrades (the Ubuntu
    // default, including the prod host that hit this on 2026-05-04).
    #[test]
    fn cl008_suppression_handles_15char_truncated_comms() {
        for comm in &["unattended-upgr", "dpkg-statoverri", "snap-update-ns"] {
            let mut ev = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
            ev.details = serde_json::json!({"pid": 1, "comm": comm, "path": "/etc/passwd"});
            let stage = RuleStage {
                layer: None,
                kind_patterns: vec!["file.read_access".into()],
                entity_must_match: false,
            };
            assert!(
                !matches_stage(&stage, &ev, &HashSet::new(), "CL-008"),
                "comm {comm:?} (truncated at 15 chars by the Linux kernel) \
                 must be in PACKAGE_MANAGER_COMMS — see neighbour comments."
            );
        }
    }

    // Wave 8a (2026-05-04): suppression is opt-in by rule_id. Other
    // chains must still fire on package-manager activity if their kind
    // patterns match — we only carve out CL-008 today.
    #[test]
    fn comm_suppression_does_not_leak_to_other_rules() {
        let mut ev = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev.details = serde_json::json!({"pid": 1, "comm": "apt-get", "path": "/etc/passwd"});
        let stage = RuleStage {
            layer: None,
            kind_patterns: vec!["file.read_access".into()],
            entity_must_match: false,
        };
        // A made-up rule id must NOT inherit CL-008's suppression list.
        assert!(matches_stage(&stage, &ev, &HashSet::new(), "CL-XXX"));
        // The dedicated helper agrees.
        assert!(!event_comm_is_suppressed("CL-XXX", &ev));
        assert!(event_comm_is_suppressed("CL-008", &ev));
    }

    #[test]
    fn cl008_no_comm_field_does_not_panic_and_falls_through() {
        // Real events from older sensors might not carry `comm`. Make sure
        // suppression returns false (event proceeds to normal kind/entity
        // matching) instead of panicking or accidentally suppressing.
        let mut ev = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev.details = serde_json::json!({"pid": 1, "path": "/etc/passwd"});
        assert!(!event_comm_is_suppressed("CL-008", &ev));
    }

    // ── PR ε (2026-05-04) — InnerWarden self-traffic suppression ──────
    //
    // Pre-fix the prod CL-008 was firing 72x in 30 min and blocking
    // outbound to:
    //   - 208.95.112.1 (a real external dependency the agent reaches)
    //   - 149.154.166.110 (Telegram - agent's own notification infra,
    //     would have been blocked but for the operator's allowlist)
    //   - 147.154.x (Oracle Cloud - the agent's OWN cloud provider)
    // All had comm = tokio-rt-worker from the agent's outbound connect
    // path. Wave 8a's PACKAGE_MANAGER_COMMS only covered apt/dpkg/etc.;
    // these anchors pin the broader self-traffic carve-out.

    #[test]
    fn cl008_suppressed_when_originating_comm_is_innerwarden_agent() {
        // Truncated comm shape that the kernel actually emits
        // (TASK_COMM_LEN - 1 = 15 chars, so `innerwarden-agent` becomes
        // `innerwarden-age`). The agent's outbound call to e.g. AbuseIPDB
        // must NOT trigger CL-008 even though the chain shape (file.read
        // + outbound connect) technically matches.
        let mut ev_read = make_event(Layer::Userspace, "file.read_access", "127.0.0.1");
        ev_read.details = serde_json::json!({
            "pid": 12345, "comm": "innerwarden-age", "path": "/etc/innerwarden/license.key"
        });
        let mut ev_connect = make_event(Layer::Network, "network.outbound_connect", "208.95.112.1");
        ev_connect.details = serde_json::json!({
            "pid": 12345, "comm": "innerwarden-age", "dst_ip": "208.95.112.1", "dst_port": 443
        });

        assert!(
            event_comm_is_suppressed("CL-008", &ev_read),
            "innerwarden-age (truncated) reading the license file must be suppressed"
        );
        assert!(
            event_comm_is_suppressed("CL-008", &ev_connect),
            "innerwarden-age (truncated) outbound connect must be suppressed"
        );
    }

    #[test]
    fn cl008_suppressed_when_originating_comm_is_tokio_rt_worker() {
        // Tokio runtime workers carry the literal string `tokio-rt-worker`
        // (15 chars exactly). The agent's HTTP / Redis / DNS calls all
        // happen on these threads; the eBPF connect() events therefore
        // carry `comm = tokio-rt-worker` in their details. The exact
        // shape that drove the AUDIT-CL008-SELF prod incident.
        let mut ev = make_event(
            Layer::Network,
            "network.outbound_connect",
            "149.154.166.110",
        );
        ev.details = serde_json::json!({
            "pid": 12346, "comm": "tokio-rt-worker", "dst_ip": "149.154.166.110", "dst_port": 443
        });
        assert!(
            event_comm_is_suppressed("CL-008", &ev),
            "tokio-rt-worker outbound to Telegram (149.154.166.110) must be suppressed"
        );
    }

    #[test]
    fn innerwarden_binary_self_traffic_suppression_is_rule_agnostic() {
        // PR ε: unlike the package-manager carve-out (Wave 8a, opt-in by
        // rule_id), suppression for our OWN binary names applies to EVERY
        // rule. A chain that wants to claim agent self-traffic for any
        // reason is wrong about the threat model. The binary names are
        // unambiguous - no third-party process produces `innerwarden-age`
        // - so the rule-agnostic suppression is safe.
        //
        // Anti-regression for accidentally attaching the list to
        // `rule_comm_suppressions` (which would scope it to CL-008 only).
        let mut ev = make_event(Layer::Network, "network.outbound_connect", "147.154.234.47");
        ev.details = serde_json::json!({
            "pid": 12347, "comm": "innerwarden-age", "dst_ip": "147.154.234.47", "dst_port": 443
        });
        for rule_id in &["CL-001", "CL-002", "CL-008", "CL-011", "CL-XXX-future"] {
            assert!(
                event_comm_is_suppressed(rule_id, &ev),
                "innerwarden-age outbound must be suppressed regardless of rule_id (rule={rule_id:?})"
            );
        }
    }

    #[test]
    fn tokio_rt_worker_only_suppressed_on_cl008_not_other_rules() {
        // PR ε: `tokio-rt-worker` is the thread name Tokio gives every
        // runtime worker, NOT something specific to the InnerWarden
        // agent. If a malicious Tokio-based attacker tool fires e.g. a
        // credential-theft chain (CL-011) using this same comm, we
        // MUST still see the chain. The carve-out is deliberately
        // CL-008-only because that one rule has a documented prod FP
        // rate from the agent's own outbound calls - all other rules
        // see `tokio-rt-worker` as a normal comm.
        //
        // Anti-regression for promoting `tokio-rt-worker` to
        // `INNERWARDEN_SELF_COMMS` (which would create a workspace-wide
        // blind spot for any Tokio-based malware).
        let mut ev = make_event(Layer::Network, "network.outbound_connect", "203.0.113.99");
        ev.details = serde_json::json!({
            "pid": 999, "comm": "tokio-rt-worker", "dst_ip": "203.0.113.99", "dst_port": 4444
        });

        // CL-008: suppressed (the documented FP class).
        assert!(
            event_comm_is_suppressed("CL-008", &ev),
            "CL-008 must suppress tokio-rt-worker (matches PR ε docs)"
        );
        // Every other rule: NOT suppressed - the chain still has to
        // fire if the kind patterns / entities line up.
        for rule_id in &["CL-001", "CL-002", "CL-011", "CL-014", "CL-XXX-future"] {
            assert!(
                !event_comm_is_suppressed(rule_id, &ev),
                "rule {rule_id:?} must NOT suppress tokio-rt-worker - this comm is not InnerWarden-specific"
            );
        }
    }

    #[test]
    fn self_traffic_suppression_does_not_match_full_untruncated_names() {
        // Anti-regression: someone reading the source might "fix" the
        // truncated entries by adding the full names too. That's
        // wrong - the kernel NEVER produces them on Linux because of
        // TASK_COMM_LEN, so the full name in the list adds dead weight
        // and could shadow a legitimate match if a future eBPF program
        // ever exposed an untruncated name via /proc/<pid>/cmdline.
        // The list pins the kernel-truth shape.
        let untruncated_full_names = [
            "innerwarden-agent",    // 17 chars, truncated to innerwarden-age
            "innerwarden-sensor",   // 18 chars, truncated to innerwarden-sen
            "innerwarden-watchdog", // 20 chars, truncated to innerwarden-watc
        ];
        for full in &untruncated_full_names {
            let mut ev = make_event(Layer::Network, "network.outbound_connect", "10.0.0.1");
            ev.details = serde_json::json!({"pid": 1, "comm": full, "dst_ip": "10.0.0.1"});
            assert!(
                !event_comm_is_suppressed("CL-008", &ev),
                "full untruncated comm {full:?} must NOT match - the kernel never emits it"
            );
        }
    }

    #[test]
    fn self_traffic_suppression_keeps_real_attacker_comms_alive() {
        // Anti-regression: the carve-out is a tight allowlist, NOT a
        // hole that disables CL-008. Common attacker tooling comms
        // (curl, wget, nc, python, perl, ssh) must STILL be allowed
        // through to chain matching.
        for comm in &["curl", "wget", "nc", "python3", "perl", "ssh", "bash"] {
            let mut ev = make_event(Layer::Network, "network.outbound_connect", "203.0.113.99");
            ev.details = serde_json::json!({"pid": 999, "comm": comm, "dst_ip": "203.0.113.99"});
            assert!(
                !event_comm_is_suppressed("CL-008", &ev),
                "comm {comm:?} must NOT be suppressed - it is plausible attacker tooling"
            );
        }
    }

    // ─── spec 050-PR7 — Cross-tactic chain rule tests (CL-051 → CL-070) ───

    fn assert_chain_fires(engine: &mut CorrelationEngine, expected_rule_id: &str) {
        let chains = engine.drain_completed();
        assert!(
            chains.iter().any(|c| c.rule_id == expected_rule_id),
            "expected {} to fire — got [{}]",
            expected_rule_id,
            chains
                .iter()
                .map(|c| c.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    #[test]
    fn cl_051_discovery_to_privesc() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.51";
        engine.observe(make_event(Layer::Userspace, "nmap_scan", ip));
        engine.observe(make_event(Layer::Userspace, "setuid_exploit_pattern", ip));
        assert_chain_fires(&mut engine, "CL-051");
    }

    #[test]
    fn cl_052_privesc_to_lateral() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.52";
        engine.observe(make_event(Layer::Userspace, "capabilities_abuse", ip));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_ssh", ip));
        assert_chain_fires(&mut engine, "CL-052");
    }

    #[test]
    fn cl_053_collection_to_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.53";
        engine.observe(make_event(
            Layer::Userspace,
            "automated_file_collection",
            ip,
        ));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_scp_rsync", ip));
        assert_chain_fires(&mut engine, "CL-053");
    }

    #[test]
    fn cl_054_web_shell_to_c2() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.54";
        engine.observe(make_event(Layer::Userspace, "web_shell", ip));
        engine.observe(make_event(Layer::Userspace, "c2_web_tunnel", ip));
        assert_chain_fires(&mut engine, "CL-054");
    }

    #[test]
    fn cl_055_persistence_to_defense_evasion() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.55";
        engine.observe(make_event(Layer::Userspace, "pam_module_change", ip));
        engine.observe(make_event(Layer::Userspace, "auditd_disable", ip));
        assert_chain_fires(&mut engine, "CL-055");
    }

    #[test]
    fn cl_056_defense_evasion_to_impact() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.56";
        engine.observe(make_event(Layer::Userspace, "auditd_disable", ip));
        engine.observe(make_event(Layer::Userspace, "data_destruction_pattern", ip));
        assert_chain_fires(&mut engine, "CL-056");
    }

    #[test]
    fn cl_057_discovery_burst_to_collection() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.57";
        engine.observe(make_event(Layer::Userspace, "discovery_burst", ip));
        engine.observe(make_event(Layer::Userspace, "archive_pwd_protected", ip));
        assert_chain_fires(&mut engine, "CL-057");
    }

    #[test]
    fn cl_058_initial_access_to_foothold() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.58";
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Userspace, "reverse_shell", ip));
        assert_chain_fires(&mut engine, "CL-058");
    }

    #[test]
    fn cl_059_foothold_to_persistence() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.59";
        engine.observe(make_event(Layer::Userspace, "reverse_shell", ip));
        engine.observe(make_event(
            Layer::Userspace,
            "startup_script_persistence",
            ip,
        ));
        assert_chain_fires(&mut engine, "CL-059");
    }

    #[test]
    fn cl_060_c2_to_discovery() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.60";
        engine.observe(make_event(Layer::Userspace, "c2_callback", ip));
        engine.observe(make_event(Layer::Userspace, "nmap_scan", ip));
        assert_chain_fires(&mut engine, "CL-060");
    }

    #[test]
    fn cl_061_discovery_to_c2() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.61";
        engine.observe(make_event(Layer::Userspace, "wordlist_scan", ip));
        engine.observe(make_event(Layer::Userspace, "c2_protocol_tunneling", ip));
        assert_chain_fires(&mut engine, "CL-061");
    }

    #[test]
    fn cl_062_reverse_shell_to_privesc() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.62";
        engine.observe(make_event(Layer::Userspace, "reverse_shell", ip));
        engine.observe(make_event(Layer::Userspace, "setuid_exploit_pattern", ip));
        assert_chain_fires(&mut engine, "CL-062");
    }

    #[test]
    fn cl_063_privesc_to_persistence() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.63";
        engine.observe(make_event(Layer::Userspace, "setuid_exploit_pattern", ip));
        engine.observe(make_event(Layer::Userspace, "pam_module_change", ip));
        assert_chain_fires(&mut engine, "CL-063");
    }

    #[test]
    fn cl_064_persistence_to_lateral() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.64";
        engine.observe(make_event(Layer::Userspace, "systemd_persistence", ip));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_ssh", ip));
        assert_chain_fires(&mut engine, "CL-064");
    }

    #[test]
    fn cl_065_lateral_to_collection() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.65";
        engine.observe(make_event(Layer::Userspace, "lateral_egress_ssh", ip));
        engine.observe(make_event(Layer::Userspace, "clipboard_read", ip));
        assert_chain_fires(&mut engine, "CL-065");
    }

    #[test]
    fn cl_066_collection_to_lateral_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.66";
        engine.observe(make_event(
            Layer::Userspace,
            "automated_file_collection",
            ip,
        ));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_scp_rsync", ip));
        assert_chain_fires(&mut engine, "CL-066");
    }

    #[test]
    fn cl_067_full_kill_chain() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.67";
        engine.observe(make_event(Layer::Userspace, "ssh_bruteforce", ip));
        engine.observe(make_event(Layer::Userspace, "reverse_shell", ip));
        engine.observe(make_event(Layer::Userspace, "pam_module_change", ip));
        engine.observe(make_event(Layer::Userspace, "auditd_disable", ip));
        engine.observe(make_event(Layer::Userspace, "data_destruction_pattern", ip));
        assert_chain_fires(&mut engine, "CL-067");
    }

    #[test]
    fn cl_068_wiper_precursor() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.68";
        engine.observe(make_event(Layer::Userspace, "selinux_apparmor_disable", ip));
        engine.observe(make_event(Layer::Userspace, "discovery_anomaly", ip));
        engine.observe(make_event(Layer::Userspace, "data_destruction_pattern", ip));
        assert_chain_fires(&mut engine, "CL-068");
    }

    #[test]
    fn cl_069_insider_exfil() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.69";
        engine.observe(make_event(Layer::Userspace, "shell.command_exec", ip));
        engine.observe(make_event(
            Layer::Userspace,
            "automated_file_collection",
            ip,
        ));
        engine.observe(make_event(Layer::Userspace, "lateral_egress_scp_rsync", ip));
        assert_chain_fires(&mut engine, "CL-069");
    }

    #[test]
    fn cl_070_pam_credential_theft_chain() {
        let mut engine = CorrelationEngine::new();
        // PAM tamper from attacker_ip, then victim auth success, then
        // lateral pivot — identity rotates, entity_must_match=false.
        engine.observe(make_event(
            Layer::Userspace,
            "pam_module_change",
            "10.0.0.70",
        ));
        engine.observe(make_event(
            Layer::Userspace,
            "ssh.login_success",
            "10.0.0.71",
        ));
        engine.observe(make_event(
            Layer::Userspace,
            "lateral_egress_ssh",
            "10.0.0.72",
        ));
        assert_chain_fires(&mut engine, "CL-070");
    }

    // ─── Post-Caldera 2026-05-17 tuning: legacy detector variants ──────────
    // These tests anchor the OR-pattern updates added after the first
    // Caldera run, where the chain rules were not firing because the
    // legacy detectors emit `data_exfil_cmd` / `data_archive` /
    // `suspicious_archive` instead of the new PR1-6 names that PR7
    // originally listed.

    #[test]
    fn cl_053_fires_on_legacy_data_archive_then_data_exfil_cmd() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.153";
        engine.observe(make_event(Layer::Userspace, "data_archive", ip));
        engine.observe(make_event(Layer::Userspace, "data_exfil_cmd", ip));
        assert_chain_fires(&mut engine, "CL-053");
    }

    #[test]
    fn cl_053_fires_on_suspicious_archive_variant() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.253";
        engine.observe(make_event(Layer::Userspace, "suspicious_archive", ip));
        engine.observe(make_event(Layer::Userspace, "data_exfil_cmd", ip));
        assert_chain_fires(&mut engine, "CL-053");
    }

    #[test]
    fn cl_057_fires_on_legacy_data_archive_after_discovery() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.157";
        engine.observe(make_event(Layer::Userspace, "discovery_burst", ip));
        engine.observe(make_event(Layer::Userspace, "data_archive", ip));
        assert_chain_fires(&mut engine, "CL-057");
    }

    #[test]
    fn cl_066_fires_on_data_archive_then_data_exfil_cmd() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.166";
        engine.observe(make_event(Layer::Userspace, "data_archive", ip));
        engine.observe(make_event(Layer::Userspace, "data_exfil_cmd", ip));
        assert_chain_fires(&mut engine, "CL-066");
    }

    #[test]
    fn cl_069_fires_on_legacy_archive_and_exfil_variants() {
        let mut engine = CorrelationEngine::new();
        let ip = "10.0.0.169";
        engine.observe(make_event(Layer::Userspace, "shell.command_exec", ip));
        engine.observe(make_event(Layer::Userspace, "suspicious_archive", ip));
        engine.observe(make_event(Layer::Userspace, "data_exfil_cmd", ip));
        assert_chain_fires(&mut engine, "CL-069");
    }
}
