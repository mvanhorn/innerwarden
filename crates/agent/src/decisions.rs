use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::ai::AiDecision;

// ---------------------------------------------------------------------------
// Decision log entry
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct DecisionEntry {
    pub ts: DateTime<Utc>,
    pub incident_id: String,
    pub host: String,
    pub ai_provider: String,

    /// Serialized AiAction tag (e.g. "block_ip", "ignore")
    pub action_type: String,
    pub target_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_user: Option<String>,
    pub skill_id: Option<String>,

    pub confidence: f32,
    pub auto_executed: bool,
    pub dry_run: bool,

    /// AI's textual reasoning
    pub reason: String,
    pub estimated_threat: String,

    /// Result of skill execution ("ok", "skipped", "failed: ...")
    pub execution_result: String,

    /// SHA-256 hash of the previous decision entry (tamper detection chain)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Decision writer
// ---------------------------------------------------------------------------

pub struct DecisionWriter {
    data_dir: std::path::PathBuf,
    current_date: String,
    writer: BufWriter<File>,
    /// SHA-256 hash of the last written decision entry for hash chaining.
    last_hash: Option<String>,
    /// Unified SQLite store (spec 016). When present every JSONL write is
    /// mirrored into the `decisions` table so the dashboard, `/metrics`, and
    /// the spec-024 drift harness all see the same reality as the audit log.
    /// Before this dual-write the sqlite copy was only populated by the
    /// one-shot legacy migration, which left production dashboards reading
    /// a stale table while the JSONL audit trail kept growing.
    store: Option<Arc<innerwarden_store::Store>>,
}

impl DecisionWriter {
    /// JSONL-only constructor retained for tests and any future callers that
    /// intentionally want to opt out of the sqlite mirror. Production uses
    /// [`DecisionWriter::with_store`] to keep the audit file and the
    /// `decisions` table in lockstep.
    #[allow(dead_code)]
    pub fn new(data_dir: &Path) -> Result<Self> {
        Self::with_store(data_dir, None)
    }

    /// Constructor that also takes an optional SQLite store. Production calls
    /// this with `Some(state.sqlite_store.clone())` so every decision written
    /// via `DecisionWriter::write` lands in both the JSONL audit file and
    /// the `decisions` table.
    pub fn with_store(
        data_dir: &Path,
        store: Option<Arc<innerwarden_store::Store>>,
    ) -> Result<Self> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let file = open_or_create(data_dir, &today)?;
        let last_hash = read_last_hash(data_dir, &today);
        Ok(Self {
            data_dir: data_dir.to_owned(),
            current_date: today,
            writer: BufWriter::new(file),
            last_hash,
            store,
        })
    }

    /// Append a decision to the daily JSONL.
    /// Rotates to a new file at midnight.
    /// Each entry includes a hash chain pointer to the previous entry.
    pub fn write(&mut self, entry: &DecisionEntry) -> Result<()> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        if today != self.current_date {
            self.writer.flush().ok();
            let file = open_or_create(&self.data_dir, &today)?;
            self.writer = BufWriter::new(file);
            self.current_date = today.clone();
            self.last_hash = read_last_hash(&self.data_dir, &today);
        }

        // Re-read the last hash from disk in case an external writer (e.g.
        // always-on honeypot) appended entries since our last write.
        let disk_hash = read_last_hash(&self.data_dir, &self.current_date);
        if disk_hash != self.last_hash {
            self.last_hash = disk_hash;
        }

        // Build a chained entry: set prev_hash from the last written entry.
        // Serialize immediately so the borrow of self.last_hash is released
        // before we update it with the new hash.
        let line = {
            let chained = ChainedEntry {
                ts: entry.ts,
                incident_id: &entry.incident_id,
                host: &entry.host,
                ai_provider: &entry.ai_provider,
                action_type: &entry.action_type,
                target_ip: entry.target_ip.as_deref(),
                target_user: entry.target_user.as_deref(),
                skill_id: entry.skill_id.as_deref(),
                confidence: entry.confidence,
                auto_executed: entry.auto_executed,
                dry_run: entry.dry_run,
                reason: &entry.reason,
                estimated_threat: &entry.estimated_threat,
                execution_result: &entry.execution_result,
                prev_hash: self.last_hash.as_deref(),
            };
            serde_json::to_string(&chained).context("failed to serialize decision entry")?
        };

        // Compute SHA-256 of the serialized entry for the next link in the chain
        self.last_hash = Some(sha256_hex(&line));

        writeln!(self.writer, "{line}").context("failed to write decision entry")?;
        // Flush immediately - audit trail must survive a crash between decisions
        self.writer
            .flush()
            .context("failed to flush decision entry")?;

        // Dual-write to sqlite. Failure to persist the row mirrors up as a
        // warning rather than an error: the JSONL write already succeeded
        // (that is the audit trail of record), and a sqlite hiccup must not
        // silently discard the whole decision.
        if let Some(ref store) = self.store {
            let row = innerwarden_store::decisions::DecisionRow {
                ts: entry.ts.to_rfc3339(),
                incident_id: entry.incident_id.clone(),
                action_type: entry.action_type.clone(),
                target_ip: entry.target_ip.clone(),
                target_user: entry.target_user.clone(),
                confidence: entry.confidence as f64,
                auto_executed: entry.auto_executed,
                reason: Some(entry.reason.clone()),
                data: line.clone(),
            };
            if let Err(e) = store.insert_decision(&row) {
                warn!(
                    incident_id = %entry.incident_id,
                    error = %e,
                    "decision written to JSONL but sqlite mirror failed"
                );
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) {
        if let Err(e) = self.writer.flush() {
            warn!("decision writer flush failed: {e}");
        }
    }
}

/// Internal serialization helper that borrows fields instead of cloning.
#[derive(Serialize)]
struct ChainedEntry<'a> {
    ts: DateTime<Utc>,
    incident_id: &'a str,
    host: &'a str,
    ai_provider: &'a str,
    action_type: &'a str,
    target_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_user: Option<&'a str>,
    skill_id: Option<&'a str>,
    confidence: f32,
    auto_executed: bool,
    dry_run: bool,
    reason: &'a str,
    estimated_threat: &'a str,
    execution_result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hash: Option<&'a str>,
}

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Read the last line of today's decisions file and compute its SHA-256 hash.
/// Returns None if the file doesn't exist or is empty.
fn read_last_hash(data_dir: &Path, date: &str) -> Option<String> {
    let path = data_dir.join(format!("decisions-{date}.jsonl"));
    let file = File::open(&path).ok()?;
    let reader = BufReader::new(file);
    let mut last_line: Option<String> = None;
    for l in reader.lines().map_while(Result::ok) {
        if !l.trim().is_empty() {
            last_line = Some(l);
        }
    }
    last_line.map(|l| sha256_hex(&l))
}

fn open_or_create(data_dir: &Path, date: &str) -> Result<File> {
    let path = data_dir.join(format!("decisions-{date}.jsonl"));
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))
}

/// Standalone hash-chained append for code paths that don't own a `DecisionWriter`
/// (e.g. the always-on honeypot task). Reads the last hash from the file, sets
/// `prev_hash`, writes the entry, and flushes.
pub fn append_chained(data_dir: &Path, entry: &DecisionEntry) -> Result<()> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let last_hash = read_last_hash(data_dir, &today);
    let chained = ChainedEntry {
        ts: entry.ts,
        incident_id: &entry.incident_id,
        host: &entry.host,
        ai_provider: &entry.ai_provider,
        action_type: &entry.action_type,
        target_ip: entry.target_ip.as_deref(),
        target_user: entry.target_user.as_deref(),
        skill_id: entry.skill_id.as_deref(),
        confidence: entry.confidence,
        auto_executed: entry.auto_executed,
        dry_run: entry.dry_run,
        reason: &entry.reason,
        estimated_threat: &entry.estimated_threat,
        execution_result: &entry.execution_result,
        prev_hash: last_hash.as_deref(),
    };
    let line = serde_json::to_string(&chained).context("failed to serialize decision entry")?;
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    use std::io::Write;
    writeln!(f, "{line}").context("failed to write decision entry")?;
    f.flush().context("failed to flush decision entry")
}

// ---------------------------------------------------------------------------
// Helper: build DecisionEntry from an AiDecision
// ---------------------------------------------------------------------------

pub fn build_entry(
    incident_id: &str,
    host: &str,
    ai_provider: &str,
    decision: &AiDecision,
    dry_run: bool,
    execution_result: &str,
) -> DecisionEntry {
    use crate::ai::AiAction;

    let (action_type, target_ip, target_user, skill_id) = match &decision.action {
        AiAction::BlockIp { ip, skill_id } => (
            "block_ip".to_string(),
            Some(ip.clone()),
            None,
            Some(skill_id.clone()),
        ),
        AiAction::Monitor { ip } => ("monitor".to_string(), Some(ip.clone()), None, None),
        AiAction::Honeypot { ip } => ("honeypot".to_string(), Some(ip.clone()), None, None),
        AiAction::SuspendUserSudo { user, .. } => (
            "suspend_user_sudo".to_string(),
            None,
            Some(user.clone()),
            Some("suspend-user-sudo".to_string()),
        ),
        AiAction::KillProcess { user, .. } => (
            "kill_process".to_string(),
            None,
            Some(user.clone()),
            Some("kill-process".to_string()),
        ),
        AiAction::BlockContainer { container_id, .. } => (
            "block_container".to_string(),
            Some(container_id.clone()),
            None,
            Some("block-container".to_string()),
        ),
        AiAction::RequestConfirmation { .. } => {
            ("request_confirmation".to_string(), None, None, None)
        }
        AiAction::KillChainResponse { .. } => (
            "kill_chain_response".to_string(),
            None,
            None,
            Some("kill-chain-response".to_string()),
        ),
        AiAction::Ignore { .. } => ("ignore".to_string(), None, None, None),
        AiAction::Dismiss { .. } => ("dismiss".to_string(), None, None, None),
    };

    DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.to_string(),
        host: host.to_string(),
        ai_provider: ai_provider.to_string(),
        action_type,
        target_ip,
        target_user,
        skill_id,
        confidence: decision.confidence,
        auto_executed: decision.auto_execute,
        dry_run,
        reason: decision.reason.clone(),
        estimated_threat: decision.estimated_threat.clone(),
        execution_result: execution_result.to_string(),
        prev_hash: None, // Set by DecisionWriter::write() via hash chaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::AiAction;

    #[test]
    fn test_build_entry_block_ip() {
        let decision = AiDecision {
            action: AiAction::BlockIp {
                ip: "10.0.0.1".to_string(),
                skill_id: "block-ip-xdp".to_string(),
            },
            confidence: 0.95,
            reason: "malicious".to_string(),
            auto_execute: true,
            estimated_threat: "high".to_string(),
            alternatives: vec![],
        };

        let entry = build_entry("inc-123", "host-1", "openai", &decision, false, "success");

        assert_eq!(entry.incident_id, "inc-123");
        assert_eq!(entry.action_type, "block_ip");
        assert_eq!(entry.target_ip, Some("10.0.0.1".to_string()));
        assert_eq!(entry.skill_id, Some("block-ip-xdp".to_string()));
        assert_eq!(entry.execution_result, "success");
    }

    #[test]
    fn decision_writer_dual_writes_to_jsonl_and_sqlite() {
        // Regression guard: before the spec-016 follow-up the writer only
        // wrote JSONL, leaving dashboards reading a decisions table that
        // had not been touched since the legacy migration. The dual-write
        // must land every entry in both the audit file and the sqlite
        // mirror so `/metrics` + the spec-024 drift harness see the same
        // reality as the audit trail of record.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(innerwarden_store::Store::open(dir.path()).expect("store"));
        let mut writer =
            DecisionWriter::with_store(dir.path(), Some(store.clone())).expect("writer");

        let entry = DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: "inc-dual-1".into(),
            host: "h".into(),
            ai_provider: "test".into(),
            action_type: "block_ip".into(),
            target_ip: Some("203.0.113.9".into()),
            target_user: None,
            skill_id: Some("block-ip-ufw".into()),
            confidence: 0.91,
            auto_executed: true,
            dry_run: false,
            reason: "synthetic".into(),
            estimated_threat: "high".into(),
            execution_result: "ok".into(),
            prev_hash: None,
        };
        writer.write(&entry).expect("write decision");

        // JSONL side.
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let jsonl_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let jsonl = std::fs::read_to_string(&jsonl_path).expect("jsonl exists");
        assert!(jsonl.contains("inc-dual-1"), "jsonl must carry the entry");

        // Sqlite side.
        let count = store.decisions_count().expect("count");
        assert_eq!(count, 1, "sqlite decisions table must receive one row");
    }

    #[test]
    fn decision_writer_without_store_keeps_jsonl_path_working() {
        // Back-compat: constructing without a store (tests, pre-016 deploys)
        // must not require the sqlite path to be available.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer = DecisionWriter::new(dir.path()).expect("writer");
        let entry = DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: "inc-jsonl-only".into(),
            host: "h".into(),
            ai_provider: "test".into(),
            action_type: "ignore".into(),
            target_ip: None,
            target_user: None,
            skill_id: None,
            confidence: 0.4,
            auto_executed: false,
            dry_run: true,
            reason: "low".into(),
            estimated_threat: "low".into(),
            execution_result: "skipped".into(),
            prev_hash: None,
        };
        writer.write(&entry).expect("write without store");
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let jsonl = std::fs::read_to_string(dir.path().join(format!("decisions-{today}.jsonl")))
            .expect("jsonl written");
        assert!(jsonl.contains("inc-jsonl-only"));
    }

    #[test]
    fn test_build_entry_suspend_user() {
        let decision = AiDecision {
            action: AiAction::SuspendUserSudo {
                user: "alice".to_string(),
                duration_secs: 3600,
            },
            confidence: 0.8,
            reason: "sudo fail".to_string(),
            auto_execute: true,
            estimated_threat: "medium".to_string(),
            alternatives: vec![],
        };

        let entry = build_entry("inc-456", "host-2", "anthropic", &decision, true, "dry ran");

        assert_eq!(entry.action_type, "suspend_user_sudo");
        assert_eq!(entry.target_user, Some("alice".to_string()));
        assert_eq!(entry.target_ip, None);
        assert_eq!(entry.dry_run, true);
    }

    #[test]
    fn test_build_entry_dismiss_uses_dismiss_action_type() {
        // Regression: before AiAction::Dismiss existed, classifier
        // predictions of "dismiss" were silently collapsed into "ignore"
        // in the decision record. Check the distinct action_type survives.
        let decision = AiDecision {
            action: AiAction::Dismiss {
                reason: "below noise floor".to_string(),
            },
            confidence: 0.95,
            reason: "noise-gate filter".to_string(),
            auto_execute: true,
            estimated_threat: "low".to_string(),
            alternatives: vec![],
        };

        let entry = build_entry(
            "inc-dismiss-1",
            "host",
            "local_classifier",
            &decision,
            false,
            "filed",
        );

        assert_eq!(entry.action_type, "dismiss");
        assert_eq!(entry.target_ip, None);
        assert_eq!(entry.target_user, None);
        assert_eq!(entry.skill_id, None);
    }
}
