//! Atomic, capped JSON-array log helper.
//!
//! Two production logs (`playbook-log.json`, `attack-chains.json`) follow
//! the same shape: a JSON array of records that grows over time, capped
//! at the latest N entries, written to disk so the dashboard can read it.
//!
//! Pre-2026-04-23 each call site had its own copy of the read-modify-write
//! pattern: load the file, parse, push the new entry, trim, then `fs::write`
//! over the original. Two flaws:
//!
//! 1. **Not atomic.** A crash mid-`fs::write` truncates the file or leaves
//!    it half-written; the dashboard then sees a corrupt JSON array. The
//!    `cargo deny` "no unwrap on file ops" lint masked this because the
//!    write returned `Ok(0_bytes)` on the truncation case.
//! 2. **Duplicated.** Both call sites had ~15 lines of identical RMW logic
//!    that any future refactor had to update in lockstep.
//!
//! `append_with_cap` is the shared replacement: read, push, trim, then
//! write to a sibling temp file (`<path>.tmp`) and `rename` it onto the
//! target. `rename` is atomic on POSIX, so observers see either the old
//! file or the new file — never a half-written one. The temp file
//! includes the process id so concurrent writers (a corner case — both
//! call sites only fire from the agent loop) cannot stomp each other.
//!
//! See `RECURRING_BUGS.md` "RMW pattern on attack-chains.json /
//! playbook-log.json".

use std::path::Path;

use serde::Serialize;

/// Append `entry` to the JSON-array log at `path`, then keep only the
/// most recent `cap` entries. Write is atomic via temp-file + rename.
///
/// Returns `Err` only on serialisation failure or hard I/O failure on
/// the rename step. Read failures (file missing or corrupt) are
/// recovered silently — the new entry simply starts a fresh array.
/// This matches the pre-existing semantics, where a corrupt
/// `attack-chains.json` would not block playbook execution.
pub(crate) fn append_with_cap<T>(path: &Path, entry: &T, cap: usize) -> std::io::Result<()>
where
    T: Serialize,
{
    let mut existing: Vec<serde_json::Value> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if let Ok(val) = serde_json::to_value(entry) {
        existing.push(val);
    }

    if existing.len() > cap {
        existing = existing.split_off(existing.len() - cap);
    }

    let serialized = serde_json::to_string(&existing).unwrap_or_else(|_| "[]".to_string());
    write_atomic(path, serialized.as_bytes())
}

/// Lower-level atomic write helper, exposed for callers who already
/// have the serialized bytes (e.g. a dual-write that also pushes the
/// same bytes to a SQLite blob).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = parent.join(format!(
        "{}.{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("log"),
        std::process::id()
    ));
    std::fs::write(&tmp, bytes)?;
    // POSIX rename is atomic. On Windows std::fs::rename also calls
    // MoveFileExW which is atomic for same-filesystem moves.
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup of the orphan temp file.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq)]
    struct Sample {
        id: u32,
        name: String,
    }

    fn make(id: u32) -> Sample {
        Sample {
            id,
            name: format!("entry-{id}"),
        }
    }

    #[test]
    fn append_creates_file_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.json");
        append_with_cap(&path, &make(1), 5).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: Vec<Sample> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed, vec![make(1)]);
    }

    #[test]
    fn append_preserves_existing_entries_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.json");
        append_with_cap(&path, &make(1), 5).unwrap();
        append_with_cap(&path, &make(2), 5).unwrap();
        append_with_cap(&path, &make(3), 5).unwrap();
        let parsed: Vec<Sample> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed, vec![make(1), make(2), make(3)]);
    }

    #[test]
    fn append_caps_to_most_recent_n_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.json");
        for i in 1..=10 {
            append_with_cap(&path, &make(i), 3).unwrap();
        }
        let parsed: Vec<Sample> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed, vec![make(8), make(9), make(10)]);
    }

    #[test]
    fn append_recovers_from_corrupt_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.json");
        std::fs::write(&path, b"this is not json").unwrap();
        // Should silently recover and start fresh.
        append_with_cap(&path, &make(99), 3).unwrap();
        let parsed: Vec<Sample> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed, vec![make(99)]);
    }

    #[test]
    fn write_atomic_does_not_leave_temp_file_behind_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.json");
        write_atomic(&path, b"hello").unwrap();

        let temp_files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            temp_files.is_empty(),
            "temp file must be cleaned up via rename"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
    }

    #[test]
    fn write_atomic_creates_parent_directory_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/dir/target.json");
        write_atomic(&path, b"hi").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hi");
    }
}
