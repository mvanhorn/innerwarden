use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use chrono::{Local, NaiveDate};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use tracing::{debug, warn};

use crate::config::DataRetentionConfig;

/// File patterns that `data_retention::cleanup` and the warm-tier
/// gzip sweep know about. Tuple: (prefix, suffix). Order matters
/// only for `cleanup`'s "first match wins" branch and for the gzip
/// sweep (same prefixes reappear).
fn warm_jsonl_patterns() -> &'static [(&'static str, &'static str)] {
    &[
        ("events-", ".jsonl"),
        ("incidents-", ".jsonl"),
        ("decisions-", ".jsonl"),
        ("telemetry-", ".jsonl"),
        ("admin-actions-", ".jsonl"),
        ("agent-guard-events-", ".jsonl"),
    ]
}

/// Remove old data files from `data_dir` according to retention config.
///
/// Runs on agent startup and in the slow loop (once per day).
/// Never removes today's files regardless of keep_days.
/// Returns number of files deleted.
pub fn cleanup(data_dir: &Path, cfg: &DataRetentionConfig) -> usize {
    let today = Local::now().date_naive();

    // (prefix, suffix, keep_days)
    // Spec 030: include `graph-snapshot-` so daily knowledge-graph
    // snapshots do not accumulate at ~40 MB/day. `.jsonl.gz` variants
    // of warm-tier files are pruned alongside the raw `.jsonl`.
    let patterns: &[(&str, &str, usize)] = &[
        ("events-", ".jsonl", cfg.events_keep_days),
        ("events-", ".jsonl.gz", cfg.events_keep_days),
        ("incidents-", ".jsonl", cfg.incidents_keep_days),
        ("incidents-", ".jsonl.gz", cfg.incidents_keep_days),
        ("decisions-", ".jsonl", cfg.decisions_keep_days),
        ("decisions-", ".jsonl.gz", cfg.decisions_keep_days),
        ("telemetry-", ".jsonl", cfg.telemetry_keep_days),
        ("telemetry-", ".jsonl.gz", cfg.telemetry_keep_days),
        ("admin-actions-", ".jsonl", cfg.decisions_keep_days),
        ("admin-actions-", ".jsonl.gz", cfg.decisions_keep_days),
        ("agent-guard-events-", ".jsonl", cfg.decisions_keep_days),
        ("agent-guard-events-", ".jsonl.gz", cfg.decisions_keep_days),
        ("trial-report-", ".json", cfg.reports_keep_days),
        ("trial-report-", ".md", cfg.reports_keep_days),
        ("summary-", ".md", cfg.reports_keep_days),
        ("graph-snapshot-", ".json", cfg.graph_snapshot_keep_days),
    ];

    // Monthly files: prefix-YYYY-MM.ext (different date format)
    let monthly_patterns: &[(&str, &str, usize)] = &[
        ("monthly-report-", ".json", cfg.reports_keep_days),
        ("monthly-report-", ".md", cfg.reports_keep_days),
    ];

    let entries = match fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("data_retention: failed to read data_dir: {e:#}");
            return 0;
        }
    };

    let mut removed = 0usize;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        for (prefix, suffix, keep_days) in patterns {
            let Some(mid) = name
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(*suffix))
            else {
                continue;
            };
            let Ok(file_date) = NaiveDate::parse_from_str(mid, "%Y-%m-%d") else {
                continue;
            };
            let age_days = (today - file_date).num_days();
            if age_days <= 0 || age_days <= *keep_days as i64 {
                break; // within retention window
            }
            let path = entry.path();
            match fs::remove_file(&path) {
                Ok(()) => {
                    debug!(
                        path = %path.display(),
                        age_days,
                        keep_days,
                        "data_retention: removed old file"
                    );
                    removed += 1;
                }
                Err(e) => {
                    warn!(path = %path.display(), "data_retention: failed to remove: {e:#}");
                }
            }
            break; // matched this pattern, no need to check other patterns for same file
        }
    }

    // Monthly file cleanup: monthly-report-YYYY-MM.{json,md}
    if let Ok(entries) = fs::read_dir(data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();

            for (prefix, suffix, keep_days) in monthly_patterns {
                let Some(mid) = name
                    .strip_prefix(prefix)
                    .and_then(|s| s.strip_suffix(*suffix))
                else {
                    continue;
                };
                // Parse YYYY-MM format: treat as 1st of that month
                let Ok(file_date) = NaiveDate::parse_from_str(&format!("{mid}-01"), "%Y-%m-%d")
                else {
                    continue;
                };
                let age_days = (today - file_date).num_days();
                if age_days <= 0 || age_days <= *keep_days as i64 {
                    break;
                }
                let path = entry.path();
                match fs::remove_file(&path) {
                    Ok(()) => {
                        debug!(
                            path = %path.display(),
                            age_days,
                            keep_days,
                            "data_retention: removed old monthly file"
                        );
                        removed += 1;
                    }
                    Err(e) => {
                        warn!(path = %path.display(), "data_retention: failed to remove: {e:#}");
                    }
                }
                break;
            }
        }
    }

    removed
}

/// Spec 030: compress warm-tier JSONL files older than
/// `cfg.warm_gzip_days` with gzip. The original file is replaced by
/// a `.jsonl.gz` sibling, then removed. Today's file is never
/// compressed (writers may still be appending). Already-compressed
/// files are skipped.
///
/// Returns `(compressed_count, bytes_saved)`.
pub fn gzip_warm_jsonl(data_dir: &Path, cfg: &DataRetentionConfig) -> (usize, i64) {
    if cfg.warm_gzip_days == 0 {
        return (0, 0);
    }
    let today = Local::now().date_naive();
    let mut compressed = 0usize;
    let mut saved: i64 = 0;

    let entries = match fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("data_retention: failed to read data_dir for gzip sweep: {e:#}");
            return (0, 0);
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();

        let Some((prefix, suffix)) = warm_jsonl_patterns()
            .iter()
            .find(|(p, s)| name.starts_with(p) && name.ends_with(s))
        else {
            continue;
        };

        let Some(mid) = name
            .strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(suffix))
        else {
            continue;
        };
        let Ok(file_date) = NaiveDate::parse_from_str(mid, "%Y-%m-%d") else {
            continue;
        };
        let age_days = (today - file_date).num_days();
        if age_days < cfg.warm_gzip_days as i64 {
            continue;
        }
        let src = entry.path();
        let gz_path = src.with_extension("jsonl.gz");
        if gz_path.exists() {
            // Already compressed from a previous sweep; remove the
            // stale raw copy defensively in case it lingered.
            if let Err(e) = fs::remove_file(&src) {
                warn!(
                    path = %src.display(),
                    "data_retention: failed to remove stale raw file: {e:#}"
                );
            }
            continue;
        }
        match gzip_file_atomic(&src, &gz_path) {
            Ok((before, after)) => {
                saved += before as i64 - after as i64;
                compressed += 1;
                debug!(
                    path = %src.display(),
                    before, after,
                    ratio = format!("{:.2}", after as f64 / before as f64),
                    "data_retention: compressed warm-tier file"
                );
                if let Err(e) = fs::remove_file(&src) {
                    warn!(
                        path = %src.display(),
                        "data_retention: compressed but failed to remove original: {e:#}"
                    );
                }
            }
            Err(e) => {
                warn!(
                    path = %src.display(),
                    "data_retention: gzip failed, leaving raw file in place: {e:#}"
                );
                // Best-effort cleanup of the partial `.gz` so the next
                // sweep retries from a clean slate.
                let _ = fs::remove_file(&gz_path);
            }
        }
    }

    (compressed, saved)
}

/// Compress `src` to `dst` with gzip (default level 6 — matches
/// `gzip -6` which is the best tradeoff between CPU and ratio for
/// JSONL logs). Writes to a temp file next to `dst` and atomically
/// renames into place so a crash mid-compress does not leave a
/// truncated `.gz`.
fn gzip_file_atomic(src: &Path, dst: &Path) -> io::Result<(u64, u64)> {
    let before = fs::metadata(src)?.len();
    let dir = dst.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "gzip destination has no parent",
        )
    })?;
    let tmp = tempfile::Builder::new()
        .prefix(".data_retention-")
        .suffix(".gz.tmp")
        .tempfile_in(dir)?;
    {
        let mut src_f = BufReader::new(fs::File::open(src)?);
        let mut enc = GzEncoder::new(BufWriter::new(tmp.as_file()), Compression::default());
        io::copy(&mut src_f, &mut enc)?;
        let mut writer = enc.finish()?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    let (_file, tmp_path) = tmp.keep().map_err(|e| e.error)?;
    fs::rename(&tmp_path, dst)?;
    let after = fs::metadata(dst)?.len();
    Ok((before, after))
}

/// Spec 030: open a JSONL file regardless of whether it is raw or
/// gzipped. Tries `path` first (the common case: today's files are
/// uncompressed). Falls back to `path.with_extension("jsonl.gz")` if
/// the raw file is missing. Returns `None` when neither exists.
///
/// Callers iterate the returned reader with `BufRead::read_line`. The
/// trait object erases the decoder choice so downstream code does
/// not branch on file extension.
///
/// Used by downstream reader modules (reader.rs, future dashboard
/// warm-tier fallback). `#[allow(dead_code)]` scopes the warning to
/// the current release window - wiring into `reader::read_new_entries`
/// is a separate PR because that path uses byte offsets which gzip
/// streams do not support.
#[allow(dead_code)]
pub fn open_jsonl_or_gz(path: &Path) -> io::Result<Option<Box<dyn BufRead>>> {
    if path.exists() {
        let f = fs::File::open(path)?;
        return Ok(Some(Box::new(BufReader::new(f))));
    }
    let gz_path: PathBuf = if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e == "jsonl")
        .unwrap_or(false)
    {
        path.with_extension("jsonl.gz")
    } else {
        let mut p = path.as_os_str().to_os_string();
        p.push(".gz");
        PathBuf::from(p)
    };
    if gz_path.exists() {
        let f = fs::File::open(&gz_path)?;
        let reader: Box<dyn Read> = Box::new(GzDecoder::new(f));
        return Ok(Some(Box::new(BufReader::new(reader))));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DataRetentionConfig;
    use chrono::Duration;
    use std::fs::File;
    use std::io::Write;

    fn write_dated_file(dir: &Path, prefix: &str, suffix: &str, date: NaiveDate) {
        let name = format!("{prefix}{}{suffix}", date.format("%Y-%m-%d"));
        let mut f = File::create(dir.join(name)).unwrap();
        writeln!(f, "test").unwrap();
    }

    #[test]
    fn removes_files_beyond_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();

        // events: keep 7 days - write one 8 days old (should be removed)
        let old = today - Duration::days(8);
        write_dated_file(tmp.path(), "events-", ".jsonl", old);

        // events: write one 6 days old (should be kept)
        let recent = today - Duration::days(6);
        write_dated_file(tmp.path(), "events-", ".jsonl", recent);

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 1, "only the 8-day-old file should be removed");
        assert!(!tmp
            .path()
            .join(format!("events-{}.jsonl", old.format("%Y-%m-%d")))
            .exists());
        assert!(tmp
            .path()
            .join(format!("events-{}.jsonl", recent.format("%Y-%m-%d")))
            .exists());
    }

    #[test]
    fn respects_decisions_longer_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();

        // decisions: default keep 90 days - write one 60 days old (should be kept)
        let recent = today - Duration::days(60);
        write_dated_file(tmp.path(), "decisions-", ".jsonl", recent);

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 0);
        assert!(tmp
            .path()
            .join(format!("decisions-{}.jsonl", recent.format("%Y-%m-%d")))
            .exists());
    }

    #[test]
    fn never_removes_todays_files() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        write_dated_file(tmp.path(), "events-", ".jsonl", today);

        let cfg = DataRetentionConfig {
            events_keep_days: 0, // even with keep=0, today must survive
            ..Default::default()
        };

        let removed = cleanup(tmp.path(), &cfg);
        assert_eq!(removed, 0);
    }

    // ── Spec 030: graph-snapshot file pruning ────────────────────────

    #[test]
    fn removes_old_graph_snapshot_files() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();

        // default: keep 3 days. Write files at 0, 2, 4, 6 days old.
        for d in [0, 2, 4, 6] {
            write_dated_file(
                tmp.path(),
                "graph-snapshot-",
                ".json",
                today - Duration::days(d),
            );
        }

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 2, "files at 4 and 6 days old should be removed");
        assert!(tmp
            .path()
            .join(format!("graph-snapshot-{}.json", today.format("%Y-%m-%d")))
            .exists());
        assert!(tmp
            .path()
            .join(format!(
                "graph-snapshot-{}.json",
                (today - Duration::days(2)).format("%Y-%m-%d")
            ))
            .exists());
    }

    // ── Spec 030: gzip compression + transparent read ────────────────

    fn write_dated_file_with_content(
        dir: &Path,
        prefix: &str,
        suffix: &str,
        date: NaiveDate,
        content: &str,
    ) {
        let name = format!("{prefix}{}{suffix}", date.format("%Y-%m-%d"));
        let mut f = File::create(dir.join(name)).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn gzip_sweep_compresses_old_jsonl_and_removes_raw() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old_date = today - Duration::days(10);

        let content = "line-1\nline-2\nline-3\n".repeat(100); // compressible
        write_dated_file_with_content(tmp.path(), "events-", ".jsonl", old_date, &content);

        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, saved) = gzip_warm_jsonl(tmp.path(), &cfg);

        assert_eq!(compressed, 1);
        assert!(saved > 0, "gzip should reduce size");

        let raw = tmp
            .path()
            .join(format!("events-{}.jsonl", old_date.format("%Y-%m-%d")));
        let gz = tmp
            .path()
            .join(format!("events-{}.jsonl.gz", old_date.format("%Y-%m-%d")));
        assert!(!raw.exists(), "raw file must be removed after compress");
        assert!(gz.exists(), "gz file must exist");
    }

    #[test]
    fn gzip_sweep_leaves_recent_jsonl_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let recent = today - Duration::days(2);

        write_dated_file_with_content(tmp.path(), "events-", ".jsonl", recent, "line\n");

        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);

        assert_eq!(compressed, 0, "recent file must not be compressed");
        assert!(tmp
            .path()
            .join(format!("events-{}.jsonl", recent.format("%Y-%m-%d")))
            .exists());
    }

    #[test]
    fn gzip_sweep_disabled_when_warm_gzip_days_is_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        write_dated_file_with_content(
            tmp.path(),
            "events-",
            ".jsonl",
            today - Duration::days(30),
            "line\n",
        );
        let cfg = DataRetentionConfig {
            warm_gzip_days: 0,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);
        assert_eq!(compressed, 0);
    }

    #[test]
    fn open_jsonl_or_gz_reads_raw_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events-2026-04-01.jsonl");
        let mut f = File::create(&path).unwrap();
        writeln!(f, "raw-line-1").unwrap();
        writeln!(f, "raw-line-2").unwrap();
        drop(f);

        let reader = open_jsonl_or_gz(&path)
            .unwrap()
            .expect("reader must be Some");
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();
        assert_eq!(lines, vec!["raw-line-1", "raw-line-2"]);
    }

    #[test]
    fn open_jsonl_or_gz_falls_back_to_gz() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old_date = today - Duration::days(10);
        let raw_path = tmp
            .path()
            .join(format!("events-{}.jsonl", old_date.format("%Y-%m-%d")));
        let mut f = File::create(&raw_path).unwrap();
        writeln!(f, "gz-line-a").unwrap();
        writeln!(f, "gz-line-b").unwrap();
        drop(f);

        // Run the sweep to produce the .gz and delete the raw.
        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);
        assert_eq!(compressed, 1);
        assert!(!raw_path.exists());

        // open_jsonl_or_gz is passed the raw path; it must transparently
        // fall back to the `.gz` sibling and decompress on the fly.
        let reader = open_jsonl_or_gz(&raw_path)
            .unwrap()
            .expect("reader must be Some");
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();
        assert_eq!(lines, vec!["gz-line-a", "gz-line-b"]);
    }

    #[test]
    fn open_jsonl_or_gz_returns_none_when_neither_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events-2026-04-01.jsonl");
        assert!(open_jsonl_or_gz(&path).unwrap().is_none());
    }

    #[test]
    fn gzip_sweep_cleans_up_stale_raw_when_gz_already_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old_date = today - Duration::days(10);

        // Simulate a mid-flight interruption: both raw and gz exist.
        write_dated_file_with_content(tmp.path(), "events-", ".jsonl", old_date, "line\n");
        let gz_path = tmp
            .path()
            .join(format!("events-{}.jsonl.gz", old_date.format("%Y-%m-%d")));
        let mut gz = File::create(&gz_path).unwrap();
        gz.write_all(b"existing-gz").unwrap();
        drop(gz);

        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);

        // No new compression happened; the stale raw was cleaned up.
        assert_eq!(compressed, 0);
        assert!(!tmp
            .path()
            .join(format!("events-{}.jsonl", old_date.format("%Y-%m-%d")))
            .exists());
        assert!(gz_path.exists());
    }

    #[test]
    fn cleanup_prunes_both_raw_and_gz_past_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old = today - Duration::days(40); // past default events_keep_days=7

        write_dated_file(tmp.path(), "events-", ".jsonl", old);
        write_dated_file(tmp.path(), "events-", ".jsonl.gz", old);

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 2, "both raw and gz should be pruned together");
    }
}
