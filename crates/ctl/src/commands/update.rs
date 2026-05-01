use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use crate::{load_env_file, systemd, Cli};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceAction {
    Restart,
    Start,
    Skip,
}

fn release_date_suffix(release_date: Option<&str>) -> String {
    release_date.map(|d| format!("  [{d}]")).unwrap_or_default()
}

fn release_date_display(release_date: Option<&str>) -> String {
    release_date.map(|d| format!(" ({d})")).unwrap_or_default()
}

fn telegram_notification_ready(bot_token: &str, chat_id: &str) -> bool {
    !bot_token.is_empty() && !chat_id.is_empty()
}

fn changelog_snippet(body: Option<&str>, max_chars: usize) -> String {
    body.unwrap_or("")
        .chars()
        .take(max_chars)
        .collect::<String>()
}

fn render_upgrade_notification(
    latest: &str,
    current: &str,
    date_suffix: &str,
    changelog: &str,
) -> String {
    format!(
        "🆕 <b>Inner Warden {latest} available</b>\n\n\
         Current: {current}\n\
         New: {latest}{date_suffix}\n\n\
         {changelog}\n\n\
         Upgrade: <code>innerwarden upgrade --yes</code>"
    )
}

fn confirmation_accepted(answer: &str) -> bool {
    let normalized = answer.trim().to_lowercase();
    normalized.is_empty() || normalized == "y" || normalized == "yes"
}

fn classify_service_action(is_active: bool, unit_exists: bool) -> ServiceAction {
    if is_active {
        ServiceAction::Restart
    } else if unit_exists {
        ServiceAction::Start
    } else {
        ServiceAction::Skip
    }
}

pub(crate) fn cmd_upgrade(
    cli: &Cli,
    check_only: bool,
    yes: bool,
    notify: bool,
    install_dir: &Path,
) -> Result<()> {
    use crate::upgrade::*;

    println!("Checking for updates...");

    let release =
        fetch_latest_release().context("could not reach GitHub - check network and try again")?;

    cmd_upgrade_with_release(cli, check_only, yes, notify, install_dir, release)
}

fn cmd_upgrade_with_release(
    cli: &Cli,
    check_only: bool,
    yes: bool,
    notify: bool,
    install_dir: &Path,
    release: crate::upgrade::GithubRelease,
) -> Result<()> {
    use crate::upgrade::*;

    let current = CURRENT_VERSION;
    let latest = strip_v(&release.tag_name);

    let date_suffix = release_date_suffix(release.release_date());

    println!("  Current version:  {current}");

    if !is_newer(current, &release.tag_name) {
        println!("  Latest release:   {latest}{date_suffix} - already up to date.");
        return Ok(());
    }

    println!(
        "  Latest release:   {latest}{date_suffix}  ({})",
        release.html_url
    );

    // --notify: send Telegram alert about available update (for cron use)
    if notify {
        let env_file = cli
            .agent_config
            .parent()
            .map(|p| p.join("agent.env"))
            .unwrap_or_else(|| std::path::PathBuf::from("/etc/innerwarden/agent.env"));
        let env_vars = load_env_file(&env_file);
        let bot_token = env_vars
            .get("TELEGRAM_BOT_TOKEN")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_BOT_TOKEN").ok())
            .unwrap_or_default();
        let chat_id = env_vars
            .get("TELEGRAM_CHAT_ID")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_CHAT_ID").ok())
            .unwrap_or_default();
        if telegram_notification_ready(&bot_token, &chat_id) {
            // Extract changelog from release body
            let changelog = changelog_snippet(release.body.as_deref(), 500);
            let text = render_upgrade_notification(latest, current, &date_suffix, &changelog);
            let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
            let _ = ureq::post(&url).send_json(serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            }));
            println!("  Telegram notification sent.");
        } else {
            println!("  --notify: Telegram not configured, skipping notification.");
        }
    }

    if check_only {
        println!("\nRun 'innerwarden upgrade' to install.");
        return Ok(());
    }

    // Auto-backup configs before upgrade
    let config_dir = cli
        .agent_config
        .parent()
        .unwrap_or(Path::new("/etc/innerwarden"));
    if config_dir.exists() {
        match tempfile::Builder::new()
            .prefix("innerwarden-backup-pre-upgrade-")
            .suffix(".tar.gz")
            .tempfile()
        {
            Ok(tmp) => {
                let backup_path = tmp.path().to_string_lossy().to_string();
                print!("  Backing up configs to {backup_path}... ");
                match std::process::Command::new("tar")
                    .args(["czf", &backup_path, "-C", "/"])
                    .arg(config_dir.strip_prefix("/").unwrap_or(config_dir))
                    .output()
                {
                    Ok(out) if out.status.success() => {
                        // Keep the backup file (prevent cleanup on drop)
                        let _ = tmp.keep();
                        println!("done");
                    }
                    _ => println!("skipped (tar failed, continuing anyway)"),
                }
            }
            Err(_) => {
                println!("  Skipping backup (could not create temp file)");
            }
        }
    }

    // Detect architecture
    let arch = detect_arch().ok_or_else(|| {
        anyhow::anyhow!(
            "unsupported CPU architecture '{}' - build from source for your platform",
            std::env::consts::ARCH
        )
    })?;

    // Build download plan
    let plan = build_plan(&release, arch);

    if plan.is_empty() {
        anyhow::bail!(
            "no assets found for linux-{arch} in release {} - \
             check {} for manual download",
            release.tag_name,
            release.html_url
        );
    }

    println!("\nAssets available for linux-{arch}:");
    for dp in &plan {
        let sha_status = if dp.sha256_asset.is_some() {
            "sha256 ✓"
        } else {
            "no sha256"
        };
        let sig_status = if dp.sig_asset.is_some() {
            "  sig ✓"
        } else {
            ""
        };
        println!(
            "  {:<28} {}  ({}{})",
            dp.target.binary,
            fmt_bytes(dp.asset.size),
            sha_status,
            sig_status
        );
    }

    let dest_paths: Vec<_> = plan
        .iter()
        .flat_map(|dp| install_paths(dp.target, install_dir))
        .collect();

    println!("\nWill install to {}:", install_dir.display());
    for p in &dest_paths {
        println!("  {}", p.display());
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nProceed? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !confirmation_accepted(&input) {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;

    for dp in &plan {
        let binary = dp.target.binary;
        print!("  Downloading {binary}... ");
        std::io::stdout().flush()?;

        let tmp_path = tmp_dir.path().join(binary);
        let bytes = download(&dp.asset.browser_download_url, &tmp_path)?;

        // Verify SHA-256 if sidecar is present
        if let Some(sha_asset) = dp.sha256_asset {
            let expected = fetch_expected_hash(&sha_asset.browser_download_url)?;
            let actual = sha256_file(&tmp_path)?;
            if actual != expected {
                anyhow::bail!(
                    "SHA-256 mismatch for {binary}:\n  expected {expected}\n  got      {actual}"
                );
            }
            print!("{}  sha256 ok", fmt_bytes(bytes));
        } else {
            print!("{}  (no sha256 sidecar)", fmt_bytes(bytes));
        }

        // Verify Ed25519 signature if .sig sidecar is present
        if let Some(sig_asset) = dp.sig_asset {
            let sig_b64 = fetch_signature(&sig_asset.browser_download_url)?;
            let binary_bytes =
                std::fs::read(&tmp_path).context("cannot read downloaded binary for sig check")?;
            verify_signature(&binary_bytes, &sig_b64)?;
            println!("  sig ok");
        } else {
            println!();
            println!("  [warn] unsigned release - signature verification skipped for {binary}");
        }

        // Install to all target names
        for dest in install_paths(dp.target, install_dir) {
            install_binary(&tmp_path, &dest, false)?;
            println!("  [done] {} → {}", binary, dest.display());
        }
    }

    // Fix permissions on existing config files - files written before v0.1.9 may
    // be root:root 600, which prevents innerwarden-agent (User=innerwarden) from
    // reading them. chmod 640 + chgrp innerwarden is fail-silent.
    fix_config_dir_permissions(
        cli.agent_config
            .parent()
            .unwrap_or(std::path::Path::new("/etc/innerwarden")),
    );

    // Restart running services; also start the agent if it has a unit file but is stopped
    println!();
    for unit in &["innerwarden-sensor", "innerwarden-agent"] {
        let unit_path = format!("/etc/systemd/system/{unit}.service");
        let unit_exists = std::path::Path::new(&unit_path).exists();
        match classify_service_action(systemd::is_service_active(unit), unit_exists) {
            ServiceAction::Restart => {
                systemd::restart_service(unit, false)?;
                println!("  [done] Restarted {unit}");
            }
            ServiceAction::Start => {
                // Unit is installed but stopped - try to start it
                match systemd::restart_service(unit, false) {
                    Ok(()) => println!("  [done] Started {unit}"),
                    Err(e) => {
                        println!("  [warn] Could not start {unit}: {e}");
                        println!("         Check logs: journalctl -u {unit} -n 30");
                    }
                }
            }
            ServiceAction::Skip => {}
        }
    }

    let date_display = release_date_display(release.release_date());

    println!(
        "\nInnerWarden upgraded to {}{} successfully.",
        release.tag_name, date_display
    );

    // Show what's new in this release
    if let Some(preview) = release.changelog_preview() {
        println!("\nWhat's new in {}:", release.tag_name);
        println!("─────────────────────────────────────────────────");
        for line in preview.lines() {
            println!("  {line}");
        }
        println!("─────────────────────────────────────────────────");
        println!("  Full release notes: {}", release.html_url);
    } else {
        println!("  Release notes: {}", release.html_url);
    }

    Ok(())
}

/// Fix permissions on all config files in the innerwarden config directory.
/// chmod 640 + chgrp innerwarden so the service user (User=innerwarden) can read them.
/// Fail-silent - best-effort in environments where the group doesn't exist.
fn fix_config_dir_permissions(config_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(entries) = std::fs::read_dir(config_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640));
            let _ = std::process::Command::new("chgrp")
                .arg("innerwarden")
                .arg(&path)
                .output();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upgrade::{detect_arch, GithubAsset, GithubRelease, CURRENT_VERSION};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use tempfile::TempDir;

    fn test_cli(dir: &TempDir, dry_run: bool) -> Cli {
        let agent_path = dir.path().join("agent.toml");
        std::fs::write(&agent_path, "").unwrap();
        Cli {
            sensor_config: dir.path().join("config.toml"),
            agent_config: agent_path,
            data_dir: dir.path().to_path_buf(),
            dry_run,
            command: None,
        }
    }

    fn release(tag_name: &str, assets: Vec<GithubAsset>) -> GithubRelease {
        GithubRelease {
            tag_name: tag_name.to_string(),
            html_url: "https://github.com/InnerWarden/innerwarden/releases/tag/test".to_string(),
            assets,
            published_at: Some("2026-04-17T12:34:56Z".to_string()),
            body: Some("release notes".to_string()),
        }
    }

    fn asset(name: impl Into<String>, size: u64) -> GithubAsset {
        let name = name.into();
        GithubAsset {
            browser_download_url: format!("https://example.com/{name}"),
            name,
            size,
        }
    }

    fn asset_with_url(name: impl Into<String>, url: String, size: u64) -> GithubAsset {
        GithubAsset {
            name: name.into(),
            browser_download_url: url,
            size,
        }
    }

    fn local_http_server(responses: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for body in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 1024];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        format!("http://{addr}")
    }

    fn matching_assets_with_sidecars(arch: &str) -> Vec<GithubAsset> {
        let mut assets = Vec::new();
        for binary in ["innerwarden-sensor", "innerwarden-agent", "innerwarden-ctl"] {
            let base = format!("{binary}-linux-{arch}");
            assets.push(asset(&base, 10_000));
            assets.push(asset(format!("{base}.sha256"), 65));
            assets.push(asset(format!("{base}.sig"), 88));
        }
        assets
    }

    fn matching_assets_without_sidecars(arch: &str) -> Vec<GithubAsset> {
        ["innerwarden-sensor", "innerwarden-agent", "innerwarden-ctl"]
            .into_iter()
            .map(|binary| asset(format!("{binary}-linux-{arch}"), 10_000))
            .collect()
    }

    fn write_release_fixture(dir: &TempDir, tag_name: &str) -> std::path::PathBuf {
        let path = dir.path().join("latest-release.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "tag_name": tag_name,
                "html_url": "https://github.com/InnerWarden/innerwarden/releases/tag/test",
                "assets": [],
                "published_at": "2026-04-17T12:34:56Z",
                "body": "release notes"
            })
            .to_string(),
        )
        .unwrap();
        path
    }

    fn with_latest_release_fixture<T>(path: &Path, f: impl FnOnce() -> T) -> T {
        static RELEASE_FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = RELEASE_FIXTURE_LOCK.lock().unwrap();
        let prior = std::env::var_os("INNERWARDEN_TEST_LATEST_RELEASE_JSON");
        std::env::set_var("INNERWARDEN_TEST_LATEST_RELEASE_JSON", path);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        match prior {
            Some(value) => std::env::set_var("INNERWARDEN_TEST_LATEST_RELEASE_JSON", value),
            None => std::env::remove_var("INNERWARDEN_TEST_LATEST_RELEASE_JSON"),
        }
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn release_date_formatters_render_expected_shapes() {
        // Ensures release date decorations remain stable for summary and success output lines.
        assert_eq!(release_date_suffix(Some("2026-04-17")), "  [2026-04-17]");
        assert_eq!(release_date_display(Some("2026-04-17")), " (2026-04-17)");
        assert_eq!(release_date_suffix(None), "");
        assert_eq!(release_date_display(None), "");
    }

    #[test]
    fn telegram_notification_ready_requires_both_values() {
        // Covers notify precondition gating so partial credentials do not trigger outbound requests.
        assert!(telegram_notification_ready("token", "chat"));
        assert!(!telegram_notification_ready("", "chat"));
        assert!(!telegram_notification_ready("token", ""));
    }

    #[test]
    fn changelog_snippet_truncates_to_limit() {
        // Verifies changelog extraction keeps deterministic maximum length for Telegram notifications.
        let body = "abcdef";
        assert_eq!(changelog_snippet(Some(body), 3), "abc");
        assert_eq!(changelog_snippet(Some(body), 10), "abcdef");
    }

    #[test]
    fn changelog_snippet_handles_missing_body() {
        // Protects optional-release-body path used when GitHub release notes are empty.
        assert_eq!(changelog_snippet(None, 500), "");
    }

    #[test]
    fn render_upgrade_notification_includes_core_fields() {
        // Ensures notification text preserves key fields and upgrade command guidance.
        let text = render_upgrade_notification("0.12.0", "0.11.0", "  [2026-04-17]", "notes");
        assert!(text.contains("Inner Warden 0.12.0 available"));
        assert!(text.contains("Current: 0.11.0"));
        assert!(text.contains("New: 0.12.0  [2026-04-17]"));
        assert!(text.contains("innerwarden upgrade --yes"));
    }

    #[test]
    fn confirmation_accepted_matches_cli_prompt_behavior() {
        // Guards confirmation parser so Enter/y/yes continue and other values abort.
        assert!(confirmation_accepted(""));
        assert!(confirmation_accepted("y"));
        assert!(confirmation_accepted("YES"));
        assert!(!confirmation_accepted("n"));
        assert!(!confirmation_accepted("later"));
    }

    #[test]
    fn classify_service_action_covers_all_runtime_states() {
        // Ensures restart loop keeps the same branch decisions for active, installed, and missing units.
        assert_eq!(classify_service_action(true, true), ServiceAction::Restart);
        assert_eq!(classify_service_action(false, true), ServiceAction::Start);
        assert_eq!(classify_service_action(false, false), ServiceAction::Skip);
    }

    #[test]
    fn cmd_upgrade_fetches_release_and_delegates_to_upgrade_flow() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);
        let fixture = write_release_fixture(&dir, &format!("v{CURRENT_VERSION}"));

        with_latest_release_fixture(&fixture, || {
            cmd_upgrade(&cli, false, true, false, dir.path()).unwrap();
        });
    }

    #[test]
    fn cmd_upgrade_with_release_returns_ok_when_already_current() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release(CURRENT_VERSION, Vec::new()),
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_check_only_skips_asset_validation() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_upgrade_with_release(
            &cli,
            true,
            true,
            false,
            dir.path(),
            release("v999.0.0", Vec::new()),
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_notify_without_credentials_skips_send() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);
        let env_file = cli.agent_config.parent().unwrap().join("agent.env");
        std::fs::write(
            &env_file,
            "TELEGRAM_BOT_TOKEN=\"\"\nTELEGRAM_CHAT_ID=\"\"\n",
        )
        .unwrap();

        cmd_upgrade_with_release(
            &cli,
            true,
            true,
            true,
            dir.path(),
            release("v999.0.0", Vec::new()),
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_errors_when_no_matching_assets_exist() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);
        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", vec![asset("innerwarden-ctl-linux-riscv64", 10)]),
        )
        .unwrap_err();

        assert!(err.to_string().contains("no assets found"));
    }

    #[test]
    fn cmd_upgrade_with_release_dry_run_renders_assets_with_sidecars() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", matching_assets_with_sidecars(arch)),
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_dry_run_allows_assets_without_sidecars() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", matching_assets_without_sidecars(arch)),
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_rejects_checksum_mismatch_before_install() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);
        let base_url = local_http_server(vec![
            "downloaded-binary".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ]);
        let binary_name = format!("innerwarden-ctl-linux-{arch}");
        let assets = vec![
            asset_with_url(&binary_name, format!("{base_url}/bin"), 17),
            asset_with_url(
                format!("{binary_name}.sha256"),
                format!("{base_url}/sha"),
                65,
            ),
        ];

        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", assets),
        )
        .unwrap_err();

        assert!(err.to_string().contains("SHA-256 mismatch"));
    }

    #[test]
    fn cmd_upgrade_with_release_surfaces_install_failure_after_download() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);
        let base_url = local_http_server(vec!["downloaded-binary".to_string()]);
        let binary_name = format!("innerwarden-ctl-linux-{arch}");
        let assets = vec![asset_with_url(&binary_name, format!("{base_url}/bin"), 17)];

        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            &dir.path().join("missing-install-dir"),
            release("v999.0.0", assets),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("install failed")
                || err.to_string().contains("failed to run install command")
        );
    }

    #[test]
    fn fix_config_dir_permissions_ignores_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        fix_config_dir_permissions(&dir.path().join("missing"));
    }

    #[test]
    fn fix_config_dir_permissions_visits_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("agent.toml");
        std::fs::write(&file, "[agent]\n").unwrap();

        fix_config_dir_permissions(dir.path());

        assert!(file.exists());
    }
}
