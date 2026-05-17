//! Discovery file for peer AI agents on the same host.
//!
//! The problem this solves: Inner Warden can detect a running AI agent
//! (OpenClaw, Codex CLI, etc.) via signature matching and `agent
//! connect` registers that agent in the dashboard's agent-guard
//! registry. But that flow is one-directional — the AI agent on the
//! other side has no idea Inner Warden exists. Without a shared
//! discovery surface, the AI agent never calls
//! `/api/agent/check-command` before running risky operations, never
//! pulls `/api/agent/security-context` before answering "is this box
//! safe?", and the operator gets the literal complaint heard on
//! 2026-05-17: "fiz a conexão mas meu OpenClaw não consegue
//! identificar o Inner Warden."
//!
//! Fix: at agent startup we drop a small, world-readable JSON file at
//! `<data_dir>/agent-discovery.json` describing how to reach Inner
//! Warden — URL, endpoints, auth mode, TLS posture. Any AI agent on
//! the same host can read that file and start using the APIs without
//! manual operator setup.
//!
//! The file lives in `/run/innerwarden/` — the FHS-standard location
//! for runtime / discovery data. We do NOT put it under `data_dir`
//! (`/var/lib/innerwarden`): in production that directory is created
//! with mode `0770 innerwarden:innerwarden`, which blocks traversal
//! by peer AI agents that run as `ubuntu` or any other non-privileged
//! user — the exact failure mode the operator hit on 2026-05-18:
//! "o arquivo de discovery em /var/lib/innerwarden/agent-discovery.json
//! deu Permission denied neste ambiente." Putting the file in `/run`
//! also matches the semantic: it's runtime state, recreated on every
//! agent boot, so vanishing after reboot is correct.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::json;

pub const DISCOVERY_FILENAME: &str = "agent-discovery.json";

/// Canonical runtime directory for the discovery file in production.
/// Lives in `/run` so peer AI agents (running as `ubuntu` etc.) can
/// always traverse into it. The agent runs as root, so it can mkdir
/// and chmod this on every boot — no systemd `RuntimeDirectory=`
/// setup required.
pub const PROD_DISCOVERY_DIR: &str = "/run/innerwarden";

/// Canonical path of the discovery file inside the agent's data
/// directory. Public so tests and `ctl` can both refer to the same
/// path without hardcoding the filename twice.
pub fn discovery_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DISCOVERY_FILENAME)
}

/// Rewrite an agent.toml bind address into a URL that an on-host AI
/// agent can use to talk to the dashboard.
///
/// Pure so the wildcard / port-default / scheme logic stays tested
/// without spinning up a dashboard. Mirrors the CTL's
/// `resolve_dashboard_url`: wildcards become `127.0.0.1`, missing
/// port defaults to `:8787`, scheme depends on TLS posture.
pub fn loopback_url_for_bind(bind: &str, tls_enabled: bool) -> String {
    let scheme = if tls_enabled { "https" } else { "http" };

    // Strip fully-qualified scheme if the operator already gave us one;
    // we'll re-prefix the right scheme based on TLS posture below.
    let stripped = bind
        .strip_prefix("https://")
        .or_else(|| bind.strip_prefix("http://"))
        .unwrap_or(bind);

    let mut addr = stripped.to_string();

    // Wildcards → loopback. AI agents on the same host call ourselves,
    // not whatever's listening on the public interface.
    if let Some(rest) = addr.strip_prefix("0.0.0.0") {
        addr = format!("127.0.0.1{rest}");
    } else if let Some(rest) = addr.strip_prefix("[::]") {
        addr = format!("127.0.0.1{rest}");
    } else if addr == "*" {
        addr = "127.0.0.1:8787".to_string();
    }

    let has_port = if addr.starts_with('[') {
        // IPv6 literal: `[::1]:8787` — port follows the closing bracket.
        addr.split_once(']')
            .is_some_and(|(_, rest)| rest.starts_with(':'))
    } else {
        addr.contains(':')
    };
    if !has_port {
        addr = format!("{addr}:8787");
    }

    format!("{scheme}://{addr}")
}

/// Build the discovery payload. Pure so the schema stays testable
/// without touching the filesystem or the system clock.
pub fn build_discovery_payload(
    dashboard_bind: &str,
    tls_enabled: bool,
    agent_version: &str,
    written_at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let url = loopback_url_for_bind(dashboard_bind, tls_enabled);
    json!({
        "schema_version": 1,
        "service": "innerwarden",
        "agent_version": agent_version,
        "url": url,
        "endpoints": {
            "security_context": "/api/agent/security-context",
            "check_command": "/api/agent/check-command",
            "check_ip": "/api/agent/check-ip",
            "agents": "/api/agent-guard/agents",
            "connect": "/api/agent-guard/connect",
            "disconnect": "/api/agent-guard/disconnect",
        },
        "auth": {
            "mode": "loopback-bypass",
            "note": "Calls from 127.0.0.1 / ::1 / localhost bypass Basic Auth (PR #680). External callers need credentials from agent.toml.",
        },
        "tls": {
            "self_signed": tls_enabled,
            "note": if tls_enabled {
                "Dashboard uses a self-signed cert. On-host callers should accept any cert (loopback)."
            } else {
                "TLS disabled by operator (--insecure-no-tls). Plain HTTP."
            },
        },
        "written_at": written_at.to_rfc3339(),
    })
}

/// Write the discovery file. The parent directory is created if
/// missing AND chmod'd to `0755` so peer AI agents running as a
/// non-privileged user can traverse into it (the original `0644`
/// file mode is useless if the directory itself is `0700`/`0770` —
/// that's the exact bug we hit on prod, see module doc). The file
/// itself is written with `0644`. Fail-soft: callers should log the
/// error but not crash the agent boot — the dashboard still works
/// without this hint file.
pub fn write_discovery(
    runtime_dir: &Path,
    dashboard_bind: &str,
    tls_enabled: bool,
    agent_version: &str,
) -> Result<PathBuf> {
    let payload = build_discovery_payload(
        dashboard_bind,
        tls_enabled,
        agent_version,
        chrono::Utc::now(),
    );
    let path = discovery_path(runtime_dir);

    std::fs::create_dir_all(runtime_dir)?;
    // World-traversable so peer agents can reach the file inside.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(runtime_dir)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(runtime_dir, perms)?;
    }

    let body = serde_json::to_string_pretty(&payload)?;
    std::fs::write(&path, body)?;

    // 0644 so unprivileged AI agents can read it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms)?;
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_url_rewrites_ipv4_wildcard() {
        assert_eq!(
            loopback_url_for_bind("0.0.0.0:8787", true),
            "https://127.0.0.1:8787"
        );
    }

    #[test]
    fn loopback_url_rewrites_ipv6_wildcard() {
        assert_eq!(
            loopback_url_for_bind("[::]:8787", true),
            "https://127.0.0.1:8787"
        );
    }

    #[test]
    fn loopback_url_keeps_explicit_loopback() {
        assert_eq!(
            loopback_url_for_bind("127.0.0.1:8787", true),
            "https://127.0.0.1:8787"
        );
        assert_eq!(
            loopback_url_for_bind("localhost:8787", true),
            "https://localhost:8787"
        );
    }

    #[test]
    fn loopback_url_defaults_port_when_missing() {
        assert_eq!(
            loopback_url_for_bind("127.0.0.1", true),
            "https://127.0.0.1:8787"
        );
        assert_eq!(loopback_url_for_bind("*", true), "https://127.0.0.1:8787");
    }

    #[test]
    fn loopback_url_honors_insecure_no_tls() {
        // Operator passed --insecure-no-tls. Discovery file must say
        // http:// so AI agents don't try TLS handshake against a plain
        // HTTP server and fail mysteriously.
        assert_eq!(
            loopback_url_for_bind("0.0.0.0:8787", false),
            "http://127.0.0.1:8787"
        );
    }

    #[test]
    fn loopback_url_strips_existing_scheme_then_reapplies_correct_one() {
        // If agent.toml has dashboard_bind = "http://0.0.0.0:8787" but
        // TLS is actually enabled (cert files present), the discovery
        // file should reflect the runtime truth (https), not the
        // operator's stale config string.
        assert_eq!(
            loopback_url_for_bind("http://0.0.0.0:8787", true),
            "https://127.0.0.1:8787"
        );
    }

    #[test]
    fn discovery_payload_includes_required_endpoints() {
        let now = chrono::Utc::now();
        let v = build_discovery_payload("127.0.0.1:8787", true, "0.13.6", now);
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["service"], "innerwarden");
        assert_eq!(v["agent_version"], "0.13.6");
        assert_eq!(v["url"], "https://127.0.0.1:8787");
        // Endpoints AI agents need today.
        for ep in &[
            "security_context",
            "check_command",
            "check_ip",
            "agents",
            "connect",
            "disconnect",
        ] {
            assert!(
                v["endpoints"][ep].is_string(),
                "endpoint {ep} missing from discovery payload"
            );
        }
        assert_eq!(v["auth"]["mode"], "loopback-bypass");
        assert_eq!(v["tls"]["self_signed"], true);
        assert!(v["written_at"].is_string());
    }

    #[test]
    fn discovery_payload_marks_tls_disabled_when_insecure() {
        let now = chrono::Utc::now();
        let v = build_discovery_payload("127.0.0.1:8787", false, "0.13.6", now);
        assert_eq!(v["url"], "http://127.0.0.1:8787");
        assert_eq!(v["tls"]["self_signed"], false);
    }

    #[test]
    fn write_discovery_creates_file_with_canonical_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = write_discovery(tmp.path(), "0.0.0.0:8787", true, "0.13.6")
            .expect("write_discovery should succeed in a fresh tempdir");
        assert_eq!(path, tmp.path().join(DISCOVERY_FILENAME));
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["url"], "https://127.0.0.1:8787");
        assert_eq!(v["agent_version"], "0.13.6");
    }

    #[test]
    #[cfg(unix)]
    fn write_discovery_chmods_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let path =
            write_discovery(tmp.path(), "0.0.0.0:8787", true, "0.13.6").expect("write should ok");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "discovery file must be world-readable (0644); unprivileged AI agents need to read it"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_discovery_chmods_parent_dir_world_traversable() {
        // Regression anchor for the 2026-05-18 prod bug: the discovery
        // file was world-readable (0644) but lived in a 0770 dir, so
        // peer agents got "Permission denied" no matter how loose the
        // file mode was. The writer must now chmod the parent dir to
        // 0755 so traversal works for any local UID.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        // Start the runtime dir with a restrictive mode so we can
        // observe whether write_discovery actually loosens it.
        let runtime = tmp.path().join("innerwarden");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pre_mode = std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777;
        assert_eq!(pre_mode, 0o700, "test fixture should start at 0700");

        write_discovery(&runtime, "0.0.0.0:8787", true, "0.13.6")
            .expect("write_discovery should chmod the parent");

        let post_mode = std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            post_mode, 0o755,
            "write_discovery must leave the runtime dir world-traversable"
        );
    }

    #[test]
    fn write_discovery_creates_parent_dir_if_missing() {
        // The agent boot path passes /run/innerwarden which does not
        // exist on a fresh host. The writer must mkdir -p, not fail.
        let tmp = tempfile::TempDir::new().unwrap();
        let runtime = tmp.path().join("nested").join("innerwarden");
        assert!(!runtime.exists(), "test fixture: dir does not exist yet");

        let path = write_discovery(&runtime, "0.0.0.0:8787", true, "0.13.6")
            .expect("write_discovery should mkdir -p the runtime dir");

        assert!(path.exists());
        assert_eq!(path.parent(), Some(runtime.as_path()));
    }

    #[test]
    fn write_discovery_overwrites_existing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let first =
            write_discovery(tmp.path(), "0.0.0.0:8787", true, "0.13.6").expect("first write");
        let body1 = std::fs::read_to_string(&first).unwrap();
        let second =
            write_discovery(tmp.path(), "0.0.0.0:8787", true, "0.13.7").expect("second write");
        assert_eq!(first, second, "path must be stable across writes");
        let body2 = std::fs::read_to_string(&second).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body2).unwrap();
        assert_eq!(v["agent_version"], "0.13.7");
        assert_ne!(body1, body2, "rewrite should reflect the new version");
    }
}
