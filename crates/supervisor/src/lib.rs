//! Process supervisor for `innerwarden-agent`.
//!
//! Detects agent death via `kill(pid, 0)` polling at 100 ms, respawns within
//! ~200 ms, rate-limits restarts to N/hour, runs a periodic HTTP health check
//! against the agent's `/metrics` endpoint and force-kills the agent when it
//! becomes unresponsive (next tick respawns it). Optionally posts Telegram
//! alerts on every restart and on integrity-style failures escalated by a
//! [`RestartHook`].
//!
//! # Where this fits
//!
//! `Restart=always` in a systemd unit recovers from crashes too, but does not
//! report restarts anywhere actionable, has no per-application health probe,
//! and gives no programmatic way to refuse a restart when the agent binary on
//! disk has been swapped. This crate is the layer that closes those gaps for
//! the open-source distribution. Anti-tamper concerns (process stealth,
//! SHA-256 integrity gating, namespace isolation) live in a separate proprietary
//! supervisor that wraps this one via [`RestartHook`].
//!
//! # Anatomy
//!
//! ```text
//!     Supervisor::run()
//!       ├── ctrlc handler installed
//!       ├── ensure_not_symlink(agent_binary)
//!       ├── hook.before_spawn()           // hook returning Err refuses the spawn
//!       ├── Monitor::spawn_agent()        // first child
//!       └── loop {
//!             if !is_alive(pid)           // 100 ms poll
//!                 → hook.before_spawn()
//!                 → Monitor::restart_agent() // rate-limited, alerts on outcome
//!             every health_interval:
//!                 HealthChecker::check()  // HTTP /metrics, kill -9 after 3 fails
//!           }
//! ```

mod alerts;
mod health;
mod hook;
mod monitor;
mod symlink;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{error, info, warn};

pub use alerts::Alerter;
pub use health::HealthChecker;
pub use hook::{NoopHook, RestartHook};
pub use monitor::Monitor;
pub use symlink::ensure_not_symlink;

/// Caller-supplied configuration for [`Supervisor`].
///
/// Build via [`SupervisorConfig::new`] + the `with_*` setters. The defaults
/// match what the OSS agent ships with: a local dashboard at `127.0.0.1:8787`,
/// 30 s health probe interval, and 10 restarts per rolling hour.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub agent_binary: std::path::PathBuf,
    pub agent_args: Vec<String>,
    pub agent_api: String,
    pub health_interval: Duration,
    pub max_restarts_per_hour: u32,
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<String>,
}

impl SupervisorConfig {
    pub fn new<P: Into<std::path::PathBuf>>(agent_binary: P) -> Self {
        Self {
            agent_binary: agent_binary.into(),
            agent_args: Vec::new(),
            // AUDIT-005: the OSS agent serves the dashboard over HTTPS by
            // default (auto-generated self-signed cert). Probing HTTP
            // gets TLS handshake bytes back, parse fails, and the
            // supervisor SIGKILLs a healthy agent every 30s. Default to
            // HTTPS; HealthChecker auto-disables cert verification for
            // loopback hosts (see crates/supervisor/src/health.rs).
            agent_api: "https://127.0.0.1:8787".into(),
            health_interval: Duration::from_secs(30),
            max_restarts_per_hour: 10,
            telegram_token: None,
            telegram_chat_id: None,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.agent_args = args;
        self
    }

    pub fn with_health(mut self, api: impl Into<String>, interval: Duration) -> Self {
        self.agent_api = api.into();
        self.health_interval = interval;
        self
    }

    pub fn with_max_restarts_per_hour(mut self, n: u32) -> Self {
        self.max_restarts_per_hour = n;
        self
    }

    pub fn with_telegram(mut self, token: String, chat_id: String) -> Self {
        self.telegram_token = Some(token);
        self.telegram_chat_id = Some(chat_id);
        self
    }
}

/// Top-level supervisor. Owns the [`Monitor`], [`HealthChecker`], and
/// [`Alerter`], plus an optional [`RestartHook`] (defaults to [`NoopHook`]).
pub struct Supervisor {
    config: SupervisorConfig,
    hook: Box<dyn RestartHook>,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("config", &self.config)
            .field("hook", &"<dyn RestartHook>")
            .finish()
    }
}

impl Supervisor {
    /// Validate the agent binary path (rejects symlinks) and prepare a
    /// supervisor that will spawn it on `run()`.
    pub fn new(config: SupervisorConfig) -> Result<Self> {
        ensure_not_symlink(&config.agent_binary)
            .context("agent binary path failed pre-spawn validation")?;
        Ok(Self {
            config,
            hook: Box::new(NoopHook),
        })
    }

    /// Replace the default [`NoopHook`] with a caller-supplied implementation.
    /// The proprietary watchdog uses this to inject SHA-256 integrity checks
    /// in front of every spawn.
    pub fn with_hook(mut self, hook: Box<dyn RestartHook>) -> Self {
        self.hook = hook;
        self
    }

    /// Install a SIGTERM/SIGINT handler, spawn the agent, then run the
    /// supervision loop until a signal arrives or an unrecoverable condition
    /// (binary tampered, restart-rate exceeded) is reached.
    pub fn run(self) -> Result<()> {
        let Self { config, hook } = self;

        let mut monitor = Monitor::new(
            config.agent_binary.clone(),
            config.agent_args.clone(),
            config.max_restarts_per_hour,
        );

        let alerter = Alerter::new(
            config.telegram_token.clone(),
            config.telegram_chat_id.clone(),
        );
        let mut health = HealthChecker::new(&config.agent_api);

        // Initial spawn: hook may refuse (e.g. paid integrity check).
        hook.before_spawn()
            .context("initial spawn refused by RestartHook")?;
        let initial_pid = monitor.spawn_agent()?;
        info!(pid = initial_pid, "monitoring agent - supervisor active");

        let running = Arc::new(AtomicBool::new(true));
        {
            let r = Arc::clone(&running);
            let _ = ctrlc::set_handler(move || {
                r.store(false, Ordering::Relaxed);
            });
        }

        let mut last_health = Instant::now();

        while running.load(Ordering::Relaxed) {
            if !monitor.is_alive() {
                let old_pid = monitor.agent_pid().unwrap_or(0);
                warn!(pid = old_pid, "agent died - attempting restart");

                if let Err(e) = hook.before_spawn() {
                    let msg = format!("{:#}", e);
                    error!("CRITICAL: hook refused restart: {}", msg);
                    alerter.restart_failed(old_pid, &msg);
                    if msg.contains("TAMPERED") {
                        alerter.integrity_violation(&msg);
                        error!("hook reported integrity violation - supervisor halting");
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(5));
                } else {
                    match monitor.restart_agent() {
                        Ok(new_pid) => {
                            info!(old_pid, new_pid, "agent restarted successfully");
                            alerter.agent_restarted(old_pid, new_pid, "process exited");
                        }
                        Err(e) => {
                            let msg = format!("{:#}", e);
                            error!("CRITICAL: restart failed: {}", msg);
                            alerter.restart_failed(old_pid, &msg);
                            if msg.contains("rate limit") {
                                error!("restart rate limit exceeded - supervisor halting");
                                break;
                            }
                            std::thread::sleep(Duration::from_secs(5));
                        }
                    }
                }
            }

            if last_health.elapsed() >= config.health_interval {
                if let Err(e) = health.check() {
                    warn!("health check failed: {:#}", e);
                    if let Some(pid) = monitor.agent_pid() {
                        warn!(pid, "killing unresponsive agent");
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid as i32),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                }
                last_health = Instant::now();
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        info!("supervisor shutting down gracefully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn tmpfile_bin() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("agent");
        std::fs::write(&bin, b"placeholder").unwrap();
        (dir, bin)
    }

    #[test]
    fn config_defaults_match_oss_agent_layout() {
        let cfg = SupervisorConfig::new("/dev/null");
        assert_eq!(cfg.agent_api, "https://127.0.0.1:8787");
        assert_eq!(cfg.health_interval, Duration::from_secs(30));
        assert_eq!(cfg.max_restarts_per_hour, 10);
        assert!(cfg.agent_args.is_empty());
        assert!(cfg.telegram_token.is_none());
        assert!(cfg.telegram_chat_id.is_none());
    }

    #[test]
    fn config_with_args_sets_args() {
        let cfg = SupervisorConfig::new("/dev/null").with_args(vec!["--config".into(), "x".into()]);
        assert_eq!(cfg.agent_args, vec!["--config", "x"]);
    }

    #[test]
    fn config_with_health_overrides_url_and_interval() {
        let cfg = SupervisorConfig::new("/dev/null")
            .with_health("http://1.2.3.4:9000", Duration::from_secs(7));
        assert_eq!(cfg.agent_api, "http://1.2.3.4:9000");
        assert_eq!(cfg.health_interval, Duration::from_secs(7));
    }

    #[test]
    fn config_with_max_restarts_per_hour_overrides_cap() {
        let cfg = SupervisorConfig::new("/dev/null").with_max_restarts_per_hour(99);
        assert_eq!(cfg.max_restarts_per_hour, 99);
    }

    #[test]
    fn config_with_telegram_sets_both_credentials() {
        let cfg = SupervisorConfig::new("/dev/null").with_telegram("tok".into(), "chat".into());
        assert_eq!(cfg.telegram_token.as_deref(), Some("tok"));
        assert_eq!(cfg.telegram_chat_id.as_deref(), Some("chat"));
    }

    #[test]
    fn supervisor_new_rejects_symlinked_agent_binary() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::write(&real, b"x").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let cfg = SupervisorConfig::new(link);
        let err = Supervisor::new(cfg).unwrap_err();
        assert!(format!("{:#}", err).contains("symlink"));
    }

    #[test]
    fn supervisor_new_accepts_regular_file() {
        let (_dir, bin) = tmpfile_bin();
        assert!(Supervisor::new(SupervisorConfig::new(bin)).is_ok());
    }

    #[test]
    fn supervisor_with_hook_replaces_default() {
        // Builder smoke test. The hook itself is observed in the run-loop
        // tests below via shared atomic state.
        let (_dir, bin) = tmpfile_bin();
        let supervisor = Supervisor::new(SupervisorConfig::new(bin))
            .unwrap()
            .with_hook(Box::new(NoopHook));
        drop(supervisor);
    }

    /// Shared-state hook that returns Ok the first `bail_after` times, then
    /// bails with `bail_msg`. Drives Supervisor::run into specific halt paths
    /// without mocking the agent process.
    struct CountingHook {
        bail_after: u32,
        bail_msg: &'static str,
        observed: Arc<AtomicU32>,
    }
    impl RestartHook for CountingHook {
        fn before_spawn(&self) -> Result<()> {
            let n = self.observed.fetch_add(1, Ordering::SeqCst);
            if n < self.bail_after {
                Ok(())
            } else {
                anyhow::bail!("{}", self.bail_msg)
            }
        }
    }

    #[test]
    fn supervisor_run_returns_err_when_initial_spawn_hook_refuses() {
        // Hook fails on the very first call so Supervisor::run propagates
        // before ever spawning the agent. Covers the initial-spawn early
        // return path.
        let (_dir, bin) = tmpfile_bin();
        let cfg = SupervisorConfig::new(bin);
        let observed = Arc::new(AtomicU32::new(0));
        let hook = CountingHook {
            bail_after: 0,
            bail_msg: "synthetic init refusal",
            observed: Arc::clone(&observed),
        };
        let result = Supervisor::new(cfg)
            .unwrap()
            .with_hook(Box::new(hook))
            .run();
        let err = result.unwrap_err();
        assert!(format!("{:#}", err).contains("synthetic init refusal"));
        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn supervisor_run_halts_when_hook_reports_tampered_after_agent_dies() {
        // Spawn /bin/sleep 0.1, agent exits naturally, supervisor calls hook
        // before restart, hook returns "TAMPERED" so loop halts with Ok.
        let cfg = SupervisorConfig::new("/bin/sleep")
            .with_args(vec!["0.1".into()])
            .with_health("http://127.0.0.1:1", Duration::from_secs(3600));
        let observed = Arc::new(AtomicU32::new(0));
        let hook = CountingHook {
            bail_after: 1,
            bail_msg: "binary TAMPERED: hash mismatch",
            observed: Arc::clone(&observed),
        };
        let result = Supervisor::new(cfg)
            .unwrap()
            .with_hook(Box::new(hook))
            .run();
        assert!(result.is_ok(), "graceful break is Ok, got {:?}", result);
        let n = observed.load(Ordering::SeqCst);
        assert!(n >= 2, "expected hook called >=2 times, got {n}");
    }
}
