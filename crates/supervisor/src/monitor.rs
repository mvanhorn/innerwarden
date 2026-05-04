//! Process spawning, liveness polling, and rate-limited restart.
//!
//! Liveness is checked via `kill(pid, 0)` because that path works regardless
//! of whether the supervisor is the parent (it is, after `spawn_agent`) or an
//! attached observer (`attach`). The 100 ms poll cadence sets the upper bound
//! on time-to-detect, and the spawn cost is sub-millisecond, so end-to-end
//! restart latency stays under ~200 ms.
//!
//! Rate limiting uses a sliding 1-hour window of restart timestamps. When the
//! window exceeds the configured cap, the next restart returns an error
//! containing `"rate limit"` - the supervisor inspects the message and halts
//! the loop. This is intentional: a hot restart loop usually means the agent
//! has a deterministic fault that another restart will not fix.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use nix::sys::signal;
use nix::unistd::Pid;
use tracing::info;

use crate::symlink::ensure_not_symlink;

pub struct Monitor {
    agent_binary: PathBuf,
    agent_args: Vec<String>,
    agent_pid: Option<u32>,
    agent_child: Option<std::process::Child>,
    restart_times: Vec<Instant>,
    max_restarts_per_hour: u32,
}

impl Monitor {
    pub fn new(agent_binary: PathBuf, agent_args: Vec<String>, max_restarts_per_hour: u32) -> Self {
        Self {
            agent_binary,
            agent_args,
            agent_pid: None,
            agent_child: None,
            restart_times: Vec::new(),
            max_restarts_per_hour,
        }
    }

    /// Spawn the agent. Re-checks the symlink invariant every time so an
    /// attacker who introduces a symlink mid-uptime is caught on next restart.
    pub fn spawn_agent(&mut self) -> Result<u32> {
        ensure_not_symlink(&self.agent_binary).context("pre-spawn symlink check")?;

        info!(
            binary = %self.agent_binary.display(),
            args = ?self.agent_args,
            "spawning agent"
        );

        let child = Command::new(&self.agent_binary)
            .args(&self.agent_args)
            .spawn()
            .with_context(|| format!("spawn {}", self.agent_binary.display()))?;

        let pid = child.id();
        self.agent_pid = Some(pid);
        self.agent_child = Some(child);
        info!(pid, "agent spawned");
        Ok(pid)
    }

    /// Attach to an already-running agent by PID (no parent-child relationship).
    pub fn attach(&mut self, pid: u32) -> Result<()> {
        if !Self::pid_alive(pid) {
            bail!("process {} does not exist", pid);
        }
        self.agent_pid = Some(pid);
        info!(pid, "attached to running agent");
        Ok(())
    }

    /// Returns whether the supervised process is still running.
    ///
    /// When the supervisor owns the child handle (the typical case after
    /// `spawn_agent`), this calls `try_wait` so a child that has exited but
    /// not yet been reaped is reported as dead AND its zombie is cleared in
    /// the same step. Without this, `kill(pid, 0)` would report the zombie
    /// as alive forever (zombies live in the kernel until their parent
    /// reaps them) and the supervisor's restart loop would never fire.
    ///
    /// When the supervisor merely attached to an existing PID (no child
    /// handle), it falls back to `kill(pid, 0)` because waitpid cannot be
    /// called on a process that is not our child. The zombie blind-spot
    /// applies in that case but is unavoidable.
    pub fn is_alive(&mut self) -> bool {
        if let Some(ref mut child) = self.agent_child {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    self.agent_child = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            self.agent_pid.is_some_and(Self::pid_alive)
        }
    }

    pub fn agent_pid(&self) -> Option<u32> {
        self.agent_pid
    }

    pub fn restart_count_last_hour(&self) -> usize {
        self.restart_times.len()
    }

    /// Reap the previous child, enforce the rate limit, then re-spawn.
    pub fn restart_agent(&mut self) -> Result<u32> {
        if let Some(ref mut child) = self.agent_child {
            let _ = child.wait();
        }
        self.agent_child = None;

        self.prune_old_restarts();
        if self.restart_times.len() >= self.max_restarts_per_hour as usize {
            bail!(
                "restart rate limit: {} in last hour (max {}). Manual intervention needed.",
                self.restart_times.len(),
                self.max_restarts_per_hour
            );
        }

        let pid = self.spawn_agent()?;
        self.restart_times.push(Instant::now());
        Ok(pid)
    }

    fn pid_alive(pid: u32) -> bool {
        signal::kill(Pid::from_raw(pid as i32), None).is_ok()
    }

    fn prune_old_restarts(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(3600);
        self.restart_times.retain(|t| *t > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_blocks_further_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nonexistent-bin");
        let mut monitor = Monitor::new(bin, vec![], 3);
        for _ in 0..3 {
            monitor.restart_times.push(Instant::now());
        }
        let err = monitor.restart_agent().unwrap_err();
        assert!(format!("{:#}", err).contains("rate limit"));
    }

    #[test]
    fn prune_drops_restarts_older_than_one_hour() {
        let dir = tempfile::tempdir().unwrap();
        let mut monitor = Monitor::new(dir.path().join("x"), vec![], 10);
        let stale = Instant::now() - Duration::from_secs(7200);
        let fresh = Instant::now() - Duration::from_secs(60);
        monitor.restart_times = vec![stale, fresh];
        monitor.prune_old_restarts();
        assert_eq!(monitor.restart_times.len(), 1);
    }

    #[test]
    fn pid_alive_returns_false_for_unused_pid() {
        // 2^31 - 1 is virtually never a live PID on Linux/macOS.
        assert!(!Monitor::pid_alive(2_147_483_647));
    }

    #[test]
    fn spawn_rejects_symlink_on_agent_binary() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::write(&real, b"#!/bin/sh\nexit 0\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut monitor = Monitor::new(link, vec![], 10);
        let err = monitor.spawn_agent().unwrap_err();
        assert!(format!("{:#}", err).contains("symlink"));
    }

    #[test]
    fn spawn_real_process_then_detect_natural_exit() {
        // /bin/sleep with a tiny duration: spawn, observe alive, wait past the
        // exit, observe dead. Covers the spawn happy path + the try_wait-based
        // is_alive that reaps zombies on detection (see is_alive doc comment
        // for why kill(pid,0) alone would report the zombie as alive).
        let mut monitor = Monitor::new("/bin/sleep".into(), vec!["0.1".into()], 5);
        let pid = monitor.spawn_agent().unwrap();
        assert_eq!(monitor.agent_pid(), Some(pid));
        assert!(monitor.is_alive());
        std::thread::sleep(Duration::from_millis(400));
        assert!(!monitor.is_alive());
        // is_alive auto-reaped via try_wait — no further cleanup needed.
        assert!(monitor.agent_child.is_none());
    }

    #[test]
    fn restart_real_process_assigns_a_new_pid() {
        let mut monitor = Monitor::new("/bin/sleep".into(), vec!["0.05".into()], 5);
        let pid1 = monitor.spawn_agent().unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let pid2 = monitor.restart_agent().unwrap();
        assert_ne!(pid1, pid2);
        assert_eq!(monitor.restart_count_last_hour(), 1);
        // Cleanup the second sleep.
        std::thread::sleep(Duration::from_millis(150));
        if let Some(ref mut child) = monitor.agent_child {
            let _ = child.wait();
        }
    }

    #[test]
    fn attach_to_current_process_succeeds() {
        let mut monitor = Monitor::new("/dev/null".into(), vec![], 5);
        let me = std::process::id();
        monitor.attach(me).unwrap();
        assert_eq!(monitor.agent_pid(), Some(me));
        assert!(monitor.is_alive());
    }

    #[test]
    fn attach_to_unused_pid_fails() {
        let mut monitor = Monitor::new("/dev/null".into(), vec![], 5);
        let err = monitor.attach(2_147_483_647).unwrap_err();
        assert!(format!("{:#}", err).contains("does not exist"));
    }

    #[test]
    fn restart_count_last_hour_starts_at_zero() {
        let monitor = Monitor::new("/dev/null".into(), vec![], 5);
        assert_eq!(monitor.restart_count_last_hour(), 0);
    }

    #[test]
    fn agent_pid_is_none_before_spawn() {
        let mut monitor = Monitor::new("/dev/null".into(), vec![], 5);
        assert_eq!(monitor.agent_pid(), None);
        assert!(!monitor.is_alive());
    }
}
