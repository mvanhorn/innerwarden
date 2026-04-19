//! Shadow-mode AI provider wrapper.
//!
//! Runs a primary provider and a shadow provider in parallel on each decision.
//! The primary's decision is returned to the caller (the agent acts on it).
//! The shadow's decision is logged to a JSONL file so operators can audit
//! agreement before promoting the shadow to primary.
//!
//! Intended use: deploy a new provider (e.g. a freshly distilled local
//! classifier) as shadow while the known-good provider (e.g. Azure OpenAI)
//! continues to drive production. After 1-2 weeks of logs showing high
//! agreement the operator can flip the config and promote the shadow.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use serde::Serialize;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::{AiAction, AiDecision, AiProvider, DecisionContext};

pub struct ShadowProvider {
    primary: Box<dyn AiProvider>,
    shadow: Box<dyn AiProvider>,
    log_path: PathBuf,
    /// Serializes writes to the JSONL file across concurrent decisions.
    write_lock: Arc<Mutex<()>>,
}

#[derive(Serialize)]
struct ShadowLogEntry<'a> {
    ts: String,
    incident_id: &'a str,
    primary_provider: &'a str,
    primary_action: &'a str,
    primary_confidence: f32,
    primary_latency_ms: u64,
    shadow_provider: &'a str,
    shadow_action: Option<&'a str>,
    shadow_confidence: Option<f32>,
    shadow_latency_ms: Option<u64>,
    shadow_error: Option<String>,
    action_match: Option<bool>,
}

impl ShadowProvider {
    pub fn new(
        primary: Box<dyn AiProvider>,
        shadow: Box<dyn AiProvider>,
        log_path: impl AsRef<Path>,
    ) -> Self {
        Self {
            primary,
            shadow,
            log_path: log_path.as_ref().to_path_buf(),
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn append_log(&self, entry: &ShadowLogEntry<'_>) {
        let Ok(mut line) = serde_json::to_string(entry) else {
            warn!("failed to serialize shadow log entry");
            return;
        };
        line.push('\n');

        let _guard = self.write_lock.lock().await;
        let open = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await;
        match open {
            Ok(mut f) => {
                if let Err(e) = f.write_all(line.as_bytes()).await {
                    warn!(err = %e, path = %self.log_path.display(), "shadow log write failed");
                    return;
                }
                // Explicit flush so operators tailing the file (or tests
                // reading it synchronously) observe the write immediately.
                if let Err(e) = f.flush().await {
                    warn!(err = %e, path = %self.log_path.display(), "shadow log flush failed");
                }
            }
            Err(e) => warn!(err = %e, path = %self.log_path.display(), "shadow log open failed"),
        }
    }
}

#[async_trait]
impl AiProvider for ShadowProvider {
    fn name(&self) -> &'static str {
        // Report the primary's name so existing telemetry/metrics keep their
        // labels. The shadow is internal detail.
        self.primary.name()
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        let incident_id = ctx.incident.incident_id.clone();

        // Run both concurrently. Primary error fails the whole call (same
        // behavior as without shadow). Shadow error is logged, not propagated.
        let t0 = Instant::now();
        let (primary_res, shadow_res) =
            tokio::join!(self.primary.decide(ctx), self.shadow.decide(ctx));

        let primary = primary_res?;
        let primary_latency = t0.elapsed().as_millis() as u64;

        let primary_action = primary.action.name();
        match shadow_res {
            Ok(shadow) => {
                let shadow_action = shadow.action.name();
                let match_ = primary_action == shadow_action;
                let entry = ShadowLogEntry {
                    ts: Utc::now().to_rfc3339(),
                    incident_id: &incident_id,
                    primary_provider: self.primary.name(),
                    primary_action,
                    primary_confidence: primary.confidence,
                    primary_latency_ms: primary_latency,
                    shadow_provider: self.shadow.name(),
                    shadow_action: Some(shadow_action),
                    shadow_confidence: Some(shadow.confidence),
                    // Shadow latency is <= primary_latency because they ran
                    // in parallel; log the total ms observed.
                    shadow_latency_ms: Some(primary_latency),
                    shadow_error: None,
                    action_match: Some(match_),
                };
                self.append_log(&entry).await;
                info!(
                    incident_id = %incident_id,
                    primary = %primary_action,
                    shadow = %shadow_action,
                    agreement = match_,
                    "shadow decision"
                );
            }
            Err(e) => {
                let entry = ShadowLogEntry {
                    ts: Utc::now().to_rfc3339(),
                    incident_id: &incident_id,
                    primary_provider: self.primary.name(),
                    primary_action,
                    primary_confidence: primary.confidence,
                    primary_latency_ms: primary_latency,
                    shadow_provider: self.shadow.name(),
                    shadow_action: None,
                    shadow_confidence: None,
                    shadow_latency_ms: None,
                    shadow_error: Some(e.to_string()),
                    action_match: None,
                };
                self.append_log(&entry).await;
                warn!(
                    incident_id = %incident_id,
                    err = %e,
                    "shadow provider errored (primary decision unaffected)"
                );
            }
        }

        Ok(primary)
    }

    async fn chat(&self, system_prompt: &str, user_message: &str) -> Result<String> {
        // Chat is only routed to the primary. Shadow is for triage decisions only.
        self.primary.chat(system_prompt, user_message).await
    }
}

// AiAction::name exists in mod.rs; ensure it is in scope here.
impl AiAction {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeProvider {
        name: &'static str,
        action: AiAction,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AiProvider for FakeProvider {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AiDecision {
                action: self.action.clone(),
                confidence: 0.9,
                auto_execute: false,
                reason: String::new(),
                alternatives: vec![],
                estimated_threat: "medium".into(),
            })
        }
        async fn chat(&self, _s: &str, _u: &str) -> Result<String> {
            Ok(format!("{} chat", self.name))
        }
    }

    fn dummy_incident() -> innerwarden_core::incident::Incident {
        use innerwarden_core::{event::Severity, incident::Incident};
        Incident {
            ts: chrono::Utc::now(),
            host: "test".into(),
            incident_id: "ssh_bruteforce:1.2.3.4:shadow-test".into(),
            severity: Severity::High,
            title: "test".into(),
            summary: "test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    #[tokio::test]
    async fn shadow_writes_log_on_agreement() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let shadow_calls = Arc::new(AtomicUsize::new(0));
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::Ignore { reason: "p".into() },
            calls: Arc::clone(&primary_calls),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: Arc::clone(&shadow_calls),
        });
        let sp = ShadowProvider::new(primary, shadow, tmp.path());

        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
            related_incidents: vec![],
            already_blocked: vec![],
            available_skills: vec![],
            ip_reputation: None,
            ip_geo: None,
            graph_context: None,
            graph_subgraph: None,
        };
        let d = sp.decide(&ctx).await.unwrap();
        assert!(matches!(d.action, AiAction::Ignore { .. }));
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(shadow_calls.load(Ordering::SeqCst), 1);

        let logged = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(logged.contains("\"action_match\":true"));
        assert!(logged.contains("\"primary_action\":\"ignore\""));
        assert!(logged.contains("\"shadow_action\":\"ignore\""));
    }

    #[tokio::test]
    async fn shadow_logs_disagreement() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::BlockIp {
                ip: "1.2.3.4".into(),
                skill_id: "block-ip-ufw".into(),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Monitor {
                ip: "1.2.3.4".into(),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let sp = ShadowProvider::new(primary, shadow, tmp.path());

        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
            related_incidents: vec![],
            already_blocked: vec![],
            available_skills: vec![],
            ip_reputation: None,
            ip_geo: None,
            graph_context: None,
            graph_subgraph: None,
        };
        let _ = sp.decide(&ctx).await.unwrap();
        let logged = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(logged.contains("\"action_match\":false"));
    }

    #[tokio::test]
    async fn primary_error_propagates_shadow_does_not() {
        struct Erroring;
        #[async_trait]
        impl AiProvider for Erroring {
            fn name(&self) -> &'static str {
                "err"
            }
            async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
                anyhow::bail!("boom")
            }
            async fn chat(&self, _s: &str, _u: &str) -> Result<String> {
                anyhow::bail!("boom")
            }
        }

        let tmp = tempfile::NamedTempFile::new().unwrap();

        // Primary errors -> overall error
        let primary = Box::new(Erroring);
        let shadow = Box::new(FakeProvider {
            name: "s",
            action: AiAction::Ignore { reason: "x".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let sp = ShadowProvider::new(primary, shadow, tmp.path());
        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
            related_incidents: vec![],
            already_blocked: vec![],
            available_skills: vec![],
            ip_reputation: None,
            ip_geo: None,
            graph_context: None,
            graph_subgraph: None,
        };
        assert!(sp.decide(&ctx).await.is_err());

        // Primary OK, shadow errors -> primary returned, shadow_error logged
        let primary = Box::new(FakeProvider {
            name: "p",
            action: AiAction::Ignore { reason: "ok".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shadow = Box::new(Erroring);
        let sp = ShadowProvider::new(primary, shadow, tmp.path());
        let d = sp.decide(&ctx).await.unwrap();
        assert!(matches!(d.action, AiAction::Ignore { .. }));
        let logged = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(logged.contains("\"shadow_error\""));
    }
}
