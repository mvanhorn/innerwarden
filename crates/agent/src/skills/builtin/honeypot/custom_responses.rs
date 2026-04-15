//! Custom honeypot responses loaded from YAML files.
//!
//! Module scaffolding — the YAML loader and response types are defined
//! but not yet wired into the fake-shell / fake-HTTP pipelines. They will
//! be consumed once custom-responses integration lands. Until then, the
//! items are retained as a documented API surface.
//!
//! Operators can drop YAML files in /etc/innerwarden/honeypot.d/ to customize
//! the honeypot behavior without modifying code:
//!
//! - Add custom commands to the fake shell
//! - Add custom HTTP routes with static responses
//! - Override default responses for existing commands
//!
//! File format:
//! ```yaml
//! # /etc/innerwarden/honeypot.d/custom-shell.yml
//! shell_commands:
//!   "cat /opt/app/config.yml":
//!     output: |
//!       database:
//!         host: db-prod.internal
//!         password: s3cret_pr0d_2024
//!   "docker ps":
//!     output: |
//!       CONTAINER ID   IMAGE          STATUS         NAMES
//!       a1b2c3d4e5f6   nginx:latest   Up 3 days      web-frontend
//!       f6e5d4c3b2a1   redis:7        Up 3 days      cache
//!
//! http_routes:
//!   "GET /api/v1/health":
//!     content_type: "application/json"
//!     body: '{"status":"ok","version":"2.4.1","uptime":259200}'
//!   "GET /api/v1/users":
//!     content_type: "application/json"
//!     body: '[{"id":1,"name":"admin","role":"superadmin"}]'
//! ```

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use tracing::{debug, info, warn};

#[derive(Debug, Deserialize, Default)]
pub struct CustomResponses {
    #[serde(default)]
    pub shell_commands: HashMap<String, ShellResponse>,
    #[serde(default)]
    pub http_routes: HashMap<String, HttpResponse>,
}

#[derive(Debug, Deserialize)]
pub struct ShellResponse {
    pub output: String,
}

#[derive(Debug, Deserialize)]
pub struct HttpResponse {
    #[serde(default = "default_content_type")]
    pub content_type: String,
    pub body: String,
}

fn default_content_type() -> String {
    "text/html".to_string()
}

impl CustomResponses {
    /// Load all YAML files from a directory and merge them.
    pub fn load_dir(dir: &Path) -> Self {
        let mut merged = Self::default();

        let Ok(entries) = std::fs::read_dir(dir) else {
            debug!(dir = %dir.display(), "honeypot custom responses dir not found");
            return merged;
        };

        let mut count = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yml")
                && path.extension().and_then(|e| e.to_str()) != Some("yaml")
            {
                continue;
            }

            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_yaml::from_str::<CustomResponses>(&content) {
                    Ok(custom) => {
                        merged.shell_commands.extend(custom.shell_commands);
                        merged.http_routes.extend(custom.http_routes);
                        count += 1;
                    }
                    Err(e) => {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "failed to parse honeypot custom responses"
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to read honeypot custom responses"
                    );
                }
            }
        }

        if count > 0 {
            info!(
                files = count,
                shell_commands = merged.shell_commands.len(),
                http_routes = merged.http_routes.len(),
                "loaded custom honeypot responses"
            );
        }

        merged
    }

    /// Try to match a shell command against custom responses.
    pub fn try_shell(&self, cmd: &str) -> Option<&str> {
        // Exact match first
        if let Some(resp) = self.shell_commands.get(cmd.trim()) {
            return Some(&resp.output);
        }
        // Prefix match (e.g., "cat /opt/app/config.yml" matches "cat /opt/app/config.yml")
        for (pattern, resp) in &self.shell_commands {
            if cmd.trim().starts_with(pattern.as_str()) {
                return Some(&resp.output);
            }
        }
        None
    }

    /// Try to match an HTTP route against custom responses.
    /// Key format: "METHOD /path" e.g. "GET /api/v1/health"
    pub fn try_http(&self, method: &str, path: &str) -> Option<(String, String)> {
        let key = format!("{method} {path}");
        self.http_routes
            .get(&key)
            .map(|r| (r.content_type.clone(), r.body.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_match() {
        let yaml = r#"
shell_commands:
  "docker ps":
    output: "CONTAINER ID   IMAGE\na1b2c3   nginx"
  "cat /opt/secret":
    output: "password=hunter2"
"#;
        let custom: CustomResponses = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            custom.try_shell("docker ps"),
            Some("CONTAINER ID   IMAGE\na1b2c3   nginx")
        );
        assert_eq!(
            custom.try_shell("cat /opt/secret"),
            Some("password=hunter2")
        );
        assert!(custom.try_shell("unknown").is_none());
    }

    #[test]
    fn test_http_match() {
        let yaml = r#"
http_routes:
  "GET /api/health":
    content_type: "application/json"
    body: '{"status":"ok"}'
"#;
        let custom: CustomResponses = serde_yaml::from_str(yaml).unwrap();
        let result = custom.try_http("GET", "/api/health");
        assert!(result.is_some());
        let (ct, body) = result.unwrap();
        assert_eq!(ct, "application/json");
        assert!(body.contains("ok"));
    }

    #[test]
    fn test_shell_prefix_match() {
        let yaml = r#"
shell_commands:
  "cat /etc/passwd":
    output: "root:x:0:0:root:/root:/bin/bash"
"#;
        let custom: CustomResponses = serde_yaml::from_str(yaml).unwrap();
        // Exact match
        assert!(custom.try_shell("cat /etc/passwd").is_some());
        // Prefix match with trailing spaces/args
        assert!(custom.try_shell("cat /etc/passwd > /tmp/out").is_some());
        // No match
        assert!(custom.try_shell("cat /etc/shadow").is_none());
    }
}
