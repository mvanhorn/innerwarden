// Cloudflare IP Access Rules integration
// When innerwarden blocks an IP, optionally push the block to Cloudflare's edge
// so the IP is blocked at the CDN level before it reaches the host.
//
// API: POST https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules
// Docs: https://developers.cloudflare.com/api/operations/ip-access-rules-for-a-zone-create-an-ip-access-rules
//
// Configuration in agent.toml:
//   [cloudflare]
//   enabled = true
//   zone_id = "abc123..."       # from Cloudflare dashboard
//   api_token = ""              # or CLOUDFLARE_API_TOKEN env var
//   auto_push_blocks = true     # push to Cloudflare when block_ip executes
//   block_notes_prefix = "innerwarden"  # prefix for note in Cloudflare rules

use serde::Deserialize;
use serde_json::json;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CloudflareResponse {
    success: bool,
    #[serde(default)]
    result: Option<CloudflareResult>,
    #[serde(default)]
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareResult {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: i64,
    #[allow(dead_code)]
    message: String,
}

/// Cloudflare API error code for "an access rule with this configuration
/// already exists" — the IP is already blocked at the edge, so from the
/// agent's perspective the push succeeded idempotently.
/// https://developers.cloudflare.com/fundamentals/api/reference/errors/
const CF_ERROR_DUPLICATE: i64 = 10009;

// ---------------------------------------------------------------------------
// CIDR validation (Wave 9g, AUDIT-017 anchor)
// ---------------------------------------------------------------------------

/// Whether a target string is a valid input for the Cloudflare IP Access Rules
/// API's `configuration.value` field.
///
/// Per https://developers.cloudflare.com/waf/tools/ip-access-rules/#prefix-lengths,
/// the API accepts:
///   - bare IPv4 / IPv6 (treated as /32 / /128 implicitly)
///   - IPv4 CIDR with prefix `/16`, `/24`, `/32`
///   - IPv6 CIDR with prefix `/32`, `/48`, `/64`
///
/// Anything else (a `/22`, a `/12`, garbage) gets rejected by Cloudflare with
/// `firewallaccessrules.api.validation_error: invalid ip provided`. AUDIT-017
/// (2026-05-04 prod) saw this happen on every mesh-block where the agent fed a
/// `/N` CIDR straight through to `push_block`. The push wasted an HTTP round
/// trip, the API call left a noisy WARN in the journal, and the operator's
/// Cloudflare edge stayed unblocked - half-functional integration.
///
/// Wave 9g (this PR): validate at the agent boundary so unsupported widths are
/// debug-logged and skipped before the round trip. The local UFW block still
/// fires from the caller; only the Cloudflare edge push is short-circuited.
pub(crate) fn cloudflare_target_is_valid(target: &str) -> bool {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return false;
    }
    let (host_part, prefix) = match trimmed.split_once('/') {
        Some((host, prefix_str)) => match prefix_str.parse::<u8>() {
            Ok(p) => (host, Some(p)),
            Err(_) => return false,
        },
        None => (trimmed, None),
    };
    let parsed: std::net::IpAddr = match host_part.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match (parsed, prefix) {
        // Bare IP - always OK.
        (_, None) => true,
        // IPv4 supports 16, 24, 32.
        (std::net::IpAddr::V4(_), Some(16 | 24 | 32)) => true,
        // IPv6 supports 32, 48, 64.
        (std::net::IpAddr::V6(_), Some(32 | 48 | 64)) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// CloudflareClient
// ---------------------------------------------------------------------------

/// Pushes IP block decisions to Cloudflare's edge via the IP Access Rules API.
///
/// Fail-silent: any network error, non-2xx response, or parse failure is logged
/// with `warn!` and the method returns `None`. Cloudflare being unavailable
/// must never stop the agent from processing events (fail-open policy).
pub struct CloudflareClient {
    zone_id: String,
    api_token: String,
    http: reqwest::Client,
    /// Prefix used in Cloudflare rule notes (e.g., "innerwarden")
    notes_prefix: String,
}

impl CloudflareClient {
    /// Create a new client. The HTTP client is configured with an 8-second timeout.
    #[allow(dead_code)]
    pub fn new(zone_id: impl Into<String>, api_token: impl Into<String>) -> Self {
        Self::with_prefix(zone_id, api_token, "innerwarden")
    }

    /// Create a new client with a custom notes prefix.
    pub fn with_prefix(
        zone_id: impl Into<String>,
        api_token: impl Into<String>,
        notes_prefix: impl Into<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .unwrap_or_default();
        Self {
            zone_id: zone_id.into(),
            api_token: api_token.into(),
            http,
            notes_prefix: notes_prefix.into(),
        }
    }

    /// Returns `true` when both `zone_id` and `api_token` are non-empty.
    pub fn is_configured(&self) -> bool {
        !self.zone_id.is_empty() && !self.api_token.is_empty()
    }

    /// Push an IP block to Cloudflare's edge via IP Access Rules.
    ///
    /// Returns the Cloudflare rule ID on success, or `None` on any error.
    /// The method is fail-silent - errors are logged with `warn!` and swallowed.
    pub async fn push_block(&self, ip: &str, reason: &str) -> Option<String> {
        if !self.is_configured() {
            warn!("Cloudflare push_block called but client is not configured");
            return None;
        }

        // Wave 9g (AUDIT-017): refuse CIDRs the Cloudflare API does not
        // accept BEFORE making the HTTP round trip. Pre-fix, mesh-block
        // CIDRs like `1.2.0.0/22` produced a non-2xx response with body
        // `firewallaccessrules.api.validation_error: invalid ip provided`,
        // wasting an API call + dirtying the journal with a WARN per
        // attempt. Now we debug-log + return None; local UFW block from
        // the caller still applies, only the edge push is skipped for
        // unsupported widths.
        if !cloudflare_target_is_valid(ip) {
            debug!(
                ip,
                "Cloudflare push_block: target is not a Cloudflare-accepted IP/CIDR shape \
                 (supported: bare IP, IPv4 /16 /24 /32, IPv6 /32 /48 /64); skipping edge push"
            );
            return None;
        }

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/firewall/access_rules/rules",
            self.zone_id
        );

        let notes = format!("{}: {}", self.notes_prefix, reason);
        let body = json!({
            "mode": "block",
            "configuration": {
                "target": "ip",
                "value": ip
            },
            "notes": notes
        });

        let resp = match self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(ip, error = %e, "Cloudflare push_block: HTTP request failed");
                return None;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body_text = resp.text().await.unwrap_or_default();
            if classify_non_2xx_as_duplicate(&body_text) {
                debug!(
                    ip,
                    status, "Cloudflare push_block: IP already blocked (duplicate rule)"
                );
                return None;
            }
            warn!(
                ip,
                status,
                body = body_text.chars().take(200).collect::<String>(),
                "Cloudflare push_block: non-2xx response"
            );
            return None;
        }

        let cf_resp: CloudflareResponse = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(ip, error = %e, "Cloudflare push_block: failed to parse response");
                return None;
            }
        };

        if !cf_resp.success {
            if cf_resp.errors.iter().any(|e| e.code == CF_ERROR_DUPLICATE) {
                debug!(
                    ip,
                    "Cloudflare push_block: IP already blocked (duplicate rule)"
                );
                return None;
            }
            warn!(ip, "Cloudflare push_block: API returned success=false");
            return None;
        }

        cf_resp.result.map(|r| r.id)
    }
}

/// Returns true when the response body indicates the block rule already
/// exists for this IP. Used on non-2xx responses, where Cloudflare reports
/// the duplicate as a `400` with a typed error body.
fn classify_non_2xx_as_duplicate(body: &str) -> bool {
    // Cheap path: look for the numeric code without full deserialization, so
    // malformed or unexpected bodies still hit the regular warn path.
    if let Ok(parsed) = serde_json::from_str::<CloudflareResponse>(body) {
        return parsed.errors.iter().any(|e| e.code == CF_ERROR_DUPLICATE);
    }
    false
}

// ---------------------------------------------------------------------------
// Helper: resolve API token
// ---------------------------------------------------------------------------

/// Resolve the Cloudflare API token.
///
/// Config value takes precedence; falls back to the `CLOUDFLARE_API_TOKEN`
/// environment variable when the config value is empty.
pub fn resolve_api_token(config_token: &str) -> String {
    if !config_token.is_empty() {
        return config_token.to_string();
    }
    std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_configured_when_both_set() {
        let client = CloudflareClient::new("zone123", "token456");
        assert!(client.is_configured());
    }

    #[test]
    fn not_configured_when_zone_empty() {
        let client = CloudflareClient::new("", "token456");
        assert!(!client.is_configured());
    }

    #[test]
    fn not_configured_when_token_empty() {
        let client = CloudflareClient::new("zone123", "");
        assert!(!client.is_configured());
    }

    #[test]
    fn resolve_api_token_prefers_config() {
        // Even if the env var is set, the config value must win.
        // We set a non-empty config value and verify it is returned as-is.
        let token = resolve_api_token("config-token-abc");
        assert_eq!(token, "config-token-abc");
    }

    #[test]
    fn block_notes_format() {
        let prefix = "innerwarden";
        let reason = "SSH brute-force from 1.2.3.4";
        let notes = format!("{}: {}", prefix, reason);
        assert_eq!(notes, "innerwarden: SSH brute-force from 1.2.3.4");
    }

    #[test]
    fn resolve_api_token_falls_back_to_env_when_config_empty() {
        // Remove env var to ensure a clean state, then check empty config
        // yields empty string (env not set in unit test environment by default).
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
        let token = resolve_api_token("");
        assert_eq!(token, "");
    }

    // ── Duplicate rule (error 10009) classification ─────────────────────────

    #[test]
    fn classify_duplicate_detects_error_10009() {
        // Verbatim shape returned by Cloudflare when a firewall access rule
        // for the same IP already exists.
        let body = r#"{
            "result": null,
            "success": false,
            "errors": [
                {"code": 10009, "message": "firewallaccessrules.api.duplicate_of_existing"}
            ],
            "messages": []
        }"#;
        assert!(classify_non_2xx_as_duplicate(body));
    }

    #[test]
    fn classify_duplicate_ignores_other_errors() {
        let body = r#"{
            "result": null,
            "success": false,
            "errors": [{"code": 10000, "message": "authentication error"}]
        }"#;
        assert!(!classify_non_2xx_as_duplicate(body));
    }

    #[test]
    fn classify_duplicate_ignores_empty_errors() {
        assert!(!classify_non_2xx_as_duplicate(
            r#"{"success": false, "errors": []}"#
        ));
    }

    #[test]
    fn classify_duplicate_ignores_malformed_body() {
        assert!(!classify_non_2xx_as_duplicate("not json at all"));
        assert!(!classify_non_2xx_as_duplicate(""));
    }

    #[test]
    fn classify_duplicate_picks_matching_code_among_many() {
        let body = r#"{
            "success": false,
            "errors": [
                {"code": 1001, "message": "other"},
                {"code": 10009, "message": "dup"}
            ]
        }"#;
        assert!(classify_non_2xx_as_duplicate(body));
    }

    #[test]
    fn cloudflare_response_deserializes_with_errors_array() {
        let body = r#"{
            "success": false,
            "errors": [{"code": 10009, "message": "dup"}]
        }"#;
        let parsed: CloudflareResponse = serde_json::from_str(body).unwrap();
        assert!(!parsed.success);
        assert!(parsed.result.is_none());
        assert_eq!(parsed.errors.len(), 1);
        assert_eq!(parsed.errors[0].code, CF_ERROR_DUPLICATE);
    }

    #[test]
    fn cloudflare_response_deserializes_success_without_errors_field() {
        // Successful creation response has no `errors` key at all — default
        // handling must produce an empty vec so the deserializer succeeds.
        let body = r#"{
            "success": true,
            "result": {"id": "abc123"}
        }"#;
        let parsed: CloudflareResponse = serde_json::from_str(body).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.result.unwrap().id, "abc123");
        assert!(parsed.errors.is_empty());
    }

    // ── Wave 9g anchors (2026-05-04) — CIDR validation gate ──────────────
    //
    // AUDIT-017 root: the agent fed mesh-block CIDRs straight to Cloudflare's
    // IP Access Rules API. Cloudflare only accepts a fixed set of prefix
    // widths (IPv4: /16 /24 /32; IPv6: /32 /48 /64). Any other shape gets a
    // 400 with `firewallaccessrules.api.validation_error: invalid ip
    // provided`. Pre-fix the agent wasted an HTTP round trip + emitted a
    // WARN per attempt. These anchors pin the validator so a future change
    // that loosens the gate (or a Cloudflare doc-set we mis-read) is caught
    // at test time, not at the next mesh-block.

    #[test]
    fn cloudflare_target_is_valid_accepts_bare_ipv4() {
        assert!(cloudflare_target_is_valid("1.2.3.4"));
        assert!(cloudflare_target_is_valid("203.0.113.42"));
        assert!(cloudflare_target_is_valid("0.0.0.0"));
    }

    #[test]
    fn cloudflare_target_is_valid_accepts_bare_ipv6() {
        assert!(cloudflare_target_is_valid("2001:db8::1"));
        assert!(cloudflare_target_is_valid("::1"));
    }

    #[test]
    fn cloudflare_target_is_valid_accepts_documented_ipv4_widths() {
        // Only /16, /24, /32 per
        // https://developers.cloudflare.com/waf/tools/ip-access-rules/.
        assert!(cloudflare_target_is_valid("1.2.0.0/16"));
        assert!(cloudflare_target_is_valid("203.0.113.0/24"));
        assert!(cloudflare_target_is_valid("203.0.113.42/32"));
    }

    #[test]
    fn cloudflare_target_is_valid_rejects_undocumented_ipv4_widths() {
        // The exact AUDIT-017 prod failure shape: a /22 mesh-block was fed
        // straight to Cloudflare and got `invalid ip provided`. Pin so we
        // never round-trip these again.
        assert!(!cloudflare_target_is_valid("1.2.0.0/22"));
        assert!(!cloudflare_target_is_valid("10.0.0.0/8"));
        assert!(!cloudflare_target_is_valid("172.16.0.0/12"));
        assert!(!cloudflare_target_is_valid("192.168.0.0/20"));
        assert!(!cloudflare_target_is_valid("203.0.113.0/27"));
        // /0 is not in Cloudflare's supported set (and would be absurd).
        assert!(!cloudflare_target_is_valid("0.0.0.0/0"));
    }

    #[test]
    fn cloudflare_target_is_valid_accepts_documented_ipv6_widths() {
        // IPv6: only /32, /48, /64.
        assert!(cloudflare_target_is_valid("2001:db8::/32"));
        assert!(cloudflare_target_is_valid("2001:db8:1::/48"));
        assert!(cloudflare_target_is_valid("2001:db8:1:2::/64"));
    }

    #[test]
    fn cloudflare_target_is_valid_rejects_undocumented_ipv6_widths() {
        // /128 (single IPv6) is technically a CIDR but Cloudflare expects
        // bare IPv6 for single hosts; require the bare form.
        assert!(!cloudflare_target_is_valid("::1/128"));
        // /16, /24 are valid for IPv4 but NOT for IPv6 per Cloudflare docs.
        assert!(!cloudflare_target_is_valid("2001:db8::/16"));
        assert!(!cloudflare_target_is_valid("2001:db8::/24"));
        assert!(!cloudflare_target_is_valid("2001:db8::/56"));
    }

    #[test]
    fn cloudflare_target_is_valid_rejects_garbage_input() {
        // Defensive: empty, whitespace, non-IP, broken CIDR.
        assert!(!cloudflare_target_is_valid(""));
        assert!(!cloudflare_target_is_valid("   "));
        assert!(!cloudflare_target_is_valid("not-an-ip"));
        assert!(!cloudflare_target_is_valid("1.2.3.4/abc"));
        assert!(!cloudflare_target_is_valid("1.2.3"));
        assert!(!cloudflare_target_is_valid("1.2.3.4/"));
        assert!(!cloudflare_target_is_valid("/24"));
    }

    #[test]
    fn cloudflare_target_is_valid_trims_surrounding_whitespace() {
        // Operator config / operator CLI often produces stray whitespace.
        // Trim before validating so a copy-pasted IP with a trailing newline
        // does not get rejected as malformed.
        assert!(cloudflare_target_is_valid("  1.2.3.4  "));
        assert!(cloudflare_target_is_valid("\t203.0.113.0/24\n"));
    }
}
