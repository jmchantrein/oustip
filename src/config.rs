//! Configuration management for OustIP.

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Valid preset values
const VALID_PRESETS: &[&str] = &["minimal", "recommended", "full", "paranoid"];

/// Secure string type that zeroizes memory on drop
/// Used for sensitive data like tokens and passwords
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Timer interval validation (e.g., "4h", "30m", "1d")
/// Requires ASCII-only input to prevent Unicode-related edge cases
fn is_valid_interval(interval: &str) -> bool {
    // Reject non-ASCII to prevent Unicode edge cases with split_at
    if !interval.is_ascii() || interval.len() < 2 {
        return false;
    }

    // Safe to use chars() since we verified ASCII-only
    let suffix = interval.chars().last().unwrap();
    let num_part = &interval[..interval.len() - 1];

    matches!(suffix, 's' | 'm' | 'h' | 'd') && num_part.parse::<u32>().is_ok()
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Language for messages (en, fr)
    pub language: String,

    /// Firewall backend (auto, iptables, nftables)
    pub backend: Backend,

    /// Filtering mode (raw, conntrack)
    pub mode: FilterMode,

    /// Alert when LAN tries to connect to blocked IP (only in conntrack mode)
    pub alert_outbound_to_blocklist: bool,

    /// Alert destinations
    pub alerts: AlertsConfig,

    /// Blocklist sources
    pub blocklists: Vec<BlocklistSource>,

    /// Automatic allowlists for CDN/Cloud providers
    pub auto_allowlist: AutoAllowlist,

    /// Manual allowlist (IPs/CIDRs to never block)
    pub allowlist: Vec<String>,

    /// Update interval for systemd timer
    pub update_interval: String,

    /// IPv6 configuration
    pub ipv6: Ipv6Config,

    /// Active preset (minimal, recommended, full, paranoid)
    pub preset: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            language: "en".to_string(),
            backend: Backend::Auto,
            mode: FilterMode::Conntrack,
            alert_outbound_to_blocklist: true,
            alerts: AlertsConfig::default(),
            blocklists: default_blocklists(),
            auto_allowlist: AutoAllowlist::default(),
            allowlist: default_allowlist(),
            update_interval: "4h".to_string(),
            ipv6: Ipv6Config::default(),
            preset: "recommended".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path.as_ref()))?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate preset if not using individual enabled flags
        if !self.preset.is_empty() && !VALID_PRESETS.contains(&self.preset.as_str()) {
            anyhow::bail!(
                "Invalid preset '{}'. Valid values: {}",
                self.preset,
                VALID_PRESETS.join(", ")
            );
        }

        // Validate update interval format
        if !is_valid_interval(&self.update_interval) {
            anyhow::bail!(
                "Invalid update_interval '{}'. Use format like '4h', '30m', '1d'",
                self.update_interval
            );
        }

        // Validate blocklist URLs use HTTPS
        for blocklist in &self.blocklists {
            if blocklist.enabled && !blocklist.url.starts_with("https://") {
                anyhow::bail!(
                    "Blocklist '{}' URL must use HTTPS: {}",
                    blocklist.name,
                    blocklist.url
                );
            }
        }

        // Validate webhook URL uses HTTPS if enabled
        if self.alerts.webhook.enabled
            && !self.alerts.webhook.url.is_empty()
            && !self.alerts.webhook.url.starts_with("https://")
        {
            anyhow::bail!("Webhook URL must use HTTPS: {}", self.alerts.webhook.url);
        }

        // Validate Gotify URL uses HTTPS if enabled
        if self.alerts.gotify.enabled
            && !self.alerts.gotify.url.is_empty()
            && !self.alerts.gotify.url.starts_with("https://")
        {
            anyhow::bail!("Gotify URL must use HTTPS: {}", self.alerts.gotify.url);
        }

        Ok(())
    }

    /// Save configuration to YAML file atomically
    ///
    /// Uses tempfile + rename pattern to prevent corruption on crash.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let path = path.as_ref();
        let content = serde_yaml::to_string(self).with_context(|| "Failed to serialize config")?;

        // Create temporary file in the same directory for atomic rename
        let parent_dir = path.parent().unwrap_or(Path::new("/etc/oustip"));
        let mut temp_file = NamedTempFile::new_in(parent_dir)
            .context("Failed to create temporary file for config")?;

        // Write content and ensure it's flushed to disk
        temp_file.write_all(content.as_bytes())?;
        temp_file.as_file().sync_all()?;

        // Atomically rename temp file to target
        temp_file
            .persist(path)
            .with_context(|| format!("Failed to persist config file: {:?}", path))?;

        Ok(())
    }

    /// Get enabled blocklists based on preset
    pub fn get_enabled_blocklists(&self, preset_override: Option<&str>) -> Vec<&BlocklistSource> {
        let preset = preset_override.unwrap_or(&self.preset);
        let preset_lists = get_preset_lists(preset);

        self.blocklists
            .iter()
            .filter(|b| {
                if let Some(ref lists) = preset_lists {
                    lists.contains(&b.name.as_str())
                } else {
                    b.enabled
                }
            })
            .collect()
    }

    /// Generate default config with comments
    pub fn generate_default_yaml() -> String {
        include_str!("../templates/config.yaml").to_string()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Auto-detect backend (checks nftables first, then iptables)
    Auto,
    /// Use iptables/ipset backend
    Iptables,
    /// Use nftables backend (default, recommended for performance)
    #[default]
    Nftables,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    /// Table raw PREROUTING (before conntrack, more performant)
    Raw,
    /// After conntrack (allows responses to LAN-initiated connections)
    #[default]
    Conntrack,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AlertsConfig {
    pub gotify: GotifyConfig,
    pub email: EmailConfig,
    pub webhook: WebhookConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GotifyConfig {
    pub enabled: bool,
    pub url: String,
    /// Token can be set directly or via OUSTIP_GOTIFY_TOKEN env var
    /// Memory is securely zeroed when dropped
    pub token: SecureString,
    /// Environment variable name to read token from (optional)
    #[serde(default)]
    pub token_env: Option<String>,
}

impl GotifyConfig {
    /// Get the effective token, checking env var first if configured
    /// Returns a SecureString that will be zeroed when dropped
    pub fn get_token(&self) -> SecureString {
        // First check custom env var if specified
        if let Some(ref env_name) = self.token_env {
            if let Ok(val) = env::var(env_name) {
                return SecureString::new(val);
            }
        }
        // Then check default env var
        if let Ok(val) = env::var("OUSTIP_GOTIFY_TOKEN") {
            return SecureString::new(val);
        }
        // Fall back to config value
        self.token.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    /// Password can be set directly or via OUSTIP_SMTP_PASSWORD env var
    /// Memory is securely zeroed when dropped
    pub smtp_password: SecureString,
    /// Environment variable name to read password from (optional)
    #[serde(default)]
    pub smtp_password_env: Option<String>,
    pub from: String,
    pub to: String,
}

impl EmailConfig {
    /// Get the effective password, checking env var first if configured
    /// Returns a SecureString that will be zeroed when dropped
    pub fn get_password(&self) -> SecureString {
        // First check custom env var if specified
        if let Some(ref env_name) = self.smtp_password_env {
            if let Ok(val) = env::var(env_name) {
                return SecureString::new(val);
            }
        }
        // Then check default env var
        if let Ok(val) = env::var("OUSTIP_SMTP_PASSWORD") {
            return SecureString::new(val);
        }
        // Fall back to config value
        self.smtp_password.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    #[serde(deserialize_with = "deserialize_headers")]
    pub headers: HashMap<String, String>,
}

/// Deserialize and validate HTTP headers (reject injection attempts)
fn deserialize_headers<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let headers: HashMap<String, String> = HashMap::deserialize(deserializer)?;

    // Validate each header for injection attacks
    for (key, value) in &headers {
        if key.contains('\r') || key.contains('\n') {
            return Err(serde::de::Error::custom(format!(
                "Invalid header name '{}': contains newline characters",
                key
            )));
        }
        if value.contains('\r') || value.contains('\n') {
            return Err(serde::de::Error::custom(format!(
                "Invalid header value for '{}': contains newline characters",
                key
            )));
        }
        // Validate header name characters (RFC 7230)
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
        {
            return Err(serde::de::Error::custom(format!(
                "Invalid header name '{}': contains invalid characters",
                key
            )));
        }
    }

    Ok(headers)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSource {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoAllowlist {
    pub cloudflare: bool,
    pub github: bool,
    pub google_cloud: bool,
    pub aws: bool,
    pub fastly: bool,
}

impl Default for AutoAllowlist {
    fn default() -> Self {
        Self {
            cloudflare: true,
            github: true,
            google_cloud: false,
            aws: false,
            fastly: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Ipv6Config {
    /// Boot state: disabled, enabled, unchanged
    pub boot_state: Ipv6BootState,
}

impl Default for Ipv6Config {
    fn default() -> Self {
        Self {
            boot_state: Ipv6BootState::Unchanged,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6BootState {
    Disabled,
    Enabled,
    #[default]
    Unchanged,
}

/// Get blocklist names for a preset
fn get_preset_lists(preset: &str) -> Option<Vec<&'static str>> {
    match preset {
        "minimal" => Some(vec!["spamhaus_drop", "spamhaus_edrop", "dshield"]),
        "recommended" => Some(vec![
            "spamhaus_drop",
            "spamhaus_edrop",
            "dshield",
            "firehol_level1",
            "firehol_level2",
        ]),
        "full" => Some(vec![
            "spamhaus_drop",
            "spamhaus_edrop",
            "dshield",
            "firehol_level1",
            "firehol_level2",
            "firehol_level3",
        ]),
        "paranoid" => Some(vec![
            "spamhaus_drop",
            "spamhaus_edrop",
            "dshield",
            "firehol_level1",
            "firehol_level2",
            "firehol_level3",
            "firehol_level4",
        ]),
        _ => None, // Use individual enabled flags
    }
}

fn default_blocklists() -> Vec<BlocklistSource> {
    vec![
        BlocklistSource {
            name: "firehol_level1".to_string(),
            url: "https://iplists.firehol.org/files/firehol_level1.netset".to_string(),
            enabled: true,
        },
        BlocklistSource {
            name: "firehol_level2".to_string(),
            url: "https://iplists.firehol.org/files/firehol_level2.netset".to_string(),
            enabled: true,
        },
        BlocklistSource {
            name: "spamhaus_drop".to_string(),
            url: "https://iplists.firehol.org/files/spamhaus_drop.netset".to_string(),
            enabled: true,
        },
        BlocklistSource {
            name: "spamhaus_edrop".to_string(),
            url: "https://iplists.firehol.org/files/spamhaus_edrop.netset".to_string(),
            enabled: true,
        },
        BlocklistSource {
            name: "dshield".to_string(),
            url: "https://iplists.firehol.org/files/dshield.netset".to_string(),
            enabled: true,
        },
        BlocklistSource {
            name: "firehol_level3".to_string(),
            url: "https://iplists.firehol.org/files/firehol_level3.netset".to_string(),
            enabled: false,
        },
        BlocklistSource {
            name: "firehol_level4".to_string(),
            url: "https://iplists.firehol.org/files/firehol_level4.netset".to_string(),
            enabled: false,
        },
    ]
}

fn default_allowlist() -> Vec<String> {
    vec![
        "192.168.0.0/16".to_string(), // RFC1918
        "10.0.0.0/8".to_string(),     // RFC1918
        "172.16.0.0/12".to_string(),  // RFC1918
        "127.0.0.0/8".to_string(),    // Loopback
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.language, "en");
        assert_eq!(config.backend, Backend::Auto);
        assert_eq!(config.mode, FilterMode::Conntrack);
        assert_eq!(config.preset, "recommended");
    }

    #[test]
    fn test_preset_lists() {
        let config = Config::default();

        let minimal = config.get_enabled_blocklists(Some("minimal"));
        assert_eq!(minimal.len(), 3);

        let recommended = config.get_enabled_blocklists(Some("recommended"));
        assert_eq!(recommended.len(), 5);

        let full = config.get_enabled_blocklists(Some("full"));
        assert_eq!(full.len(), 6);

        let paranoid = config.get_enabled_blocklists(Some("paranoid"));
        assert_eq!(paranoid.len(), 7);
    }

    #[test]
    fn test_serialize_deserialize() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.language, config.language);
        assert_eq!(parsed.preset, config.preset);
    }

    #[test]
    fn test_secure_string_debug_redacted() {
        let secret = SecureString::new("my-secret-token".to_string());
        let debug_str = format!("{:?}", secret);
        assert_eq!(debug_str, "[REDACTED]");
        assert!(!debug_str.contains("my-secret-token"));
    }

    #[test]
    fn test_secure_string_as_str() {
        let secret = SecureString::new("test-value".to_string());
        assert_eq!(secret.as_str(), "test-value");
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_secure_string_default_empty() {
        let secret = SecureString::default();
        assert!(secret.is_empty());
        assert_eq!(secret.as_str(), "");
    }

    #[test]
    fn test_valid_interval() {
        // Valid intervals
        assert!(is_valid_interval("4h"));
        assert!(is_valid_interval("30m"));
        assert!(is_valid_interval("1d"));
        assert!(is_valid_interval("60s"));
        assert!(is_valid_interval("12h"));

        // Invalid intervals
        assert!(!is_valid_interval(""));
        assert!(!is_valid_interval("h"));
        assert!(!is_valid_interval("4"));
        assert!(!is_valid_interval("4x"));
        assert!(!is_valid_interval("abc"));

        // Unicode rejection (security fix) - non-ASCII characters should be rejected
        assert!(!is_valid_interval("４h")); // Full-width digit 4 (non-ASCII)
        assert!(!is_valid_interval("4ℎ")); // Planck constant symbol (non-ASCII h-like)
    }

    #[test]
    fn test_header_validation_rejects_newlines() {
        let yaml = r#"
enabled: true
url: "https://example.com/webhook"
headers:
  "X-Evil": "value\r\ninjected"
"#;
        let result: Result<WebhookConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_validation_rejects_invalid_chars() {
        let yaml = r#"
enabled: true
url: "https://example.com/webhook"
headers:
  "X-Header:Invalid": "value"
"#;
        let result: Result<WebhookConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_validation_accepts_valid() {
        let yaml = r#"
enabled: true
url: "https://example.com/webhook"
headers:
  "X-Custom-Header": "some-value"
  "Authorization": "Bearer token"
"#;
        let result: Result<WebhookConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.headers.len(), 2);
    }

    #[test]
    fn test_config_validation_invalid_preset() {
        let config = Config {
            preset: "invalid_preset".to_string(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid preset"));
    }

    #[test]
    fn test_config_validation_invalid_interval() {
        let config = Config {
            update_interval: "invalid".to_string(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid update_interval"));
    }

    #[test]
    fn test_config_validation_http_url_rejected() {
        let mut blocklists = default_blocklists();
        blocklists[0].url = "http://example.com/list".to_string();
        let config = Config {
            blocklists,
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_config_validation_webhook_http_rejected() {
        let config = Config {
            alerts: AlertsConfig {
                webhook: WebhookConfig {
                    enabled: true,
                    url: "http://example.com/webhook".to_string(),
                    headers: HashMap::new(),
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Webhook"));
    }

    #[test]
    fn test_config_validation_gotify_http_rejected() {
        let config = Config {
            alerts: AlertsConfig {
                gotify: GotifyConfig {
                    enabled: true,
                    url: "http://gotify.example.com".to_string(),
                    token: SecureString::new("token".to_string()),
                    token_env: None,
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Gotify"));
    }

    #[test]
    fn test_config_validation_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_secure_string_from_str() {
        let secure: SecureString = "test".into();
        assert_eq!(secure.as_str(), "test");
    }

    #[test]
    fn test_secure_string_from_string() {
        let secure: SecureString = String::from("test").into();
        assert_eq!(secure.as_str(), "test");
    }

    #[test]
    fn test_backend_default() {
        assert_eq!(Backend::default(), Backend::Nftables);
    }

    #[test]
    fn test_filter_mode_default() {
        assert_eq!(FilterMode::default(), FilterMode::Conntrack);
    }

    #[test]
    fn test_ipv6_boot_state_default() {
        assert_eq!(Ipv6BootState::default(), Ipv6BootState::Unchanged);
    }

    #[test]
    fn test_auto_allowlist_default() {
        let aal = AutoAllowlist::default();
        assert!(aal.cloudflare);
        assert!(aal.github);
        assert!(!aal.google_cloud);
        assert!(!aal.aws);
        assert!(!aal.fastly);
    }

    #[test]
    fn test_default_blocklists_has_expected_entries() {
        let blocklists = default_blocklists();
        assert_eq!(blocklists.len(), 7);

        let names: Vec<&str> = blocklists.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"spamhaus_drop"));
        assert!(names.contains(&"spamhaus_edrop"));
        assert!(names.contains(&"dshield"));
        assert!(names.contains(&"firehol_level1"));
    }

    #[test]
    fn test_default_allowlist_has_rfc1918() {
        let allowlist = default_allowlist();
        assert!(allowlist.contains(&"192.168.0.0/16".to_string()));
        assert!(allowlist.contains(&"10.0.0.0/8".to_string()));
        assert!(allowlist.contains(&"172.16.0.0/12".to_string()));
        assert!(allowlist.contains(&"127.0.0.0/8".to_string()));
    }

    #[test]
    fn test_get_preset_lists_minimal() {
        let lists = get_preset_lists("minimal").unwrap();
        assert_eq!(lists.len(), 3);
        assert!(lists.contains(&"spamhaus_drop"));
    }

    #[test]
    fn test_get_preset_lists_recommended() {
        let lists = get_preset_lists("recommended").unwrap();
        assert_eq!(lists.len(), 5);
    }

    #[test]
    fn test_get_preset_lists_full() {
        let lists = get_preset_lists("full").unwrap();
        assert_eq!(lists.len(), 6);
    }

    #[test]
    fn test_get_preset_lists_paranoid() {
        let lists = get_preset_lists("paranoid").unwrap();
        assert_eq!(lists.len(), 7);
    }

    #[test]
    fn test_get_preset_lists_unknown() {
        let lists = get_preset_lists("unknown");
        assert!(lists.is_none());
    }

    #[test]
    fn test_valid_presets_constant() {
        assert!(VALID_PRESETS.contains(&"minimal"));
        assert!(VALID_PRESETS.contains(&"recommended"));
        assert!(VALID_PRESETS.contains(&"full"));
        assert!(VALID_PRESETS.contains(&"paranoid"));
        assert_eq!(VALID_PRESETS.len(), 4);
    }

    #[test]
    fn test_config_disabled_blocklist_http_allowed() {
        // HTTP URLs are allowed for disabled blocklists
        let mut blocklists = default_blocklists();
        blocklists[5].url = "http://example.com/list".to_string(); // firehol_level3 is disabled
        let config = Config {
            blocklists,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_webhook_config_default() {
        let config = WebhookConfig::default();
        assert!(!config.enabled);
        assert!(config.url.is_empty());
        assert!(config.headers.is_empty());
    }

    #[test]
    fn test_email_config_default() {
        let config = EmailConfig::default();
        assert!(!config.enabled);
        assert!(config.smtp_host.is_empty());
        assert_eq!(config.smtp_port, 0);
    }

    #[test]
    fn test_gotify_config_default() {
        let config = GotifyConfig::default();
        assert!(!config.enabled);
        assert!(config.url.is_empty());
        assert!(config.token.is_empty());
    }

    #[test]
    fn test_blocklist_source_structure() {
        let source = BlocklistSource {
            name: "test".to_string(),
            url: "https://example.com".to_string(),
            enabled: true,
        };
        assert_eq!(source.name, "test");
        assert!(source.url.starts_with("https://"));
        assert!(source.enabled);
    }
}
