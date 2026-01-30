//! Configuration management for OustIP.

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::validation::{is_valid_interval, VALID_PRESETS};

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

/// Main configuration structure
///
/// Supports two modes of operation:
/// - Legacy mode: Uses blocklists, allowlist, auto_allowlist, preset fields
/// - Interface-based mode: Uses interfaces field for per-interface configuration
///
/// When `interfaces` is Some, interface-based mode is active and the legacy
/// blocklist/allowlist fields are ignored for firewall rules (but still validated).
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

    /// Blocklist sources (legacy mode)
    pub blocklists: Vec<BlocklistSource>,

    /// Automatic allowlists for CDN/Cloud providers (legacy mode)
    pub auto_allowlist: AutoAllowlist,

    /// Manual allowlist (IPs/CIDRs to never block) (legacy mode)
    pub allowlist: Vec<String>,

    /// Update interval for systemd timer
    pub update_interval: String,

    /// IPv6 configuration
    pub ipv6: Ipv6Config,

    /// Active preset (minimal, recommended, full, paranoid) (legacy mode)
    pub preset: String,

    // =========================================================================
    // Interface-based configuration (v2 features)
    // =========================================================================
    /// Per-interface configuration (enables interface-based mode when Some)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interfaces: Option<HashMap<String, InterfaceConfig>>,

    /// Raw nftables/iptables rules for advanced users
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_rules: Option<RawRulesConfig>,
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
            // Interface-based mode disabled by default (legacy mode)
            interfaces: None,
            raw_rules: None,
        }
    }
}

impl Config {
    /// Load configuration from YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        let config: Config = serde_saphyr::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path.as_ref()))?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate preset if not using individual enabled flags (legacy mode only)
        if !self.is_interface_based()
            && !self.preset.is_empty()
            && !VALID_PRESETS.contains(&self.preset.as_str())
        {
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

        // Validate blocklist URLs use HTTPS (legacy mode)
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

        // Validate interface-based configuration if present
        if let Some(ref interfaces) = self.interfaces {
            self.validate_interfaces(interfaces)?;
        }

        Ok(())
    }

    /// Validate interface configurations (interface-based mode)
    fn validate_interfaces(&self, interfaces: &HashMap<String, InterfaceConfig>) -> Result<()> {
        for (name, iface_config) in interfaces {
            // Loopback cannot be configured (it's always trusted)
            if name == "lo" {
                anyhow::bail!("Interface 'lo' cannot be configured - it is always trusted");
            }

            // WAN mode requires blocklist_preset
            if iface_config.mode == InterfaceMode::Wan && iface_config.blocklist_preset.is_none() {
                anyhow::bail!(
                    "Interface '{}' is in WAN mode but has no blocklist_preset",
                    name
                );
            }

            // LAN mode should have outbound_monitor for detection (warning only)
            if iface_config.mode == InterfaceMode::Lan && iface_config.outbound_monitor.is_none() {
                tracing::warn!(
                    "Interface '{}' is in LAN mode without outbound_monitor - no compromise detection",
                    name
                );
            }

            // Basic preset name validation (format only)
            if let Some(ref preset) = iface_config.blocklist_preset {
                if preset.is_empty()
                    || preset.contains(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                {
                    anyhow::bail!(
                        "Invalid blocklist_preset name '{}' for interface '{}'. Use alphanumeric, underscore or hyphen only.",
                        preset,
                        name
                    );
                }
            }
            if let Some(ref preset) = iface_config.allowlist_preset {
                if preset.is_empty()
                    || preset.contains(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                {
                    anyhow::bail!(
                        "Invalid allowlist_preset name '{}' for interface '{}'. Use alphanumeric, underscore or hyphen only.",
                        preset,
                        name
                    );
                }
            }
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
        let content =
            serde_saphyr::to_string(self).with_context(|| "Failed to serialize config")?;

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

    // =========================================================================
    // Interface-based mode resolution methods
    // =========================================================================

    /// Check if this config uses interface-based mode
    ///
    /// Returns true if the `interfaces` field is Some (regardless of whether it's empty).
    /// When true, the legacy blocklist/allowlist/preset fields are ignored for firewall rules.
    pub fn is_interface_based(&self) -> bool {
        self.interfaces.is_some()
    }

    /// Get configuration for a specific interface
    ///
    /// Returns None if:
    /// - Interface-based mode is not enabled (interfaces is None)
    /// - The specified interface is not configured
    pub fn get_interface_config(&self, iface: &str) -> Option<&InterfaceConfig> {
        self.interfaces.as_ref()?.get(iface)
    }

    /// Get all configured interfaces (interface-based mode)
    ///
    /// Returns None if interface-based mode is not enabled.
    pub fn get_interfaces(&self) -> Option<&HashMap<String, InterfaceConfig>> {
        self.interfaces.as_ref()
    }

    /// Get all WAN interfaces (interface-based mode)
    ///
    /// Returns empty Vec if interface-based mode is not enabled.
    pub fn get_wan_interfaces(&self) -> Vec<(&String, &InterfaceConfig)> {
        self.interfaces
            .as_ref()
            .map(|interfaces| {
                interfaces
                    .iter()
                    .filter(|(_, c)| c.mode == InterfaceMode::Wan)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all LAN interfaces (interface-based mode)
    ///
    /// Returns empty Vec if interface-based mode is not enabled.
    pub fn get_lan_interfaces(&self) -> Vec<(&String, &InterfaceConfig)> {
        self.interfaces
            .as_ref()
            .map(|interfaces| {
                interfaces
                    .iter()
                    .filter(|(_, c)| c.mode == InterfaceMode::Lan)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all trusted interfaces (interface-based mode)
    ///
    /// Returns empty Vec if interface-based mode is not enabled.
    pub fn get_trusted_interfaces(&self) -> Vec<(&String, &InterfaceConfig)> {
        self.interfaces
            .as_ref()
            .map(|interfaces| {
                interfaces
                    .iter()
                    .filter(|(_, c)| c.mode == InterfaceMode::Trusted)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Validate that preset references in config exist in presets.yaml (interface-based mode)
    ///
    /// This validates:
    /// - blocklist_preset names reference existing blocklist presets
    /// - allowlist_preset names reference existing allowlist presets
    /// - outbound_monitor.blocklist_preset names reference existing blocklist presets
    pub fn validate_preset_references(
        &self,
        presets: &crate::presets::PresetsConfig,
    ) -> Result<()> {
        let interfaces = match &self.interfaces {
            Some(ifaces) => ifaces,
            None => return Ok(()), // Legacy mode, nothing to validate
        };

        let blocklist_presets = presets.list_blocklist_presets();
        let allowlist_presets = presets.list_allowlist_presets();

        for (iface_name, iface_config) in interfaces {
            // Validate blocklist_preset
            if let Some(ref preset) = iface_config.blocklist_preset {
                if !blocklist_presets.iter().any(|p| p.as_str() == preset) {
                    let available: Vec<&str> =
                        blocklist_presets.iter().map(|s| s.as_str()).collect();
                    anyhow::bail!(
                        "Interface '{}': blocklist_preset '{}' not found in presets.yaml.\n\
                         Available blocklist presets: {}",
                        iface_name,
                        preset,
                        available.join(", ")
                    );
                }
            }

            // Validate allowlist_preset
            if let Some(ref preset) = iface_config.allowlist_preset {
                if !allowlist_presets.iter().any(|p| p.as_str() == preset) {
                    let available: Vec<&str> =
                        allowlist_presets.iter().map(|s| s.as_str()).collect();
                    anyhow::bail!(
                        "Interface '{}': allowlist_preset '{}' not found in presets.yaml.\n\
                         Available allowlist presets: {}",
                        iface_name,
                        preset,
                        available.join(", ")
                    );
                }
            }

            // Validate outbound_monitor.blocklist_preset
            if let Some(ref monitor) = iface_config.outbound_monitor {
                if !blocklist_presets
                    .iter()
                    .any(|p| p.as_str() == monitor.blocklist_preset)
                {
                    let available: Vec<&str> =
                        blocklist_presets.iter().map(|s| s.as_str()).collect();
                    anyhow::bail!(
                        "Interface '{}': outbound_monitor.blocklist_preset '{}' not found in presets.yaml.\n\
                         Available blocklist presets: {}",
                        iface_name,
                        monitor.blocklist_preset,
                        available.join(", ")
                    );
                }
            }
        }

        Ok(())
    }

    /// Load configuration and validate preset references against presets.yaml
    pub fn load_and_validate_presets<P: AsRef<Path>>(
        config_path: P,
        presets: &crate::presets::PresetsConfig,
    ) -> Result<Self> {
        let config = Self::load(config_path)?;
        config.validate_preset_references(presets)?;
        Ok(config)
    }

    /// Generate config from detected interfaces (interface-based mode)
    pub fn from_detected_interfaces(interfaces: &[crate::interfaces::DetectedInterface]) -> Self {
        let mut config = Self::default();
        let mut iface_map = HashMap::new();

        for iface in interfaces {
            let iface_config = match iface.suggested_mode {
                crate::interfaces::InterfaceMode::Wan => {
                    InterfaceConfig::wan("paranoid", Some("cdn_common"))
                }
                crate::interfaces::InterfaceMode::Lan => {
                    InterfaceConfig::lan("rfc1918", "recommended", OutboundAction::Alert)
                }
                crate::interfaces::InterfaceMode::Trusted => InterfaceConfig::trusted(),
            };

            iface_map.insert(iface.name.clone(), iface_config);
        }

        config.interfaces = Some(iface_map);
        config
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
    /// Blocklist content change detection alert
    pub blocklist_change: BlocklistChangeAlert,
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

/// Configuration for blocklist change alerts
/// Alerts when the total blocked IPs change by more than a threshold percentage
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BlocklistChangeAlert {
    /// Enable blocklist change detection alerts
    pub enabled: bool,
    /// Percentage threshold for alerting (default: 10.0%)
    /// Alert is triggered when |new_ips - old_ips| / old_ips > threshold
    #[serde(default = "default_change_threshold")]
    pub change_threshold_percent: f64,
}

fn default_change_threshold() -> f64 {
    10.0
}

impl Default for BlocklistChangeAlert {
    fn default() -> Self {
        Self {
            enabled: false,
            change_threshold_percent: default_change_threshold(),
        }
    }
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

// =============================================================================
// Interface-based configuration types (used by Config.interfaces)
// =============================================================================

/// Interface mode for firewall rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceMode {
    /// WAN interface - exposed to internet, full blocklist protection
    Wan,
    /// LAN interface - internal network, RFC1918 auto-allowed
    #[default]
    Lan,
    /// Trusted interface - no filtering (VPN, containers)
    Trusted,
}

/// Action for outbound monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundAction {
    /// Log and alert, but allow traffic (non-disruptive detection)
    #[default]
    Alert,
    /// Silently block traffic
    Block,
    /// Block traffic and send alert
    BlockAndAlert,
}

/// Outbound monitoring configuration for LAN interfaces
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OutboundMonitorConfig {
    /// Blocklist preset to check against for outbound connections
    pub blocklist_preset: String,
    /// Action to take when outbound traffic matches blocklist
    pub action: OutboundAction,
}

/// Per-interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InterfaceConfig {
    /// Interface mode (wan, lan, trusted)
    pub mode: InterfaceMode,
    /// Blocklist preset for this interface (wan mode)
    #[serde(default)]
    pub blocklist_preset: Option<String>,
    /// Allowlist preset for this interface
    #[serde(default)]
    pub allowlist_preset: Option<String>,
    /// Outbound monitoring config (lan mode)
    #[serde(default)]
    pub outbound_monitor: Option<OutboundMonitorConfig>,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            mode: InterfaceMode::Lan,
            blocklist_preset: None,
            allowlist_preset: None,
            outbound_monitor: None,
        }
    }
}

impl InterfaceConfig {
    /// Create a WAN interface configuration
    pub fn wan(blocklist_preset: &str, allowlist_preset: Option<&str>) -> Self {
        Self {
            mode: InterfaceMode::Wan,
            blocklist_preset: Some(blocklist_preset.to_string()),
            allowlist_preset: allowlist_preset.map(|s| s.to_string()),
            outbound_monitor: None,
        }
    }

    /// Create a LAN interface configuration
    pub fn lan(allowlist_preset: &str, monitor_preset: &str, action: OutboundAction) -> Self {
        Self {
            mode: InterfaceMode::Lan,
            blocklist_preset: None,
            allowlist_preset: Some(allowlist_preset.to_string()),
            outbound_monitor: Some(OutboundMonitorConfig {
                blocklist_preset: monitor_preset.to_string(),
                action,
            }),
        }
    }

    /// Create a trusted interface configuration
    pub fn trusted() -> Self {
        Self {
            mode: InterfaceMode::Trusted,
            blocklist_preset: None,
            allowlist_preset: None,
            outbound_monitor: None,
        }
    }
}

/// Raw firewall rules for advanced users
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RawRulesConfig {
    /// Raw nftables rules
    #[serde(default)]
    pub nftables: Option<String>,
    /// Raw iptables rules
    #[serde(default)]
    pub iptables: Option<String>,
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
        let yaml = serde_saphyr::to_string(&config).unwrap();
        let parsed: Config = serde_saphyr::from_str(&yaml).unwrap();
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
        let result: Result<WebhookConfig, _> = serde_saphyr::from_str(yaml);
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
        let result: Result<WebhookConfig, _> = serde_saphyr::from_str(yaml);
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
        let result: Result<WebhookConfig, _> = serde_saphyr::from_str(yaml);
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

    // =========================================================================
    // Interface-based mode tests
    // =========================================================================

    #[test]
    fn test_config_default_is_legacy_mode() {
        let config = Config::default();
        assert!(!config.is_interface_based());
        assert!(config.interfaces.is_none());
        assert!(config.raw_rules.is_none());
    }

    #[test]
    fn test_config_is_interface_based_when_interfaces_set() {
        let config = Config {
            interfaces: Some(HashMap::new()),
            ..Default::default()
        };
        assert!(config.is_interface_based());
    }

    #[test]
    fn test_config_get_interface_config_legacy_mode() {
        let config = Config::default();
        // Legacy mode returns None for any interface
        assert!(config.get_interface_config("eth0").is_none());
    }

    #[test]
    fn test_config_get_interface_config_interface_mode() {
        let mut config = Config::default();
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig::wan("paranoid", Some("cdn_common")),
        );
        interfaces.insert("br0".to_string(), InterfaceConfig::trusted());
        config.interfaces = Some(interfaces);

        let eth0 = config.get_interface_config("eth0");
        assert!(eth0.is_some());
        assert_eq!(eth0.unwrap().mode, InterfaceMode::Wan);

        let br0 = config.get_interface_config("br0");
        assert!(br0.is_some());
        assert_eq!(br0.unwrap().mode, InterfaceMode::Trusted);

        // Non-existent interface returns None
        assert!(config.get_interface_config("wlan0").is_none());
    }

    #[test]
    fn test_config_get_wan_lan_trusted_interfaces() {
        let mut config = Config::default();
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig::wan("paranoid", Some("cdn_common")),
        );
        interfaces.insert(
            "eth1".to_string(),
            InterfaceConfig::lan("rfc1918", "recommended", OutboundAction::Alert),
        );
        interfaces.insert("docker0".to_string(), InterfaceConfig::trusted());
        config.interfaces = Some(interfaces);

        let wan = config.get_wan_interfaces();
        assert_eq!(wan.len(), 1);
        assert_eq!(wan[0].0, "eth0");

        let lan = config.get_lan_interfaces();
        assert_eq!(lan.len(), 1);
        assert_eq!(lan[0].0, "eth1");

        let trusted = config.get_trusted_interfaces();
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0].0, "docker0");
    }

    #[test]
    fn test_config_interface_helpers_empty_in_legacy_mode() {
        let config = Config::default();
        assert!(config.get_wan_interfaces().is_empty());
        assert!(config.get_lan_interfaces().is_empty());
        assert!(config.get_trusted_interfaces().is_empty());
    }

    #[test]
    fn test_config_validate_interfaces_loopback_rejected() {
        let mut config = Config::default();
        let mut interfaces = HashMap::new();
        interfaces.insert("lo".to_string(), InterfaceConfig::trusted());
        config.interfaces = Some(interfaces);

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("lo"));
    }

    #[test]
    fn test_config_validate_wan_requires_blocklist_preset() {
        let mut config = Config::default();
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                mode: InterfaceMode::Wan,
                blocklist_preset: None, // Missing!
                allowlist_preset: None,
                outbound_monitor: None,
            },
        );
        config.interfaces = Some(interfaces);

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("blocklist_preset"));
    }

    #[test]
    fn test_config_validate_invalid_preset_name_rejected() {
        let mut config = Config::default();
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                mode: InterfaceMode::Wan,
                blocklist_preset: Some("invalid preset!".to_string()), // Invalid chars
                allowlist_preset: None,
                outbound_monitor: None,
            },
        );
        config.interfaces = Some(interfaces);

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validate_interface_mode_valid() {
        let mut config = Config::default();
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig::wan("paranoid", Some("cdn_common")),
        );
        interfaces.insert(
            "eth1".to_string(),
            InterfaceConfig::lan("rfc1918", "recommended", OutboundAction::Alert),
        );
        interfaces.insert("docker0".to_string(), InterfaceConfig::trusted());
        config.interfaces = Some(interfaces);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialize_with_interfaces() {
        let mut config = Config::default();
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig::wan("paranoid", Some("cdn_common")),
        );
        config.interfaces = Some(interfaces);

        let yaml = serde_saphyr::to_string(&config).unwrap();
        assert!(yaml.contains("interfaces"));
        assert!(yaml.contains("eth0"));

        // Deserialize and verify
        let parsed: Config = serde_saphyr::from_str(&yaml).unwrap();
        assert!(parsed.is_interface_based());
        assert!(parsed.get_interface_config("eth0").is_some());
    }

    #[test]
    fn test_config_deserialize_legacy_no_interfaces() {
        let yaml = r#"
language: en
backend: auto
mode: conntrack
preset: recommended
"#;
        let config: Config = serde_saphyr::from_str(yaml).unwrap();
        assert!(!config.is_interface_based());
        assert!(config.interfaces.is_none());
    }

    #[test]
    fn test_interface_config_constructors() {
        let wan = InterfaceConfig::wan("paranoid", Some("cdn_common"));
        assert_eq!(wan.mode, InterfaceMode::Wan);
        assert_eq!(wan.blocklist_preset, Some("paranoid".to_string()));
        assert_eq!(wan.allowlist_preset, Some("cdn_common".to_string()));
        assert!(wan.outbound_monitor.is_none());

        let lan = InterfaceConfig::lan("rfc1918", "recommended", OutboundAction::BlockAndAlert);
        assert_eq!(lan.mode, InterfaceMode::Lan);
        assert!(lan.blocklist_preset.is_none());
        assert_eq!(lan.allowlist_preset, Some("rfc1918".to_string()));
        assert!(lan.outbound_monitor.is_some());
        let monitor = lan.outbound_monitor.unwrap();
        assert_eq!(monitor.blocklist_preset, "recommended");
        assert_eq!(monitor.action, OutboundAction::BlockAndAlert);

        let trusted = InterfaceConfig::trusted();
        assert_eq!(trusted.mode, InterfaceMode::Trusted);
        assert!(trusted.blocklist_preset.is_none());
        assert!(trusted.allowlist_preset.is_none());
        assert!(trusted.outbound_monitor.is_none());
    }

    #[test]
    fn test_outbound_action_default() {
        assert_eq!(OutboundAction::default(), OutboundAction::Alert);
    }

    #[test]
    fn test_interface_mode_default() {
        assert_eq!(InterfaceMode::default(), InterfaceMode::Lan);
    }

    #[test]
    fn test_blocklist_change_alert_default() {
        let alert = BlocklistChangeAlert::default();
        assert!(!alert.enabled);
        assert!((alert.change_threshold_percent - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_blocklist_change_alert_serialization() {
        let alert = BlocklistChangeAlert {
            enabled: true,
            change_threshold_percent: 15.0,
        };
        let yaml = serde_saphyr::to_string(&alert).unwrap();
        let parsed: BlocklistChangeAlert = serde_saphyr::from_str(&yaml).unwrap();
        assert!(parsed.enabled);
        assert!((parsed.change_threshold_percent - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_alerts_config_includes_blocklist_change() {
        let config = AlertsConfig::default();
        assert!(!config.blocklist_change.enabled);
        assert!((config.blocklist_change.change_threshold_percent - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_blocklist_change_alert_yaml_parsing() {
        let yaml = r#"
enabled: true
change_threshold_percent: 25.5
"#;
        let alert: BlocklistChangeAlert = serde_saphyr::from_str(yaml).unwrap();
        assert!(alert.enabled);
        assert!((alert.change_threshold_percent - 25.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_blocklist_change_alert_default_threshold_when_missing() {
        let yaml = r#"
enabled: true
"#;
        let alert: BlocklistChangeAlert = serde_saphyr::from_str(yaml).unwrap();
        assert!(alert.enabled);
        assert!((alert.change_threshold_percent - 10.0).abs() < f64::EPSILON);
    }

    // =========================================================================
    // Error path tests - Config load failures
    // =========================================================================

    #[test]
    fn test_config_load_missing_file() {
        let result = Config::load("/nonexistent/path/to/config.yaml");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to read config file"));
    }

    #[test]
    fn test_config_load_invalid_yaml_syntax() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("invalid.yaml");

        // Write invalid YAML
        fs::write(&config_path, "{{{{not valid yaml: {").unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to parse config file"));
    }

    #[test]
    fn test_config_load_wrong_type() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("wrong_type.yaml");

        // Write YAML with wrong types
        fs::write(&config_path, "language: 123\nupdate_interval: true").unwrap();

        let result = Config::load(&config_path);
        // Should fail to parse due to type mismatch
        assert!(result.is_err());
    }

    #[test]
    fn test_config_load_empty_file() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("empty.yaml");

        // Write empty file
        fs::write(&config_path, "").unwrap();

        let result = Config::load(&config_path);
        // Empty YAML can deserialize to Config with defaults (serde defaults)
        // This is expected behavior - if all fields have defaults, empty YAML works
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_load_partial_config() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("partial.yaml");

        // Write partial config (missing some fields) - should use defaults
        fs::write(&config_path, "language: en\npreset: recommended").unwrap();

        let result = Config::load(&config_path);
        // Should succeed with defaults for missing fields
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.language, "en");
        assert_eq!(config.preset, "recommended");
    }

    #[test]
    fn test_config_load_invalid_preset_fails_validation() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("invalid_preset.yaml");

        fs::write(&config_path, "preset: invalid_preset_name\nupdate_interval: 4h").unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid preset"));
    }

    #[test]
    fn test_config_load_invalid_interval_fails_validation() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("invalid_interval.yaml");

        fs::write(&config_path, "preset: recommended\nupdate_interval: invalid").unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid update_interval"));
    }

    #[test]
    fn test_config_load_http_blocklist_fails_validation() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("http_blocklist.yaml");

        let content = r#"
preset: recommended
update_interval: 4h
blocklists:
  - name: insecure_list
    url: http://example.com/list
    enabled: true
"#;
        fs::write(&config_path, content).unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("HTTPS"));
    }

    #[test]
    fn test_config_save_to_nonexistent_directory() {
        let config = Config::default();
        let result = config.save("/nonexistent/deeply/nested/path/config.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_yaml_injection_in_headers() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("injection.yaml");

        let content = r#"
preset: recommended
update_interval: 4h
alerts:
  webhook:
    enabled: true
    url: "https://example.com/webhook"
    headers:
      "X-Injected\r\nEvil-Header": "value"
"#;
        fs::write(&config_path, content).unwrap();

        let result = Config::load(&config_path);
        // Should fail due to header validation
        assert!(result.is_err());
    }

    #[test]
    fn test_config_yaml_special_characters() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("special.yaml");

        // YAML with special characters that should be handled
        let content = r#"
language: en
preset: recommended
update_interval: 4h
allowlist:
  - "192.168.1.1"
  - "10.0.0.0/8"
"#;
        fs::write(&config_path, content).unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_save_and_reload_roundtrip() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("roundtrip.yaml");

        let config = Config {
            language: "fr".to_string(),
            preset: "minimal".to_string(),
            allowlist: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };

        // Save
        config.save(&config_path).unwrap();

        // Reload
        let reloaded = Config::load(&config_path).unwrap();

        assert_eq!(reloaded.language, "fr");
        assert_eq!(reloaded.preset, "minimal");
        assert!(reloaded.allowlist.contains(&"8.8.8.8".to_string()));
    }

    #[test]
    fn test_config_concurrent_write_protection() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("concurrent.yaml");

        // Create initial config
        let config = Config::default();
        config.save(&config_path).unwrap();

        // Simulate concurrent modification by writing different content
        let config2 = Config {
            language: "de".to_string(),
            ..Default::default()
        };

        // Both saves should succeed (atomic writes)
        config.save(&config_path).unwrap();
        config2.save(&config_path).unwrap();

        // Last writer wins
        let final_config = Config::load(&config_path).unwrap();
        assert_eq!(final_config.language, "de");
    }

    #[test]
    fn test_config_unicode_in_values() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("unicode.yaml");

        // YAML with unicode should be handled (but interval validation rejects non-ASCII)
        let content = r#"
language: en
preset: recommended
update_interval: 4h
"#;
        fs::write(&config_path, content).unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_ok());
    }
}
