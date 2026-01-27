//! Configuration management for OustIP.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

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

    /// Log file path
    pub log_file: String,

    /// Log level (debug, info, warn, error)
    pub log_level: String,

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
            log_file: "/var/log/oustip.log".to_string(),
            log_level: "info".to_string(),
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
            .with_context(|| "Failed to parse config file")?;
        Ok(config)
    }

    /// Save configuration to YAML file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_yaml::to_string(self)
            .with_context(|| "Failed to serialize config")?;
        std::fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write config file: {:?}", path.as_ref()))?;
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Auto,
    Iptables,
    Nftables,
}

impl Default for Backend {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    /// Table raw PREROUTING (before conntrack, more performant)
    Raw,
    /// After conntrack (allows responses to LAN-initiated connections)
    Conntrack,
}

impl Default for FilterMode {
    fn default() -> Self {
        Self::Conntrack
    }
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
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    pub headers: HashMap<String, String>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6BootState {
    Disabled,
    Enabled,
    Unchanged,
}

impl Default for Ipv6BootState {
    fn default() -> Self {
        Self::Unchanged
    }
}

/// Get blocklist names for a preset
fn get_preset_lists(preset: &str) -> Option<Vec<&'static str>> {
    match preset {
        "minimal" => Some(vec![
            "spamhaus_drop",
            "spamhaus_edrop",
            "dshield",
        ]),
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
        "192.168.0.0/16".to_string(),  // RFC1918
        "10.0.0.0/8".to_string(),       // RFC1918
        "172.16.0.0/12".to_string(),    // RFC1918
        "127.0.0.0/8".to_string(),      // Loopback
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
}
