//! Presets configuration management for OustIP.
//!
//! This module handles the parsing and resolution of presets.yaml,
//! which defines blocklist and allowlist sources and presets with inheritance.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Default presets file path
pub const DEFAULT_PRESETS_PATH: &str = "/etc/oustip/presets.yaml";

/// Main presets configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PresetsConfig {
    /// Blocklist source definitions
    pub blocklist_sources: HashMap<String, BlocklistSourceDef>,

    /// Blocklist preset definitions
    pub blocklist_presets: HashMap<String, PresetDef>,

    /// Allowlist source definitions
    pub allowlist_sources: HashMap<String, AllowlistSourceDef>,

    /// Allowlist preset definitions
    pub allowlist_presets: HashMap<String, PresetDef>,
}

/// Definition of a blocklist source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSourceDef {
    /// URL to fetch the blocklist from
    pub url: String,

    /// Human-readable description (bilingual)
    #[serde(default)]
    pub description: BilingualText,
}

/// Definition of an allowlist source
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowlistSourceDef {
    /// Static allowlist (inline IP ranges)
    Static {
        /// Static IP ranges
        #[serde(rename = "static")]
        ranges: Vec<String>,
        /// Description
        #[serde(default)]
        description: BilingualText,
    },
    /// Dynamic allowlist (fetched from URL)
    Dynamic {
        /// Primary URL
        url: String,
        /// IPv6 URL (optional)
        #[serde(default)]
        url_v6: Option<String>,
        /// JSON path for extracting IPs (optional)
        #[serde(default)]
        json_path: Option<String>,
        /// Description
        #[serde(default)]
        description: BilingualText,
    },
}

impl AllowlistSourceDef {
    /// Check if this is a static source
    pub fn is_static(&self) -> bool {
        matches!(self, AllowlistSourceDef::Static { .. })
    }

    /// Get static ranges if this is a static source
    pub fn get_static_ranges(&self) -> Option<&Vec<String>> {
        match self {
            AllowlistSourceDef::Static { ranges, .. } => Some(ranges),
            _ => None,
        }
    }

    /// Get URL if this is a dynamic source
    pub fn get_url(&self) -> Option<&str> {
        match self {
            AllowlistSourceDef::Dynamic { url, .. } => Some(url),
            _ => None,
        }
    }

    /// Get JSON path if this is a dynamic source with JSON extraction
    pub fn get_json_path(&self) -> Option<&str> {
        match self {
            AllowlistSourceDef::Dynamic { json_path, .. } => json_path.as_deref(),
            _ => None,
        }
    }
}

/// Bilingual text for descriptions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BilingualText {
    #[serde(default)]
    pub en: String,
    #[serde(default)]
    pub fr: String,
}

impl BilingualText {
    /// Get text in the specified language, falling back to English
    pub fn get(&self, lang: &str) -> &str {
        match lang {
            "fr" if !self.fr.is_empty() => &self.fr,
            _ => &self.en,
        }
    }
}

/// Preset definition with optional inheritance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetDef {
    /// Human-readable description
    #[serde(default)]
    pub description: BilingualText,

    /// Parent preset to inherit from
    #[serde(default)]
    pub extends: Option<String>,

    /// Source names included in this preset
    #[serde(default)]
    pub sources: Vec<String>,
}

impl PresetsConfig {
    /// Load presets configuration from YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read presets file: {:?}", path.as_ref()))?;

        let config: PresetsConfig = serde_yml::from_str(&content)
            .with_context(|| format!("Failed to parse presets file: {:?}", path.as_ref()))?;

        config.validate()?;
        Ok(config)
    }

    /// Load presets from default path, falling back to embedded defaults
    pub fn load_or_default() -> Result<Self> {
        let path = Path::new(DEFAULT_PRESETS_PATH);
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default_presets())
        }
    }

    /// Validate the presets configuration
    pub fn validate(&self) -> Result<()> {
        // Validate blocklist preset references
        for (name, preset) in &self.blocklist_presets {
            // Check extends reference exists
            if let Some(ref parent) = preset.extends {
                if !self.blocklist_presets.contains_key(parent) {
                    anyhow::bail!(
                        "Blocklist preset '{}' extends unknown preset '{}'",
                        name,
                        parent
                    );
                }
            }

            // Check source references exist
            for source in &preset.sources {
                if !self.blocklist_sources.contains_key(source) {
                    anyhow::bail!(
                        "Blocklist preset '{}' references unknown source '{}'",
                        name,
                        source
                    );
                }
            }
        }

        // Validate allowlist preset references
        for (name, preset) in &self.allowlist_presets {
            if let Some(ref parent) = preset.extends {
                if !self.allowlist_presets.contains_key(parent) {
                    anyhow::bail!(
                        "Allowlist preset '{}' extends unknown preset '{}'",
                        name,
                        parent
                    );
                }
            }

            for source in &preset.sources {
                if !self.allowlist_sources.contains_key(source) {
                    anyhow::bail!(
                        "Allowlist preset '{}' references unknown source '{}'",
                        name,
                        source
                    );
                }
            }
        }

        // Check for circular inheritance
        self.check_circular_inheritance("blocklist", &self.blocklist_presets)?;
        self.check_circular_inheritance("allowlist", &self.allowlist_presets)?;

        Ok(())
    }

    /// Check for circular inheritance in presets
    fn check_circular_inheritance(
        &self,
        preset_type: &str,
        presets: &HashMap<String, PresetDef>,
    ) -> Result<()> {
        for name in presets.keys() {
            let mut visited = Vec::new();
            let mut current = Some(name.as_str());

            while let Some(preset_name) = current {
                if visited.contains(&preset_name) {
                    anyhow::bail!(
                        "Circular inheritance detected in {} presets: {} -> {}",
                        preset_type,
                        visited.join(" -> "),
                        preset_name
                    );
                }
                visited.push(preset_name);

                current = presets
                    .get(preset_name)
                    .and_then(|p| p.extends.as_deref());
            }
        }
        Ok(())
    }

    /// Resolve a blocklist preset to its full list of sources (including inherited)
    pub fn resolve_blocklist_preset(&self, name: &str) -> Result<Vec<String>> {
        self.resolve_preset(name, &self.blocklist_presets, "blocklist")
    }

    /// Resolve an allowlist preset to its full list of sources (including inherited)
    pub fn resolve_allowlist_preset(&self, name: &str) -> Result<Vec<String>> {
        self.resolve_preset(name, &self.allowlist_presets, "allowlist")
    }

    /// Generic preset resolution with inheritance
    fn resolve_preset(
        &self,
        name: &str,
        presets: &HashMap<String, PresetDef>,
        preset_type: &str,
    ) -> Result<Vec<String>> {
        let preset = presets.get(name).ok_or_else(|| {
            anyhow::anyhow!("Unknown {} preset: '{}'", preset_type, name)
        })?;

        let mut sources = Vec::new();

        // First, add inherited sources
        if let Some(ref parent) = preset.extends {
            sources = self.resolve_preset(parent, presets, preset_type)?;
        }

        // Then add this preset's sources (avoiding duplicates)
        for source in &preset.sources {
            if !sources.contains(source) {
                sources.push(source.clone());
            }
        }

        Ok(sources)
    }

    /// Get blocklist URLs for a preset
    pub fn get_blocklist_urls(&self, preset_name: &str) -> Result<Vec<(String, String)>> {
        let sources = self.resolve_blocklist_preset(preset_name)?;
        let mut urls = Vec::new();

        for source_name in sources {
            if let Some(source) = self.blocklist_sources.get(&source_name) {
                urls.push((source_name, source.url.clone()));
            }
        }

        Ok(urls)
    }

    /// Get allowlist data for a preset (both static and dynamic sources)
    pub fn get_allowlist_sources(&self, preset_name: &str) -> Result<Vec<(String, &AllowlistSourceDef)>> {
        let sources = self.resolve_allowlist_preset(preset_name)?;
        let mut result = Vec::new();

        for source_name in sources {
            if let Some(source) = self.allowlist_sources.get(&source_name) {
                result.push((source_name, source));
            }
        }

        Ok(result)
    }

    /// List all available blocklist presets
    pub fn list_blocklist_presets(&self) -> Vec<&String> {
        self.blocklist_presets.keys().collect()
    }

    /// List all available allowlist presets
    pub fn list_allowlist_presets(&self) -> Vec<&String> {
        self.allowlist_presets.keys().collect()
    }

    /// Generate default presets configuration
    pub fn default_presets() -> Self {
        let mut blocklist_sources = HashMap::new();
        let mut blocklist_presets = HashMap::new();
        let mut allowlist_sources = HashMap::new();
        let mut allowlist_presets = HashMap::new();

        // Blocklist sources
        blocklist_sources.insert(
            "spamhaus_drop".to_string(),
            BlocklistSourceDef {
                url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
                description: BilingualText {
                    en: "Spamhaus DROP - Hijacked/leased for spam/malware".to_string(),
                    fr: "Spamhaus DROP - Détournées/louées pour spam/malware".to_string(),
                },
            },
        );
        blocklist_sources.insert(
            "spamhaus_edrop".to_string(),
            BlocklistSourceDef {
                url: "https://www.spamhaus.org/drop/edrop.txt".to_string(),
                description: BilingualText {
                    en: "Spamhaus EDROP - Extended DROP list".to_string(),
                    fr: "Spamhaus EDROP - Liste DROP étendue".to_string(),
                },
            },
        );
        blocklist_sources.insert(
            "dshield".to_string(),
            BlocklistSourceDef {
                url: "https://www.dshield.org/block.txt".to_string(),
                description: BilingualText {
                    en: "DShield - Top attacking IPs".to_string(),
                    fr: "DShield - IPs les plus attaquantes".to_string(),
                },
            },
        );
        blocklist_sources.insert(
            "firehol_level1".to_string(),
            BlocklistSourceDef {
                url: "https://iplists.firehol.org/files/firehol_level1.netset".to_string(),
                description: BilingualText {
                    en: "FireHOL L1 - High confidence, production safe".to_string(),
                    fr: "FireHOL L1 - Haute confiance, safe production".to_string(),
                },
            },
        );
        blocklist_sources.insert(
            "firehol_level2".to_string(),
            BlocklistSourceDef {
                url: "https://iplists.firehol.org/files/firehol_level2.netset".to_string(),
                description: BilingualText {
                    en: "FireHOL L2 - Medium confidence".to_string(),
                    fr: "FireHOL L2 - Confiance moyenne".to_string(),
                },
            },
        );
        blocklist_sources.insert(
            "firehol_level3".to_string(),
            BlocklistSourceDef {
                url: "https://iplists.firehol.org/files/firehol_level3.netset".to_string(),
                description: BilingualText {
                    en: "FireHOL L3 - Aggressive, possible false positives".to_string(),
                    fr: "FireHOL L3 - Agressif, faux positifs possibles".to_string(),
                },
            },
        );
        blocklist_sources.insert(
            "firehol_level4".to_string(),
            BlocklistSourceDef {
                url: "https://iplists.firehol.org/files/firehol_level4.netset".to_string(),
                description: BilingualText {
                    en: "FireHOL L4 - Research lists, expect false positives".to_string(),
                    fr: "FireHOL L4 - Listes recherche, faux positifs probables".to_string(),
                },
            },
        );

        // Blocklist presets with inheritance
        blocklist_presets.insert(
            "minimal".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "Production servers - near-zero false positives".to_string(),
                    fr: "Serveurs production - quasi-zéro faux positifs".to_string(),
                },
                extends: None,
                sources: vec![
                    "spamhaus_drop".to_string(),
                    "spamhaus_edrop".to_string(),
                    "dshield".to_string(),
                ],
            },
        );
        blocklist_presets.insert(
            "recommended".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "Recommended default - good balance".to_string(),
                    fr: "Défaut recommandé - bon équilibre".to_string(),
                },
                extends: Some("minimal".to_string()),
                sources: vec![
                    "firehol_level1".to_string(),
                    "firehol_level2".to_string(),
                ],
            },
        );
        blocklist_presets.insert(
            "full".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "High security - rare false positives".to_string(),
                    fr: "Haute sécurité - faux positifs rares".to_string(),
                },
                extends: Some("recommended".to_string()),
                sources: vec!["firehol_level3".to_string()],
            },
        );
        blocklist_presets.insert(
            "paranoid".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "Maximum protection - expect false positives".to_string(),
                    fr: "Protection maximale - faux positifs probables".to_string(),
                },
                extends: Some("full".to_string()),
                sources: vec!["firehol_level4".to_string()],
            },
        );

        // Allowlist sources
        allowlist_sources.insert(
            "rfc1918".to_string(),
            AllowlistSourceDef::Static {
                ranges: vec![
                    "10.0.0.0/8".to_string(),
                    "172.16.0.0/12".to_string(),
                    "192.168.0.0/16".to_string(),
                ],
                description: BilingualText {
                    en: "RFC1918 private networks".to_string(),
                    fr: "Réseaux privés RFC1918".to_string(),
                },
            },
        );
        allowlist_sources.insert(
            "rfc6598".to_string(),
            AllowlistSourceDef::Static {
                ranges: vec!["100.64.0.0/10".to_string()],
                description: BilingualText {
                    en: "RFC6598 Carrier-Grade NAT".to_string(),
                    fr: "RFC6598 NAT opérateur".to_string(),
                },
            },
        );
        allowlist_sources.insert(
            "loopback".to_string(),
            AllowlistSourceDef::Static {
                ranges: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
                description: BilingualText {
                    en: "Loopback addresses".to_string(),
                    fr: "Adresses loopback".to_string(),
                },
            },
        );
        allowlist_sources.insert(
            "link_local".to_string(),
            AllowlistSourceDef::Static {
                ranges: vec!["169.254.0.0/16".to_string(), "fe80::/10".to_string()],
                description: BilingualText {
                    en: "Link-local addresses".to_string(),
                    fr: "Adresses link-local".to_string(),
                },
            },
        );
        allowlist_sources.insert(
            "cloudflare".to_string(),
            AllowlistSourceDef::Dynamic {
                url: "https://www.cloudflare.com/ips-v4".to_string(),
                url_v6: Some("https://www.cloudflare.com/ips-v6".to_string()),
                json_path: None,
                description: BilingualText {
                    en: "Cloudflare CDN IP ranges".to_string(),
                    fr: "Plages IP Cloudflare CDN".to_string(),
                },
            },
        );
        allowlist_sources.insert(
            "github".to_string(),
            AllowlistSourceDef::Dynamic {
                url: "https://api.github.com/meta".to_string(),
                url_v6: None,
                json_path: Some("hooks".to_string()),
                description: BilingualText {
                    en: "GitHub webhook/actions IPs".to_string(),
                    fr: "IPs webhooks/actions GitHub".to_string(),
                },
            },
        );
        allowlist_sources.insert(
            "fastly".to_string(),
            AllowlistSourceDef::Dynamic {
                url: "https://api.fastly.com/public-ip-list".to_string(),
                url_v6: None,
                json_path: Some("addresses".to_string()),
                description: BilingualText {
                    en: "Fastly CDN IP ranges".to_string(),
                    fr: "Plages IP Fastly CDN".to_string(),
                },
            },
        );

        // Allowlist presets
        allowlist_presets.insert(
            "rfc1918".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "Private networks only".to_string(),
                    fr: "Réseaux privés uniquement".to_string(),
                },
                extends: None,
                sources: vec!["rfc1918".to_string()],
            },
        );
        allowlist_presets.insert(
            "private_full".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "All private/reserved ranges".to_string(),
                    fr: "Toutes les plages privées/réservées".to_string(),
                },
                extends: None,
                sources: vec![
                    "rfc1918".to_string(),
                    "rfc6598".to_string(),
                    "link_local".to_string(),
                ],
            },
        );
        allowlist_presets.insert(
            "cdn_cloudflare".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "Cloudflare CDN".to_string(),
                    fr: "CDN Cloudflare".to_string(),
                },
                extends: None,
                sources: vec!["cloudflare".to_string()],
            },
        );
        allowlist_presets.insert(
            "cdn_github".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "GitHub services".to_string(),
                    fr: "Services GitHub".to_string(),
                },
                extends: None,
                sources: vec!["github".to_string()],
            },
        );
        allowlist_presets.insert(
            "cdn_common".to_string(),
            PresetDef {
                description: BilingualText {
                    en: "Common CDNs (Cloudflare, GitHub, Fastly)".to_string(),
                    fr: "CDNs courants (Cloudflare, GitHub, Fastly)".to_string(),
                },
                extends: None,
                sources: vec![
                    "cloudflare".to_string(),
                    "github".to_string(),
                    "fastly".to_string(),
                ],
            },
        );

        Self {
            blocklist_sources,
            blocklist_presets,
            allowlist_sources,
            allowlist_presets,
        }
    }

    /// Generate default presets YAML content
    pub fn generate_default_yaml() -> String {
        include_str!("../templates/presets.yaml").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_presets_valid() {
        let presets = PresetsConfig::default_presets();
        assert!(presets.validate().is_ok());
    }

    #[test]
    fn test_resolve_minimal_preset() {
        let presets = PresetsConfig::default_presets();
        let sources = presets.resolve_blocklist_preset("minimal").unwrap();
        assert_eq!(sources.len(), 3);
        assert!(sources.contains(&"spamhaus_drop".to_string()));
    }

    #[test]
    fn test_resolve_recommended_inherits_minimal() {
        let presets = PresetsConfig::default_presets();
        let sources = presets.resolve_blocklist_preset("recommended").unwrap();
        assert_eq!(sources.len(), 5);
        assert!(sources.contains(&"spamhaus_drop".to_string()));
        assert!(sources.contains(&"firehol_level1".to_string()));
    }

    #[test]
    fn test_resolve_paranoid_inherits_all() {
        let presets = PresetsConfig::default_presets();
        let sources = presets.resolve_blocklist_preset("paranoid").unwrap();
        assert_eq!(sources.len(), 7);
    }

    #[test]
    fn test_unknown_preset_error() {
        let presets = PresetsConfig::default_presets();
        let result = presets.resolve_blocklist_preset("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_bilingual_text() {
        let text = BilingualText {
            en: "English".to_string(),
            fr: "Français".to_string(),
        };
        assert_eq!(text.get("en"), "English");
        assert_eq!(text.get("fr"), "Français");
        assert_eq!(text.get("de"), "English"); // Fallback to English
    }

    #[test]
    fn test_allowlist_static_source() {
        let presets = PresetsConfig::default_presets();
        let source = presets.allowlist_sources.get("rfc1918").unwrap();
        assert!(source.is_static());
        let ranges = source.get_static_ranges().unwrap();
        assert!(ranges.contains(&"10.0.0.0/8".to_string()));
    }

    #[test]
    fn test_allowlist_dynamic_source() {
        let presets = PresetsConfig::default_presets();
        let source = presets.allowlist_sources.get("cloudflare").unwrap();
        assert!(!source.is_static());
        assert!(source.get_url().is_some());
    }

    #[test]
    fn test_circular_inheritance_detection() {
        let mut presets = PresetsConfig::default_presets();

        // Create circular reference: a -> b -> a
        presets.blocklist_presets.insert(
            "test_a".to_string(),
            PresetDef {
                description: BilingualText::default(),
                extends: Some("test_b".to_string()),
                sources: vec![],
            },
        );
        presets.blocklist_presets.insert(
            "test_b".to_string(),
            PresetDef {
                description: BilingualText::default(),
                extends: Some("test_a".to_string()),
                sources: vec![],
            },
        );

        let result = presets.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular"));
    }

    #[test]
    fn test_list_presets() {
        let presets = PresetsConfig::default_presets();
        let blocklist_presets = presets.list_blocklist_presets();
        assert!(blocklist_presets.len() >= 4);

        let allowlist_presets = presets.list_allowlist_presets();
        assert!(allowlist_presets.len() >= 5);
    }
}
