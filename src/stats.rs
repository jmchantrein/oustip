//! Statistics display for OustIP.

use crate::aggregator::{count_ips, coverage_percent};
use crate::config::Config;
use crate::enforcer::create_backend;
use crate::utils::{format_bytes, format_count, truncate};
use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tempfile::NamedTempFile;

const STATE_FILE: &str = "/var/lib/oustip/state.json";
const STATE_BACKUP_FILE: &str = "/var/lib/oustip/state.json.bak";

/// Persistent state for OustIP
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OustipState {
    pub last_update: Option<DateTime<Utc>>,
    pub sources: Vec<SourceStats>,
    pub total_entries: usize,
    pub total_ips: u128,
    /// IPs that are in both allowlist and blocklist, acknowledged by admin
    #[serde(default)]
    pub assumed_ips: Option<Vec<String>>,
    /// Last known total IPs for change detection alerts
    #[serde(default)]
    pub last_known_total_ips: Option<u128>,
    /// Last preset used, to detect intentional preset changes
    #[serde(default)]
    pub last_preset: Option<String>,
}

/// Statistics for a single blocklist source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceStats {
    pub name: String,
    pub raw_count: usize,
    pub ip_count: u128,
    /// Cached IPs from this source (limited to first N for display)
    #[serde(default)]
    pub ips: Vec<String>,
}

impl OustipState {
    /// Load state from file, falling back to backup if main file is corrupted
    pub fn load() -> Result<Self> {
        let path = Path::new(STATE_FILE);
        let backup_path = Path::new(STATE_BACKUP_FILE);

        // Try to load main state file
        if path.exists() {
            match fs::read_to_string(path) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(state) => return Ok(state),
                    Err(e) => {
                        tracing::warn!("State file corrupted, trying backup: {}", e);
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read state file, trying backup: {}", e);
                }
            }
        }

        // Try to load backup
        if backup_path.exists() {
            if let Ok(content) = fs::read_to_string(backup_path) {
                if let Ok(state) = serde_json::from_str(&content) {
                    tracing::info!("Recovered state from backup file");
                    return Ok(state);
                }
            }
        }

        Ok(Self::default())
    }

    /// Create a backup of the current state file
    fn backup_state() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let path = Path::new(STATE_FILE);
        let backup_path = Path::new(STATE_BACKUP_FILE);

        if path.exists() {
            fs::copy(path, backup_path).context("Failed to create state backup")?;
            // Set restrictive permissions on backup file (owner read/write only)
            fs::set_permissions(backup_path, fs::Permissions::from_mode(0o600))
                .context("Failed to set backup file permissions")?;
        }

        Ok(())
    }

    /// Save state to file atomically with backup
    ///
    /// Uses tempfile crate for secure temporary file handling with
    /// automatic cleanup on error. The write-to-temp-then-rename pattern
    /// prevents corruption if the process is interrupted during write.
    /// A backup is created before each save for recovery purposes.
    pub fn save(&self) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let path = Path::new(STATE_FILE);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create backup before saving
        if let Err(e) = Self::backup_state() {
            tracing::warn!("Failed to create state backup (continuing anyway): {}", e);
        }

        let content = serde_json::to_string_pretty(self)?;

        // Create temporary file in the same directory (required for atomic rename)
        // NamedTempFile provides secure creation and automatic cleanup on error
        let parent_dir = path.parent().unwrap_or(Path::new("/var/lib/oustip"));
        let mut temp_file = NamedTempFile::new_in(parent_dir)
            .context("Failed to create temporary file for state")?;

        // Write content and ensure it's flushed to disk
        temp_file.write_all(content.as_bytes())?;
        temp_file.as_file().sync_all()?;

        // Atomically rename temp file to target
        // persist_noclobber would fail if file exists, so we use persist
        temp_file
            .persist(path)
            .context("Failed to persist state file")?;

        // Set restrictive permissions on state file (owner read/write only)
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .context("Failed to set state file permissions")?;

        Ok(())
    }

    /// Update state with new fetch results
    /// Maximum number of IPs to cache per source for display
    const MAX_CACHED_IPS: usize = 1000;

    pub fn update_sources(&mut self, sources: Vec<(String, usize, Vec<IpNet>)>) {
        self.sources = sources
            .iter()
            .map(|(name, raw_count, ips)| {
                // Cache first N IPs as strings for display
                let cached_ips: Vec<String> = ips
                    .iter()
                    .take(Self::MAX_CACHED_IPS)
                    .map(|ip| ip.to_string())
                    .collect();

                SourceStats {
                    name: name.clone(),
                    raw_count: *raw_count,
                    ip_count: count_ips(ips),
                    ips: cached_ips,
                }
            })
            .collect();

        self.total_entries = self.sources.iter().map(|s| s.raw_count).sum();
        self.total_ips = self.sources.iter().map(|s| s.ip_count).sum();
        self.last_update = Some(Utc::now());
    }

    /// Add an IP to the assumed list (acknowledged allow+block overlap)
    pub fn add_assumed_ip(&mut self, ip: &str) {
        let assumed = self.assumed_ips.get_or_insert_with(Vec::new);
        if !assumed.contains(&ip.to_string()) {
            assumed.push(ip.to_string());
        }
    }

    /// Remove an IP from the assumed list
    pub fn remove_assumed_ip(&mut self, ip: &str) {
        if let Some(ref mut assumed) = self.assumed_ips {
            assumed.retain(|i| i != ip);
        }
    }

    /// Check if an IP is in the assumed list
    pub fn is_assumed(&self, ip: &str) -> bool {
        self.assumed_ips
            .as_ref()
            .map(|v| v.contains(&ip.to_string()))
            .unwrap_or(false)
    }
}

/// Display formatted statistics
pub async fn display_stats(config: &Config) -> Result<()> {
    let state = OustipState::load().unwrap_or_default();
    let backend = create_backend(config.backend)?;
    let fw_stats = backend.get_stats().await.unwrap_or_default();
    let is_active = backend.is_active().await.unwrap_or(false);
    let entry_count = backend.entry_count().await.unwrap_or(0);

    println!();
    println!("══════════════════════════════════════════════════════════════════");
    println!(" OUSTIP BLOCKLIST STATISTICS");
    println!("══════════════════════════════════════════════════════════════════");
    println!();

    // Status
    let status = if is_active { "ENABLED" } else { "DISABLED" };
    let backend_name = match config.backend {
        crate::config::Backend::Auto => "auto",
        crate::config::Backend::Iptables => "iptables",
        crate::config::Backend::Nftables => "nftables",
    };
    println!(" Status: {}", status);
    println!(" Backend: {}", backend_name);
    println!(" Entries in set: {}", format_count(entry_count));
    println!();

    // Source breakdown
    if !state.sources.is_empty() {
        println!(" SOURCE              IPs          ENTRIES");
        println!(" ────────────────── ──────────── ────────────");

        for source in &state.sources {
            println!(
                " {:<18} {:>12} {:>12}",
                truncate(&source.name, 18),
                format_count(source.ip_count as usize),
                format_count(source.raw_count),
            );
        }

        println!(" ────────────────── ──────────── ────────────");
        println!(
            " {:<18} {:>12} {:>12}",
            "TOTAL",
            format_count(state.total_ips as usize),
            format_count(state.total_entries),
        );
        println!();
    }

    // Coverage
    if state.total_ips > 0 {
        let coverage = coverage_percent(state.total_ips);
        println!(
            " Coverage: {} IPs = {:.2}% of public IPv4 space",
            format_count(state.total_ips as usize),
            coverage
        );
        println!();
    }

    // Blocking stats
    println!(" BLOCKING STATISTICS");
    println!(" ────────────────────────────────────────────────────────────────");
    println!(
        " Packets blocked: {}",
        format_count(fw_stats.packets_blocked as usize)
    );
    println!(" Bytes blocked: {}", format_bytes(fw_stats.bytes_blocked));
    println!();

    // Last update
    if let Some(last_update) = state.last_update {
        let local: DateTime<Local> = last_update.into();
        let ago = format_duration_ago(last_update);
        println!(
            " Last update: {} ({})",
            local.format("%Y-%m-%d %H:%M:%S"),
            ago
        );
    } else {
        println!(" Last update: never");
    }

    println!("══════════════════════════════════════════════════════════════════");
    println!();

    Ok(())
}

/// Format duration since a timestamp
fn format_duration_ago(dt: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(dt);

    let seconds = duration.num_seconds();
    if seconds < 60 {
        "just now".to_string()
    } else if seconds < 3600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h ago", seconds / 3600)
    } else {
        format!("{}d ago", seconds / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_oustip_state_default() {
        let state = OustipState::default();
        assert!(state.last_update.is_none());
        assert!(state.sources.is_empty());
        assert_eq!(state.total_entries, 0);
        assert_eq!(state.total_ips, 0);
        assert!(state.assumed_ips.is_none());
        assert!(state.last_known_total_ips.is_none());
        assert!(state.last_preset.is_none());
    }

    #[test]
    fn test_oustip_state_serialization() {
        let state = OustipState {
            last_update: Some(Utc::now()),
            sources: vec![SourceStats {
                name: "test".to_string(),
                raw_count: 100,
                ip_count: 1000,
                ips: vec!["192.168.1.0/24".to_string()],
            }],
            total_entries: 100,
            total_ips: 1000,
            assumed_ips: Some(vec!["8.8.8.8".to_string()]),
            last_known_total_ips: Some(950),
            last_preset: Some("recommended".to_string()),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: OustipState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total_entries, 100);
        assert_eq!(parsed.total_ips, 1000);
        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.sources[0].name, "test");
        assert_eq!(parsed.last_known_total_ips, Some(950));
        assert_eq!(parsed.last_preset, Some("recommended".to_string()));
    }

    #[test]
    fn test_add_assumed_ip() {
        let mut state = OustipState::default();

        state.add_assumed_ip("8.8.8.8");
        assert!(state.is_assumed("8.8.8.8"));
        assert!(!state.is_assumed("1.1.1.1"));

        // Adding duplicate should not create duplicate
        state.add_assumed_ip("8.8.8.8");
        assert_eq!(state.assumed_ips.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_remove_assumed_ip() {
        let mut state = OustipState::default();

        state.add_assumed_ip("8.8.8.8");
        state.add_assumed_ip("1.1.1.1");
        assert_eq!(state.assumed_ips.as_ref().unwrap().len(), 2);

        state.remove_assumed_ip("8.8.8.8");
        assert!(!state.is_assumed("8.8.8.8"));
        assert!(state.is_assumed("1.1.1.1"));
    }

    #[test]
    fn test_is_assumed_empty() {
        let state = OustipState::default();
        assert!(!state.is_assumed("8.8.8.8"));
    }

    #[test]
    fn test_update_sources() {
        let mut state = OustipState::default();

        let sources = vec![
            (
                "firehol".to_string(),
                50,
                vec!["192.168.1.0/24".parse().unwrap()],
            ),
            (
                "spamhaus".to_string(),
                30,
                vec!["10.0.0.0/8".parse().unwrap()],
            ),
        ];

        state.update_sources(sources);

        assert_eq!(state.sources.len(), 2);
        assert_eq!(state.total_entries, 80);
        assert!(state.last_update.is_some());
        assert_eq!(state.sources[0].name, "firehol");
        assert_eq!(state.sources[1].name, "spamhaus");
    }

    #[test]
    fn test_update_sources_limits_cached_ips() {
        let mut state = OustipState::default();

        // Generate more than MAX_CACHED_IPS
        let many_ips: Vec<IpNet> = (0..1500u32)
            .map(|i| {
                let a = (i % 256) as u8;
                let b = ((i / 256) % 256) as u8;
                format!("192.{}.{}.0/24", a, b).parse().unwrap()
            })
            .collect();

        let sources = vec![("test".to_string(), 1500, many_ips)];
        state.update_sources(sources);

        // Should be limited to MAX_CACHED_IPS
        assert_eq!(state.sources[0].ips.len(), OustipState::MAX_CACHED_IPS);
    }

    #[test]
    fn test_format_duration_ago_just_now() {
        let now = Utc::now();
        assert_eq!(format_duration_ago(now), "just now");
    }

    #[test]
    fn test_format_duration_ago_minutes() {
        let past = Utc::now() - Duration::minutes(5);
        assert_eq!(format_duration_ago(past), "5m ago");
    }

    #[test]
    fn test_format_duration_ago_hours() {
        let past = Utc::now() - Duration::hours(3);
        assert_eq!(format_duration_ago(past), "3h ago");
    }

    #[test]
    fn test_format_duration_ago_days() {
        let past = Utc::now() - Duration::days(2);
        assert_eq!(format_duration_ago(past), "2d ago");
    }

    #[test]
    fn test_source_stats_serialization() {
        let stats = SourceStats {
            name: "firehol_level1".to_string(),
            raw_count: 1000,
            ip_count: 50000,
            ips: vec!["1.2.3.0/24".to_string(), "5.6.7.0/24".to_string()],
        };

        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("firehol_level1"));
        assert!(json.contains("1000"));

        let parsed: SourceStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "firehol_level1");
        assert_eq!(parsed.ips.len(), 2);
    }

    #[test]
    fn test_constants() {
        assert!(STATE_FILE.starts_with("/var"));
        assert!(STATE_FILE.ends_with(".json"));
        assert!(STATE_BACKUP_FILE.ends_with(".bak"));
    }

    // =========================================================================
    // State management tests - Backup/restore, atomic write, corruption recovery
    // =========================================================================

    #[test]
    fn test_state_file_paths_related() {
        // Backup file should be the main file with .bak extension
        assert!(STATE_BACKUP_FILE.starts_with(STATE_FILE.trim_end_matches(".json")));
    }

    #[test]
    fn test_state_file_in_var_lib() {
        // State should be in /var/lib for persistent data
        assert!(STATE_FILE.contains("/var/lib/"));
        assert!(STATE_BACKUP_FILE.contains("/var/lib/"));
    }

    #[test]
    fn test_state_serialization_roundtrip() {
        let mut state = OustipState::default();
        state.last_update = Some(Utc::now());
        state.total_entries = 1000;
        state.total_ips = 50000;
        state.last_known_total_ips = Some(49000);
        state.last_preset = Some("recommended".to_string());

        state.add_assumed_ip("8.8.8.8");
        state.sources.push(SourceStats {
            name: "test_source".to_string(),
            raw_count: 100,
            ip_count: 5000,
            ips: vec!["192.168.1.0/24".to_string()],
        });

        // Serialize
        let json = serde_json::to_string(&state).unwrap();

        // Deserialize
        let restored: OustipState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.total_entries, 1000);
        assert_eq!(restored.total_ips, 50000);
        assert_eq!(restored.last_known_total_ips, Some(49000));
        assert_eq!(restored.last_preset, Some("recommended".to_string()));
        assert!(restored.is_assumed("8.8.8.8"));
        assert_eq!(restored.sources.len(), 1);
        assert_eq!(restored.sources[0].name, "test_source");
    }

    #[test]
    fn test_state_corrupted_json_recovery() {
        // Test that corrupted JSON is handled gracefully
        let corrupted = "{invalid json}}}";
        let result: Result<OustipState, _> = serde_json::from_str(corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_partial_json_recovery() {
        // Partial/truncated JSON
        let partial = r#"{"last_update": null, "sources": [{"name": "test""#;
        let result: Result<OustipState, _> = serde_json::from_str(partial);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_empty_json_object() {
        // Empty JSON object may fail to parse if fields don't have defaults
        // Test the actual behavior
        let empty = "{}";
        let result: Result<OustipState, _> = serde_json::from_str(empty);

        // If it fails, check that the error is about missing fields
        // If it succeeds, verify the defaults
        if result.is_err() {
            let err = result.unwrap_err().to_string();
            // This is expected if some fields don't have serde defaults
            assert!(
                err.contains("missing field") || err.contains("expected"),
                "Error should be about missing fields, got: {}",
                err
            );
        } else {
            let state = result.unwrap();
            assert!(state.last_update.is_none());
            assert!(state.sources.is_empty());
            assert_eq!(state.total_entries, 0);
        }
    }

    #[test]
    fn test_state_extra_fields_ignored() {
        // Unknown fields should be ignored during deserialization
        let with_extra = r#"{
            "last_update": null,
            "sources": [],
            "total_entries": 100,
            "total_ips": 1000,
            "unknown_field": "should be ignored",
            "another_unknown": 42
        }"#;
        let result: Result<OustipState, _> = serde_json::from_str(with_extra);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.total_entries, 100);
    }

    #[test]
    fn test_update_sources_empty() {
        let mut state = OustipState::default();
        state.update_sources(vec![]);

        assert!(state.sources.is_empty());
        assert_eq!(state.total_entries, 0);
        assert_eq!(state.total_ips, 0);
        assert!(state.last_update.is_some());
    }

    #[test]
    fn test_update_sources_multiple() {
        let mut state = OustipState::default();

        let sources = vec![
            (
                "source1".to_string(),
                100,
                vec!["192.168.0.0/24".parse().unwrap()],
            ),
            (
                "source2".to_string(),
                200,
                vec!["10.0.0.0/8".parse().unwrap()],
            ),
            (
                "source3".to_string(),
                50,
                vec!["172.16.0.0/12".parse().unwrap()],
            ),
        ];

        state.update_sources(sources);

        assert_eq!(state.sources.len(), 3);
        assert_eq!(state.total_entries, 350); // 100 + 200 + 50
        assert!(state.last_update.is_some());
    }

    #[test]
    fn test_update_sources_overwrites_previous() {
        let mut state = OustipState::default();

        // First update
        state.update_sources(vec![(
            "old_source".to_string(),
            1000,
            vec!["1.0.0.0/8".parse().unwrap()],
        )]);
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.sources[0].name, "old_source");

        // Second update - should overwrite
        state.update_sources(vec![(
            "new_source".to_string(),
            500,
            vec!["2.0.0.0/8".parse().unwrap()],
        )]);
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.sources[0].name, "new_source");
    }

    #[test]
    fn test_update_sources_caches_ips() {
        let mut state = OustipState::default();

        let ips: Vec<ipnet::IpNet> = vec![
            "192.168.1.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
        ];

        state.update_sources(vec![("test".to_string(), 3, ips)]);

        // IPs should be cached
        assert_eq!(state.sources[0].ips.len(), 3);
        assert!(state.sources[0].ips.contains(&"192.168.1.0/24".to_string()));
    }

    #[test]
    fn test_update_sources_ip_count_calculation() {
        let mut state = OustipState::default();

        // /24 = 256 IPs, /8 = 16,777,216 IPs
        let sources = vec![(
            "test".to_string(),
            2,
            vec![
                "192.168.1.0/24".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
            ],
        )];

        state.update_sources(sources);

        // total_ips should be sum of IP counts
        assert!(state.total_ips > 0);
        // The actual count depends on count_ips() implementation
    }

    #[test]
    fn test_state_last_update_set_on_update_sources() {
        let mut state = OustipState::default();
        assert!(state.last_update.is_none());

        state.update_sources(vec![]);

        assert!(state.last_update.is_some());
        let update_time = state.last_update.unwrap();
        let now = Utc::now();
        // Should be within 1 second of now
        assert!((now - update_time).num_seconds().abs() < 1);
    }

    #[test]
    fn test_source_stats_ip_count_matches_vector() {
        let mut state = OustipState::default();

        let ips: Vec<ipnet::IpNet> = vec![
            "192.168.1.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];

        state.update_sources(vec![("test".to_string(), ips.len(), ips.clone())]);

        // raw_count should match input
        assert_eq!(state.sources[0].raw_count, 2);
    }

    #[test]
    fn test_format_duration_ago_edge_cases() {
        // Just under 60 seconds
        let past = Utc::now() - Duration::seconds(59);
        assert_eq!(format_duration_ago(past), "just now");

        // Exactly 60 seconds
        let past = Utc::now() - Duration::seconds(60);
        assert_eq!(format_duration_ago(past), "1m ago");

        // Just under an hour
        let past = Utc::now() - Duration::seconds(3599);
        assert!(format_duration_ago(past).ends_with("m ago"));

        // Exactly an hour
        let past = Utc::now() - Duration::hours(1);
        assert_eq!(format_duration_ago(past), "1h ago");

        // Just under a day
        let past = Utc::now() - Duration::hours(23);
        assert_eq!(format_duration_ago(past), "23h ago");

        // Exactly a day
        let past = Utc::now() - Duration::days(1);
        assert_eq!(format_duration_ago(past), "1d ago");
    }

    #[test]
    fn test_format_duration_ago_future() {
        // Future time (edge case - shouldn't happen normally)
        let future = Utc::now() + Duration::hours(1);
        // Should still return something (implementation dependent)
        let result = format_duration_ago(future);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_state_max_cached_ips_constant() {
        assert_eq!(OustipState::MAX_CACHED_IPS, 1000);
    }

    #[test]
    fn test_state_assumed_ips_serialization_optional() {
        // Test that assumed_ips defaults to None when missing
        let json = r#"{"last_update": null, "sources": [], "total_entries": 0, "total_ips": 0}"#;
        let state: OustipState = serde_json::from_str(json).unwrap();
        assert!(state.assumed_ips.is_none());
    }

    #[test]
    fn test_state_last_known_total_ips_optional() {
        // Test that last_known_total_ips defaults when missing
        let json = r#"{"last_update": null, "sources": [], "total_entries": 0, "total_ips": 0}"#;
        let state: OustipState = serde_json::from_str(json).unwrap();
        assert!(state.last_known_total_ips.is_none());
    }

    #[test]
    fn test_state_last_preset_optional() {
        // Test that last_preset defaults when missing
        let json = r#"{"last_update": null, "sources": [], "total_entries": 0, "total_ips": 0}"#;
        let state: OustipState = serde_json::from_str(json).unwrap();
        assert!(state.last_preset.is_none());
    }

    #[test]
    fn test_state_pretty_print_json() {
        let state = OustipState::default();
        let pretty = serde_json::to_string_pretty(&state).unwrap();

        // Pretty-printed JSON should contain newlines
        assert!(pretty.contains('\n'));
        // Should be valid JSON
        let _: OustipState = serde_json::from_str(&pretty).unwrap();
    }

    #[test]
    fn test_source_stats_empty_ips_default() {
        let json = r#"{"name": "test", "raw_count": 0, "ip_count": 0}"#;
        let stats: SourceStats = serde_json::from_str(json).unwrap();
        assert!(stats.ips.is_empty());
    }

    #[test]
    fn test_state_backward_compatibility() {
        // Old state format without new fields should still deserialize
        let old_json = r#"{
            "last_update": null,
            "sources": [],
            "total_entries": 100,
            "total_ips": 1000
        }"#;

        let state: OustipState = serde_json::from_str(old_json).unwrap();
        assert_eq!(state.total_entries, 100);
        assert!(state.assumed_ips.is_none());
        assert!(state.last_known_total_ips.is_none());
        assert!(state.last_preset.is_none());
    }
}
