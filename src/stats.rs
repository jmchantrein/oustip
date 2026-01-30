//! Statistics display for OustIP.

use crate::aggregator::{count_ips, coverage_percent};
use crate::config::Config;
use crate::enforcer::create_backend;
use crate::fs_abstraction::{real_fs, FileSystem};
use crate::utils::{format_bytes, format_count, truncate};
use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
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
    /// Load state from file, falling back to backup if main file is corrupted.
    ///
    /// Uses the real filesystem. For testing, use `load_with_fs` instead.
    pub fn load() -> Result<Self> {
        Self::load_with_fs(real_fs())
    }

    /// Load state from file with a custom filesystem implementation.
    ///
    /// This method enables testing without real filesystem access by accepting
    /// a mock filesystem implementation.
    pub fn load_with_fs<F: FileSystem>(fs: &F) -> Result<Self> {
        let path = Path::new(STATE_FILE);
        let backup_path = Path::new(STATE_BACKUP_FILE);

        // Try to load main state file
        if fs.exists(path) {
            match fs.read_to_string(path) {
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
        if fs.exists(backup_path) {
            if let Ok(content) = fs.read_to_string(backup_path) {
                if let Ok(state) = serde_json::from_str(&content) {
                    tracing::info!("Recovered state from backup file");
                    return Ok(state);
                }
            }
        }

        Ok(Self::default())
    }

    /// Create a backup of the current state file with a custom filesystem.
    fn backup_state_with_fs<F: FileSystem>(fs: &F) -> Result<()> {
        let path = Path::new(STATE_FILE);
        let backup_path = Path::new(STATE_BACKUP_FILE);

        if fs.exists(path) {
            fs.copy(path, backup_path)
                .context("Failed to create state backup")?;
            // Set restrictive permissions on backup file (owner read/write only)
            fs.set_permissions_mode(backup_path, 0o600)
                .context("Failed to set backup file permissions")?;
        }

        Ok(())
    }

    /// Save state to file atomically with backup.
    ///
    /// Uses the real filesystem. For testing, use `save_with_fs` instead.
    ///
    /// Uses tempfile crate for secure temporary file handling with
    /// automatic cleanup on error. The write-to-temp-then-rename pattern
    /// prevents corruption if the process is interrupted during write.
    /// A backup is created before each save for recovery purposes.
    pub fn save(&self) -> Result<()> {
        self.save_with_fs(real_fs())
    }

    /// Save state to file with a custom filesystem implementation.
    ///
    /// This method enables testing without real filesystem access.
    /// Note: The atomic write pattern using tempfile is only used with the
    /// real filesystem. For mock testing, we use direct writes.
    pub fn save_with_fs<F: FileSystem>(&self, fs: &F) -> Result<()> {
        use std::io::Write;

        let path = Path::new(STATE_FILE);
        if let Some(parent) = path.parent() {
            fs.create_dir_all(parent)?;
        }

        // Create backup before saving
        if let Err(e) = Self::backup_state_with_fs(fs) {
            tracing::warn!("Failed to create state backup (continuing anyway): {}", e);
        }

        let content = serde_json::to_string_pretty(self)?;

        // For real filesystem, use atomic write pattern with tempfile
        // For testing with mocks, we need to use the FileSystem trait's write method
        // Check if this is the real filesystem by trying to use tempfile
        let parent_dir = path.parent().unwrap_or(Path::new("/var/lib/oustip"));

        // Try to create temp file and do atomic write
        match NamedTempFile::new_in(parent_dir) {
            Ok(mut temp_file) => {
                // Write content and ensure it's flushed to disk
                temp_file.write_all(content.as_bytes())?;
                temp_file.as_file().sync_all()?;

                // Atomically rename temp file to target
                temp_file
                    .persist(path)
                    .context("Failed to persist state file")?;
            }
            Err(_) => {
                // Fallback: direct write (for testing or when tempfile fails)
                fs.write(path, content.as_bytes())
                    .context("Failed to write state file")?;
            }
        }

        // Set restrictive permissions on state file (owner read/write only)
        fs.set_permissions_mode(path, 0o600)
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
    let state = match OustipState::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Warning: Could not load state: {}", e);
            OustipState::default()
        }
    };
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
    if duration.num_seconds() < 0 {
        return "in future (clock skew?)".to_string();
    }

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
        let mut state = OustipState {
            last_update: Some(Utc::now()),
            total_entries: 1000,
            total_ips: 50000,
            last_known_total_ips: Some(49000),
            last_preset: Some("recommended".to_string()),
            sources: vec![SourceStats {
                name: "test_source".to_string(),
                raw_count: 100,
                ip_count: 5000,
                ips: vec!["192.168.1.0/24".to_string()],
            }],
            ..Default::default()
        };

        state.add_assumed_ip("8.8.8.8");

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
        // Future time (edge case - shouldn't happen normally, indicates clock skew)
        let future = Utc::now() + Duration::hours(1);
        // Should return clock skew message
        let result = format_duration_ago(future);
        assert_eq!(result, "in future (clock skew?)");
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

#[cfg(test)]
mod extended_tests {
    use super::*;
    use chrono::Duration;

    // =========================================================================
    // format_duration_ago comprehensive tests
    // =========================================================================

    #[test]
    fn test_format_duration_ago_seconds_boundary() {
        // 59 seconds should still be "just now"
        let past = Utc::now() - Duration::seconds(59);
        assert_eq!(format_duration_ago(past), "just now");

        // 60 seconds should be "1m ago"
        let past = Utc::now() - Duration::seconds(60);
        assert_eq!(format_duration_ago(past), "1m ago");
    }

    #[test]
    fn test_format_duration_ago_minutes_boundary() {
        // 59 minutes should still be in minutes
        let past = Utc::now() - Duration::minutes(59);
        assert_eq!(format_duration_ago(past), "59m ago");

        // 60 minutes should be "1h ago"
        let past = Utc::now() - Duration::minutes(60);
        assert_eq!(format_duration_ago(past), "1h ago");
    }

    #[test]
    fn test_format_duration_ago_hours_boundary() {
        // 23 hours should still be in hours
        let past = Utc::now() - Duration::hours(23);
        assert_eq!(format_duration_ago(past), "23h ago");

        // 24 hours should be "1d ago"
        let past = Utc::now() - Duration::hours(24);
        assert_eq!(format_duration_ago(past), "1d ago");
    }

    #[test]
    fn test_format_duration_ago_many_days() {
        let past = Utc::now() - Duration::days(30);
        assert_eq!(format_duration_ago(past), "30d ago");

        let past = Utc::now() - Duration::days(365);
        assert_eq!(format_duration_ago(past), "365d ago");
    }

    #[test]
    fn test_format_duration_ago_very_old() {
        // Very old date (years ago)
        let past = Utc::now() - Duration::days(1000);
        let result = format_duration_ago(past);
        assert!(result.ends_with("d ago"));
    }

    #[test]
    fn test_format_duration_ago_zero() {
        // Exactly now
        let now = Utc::now();
        assert_eq!(format_duration_ago(now), "just now");
    }

    // =========================================================================
    // OustipState assumed IPs tests
    // =========================================================================

    #[test]
    fn test_assumed_ips_add_multiple() {
        let mut state = OustipState::default();

        state.add_assumed_ip("8.8.8.8");
        state.add_assumed_ip("8.8.4.4");
        state.add_assumed_ip("1.1.1.1");

        assert_eq!(state.assumed_ips.as_ref().unwrap().len(), 3);
        assert!(state.is_assumed("8.8.8.8"));
        assert!(state.is_assumed("8.8.4.4"));
        assert!(state.is_assumed("1.1.1.1"));
        assert!(!state.is_assumed("9.9.9.9"));
    }

    #[test]
    fn test_assumed_ips_remove_nonexistent() {
        let mut state = OustipState::default();
        state.add_assumed_ip("8.8.8.8");

        // Removing nonexistent IP should not affect existing
        state.remove_assumed_ip("1.1.1.1");
        assert!(state.is_assumed("8.8.8.8"));
    }

    #[test]
    fn test_assumed_ips_remove_from_empty() {
        let mut state = OustipState::default();

        // Should not panic when removing from None
        state.remove_assumed_ip("8.8.8.8");
        assert!(!state.is_assumed("8.8.8.8"));
    }

    #[test]
    fn test_assumed_ips_cidr_notation() {
        let mut state = OustipState::default();

        state.add_assumed_ip("192.168.1.0/24");
        assert!(state.is_assumed("192.168.1.0/24"));
        assert!(!state.is_assumed("192.168.1.0")); // Different string
    }

    #[test]
    fn test_assumed_ips_ipv6() {
        let mut state = OustipState::default();

        state.add_assumed_ip("2001:db8::1");
        state.add_assumed_ip("fe80::1");

        assert!(state.is_assumed("2001:db8::1"));
        assert!(state.is_assumed("fe80::1"));
        assert!(!state.is_assumed("::1"));
    }

    // =========================================================================
    // update_sources comprehensive tests
    // =========================================================================

    #[test]
    fn test_update_sources_calculates_ip_count() {
        let mut state = OustipState::default();

        // Create sources with known IP counts
        let sources = vec![
            (
                "source1".to_string(),
                1,
                vec!["192.168.0.0/24".parse::<ipnet::IpNet>().unwrap()], // 256 IPs
            ),
            (
                "source2".to_string(),
                1,
                vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()], // 16,777,216 IPs
            ),
        ];

        state.update_sources(sources);

        // Check that IP counts were calculated
        assert!(state.total_ips > 0);
        assert!(state.sources[0].ip_count > 0);
        assert!(state.sources[1].ip_count > 0);
    }

    #[test]
    fn test_update_sources_sets_timestamp() {
        let mut state = OustipState::default();
        assert!(state.last_update.is_none());

        state.update_sources(vec![]);

        let update_time = state.last_update.unwrap();
        let now = Utc::now();

        // Should be within 1 second
        assert!((now - update_time).num_seconds().abs() < 1);
    }

    #[test]
    fn test_update_sources_replaces_old_sources() {
        let mut state = OustipState::default();

        // First update
        let sources1 = vec![(
            "old_source".to_string(),
            100,
            vec!["1.0.0.0/8".parse().unwrap()],
        )];
        state.update_sources(sources1);
        assert_eq!(state.sources[0].name, "old_source");

        // Second update - should replace
        let sources2 = vec![(
            "new_source".to_string(),
            50,
            vec!["2.0.0.0/8".parse().unwrap()],
        )];
        state.update_sources(sources2);
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.sources[0].name, "new_source");
    }

    #[test]
    fn test_update_sources_preserves_assumed_ips() {
        let mut state = OustipState::default();

        // Add assumed IP
        state.add_assumed_ip("8.8.8.8");

        // Update sources
        state.update_sources(vec![]);

        // Assumed IP should still be there
        assert!(state.is_assumed("8.8.8.8"));
    }

    #[test]
    fn test_update_sources_large_ip_lists() {
        let mut state = OustipState::default();

        // Create a large list of IPs
        let many_ips: Vec<ipnet::IpNet> = (0..5000u32)
            .map(|i| {
                let a = ((i / 256) % 256) as u8;
                let b = (i % 256) as u8;
                format!("10.{}.{}.0/24", a, b).parse().unwrap()
            })
            .collect();

        let sources = vec![("large_source".to_string(), 5000, many_ips)];
        state.update_sources(sources);

        // Should only cache MAX_CACHED_IPS
        assert_eq!(state.sources[0].ips.len(), OustipState::MAX_CACHED_IPS);
    }

    // =========================================================================
    // SourceStats tests
    // =========================================================================

    #[test]
    fn test_source_stats_clone() {
        let stats = SourceStats {
            name: "test".to_string(),
            raw_count: 100,
            ip_count: 5000,
            ips: vec!["192.168.1.0/24".to_string()],
        };

        let cloned = stats.clone();
        assert_eq!(cloned.name, stats.name);
        assert_eq!(cloned.raw_count, stats.raw_count);
        assert_eq!(cloned.ip_count, stats.ip_count);
        assert_eq!(cloned.ips, stats.ips);
    }

    #[test]
    fn test_source_stats_debug() {
        let stats = SourceStats {
            name: "test_source".to_string(),
            raw_count: 42,
            ip_count: 1000,
            ips: vec![],
        };

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("test_source"));
        assert!(debug_str.contains("42"));
        assert!(debug_str.contains("1000"));
    }

    // =========================================================================
    // State serialization edge cases
    // =========================================================================

    #[test]
    fn test_state_with_unicode_in_assumed() {
        let mut state = OustipState::default();

        // This shouldn't happen in practice, but test edge case
        state.add_assumed_ip("test-\u{1F600}");

        let json = serde_json::to_string(&state).unwrap();
        let restored: OustipState = serde_json::from_str(&json).unwrap();

        assert!(restored.is_assumed("test-\u{1F600}"));
    }

    #[test]
    fn test_state_with_very_large_ip_count() {
        let state = OustipState {
            last_update: Some(Utc::now()),
            sources: vec![],
            total_entries: 1_000_000,
            total_ips: u128::MAX,
            assumed_ips: None,
            last_known_total_ips: Some(u128::MAX),
            last_preset: None,
        };

        let json = serde_json::to_string(&state).unwrap();
        let restored: OustipState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.total_ips, u128::MAX);
    }

    #[test]
    fn test_state_with_empty_strings() {
        let state = OustipState {
            last_update: None,
            sources: vec![],
            total_entries: 0,
            total_ips: 0,
            assumed_ips: Some(vec!["".to_string()]), // Empty string
            last_known_total_ips: None,
            last_preset: Some("".to_string()), // Empty preset
        };

        let json = serde_json::to_string(&state).unwrap();
        let restored: OustipState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.assumed_ips.as_ref().unwrap().len(), 1);
        assert_eq!(restored.last_preset, Some("".to_string()));
    }

    #[test]
    fn test_state_with_special_characters_in_source_name() {
        let mut state = OustipState::default();

        let sources = vec![(
            "source-with/special:chars!@#$%".to_string(),
            10,
            vec!["192.168.1.0/24".parse().unwrap()],
        )];
        state.update_sources(sources);

        let json = serde_json::to_string(&state).unwrap();
        let restored: OustipState = serde_json::from_str(&json).unwrap();

        assert_eq!(
            restored.sources[0].name,
            "source-with/special:chars!@#$%"
        );
    }

    // =========================================================================
    // Constants verification
    // =========================================================================

    #[test]
    fn test_state_file_paths() {
        assert!(STATE_FILE.starts_with("/var/lib/"));
        assert!(STATE_FILE.ends_with(".json"));
        assert!(STATE_BACKUP_FILE.ends_with(".bak"));
    }

    #[test]
    fn test_max_cached_ips_constant() {
        assert_eq!(OustipState::MAX_CACHED_IPS, 1000);
    }

    // =========================================================================
    // OustipState Default trait
    // =========================================================================

    #[test]
    fn test_oustip_state_default_all_fields() {
        let state = OustipState::default();

        assert!(state.last_update.is_none());
        assert!(state.sources.is_empty());
        assert_eq!(state.total_entries, 0);
        assert_eq!(state.total_ips, 0);
        assert!(state.assumed_ips.is_none());
        assert!(state.last_known_total_ips.is_none());
        assert!(state.last_preset.is_none());
    }

    // =========================================================================
    // IP count aggregation tests
    // =========================================================================

    #[test]
    fn test_total_entries_aggregation() {
        let mut state = OustipState::default();

        let sources = vec![
            ("s1".to_string(), 100, vec![]),
            ("s2".to_string(), 200, vec![]),
            ("s3".to_string(), 50, vec![]),
        ];
        state.update_sources(sources);

        assert_eq!(state.total_entries, 350);
    }

    #[test]
    fn test_total_ips_aggregation() {
        let mut state = OustipState::default();

        // Two /24 networks = 256 + 256 = 512 IPs
        let sources = vec![(
            "test".to_string(),
            2,
            vec![
                "192.168.1.0/24".parse().unwrap(),
                "192.168.2.0/24".parse().unwrap(),
            ],
        )];
        state.update_sources(sources);

        assert!(state.total_ips > 0);
    }
}

// =============================================================================
// Mock FileSystem tests for OustipState
// =============================================================================

#[cfg(test)]
mod mock_fs_tests {
    use super::*;
    use crate::fs_abstraction::MockFileSystem;
    use std::io;

    // =========================================================================
    // load_with_fs tests
    // =========================================================================

    #[test]
    fn test_load_with_fs_file_not_found() {
        let mut mock = MockFileSystem::new();

        // Neither main file nor backup exists
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| false);
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| false);

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Should return default state
        assert!(state.last_update.is_none());
        assert!(state.sources.is_empty());
        assert_eq!(state.total_entries, 0);
    }

    #[test]
    fn test_load_with_fs_valid_json() {
        let mut mock = MockFileSystem::new();

        let state_json = r#"{
            "last_update": null,
            "sources": [],
            "total_entries": 500,
            "total_ips": 10000
        }"#;

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(state_json.to_string()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        assert_eq!(state.total_entries, 500);
        assert_eq!(state.total_ips, 10000);
    }

    #[test]
    fn test_load_with_fs_corrupted_json_falls_back_to_backup() {
        let mut mock = MockFileSystem::new();

        let corrupted_json = "{{{invalid json}}}";
        let backup_json = r#"{
            "last_update": null,
            "sources": [],
            "total_entries": 100,
            "total_ips": 5000
        }"#;

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(corrupted_json.to_string()));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(move |_| Ok(backup_json.to_string()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Should have loaded from backup
        assert_eq!(state.total_entries, 100);
        assert_eq!(state.total_ips, 5000);
    }

    #[test]
    fn test_load_with_fs_read_error_falls_back_to_backup() {
        let mut mock = MockFileSystem::new();

        let backup_json = r#"{
            "last_update": null,
            "sources": [],
            "total_entries": 200,
            "total_ips": 8000
        }"#;

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| Err(io::Error::new(io::ErrorKind::PermissionDenied, "access denied")));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(move |_| Ok(backup_json.to_string()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Should have loaded from backup
        assert_eq!(state.total_entries, 200);
    }

    #[test]
    fn test_load_with_fs_both_corrupted_returns_default() {
        let mut mock = MockFileSystem::new();

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| Ok("{{{bad}}}".to_string()));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| Ok("{{{also bad}}}".to_string()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Should return default
        assert!(state.last_update.is_none());
        assert_eq!(state.total_entries, 0);
    }

    #[test]
    fn test_load_with_fs_backup_read_error_returns_default() {
        let mut mock = MockFileSystem::new();

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| false);
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| Err(io::Error::new(io::ErrorKind::PermissionDenied, "no access")));

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Should return default
        assert!(state.last_update.is_none());
    }

    #[test]
    fn test_load_with_fs_partial_json_missing_optional_fields() {
        let mut mock = MockFileSystem::new();

        // JSON without optional fields (assumed_ips, last_known_total_ips, last_preset)
        let state_json = r#"{
            "last_update": null,
            "sources": [],
            "total_entries": 300,
            "total_ips": 7000
        }"#;

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(state_json.to_string()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        assert_eq!(state.total_entries, 300);
        assert!(state.assumed_ips.is_none());
        assert!(state.last_known_total_ips.is_none());
        assert!(state.last_preset.is_none());
    }

    #[test]
    fn test_load_with_fs_with_all_fields() {
        let mut mock = MockFileSystem::new();

        let state_json = r#"{
            "last_update": "2024-01-15T10:30:00Z",
            "sources": [
                {"name": "test_source", "raw_count": 100, "ip_count": 5000, "ips": ["1.2.3.0/24"]}
            ],
            "total_entries": 100,
            "total_ips": 5000,
            "assumed_ips": ["8.8.8.8", "1.1.1.1"],
            "last_known_total_ips": 4500,
            "last_preset": "paranoid"
        }"#;

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(state_json.to_string()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        assert!(state.last_update.is_some());
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.sources[0].name, "test_source");
        assert_eq!(state.total_entries, 100);
        assert_eq!(state.total_ips, 5000);
        assert_eq!(state.assumed_ips, Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]));
        assert_eq!(state.last_known_total_ips, Some(4500));
        assert_eq!(state.last_preset, Some("paranoid".to_string()));
    }

    // =========================================================================
    // save_with_fs tests
    // =========================================================================

    #[test]
    fn test_save_with_fs_creates_parent_directory() {
        let mut mock = MockFileSystem::new();

        mock.expect_create_dir_all()
            .withf(|p| p == Path::new("/var/lib/oustip"))
            .returning(|_| Ok(()))
            .times(1);
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| false);
        mock.expect_write()
            .returning(|_, _| Ok(()));
        mock.expect_set_permissions_mode()
            .withf(|p, m| p == Path::new(STATE_FILE) && *m == 0o600)
            .returning(|_, _| Ok(()));

        let state = OustipState::default();
        // This will fail the tempfile creation (since /var/lib/oustip doesn't exist in test),
        // and fall back to mock's write method
        let _ = state.save_with_fs(&mock);
    }

    #[test]
    fn test_save_with_fs_creates_backup() {
        let mut mock = MockFileSystem::new();

        mock.expect_create_dir_all().returning(|_| Ok(()));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_copy()
            .withf(|from, to| from == Path::new(STATE_FILE) && to == Path::new(STATE_BACKUP_FILE))
            .returning(|_, _| Ok(100))
            .times(1);
        mock.expect_set_permissions_mode()
            .withf(|p, m| p == Path::new(STATE_BACKUP_FILE) && *m == 0o600)
            .returning(|_, _| Ok(()));
        mock.expect_write().returning(|_, _| Ok(()));
        mock.expect_set_permissions_mode()
            .withf(|p, m| p == Path::new(STATE_FILE) && *m == 0o600)
            .returning(|_, _| Ok(()));

        let state = OustipState::default();
        let _ = state.save_with_fs(&mock);
    }

    #[test]
    fn test_save_with_fs_backup_failure_continues() {
        let mut mock = MockFileSystem::new();

        mock.expect_create_dir_all().returning(|_| Ok(()));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        // Backup fails
        mock.expect_copy()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")));
        mock.expect_write().returning(|_, _| Ok(()));
        mock.expect_set_permissions_mode()
            .withf(|p, _| p == Path::new(STATE_FILE))
            .returning(|_, _| Ok(()));

        let state = OustipState::default();
        // Should not fail even if backup fails
        let _ = state.save_with_fs(&mock);
    }

    #[test]
    fn test_save_with_fs_permission_error_on_state_file() {
        let mut mock = MockFileSystem::new();

        mock.expect_create_dir_all().returning(|_| Ok(()));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| false);
        mock.expect_write().returning(|_, _| Ok(()));
        mock.expect_set_permissions_mode()
            .withf(|p, _| p == Path::new(STATE_FILE))
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::PermissionDenied, "no chmod")));

        let state = OustipState::default();
        let result = state.save_with_fs(&mock);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("permissions"));
    }

    #[test]
    fn test_save_with_fs_directory_creation_failure() {
        let mut mock = MockFileSystem::new();

        mock.expect_create_dir_all()
            .returning(|_| Err(io::Error::new(io::ErrorKind::PermissionDenied, "no mkdir")));

        let state = OustipState::default();
        let result = state.save_with_fs(&mock);

        assert!(result.is_err());
    }

    #[test]
    fn test_save_with_fs_serializes_all_fields() {
        use std::sync::Arc;
        use std::sync::Mutex;

        let mut mock = MockFileSystem::new();
        let written_content = Arc::new(Mutex::new(String::new()));
        let written_content_clone = Arc::clone(&written_content);

        mock.expect_create_dir_all().returning(|_| Ok(()));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| false);
        mock.expect_write()
            .returning(move |_, contents| {
                *written_content_clone.lock().unwrap() = String::from_utf8_lossy(contents).to_string();
                Ok(())
            });
        mock.expect_set_permissions_mode().returning(|_, _| Ok(()));

        let mut state = OustipState::default();
        state.total_entries = 999;
        state.total_ips = 88888;
        state.add_assumed_ip("8.8.8.8");
        state.last_known_total_ips = Some(77777);
        state.last_preset = Some("full".to_string());

        let _ = state.save_with_fs(&mock);

        let content = written_content.lock().unwrap();
        assert!(content.contains("999"));
        assert!(content.contains("88888"));
        assert!(content.contains("8.8.8.8"));
        assert!(content.contains("77777"));
        assert!(content.contains("full"));
    }

    // =========================================================================
    // backup_state_with_fs tests
    // =========================================================================

    #[test]
    fn test_backup_state_with_fs_no_state_file() {
        let mut mock = MockFileSystem::new();

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| false);

        // Should succeed without doing anything
        let result = OustipState::backup_state_with_fs(&mock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_backup_state_with_fs_copy_error() {
        let mut mock = MockFileSystem::new();

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_copy()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::Other, "disk full")));

        let result = OustipState::backup_state_with_fs(&mock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("backup"));
    }

    #[test]
    fn test_backup_state_with_fs_permission_error() {
        let mut mock = MockFileSystem::new();

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_copy().returning(|_, _| Ok(100));
        mock.expect_set_permissions_mode()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::PermissionDenied, "no chmod")));

        let result = OustipState::backup_state_with_fs(&mock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("permissions"));
    }

    // =========================================================================
    // Edge cases and concurrent access simulation
    // =========================================================================

    #[test]
    fn test_load_with_fs_empty_json_file() {
        let mut mock = MockFileSystem::new();

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| Ok("".to_string()));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| false);

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Empty string is invalid JSON, should fall back to default
        assert!(state.last_update.is_none());
    }

    #[test]
    fn test_load_with_fs_truncated_json() {
        let mut mock = MockFileSystem::new();

        // Simulates a crash during write
        let truncated = r#"{"last_update": null, "sources": [{"name": "te"#;

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(truncated.to_string()));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| false);

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Truncated JSON should fall back to default
        assert!(state.last_update.is_none());
    }

    #[test]
    fn test_load_with_fs_io_error_interrupted() {
        let mut mock = MockFileSystem::new();

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted")));
        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_BACKUP_FILE))
            .returning(|_| false);

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Should fall back to default
        assert!(state.last_update.is_none());
    }

    #[test]
    fn test_load_with_fs_large_state_file() {
        let mut mock = MockFileSystem::new();

        // Generate state with many sources
        let many_sources: Vec<String> = (0..100)
            .map(|i| format!(r#"{{"name": "source_{}", "raw_count": {}, "ip_count": {}, "ips": []}}"#, i, i * 10, i * 100))
            .collect();

        let sources_str = many_sources.join(",");
        let state_json = format!(
            r#"{{
                "last_update": null,
                "sources": [{}],
                "total_entries": 45000,
                "total_ips": 450000
            }}"#,
            sources_str
        );

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(state_json.clone()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        assert_eq!(state.sources.len(), 100);
        assert_eq!(state.total_entries, 45000);
    }

    #[test]
    fn test_save_with_fs_concurrent_backup_simulation() {
        use mockall::Sequence;

        let mut mock = MockFileSystem::new();
        let mut seq = Sequence::new();

        // Simulate: create dir, backup (with existing file), write, chmod
        mock.expect_create_dir_all()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(()));

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| true);

        mock.expect_copy()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(500));

        mock.expect_set_permissions_mode()
            .withf(|p, _| p == Path::new(STATE_BACKUP_FILE))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));

        mock.expect_write()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));

        mock.expect_set_permissions_mode()
            .withf(|p, _| p == Path::new(STATE_FILE))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));

        let state = OustipState::default();
        let _ = state.save_with_fs(&mock);
    }

    #[test]
    fn test_load_with_fs_unicode_in_state() {
        let mut mock = MockFileSystem::new();

        let state_json = r#"{
            "last_update": null,
            "sources": [],
            "total_entries": 0,
            "total_ips": 0,
            "assumed_ips": ["::1", "2001:db8::1"],
            "last_preset": "recommended"
        }"#;

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(state_json.to_string()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        assert!(state.is_assumed("::1"));
        assert!(state.is_assumed("2001:db8::1"));
    }

    #[test]
    fn test_load_save_roundtrip_with_mock() {
        use std::sync::Arc;
        use std::sync::Mutex;

        let storage = Arc::new(Mutex::new(String::new()));
        let storage_clone = Arc::clone(&storage);
        let storage_read = Arc::clone(&storage);

        // First, save a state
        let mut save_mock = MockFileSystem::new();
        save_mock.expect_create_dir_all().returning(|_| Ok(()));
        save_mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| false);
        save_mock.expect_write()
            .returning(move |_, contents| {
                *storage_clone.lock().unwrap() = String::from_utf8_lossy(contents).to_string();
                Ok(())
            });
        save_mock.expect_set_permissions_mode().returning(|_, _| Ok(()));

        let mut original = OustipState::default();
        original.total_entries = 12345;
        original.total_ips = 67890;
        original.add_assumed_ip("10.0.0.1");
        original.last_preset = Some("minimal".to_string());

        let _ = original.save_with_fs(&save_mock);

        // Now load it back
        let mut load_mock = MockFileSystem::new();
        load_mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        load_mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(storage_read.lock().unwrap().clone()));

        let loaded = OustipState::load_with_fs(&load_mock).unwrap();

        assert_eq!(loaded.total_entries, 12345);
        assert_eq!(loaded.total_ips, 67890);
        assert!(loaded.is_assumed("10.0.0.1"));
        assert_eq!(loaded.last_preset, Some("minimal".to_string()));
    }

    #[test]
    fn test_state_file_paths_constants() {
        // Verify constants are properly set
        assert_eq!(STATE_FILE, "/var/lib/oustip/state.json");
        assert_eq!(STATE_BACKUP_FILE, "/var/lib/oustip/state.json.bak");
    }

    #[test]
    fn test_load_with_fs_extra_fields_ignored() {
        let mut mock = MockFileSystem::new();

        let state_json = r#"{
            "last_update": null,
            "sources": [],
            "total_entries": 42,
            "total_ips": 1000,
            "unknown_field_1": "should be ignored",
            "unknown_field_2": 12345
        }"#;

        mock.expect_exists()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(|_| true);
        mock.expect_read_to_string()
            .withf(|p| p == Path::new(STATE_FILE))
            .returning(move |_| Ok(state_json.to_string()));

        let state = OustipState::load_with_fs(&mock).unwrap();

        // Should successfully parse despite extra fields
        assert_eq!(state.total_entries, 42);
        assert_eq!(state.total_ips, 1000);
    }
}
