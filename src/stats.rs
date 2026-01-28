//! Statistics display for OustIP.

use crate::aggregator::{count_ips, coverage_percent};
use crate::config::Config;
use crate::enforcer::create_backend;
use crate::fetcher::format_count;
use crate::utils::{format_bytes, truncate};
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
        let path = Path::new(STATE_FILE);
        let backup_path = Path::new(STATE_BACKUP_FILE);

        if path.exists() {
            fs::copy(path, backup_path).context("Failed to create state backup")?;
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
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: OustipState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total_entries, 100);
        assert_eq!(parsed.total_ips, 1000);
        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.sources[0].name, "test");
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
}
