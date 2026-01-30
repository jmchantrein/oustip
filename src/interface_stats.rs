//! Interface and preset statistics persistence.
//!
//! This module provides persistent statistics storage for:
//! - Per-interface blocking statistics (packets, bytes, last blocked IP)
//! - Per-preset usage statistics (IP count, last update)
//! - Global statistics (total blocked, uptime)
//!
//! Statistics are stored in `/var/lib/oustip/stats/` as separate YAML files
//! for easy inspection and editing.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Directory for statistics files
const STATS_DIR: &str = "/var/lib/oustip/stats";

/// Statistics for a single interface
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InterfaceStats {
    /// Interface name
    pub name: String,
    /// Mode (wan, lan, trusted)
    pub mode: String,
    /// Total packets blocked on this interface
    pub packets_blocked: u64,
    /// Total bytes blocked on this interface
    pub bytes_blocked: u64,
    /// Last blocked IP (for quick reference)
    pub last_blocked_ip: Option<String>,
    /// Timestamp of last block event
    pub last_block_time: Option<DateTime<Utc>>,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
    /// Number of IPs in the blocklist for this interface
    pub blocklist_ip_count: usize,
    /// Number of IPs in the allowlist for this interface
    pub allowlist_ip_count: usize,
}

impl InterfaceStats {
    /// Create new interface stats
    pub fn new(name: &str, mode: &str) -> Self {
        Self {
            name: name.to_string(),
            mode: mode.to_string(),
            last_update: Utc::now(),
            ..Default::default()
        }
    }

    /// Update blocking statistics
    pub fn record_block(&mut self, ip: &str, bytes: u64) {
        self.packets_blocked += 1;
        self.bytes_blocked += bytes;
        self.last_blocked_ip = Some(ip.to_string());
        self.last_block_time = Some(Utc::now());
    }

    /// Update IP counts after list refresh
    pub fn update_counts(&mut self, blocklist_count: usize, allowlist_count: usize) {
        self.blocklist_ip_count = blocklist_count;
        self.allowlist_ip_count = allowlist_count;
        self.last_update = Utc::now();
    }
}

/// Statistics for a preset
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PresetStats {
    /// Preset name
    pub name: String,
    /// Preset type (blocklist or allowlist)
    pub preset_type: String,
    /// Number of sources in this preset
    pub source_count: usize,
    /// Total IP/CIDR count after aggregation
    pub ip_count: usize,
    /// Raw IP count before aggregation
    pub raw_ip_count: usize,
    /// Last fetch timestamp
    pub last_fetch: Option<DateTime<Utc>>,
    /// Fetch duration in milliseconds
    pub fetch_duration_ms: Option<u64>,
    /// Number of interfaces using this preset
    pub usage_count: usize,
}

impl PresetStats {
    /// Create new preset stats
    pub fn new(name: &str, preset_type: &str) -> Self {
        Self {
            name: name.to_string(),
            preset_type: preset_type.to_string(),
            ..Default::default()
        }
    }

    /// Record fetch results
    pub fn record_fetch(
        &mut self,
        source_count: usize,
        raw_count: usize,
        aggregated_count: usize,
        duration_ms: u64,
    ) {
        self.source_count = source_count;
        self.raw_ip_count = raw_count;
        self.ip_count = aggregated_count;
        self.fetch_duration_ms = Some(duration_ms);
        self.last_fetch = Some(Utc::now());
    }
}

/// Global statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalStats {
    /// Total packets blocked across all interfaces
    pub total_packets_blocked: u64,
    /// Total bytes blocked across all interfaces
    pub total_bytes_blocked: u64,
    /// Service start time
    pub service_start: Option<DateTime<Utc>>,
    /// Last update time
    pub last_update: DateTime<Utc>,
    /// Number of active interfaces
    pub active_interfaces: usize,
    /// Number of active presets
    pub active_presets: usize,
    /// Total unique IPs in all blocklists (after dedup)
    pub total_blocklist_ips: usize,
    /// Total unique IPs in all allowlists (after dedup)
    pub total_allowlist_ips: usize,
    /// Last successful update
    pub last_successful_update: Option<DateTime<Utc>>,
    /// Number of updates performed
    pub update_count: u64,
}

impl GlobalStats {
    /// Create new global stats
    pub fn new() -> Self {
        Self {
            service_start: Some(Utc::now()),
            last_update: Utc::now(),
            ..Default::default()
        }
    }

    /// Mark service start
    pub fn mark_start(&mut self) {
        if self.service_start.is_none() {
            self.service_start = Some(Utc::now());
        }
    }

    /// Record successful update
    pub fn record_update(
        &mut self,
        interfaces: usize,
        presets: usize,
        blocklist_ips: usize,
        allowlist_ips: usize,
    ) {
        self.active_interfaces = interfaces;
        self.active_presets = presets;
        self.total_blocklist_ips = blocklist_ips;
        self.total_allowlist_ips = allowlist_ips;
        self.last_successful_update = Some(Utc::now());
        self.last_update = Utc::now();
        self.update_count += 1;
    }

    /// Aggregate blocking stats from interfaces
    pub fn aggregate_from_interfaces(&mut self, interfaces: &[InterfaceStats]) {
        self.total_packets_blocked = interfaces.iter().map(|i| i.packets_blocked).sum();
        self.total_bytes_blocked = interfaces.iter().map(|i| i.bytes_blocked).sum();
        self.last_update = Utc::now();
    }
}

/// Statistics manager for persistent storage
pub struct StatsManager {
    stats_dir: PathBuf,
}

impl StatsManager {
    /// Create a new stats manager
    pub fn new() -> Self {
        Self {
            stats_dir: PathBuf::from(STATS_DIR),
        }
    }

    /// Create stats manager with custom directory (for testing)
    pub fn with_dir<P: AsRef<Path>>(dir: P) -> Self {
        Self {
            stats_dir: dir.as_ref().to_path_buf(),
        }
    }

    /// Ensure stats directory exists
    fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.stats_dir)
            .with_context(|| format!("Failed to create stats directory: {:?}", self.stats_dir))?;
        Ok(())
    }

    /// Get path for interface stats file
    fn interface_stats_path(&self, name: &str) -> PathBuf {
        self.stats_dir.join(format!("interface_{}.yaml", name))
    }

    /// Get path for preset stats file
    fn preset_stats_path(&self, name: &str, preset_type: &str) -> PathBuf {
        self.stats_dir
            .join(format!("preset_{}_{}.yaml", preset_type, name))
    }

    /// Get path for global stats file
    fn global_stats_path(&self) -> PathBuf {
        self.stats_dir.join("global.yaml")
    }

    // =========================================================================
    // Interface stats
    // =========================================================================

    /// Load interface stats (creates default if not exists)
    pub fn load_interface_stats(&self, name: &str, mode: &str) -> Result<InterfaceStats> {
        let path = self.interface_stats_path(name);
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read interface stats: {:?}", path))?;
            let stats: InterfaceStats = serde_saphyr::from_str(&content)
                .with_context(|| format!("Failed to parse interface stats: {:?}", path))?;
            Ok(stats)
        } else {
            Ok(InterfaceStats::new(name, mode))
        }
    }

    /// Save interface stats
    pub fn save_interface_stats(&self, stats: &InterfaceStats) -> Result<()> {
        self.ensure_dir()?;
        let path = self.interface_stats_path(&stats.name);

        let yaml = serde_saphyr::to_string(stats).context("Failed to serialize interface stats")?;

        // Add header comment
        let content = format!(
            "# OustIP Interface Statistics: {}\n\
             # Last updated: {}\n\
             # This file is auto-generated but can be manually edited.\n\n{}",
            stats.name,
            stats.last_update.format("%Y-%m-%d %H:%M:%S UTC"),
            yaml
        );

        atomic_write(&path, &content)?;
        Ok(())
    }

    /// Load all interface stats
    pub fn load_all_interface_stats(&self) -> Result<Vec<InterfaceStats>> {
        let mut stats = Vec::new();
        if self.stats_dir.exists() {
            for entry in fs::read_dir(&self.stats_dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("interface_") && name.ends_with(".yaml") {
                    let iface_name = name
                        .strip_prefix("interface_")
                        .and_then(|s| s.strip_suffix(".yaml"))
                        .unwrap_or("");
                    if !iface_name.is_empty() {
                        if let Ok(s) = self.load_interface_stats(iface_name, "unknown") {
                            stats.push(s);
                        }
                    }
                }
            }
        }
        Ok(stats)
    }

    // =========================================================================
    // Preset stats
    // =========================================================================

    /// Load preset stats (creates default if not exists)
    pub fn load_preset_stats(&self, name: &str, preset_type: &str) -> Result<PresetStats> {
        let path = self.preset_stats_path(name, preset_type);
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read preset stats: {:?}", path))?;
            let stats: PresetStats = serde_saphyr::from_str(&content)
                .with_context(|| format!("Failed to parse preset stats: {:?}", path))?;
            Ok(stats)
        } else {
            Ok(PresetStats::new(name, preset_type))
        }
    }

    /// Save preset stats
    pub fn save_preset_stats(&self, stats: &PresetStats) -> Result<()> {
        self.ensure_dir()?;
        let path = self.preset_stats_path(&stats.name, &stats.preset_type);

        let yaml = serde_saphyr::to_string(stats).context("Failed to serialize preset stats")?;

        // Add header comment
        let content = format!(
            "# OustIP Preset Statistics: {} ({})\n\
             # Last fetched: {}\n\
             # This file is auto-generated but can be manually edited.\n\n{}",
            stats.name,
            stats.preset_type,
            stats
                .last_fetch
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "never".to_string()),
            yaml
        );

        atomic_write(&path, &content)?;
        Ok(())
    }

    /// Load all preset stats
    pub fn load_all_preset_stats(&self) -> Result<Vec<PresetStats>> {
        let mut stats = Vec::new();
        if self.stats_dir.exists() {
            for entry in fs::read_dir(&self.stats_dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("preset_") && name.ends_with(".yaml") {
                    let content = fs::read_to_string(entry.path())?;
                    if let Ok(s) = serde_saphyr::from_str(&content) {
                        stats.push(s);
                    }
                }
            }
        }
        Ok(stats)
    }

    // =========================================================================
    // Global stats
    // =========================================================================

    /// Load global stats (creates default if not exists)
    pub fn load_global_stats(&self) -> Result<GlobalStats> {
        let path = self.global_stats_path();
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read global stats: {:?}", path))?;
            let stats: GlobalStats = serde_saphyr::from_str(&content)
                .with_context(|| format!("Failed to parse global stats: {:?}", path))?;
            Ok(stats)
        } else {
            Ok(GlobalStats::new())
        }
    }

    /// Save global stats
    pub fn save_global_stats(&self, stats: &GlobalStats) -> Result<()> {
        self.ensure_dir()?;
        let path = self.global_stats_path();

        let yaml = serde_saphyr::to_string(stats).context("Failed to serialize global stats")?;

        // Add header comment
        let content = format!(
            "# OustIP Global Statistics\n\
             # Last updated: {}\n\
             # Service started: {}\n\
             # This file is auto-generated but can be manually edited.\n\n{}",
            stats.last_update.format("%Y-%m-%d %H:%M:%S UTC"),
            stats
                .service_start
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            yaml
        );

        atomic_write(&path, &content)?;
        Ok(())
    }

    // =========================================================================
    // Cleanup
    // =========================================================================

    /// Remove stats for an interface that no longer exists
    pub fn remove_interface_stats(&self, name: &str) -> Result<()> {
        let path = self.interface_stats_path(name);
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove interface stats: {:?}", path))?;
        }
        Ok(())
    }

    /// Remove all stats (for uninstall)
    pub fn remove_all_stats(&self) -> Result<()> {
        if self.stats_dir.exists() {
            fs::remove_dir_all(&self.stats_dir).with_context(|| {
                format!("Failed to remove stats directory: {:?}", self.stats_dir)
            })?;
        }
        Ok(())
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Atomic file write (write to temp, then rename)
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    let temp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));

    let mut file = fs::File::create(&temp_path)
        .with_context(|| format!("Failed to create temp file: {:?}", temp_path))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("Failed to write temp file: {:?}", temp_path))?;
    file.sync_all()?;
    drop(file);

    fs::rename(&temp_path, path)
        .with_context(|| format!("Failed to rename temp file to {:?}", path))?;

    Ok(())
}

/// Format bytes for human display
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format packet count for human display
pub fn format_packets(count: u64) -> String {
    if count >= 1_000_000 {
        format!("{:.2}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.2}K", count as f64 / 1_000.0)
    } else {
        count.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_interface_stats_new() {
        let stats = InterfaceStats::new("eth0", "wan");
        assert_eq!(stats.name, "eth0");
        assert_eq!(stats.mode, "wan");
        assert_eq!(stats.packets_blocked, 0);
    }

    #[test]
    fn test_interface_stats_record_block() {
        let mut stats = InterfaceStats::new("eth0", "wan");
        stats.record_block("1.2.3.4", 1500);
        assert_eq!(stats.packets_blocked, 1);
        assert_eq!(stats.bytes_blocked, 1500);
        assert_eq!(stats.last_blocked_ip, Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_preset_stats_new() {
        let stats = PresetStats::new("paranoid", "blocklist");
        assert_eq!(stats.name, "paranoid");
        assert_eq!(stats.preset_type, "blocklist");
    }

    #[test]
    fn test_preset_stats_record_fetch() {
        let mut stats = PresetStats::new("paranoid", "blocklist");
        stats.record_fetch(5, 100000, 50000, 1500);
        assert_eq!(stats.source_count, 5);
        assert_eq!(stats.raw_ip_count, 100000);
        assert_eq!(stats.ip_count, 50000);
        assert_eq!(stats.fetch_duration_ms, Some(1500));
    }

    #[test]
    fn test_global_stats_new() {
        let stats = GlobalStats::new();
        assert!(stats.service_start.is_some());
        assert_eq!(stats.update_count, 0);
    }

    #[test]
    fn test_global_stats_record_update() {
        let mut stats = GlobalStats::new();
        stats.record_update(3, 4, 50000, 1000);
        assert_eq!(stats.active_interfaces, 3);
        assert_eq!(stats.active_presets, 4);
        assert_eq!(stats.total_blocklist_ips, 50000);
        assert_eq!(stats.update_count, 1);
    }

    #[test]
    fn test_stats_manager_interface_roundtrip() {
        let dir = tempdir().unwrap();
        let manager = StatsManager::with_dir(dir.path());

        let mut stats = InterfaceStats::new("eth0", "wan");
        stats.record_block("1.2.3.4", 1500);
        stats.update_counts(50000, 1000);

        manager.save_interface_stats(&stats).unwrap();

        let loaded = manager.load_interface_stats("eth0", "wan").unwrap();
        assert_eq!(loaded.packets_blocked, 1);
        assert_eq!(loaded.blocklist_ip_count, 50000);
    }

    #[test]
    fn test_stats_manager_preset_roundtrip() {
        let dir = tempdir().unwrap();
        let manager = StatsManager::with_dir(dir.path());

        let mut stats = PresetStats::new("paranoid", "blocklist");
        stats.record_fetch(5, 100000, 50000, 1500);

        manager.save_preset_stats(&stats).unwrap();

        let loaded = manager.load_preset_stats("paranoid", "blocklist").unwrap();
        assert_eq!(loaded.ip_count, 50000);
        assert_eq!(loaded.fetch_duration_ms, Some(1500));
    }

    #[test]
    fn test_stats_manager_global_roundtrip() {
        let dir = tempdir().unwrap();
        let manager = StatsManager::with_dir(dir.path());

        let mut stats = GlobalStats::new();
        stats.record_update(3, 4, 50000, 1000);

        manager.save_global_stats(&stats).unwrap();

        let loaded = manager.load_global_stats().unwrap();
        assert_eq!(loaded.active_interfaces, 3);
        assert_eq!(loaded.update_count, 1);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.46 KB");
        assert_eq!(format_bytes(1_500_000), "1.43 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.40 GB");
    }

    #[test]
    fn test_format_packets() {
        assert_eq!(format_packets(500), "500");
        assert_eq!(format_packets(1500), "1.50K");
        assert_eq!(format_packets(1_500_000), "1.50M");
    }
}
