//! Statistics display for OustIP.

use crate::aggregator::{count_ips, coverage_percent};
use crate::config::Config;
use crate::enforcer::create_backend;
use crate::fetcher::format_count;
use anyhow::Result;
use chrono::{DateTime, Local, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const STATE_FILE: &str = "/var/lib/oustip/state.json";

/// Persistent state for OustIP
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OustipState {
    pub last_update: Option<DateTime<Utc>>,
    pub sources: Vec<SourceStats>,
    pub total_entries: usize,
    pub total_ips: u128,
}

/// Statistics for a single blocklist source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceStats {
    pub name: String,
    pub raw_count: usize,
    pub ip_count: u128,
}

impl OustipState {
    /// Load state from file
    pub fn load() -> Result<Self> {
        let path = Path::new(STATE_FILE);
        if path.exists() {
            let content = fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    /// Save state to file
    pub fn save(&self) -> Result<()> {
        let path = Path::new(STATE_FILE);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Update state with new fetch results
    pub fn update_sources(&mut self, sources: Vec<(String, usize, Vec<IpNet>)>) {
        self.sources = sources
            .iter()
            .map(|(name, raw_count, ips)| SourceStats {
                name: name.clone(),
                raw_count: *raw_count,
                ip_count: count_ips(ips),
            })
            .collect();

        self.total_entries = self.sources.iter().map(|s| s.raw_count).sum();
        self.total_ips = self.sources.iter().map(|s| s.ip_count).sum();
        self.last_update = Some(Utc::now());
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
    println!(
        " Bytes blocked: {}",
        format_bytes(fw_stats.bytes_blocked)
    );
    println!();

    // Last update
    if let Some(last_update) = state.last_update {
        let local: DateTime<Local> = last_update.into();
        let ago = format_duration_ago(last_update);
        println!(" Last update: {} ({})", local.format("%Y-%m-%d %H:%M:%S"), ago);
    } else {
        println!(" Last update: never");
    }

    println!("══════════════════════════════════════════════════════════════════");
    println!();

    Ok(())
}

/// Format bytes in human-readable form
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
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

/// Truncate a string to a maximum length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.4 GB");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a long string", 10), "this is...");
    }
}
