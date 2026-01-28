//! Installation and uninstallation of OustIP.

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::config::Config;

const CONFIG_DIR: &str = "/etc/oustip";
const CONFIG_FILE: &str = "/etc/oustip/config.yaml";
const STATE_DIR: &str = "/var/lib/oustip";
const SYSTEMD_SERVICE: &str = "/etc/systemd/system/oustip.service";
const SYSTEMD_TIMER: &str = "/etc/systemd/system/oustip.timer";

/// Valid preset values (must match config.rs)
const VALID_PRESETS: &[&str] = &["minimal", "recommended", "full", "paranoid"];

/// Validate preset value to prevent injection
fn validate_preset(preset: &str) -> Result<()> {
    if !VALID_PRESETS.contains(&preset) {
        anyhow::bail!(
            "Invalid preset '{}'. Valid values: {}",
            preset,
            VALID_PRESETS.join(", ")
        );
    }
    Ok(())
}

/// Validate timer interval format to prevent injection
/// Accepts formats like: 30s, 5m, 4h, 1d
/// Requires ASCII-only input to prevent Unicode-related edge cases
fn validate_interval(interval: &str) -> Result<()> {
    if interval.is_empty() {
        anyhow::bail!("Timer interval cannot be empty");
    }

    // Reject non-ASCII to prevent Unicode edge cases
    if !interval.is_ascii() {
        anyhow::bail!(
            "Invalid timer interval '{}'. Only ASCII characters allowed",
            interval
        );
    }

    if interval.len() < 2 {
        anyhow::bail!(
            "Invalid timer interval '{}'. Use format like '4h', '30m', '1d'",
            interval
        );
    }

    // Safe to use chars() since we verified ASCII-only
    let suffix = interval.chars().last().unwrap();
    let num_part = &interval[..interval.len() - 1];

    // Validate suffix
    if !matches!(suffix, 's' | 'm' | 'h' | 'd') {
        anyhow::bail!(
            "Invalid timer interval '{}'. Suffix must be s, m, h, or d",
            interval
        );
    }

    // Validate number part
    if num_part.parse::<u32>().is_err() {
        anyhow::bail!(
            "Invalid timer interval '{}'. Number part must be a positive integer",
            interval
        );
    }

    Ok(())
}

/// Install OustIP
pub fn install(preset: Option<&str>) -> Result<()> {
    // Validate preset if provided (prevents injection attacks)
    if let Some(p) = preset {
        validate_preset(p)?;
    }

    // Check if already installed
    if Path::new(CONFIG_FILE).exists() {
        anyhow::bail!(
            "OustIP is already installed. Config exists at {}.\n\
             Use 'oustip uninstall' first if you want to reinstall.",
            CONFIG_FILE
        );
    }

    // Create directories
    info!("Creating directories...");
    fs::create_dir_all(CONFIG_DIR).context("Failed to create config directory")?;
    fs::create_dir_all(STATE_DIR).context("Failed to create state directory")?;

    // Set restrictive permissions on state directory
    fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700))
        .context("Failed to set state directory permissions")?;

    // Create config file
    info!("Creating {}...", CONFIG_FILE);
    let mut config_content = Config::generate_default_yaml();

    // Override preset if specified (already validated above)
    if let Some(p) = preset {
        config_content = config_content.replace("preset: recommended", &format!("preset: {}", p));
    }

    fs::write(CONFIG_FILE, config_content).context("Failed to write config file")?;

    // Set permissions (readable only by root)
    fs::set_permissions(CONFIG_FILE, fs::Permissions::from_mode(0o600))
        .context("Failed to set config permissions")?;

    // Create systemd service
    info!("Creating {}...", SYSTEMD_SERVICE);
    fs::write(SYSTEMD_SERVICE, generate_service_unit())
        .context("Failed to write systemd service")?;

    // Create systemd timer
    info!("Creating {}...", SYSTEMD_TIMER);
    fs::write(SYSTEMD_TIMER, generate_timer_unit("4h"))
        .context("Failed to write systemd timer")?;

    // Reload systemd
    info!("Reloading systemd...");
    Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .context("Failed to reload systemd")?;

    // Enable timer
    info!("Enabling oustip.timer...");
    Command::new("systemctl")
        .args(["enable", "oustip.timer"])
        .status()
        .context("Failed to enable timer")?;

    // Enable service (for boot)
    Command::new("systemctl")
        .args(["enable", "oustip.service"])
        .status()
        .context("Failed to enable service")?;

    // Start timer
    info!("Starting oustip.timer...");
    Command::new("systemctl")
        .args(["start", "oustip.timer"])
        .status()
        .context("Failed to start timer")?;

    println!();
    println!("[OK] Installation complete!");
    println!();
    println!("Next steps:");
    println!("  1. Edit configuration: {}", CONFIG_FILE);
    println!("  2. Apply rules: oustip update");
    println!("  3. Check status: oustip status");
    println!();

    Ok(())
}

/// Uninstall OustIP
pub fn uninstall() -> Result<()> {
    info!("Uninstalling OustIP...");

    // Stop and disable timer
    let _ = Command::new("systemctl")
        .args(["stop", "oustip.timer"])
        .status();
    let _ = Command::new("systemctl")
        .args(["disable", "oustip.timer"])
        .status();

    // Stop and disable service
    let _ = Command::new("systemctl")
        .args(["stop", "oustip.service"])
        .status();
    let _ = Command::new("systemctl")
        .args(["disable", "oustip.service"])
        .status();

    // Remove systemd files
    if Path::new(SYSTEMD_SERVICE).exists() {
        info!("Removing {}...", SYSTEMD_SERVICE);
        fs::remove_file(SYSTEMD_SERVICE)?;
    }
    if Path::new(SYSTEMD_TIMER).exists() {
        info!("Removing {}...", SYSTEMD_TIMER);
        fs::remove_file(SYSTEMD_TIMER)?;
    }

    // Reload systemd
    let _ = Command::new("systemctl")
        .args(["daemon-reload"])
        .status();

    // Remove config directory
    if Path::new(CONFIG_DIR).exists() {
        info!("Removing {}...", CONFIG_DIR);
        fs::remove_dir_all(CONFIG_DIR)?;
    }

    // Remove state directory
    if Path::new(STATE_DIR).exists() {
        info!("Removing {}...", STATE_DIR);
        fs::remove_dir_all(STATE_DIR)?;
    }

    println!();
    println!("[OK] OustIP uninstalled successfully.");
    println!();
    println!("Note: Firewall rules have been removed.");
    println!("      The binary at /usr/local/bin/oustip was not removed.");
    println!();

    Ok(())
}

/// Update systemd timer interval
pub fn update_timer_interval(interval: &str) -> Result<()> {
    // Validate interval format (prevents injection attacks)
    validate_interval(interval)?;

    info!("Updating timer interval to {}...", interval);
    fs::write(SYSTEMD_TIMER, generate_timer_unit(interval))
        .context("Failed to update timer")?;

    Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .context("Failed to reload systemd")?;

    Command::new("systemctl")
        .args(["restart", "oustip.timer"])
        .status()
        .context("Failed to restart timer")?;

    Ok(())
}

/// Generate systemd service unit
fn generate_service_unit() -> String {
    r#"[Unit]
Description=OustIP Blocklist Manager
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/jmchantrein/oustip

[Service]
Type=oneshot
ExecStart=/usr/local/bin/oustip update --quiet
RemainAfterExit=yes

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/oustip /var/log

# Required capabilities for firewall manipulation
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"#
    .to_string()
}

/// Generate systemd timer unit
fn generate_timer_unit(interval: &str) -> String {
    format!(
        r#"[Unit]
Description=OustIP periodic blocklist update
Documentation=https://github.com/jmchantrein/oustip

[Timer]
OnBootSec=5min
OnUnitActiveSec={}
Persistent=true

[Install]
WantedBy=timers.target
"#,
        interval
    )
}

/// Check if OustIP is installed
pub fn is_installed() -> bool {
    Path::new(CONFIG_FILE).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_service_unit() {
        let unit = generate_service_unit();
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("oustip update"));
    }

    #[test]
    fn test_generate_timer_unit() {
        let unit = generate_timer_unit("6h");
        assert!(unit.contains("[Timer]"));
        assert!(unit.contains("OnUnitActiveSec=6h"));
    }
}
