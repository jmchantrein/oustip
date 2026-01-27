//! IPv6 management command implementation.

use anyhow::{Context, Result};
use std::fs;
use std::process::Command;
use tracing::info;

use crate::cli::Ipv6Action;
use crate::enforcer::check_root;

const SYSCTL_CONF: &str = "/etc/sysctl.d/99-oustip-ipv6.conf";

/// Run the ipv6 command
pub async fn run(action: Ipv6Action) -> Result<()> {
    match action {
        Ipv6Action::Disable => disable_ipv6().await,
        Ipv6Action::Enable => enable_ipv6().await,
        Ipv6Action::Status => show_ipv6_status().await,
    }
}

/// Disable IPv6 via sysctl
async fn disable_ipv6() -> Result<()> {
    check_root()?;

    info!("Disabling IPv6...");

    // Create sysctl config file
    let config = r#"# OustIP IPv6 configuration
# Disable IPv6 on all interfaces
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
"#;

    fs::write(SYSCTL_CONF, config).context("Failed to write sysctl config")?;

    // Apply immediately
    Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.disable_ipv6=1"])
        .status()
        .context("Failed to apply sysctl")?;

    Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.default.disable_ipv6=1"])
        .status()
        .context("Failed to apply sysctl")?;

    println!("[OK] IPv6 disabled");
    println!("     Configuration saved to {}", SYSCTL_CONF);
    println!("     This setting persists across reboots.");

    Ok(())
}

/// Enable IPv6 via sysctl
async fn enable_ipv6() -> Result<()> {
    check_root()?;

    info!("Enabling IPv6...");

    // Remove our sysctl config if it exists
    if std::path::Path::new(SYSCTL_CONF).exists() {
        fs::remove_file(SYSCTL_CONF).context("Failed to remove sysctl config")?;
    }

    // Apply immediately
    Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.disable_ipv6=0"])
        .status()
        .context("Failed to apply sysctl")?;

    Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.default.disable_ipv6=0"])
        .status()
        .context("Failed to apply sysctl")?;

    println!("[OK] IPv6 enabled");
    println!("     Note: You may need to restart network services or reboot");
    println!("     for full IPv6 functionality to be restored.");

    Ok(())
}

/// Show IPv6 status
async fn show_ipv6_status() -> Result<()> {
    // Read current sysctl value
    let output = Command::new("sysctl")
        .args(["-n", "net.ipv6.conf.all.disable_ipv6"])
        .output()
        .context("Failed to read sysctl")?;

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();

    println!();
    if value == "1" {
        println!("IPv6: DISABLED");
    } else {
        println!("IPv6: ENABLED");
    }

    // Check if our config file exists
    if std::path::Path::new(SYSCTL_CONF).exists() {
        println!("Managed by: OustIP ({})", SYSCTL_CONF);
    } else {
        println!("Managed by: System default");
    }
    println!();

    Ok(())
}
