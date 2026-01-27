//! Status command implementation.

use anyhow::Result;
use std::path::Path;

use crate::config::Config;
use crate::enforcer::create_backend;
use crate::fetcher::format_count;
use crate::installer::is_installed;
use crate::stats::OustipState;

/// Run the status command
pub async fn run(config_path: &Path) -> Result<()> {
    println!();

    // Check installation
    if !is_installed() {
        println!("OustIP: NOT INSTALLED");
        println!();
        println!("Run 'oustip install' to install.");
        return Ok(());
    }

    // Load config
    let config = Config::load(config_path)?;
    let backend = create_backend(config.backend)?;

    // Check if active
    let is_active = backend.is_active().await?;
    let status = if is_active { "ENABLED" } else { "DISABLED" };

    // Get entry count
    let entry_count = if is_active {
        backend.entry_count().await.unwrap_or(0)
    } else {
        0
    };

    // Get state
    let state = OustipState::load().unwrap_or_default();

    // Backend name
    let backend_name = match config.backend {
        crate::config::Backend::Auto => {
            // Detect actual backend
            if std::process::Command::new("nft")
                .arg("--version")
                .output()
                .is_ok()
            {
                "nftables (auto)"
            } else {
                "iptables (auto)"
            }
        }
        crate::config::Backend::Iptables => "iptables",
        crate::config::Backend::Nftables => "nftables",
    };

    // Mode name
    let mode_name = match config.mode {
        crate::config::FilterMode::Raw => "raw (before conntrack)",
        crate::config::FilterMode::Conntrack => "conntrack (after conntrack)",
    };

    // Display status
    println!("OustIP: {}", status);
    println!("Backend: {}", backend_name);
    println!("Mode: {}", mode_name);
    println!("Preset: {}", config.preset);
    println!();

    if is_active {
        println!("Entries in set: {}", format_count(entry_count));
        println!("IPs covered: {}", format_count(state.total_ips as usize));
    }

    // Blocklists status
    let enabled_count = config
        .get_enabled_blocklists(None)
        .len();
    println!("Blocklists: {} enabled", enabled_count);

    // Last update
    if let Some(last_update) = state.last_update {
        let local: chrono::DateTime<chrono::Local> = last_update.into();
        println!("Last update: {}", local.format("%Y-%m-%d %H:%M:%S"));
    } else {
        println!("Last update: never");
    }

    println!();

    Ok(())
}
