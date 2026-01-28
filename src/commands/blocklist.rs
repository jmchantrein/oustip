//! Blocklist management command implementation.

use anyhow::Result;
use std::path::Path;

use crate::cli::BlocklistAction;
use crate::config::Config;
use crate::enforcer::check_root;
use crate::lock::LockGuard;
use crate::stats::OustipState;

/// Run the blocklist command
pub async fn run(action: BlocklistAction, config_path: &Path) -> Result<()> {
    match action {
        BlocklistAction::Enable { name } => enable_blocklist(&name, config_path).await,
        BlocklistAction::Disable { name } => disable_blocklist(&name, config_path).await,
        BlocklistAction::List => list_blocklists(config_path).await,
        BlocklistAction::Show { name, dns, limit } => {
            show_blocklist(&name, dns, limit, config_path).await
        }
    }
}

/// Enable a blocklist source
async fn enable_blocklist(name: &str, config_path: &Path) -> Result<()> {
    check_root()?;

    // Acquire lock to prevent concurrent config modifications
    let _lock = LockGuard::acquire()?;

    // Load config
    let mut config = Config::load(config_path)?;

    // Find blocklist index by name
    let idx = config
        .blocklists
        .iter()
        .position(|b| b.name.eq_ignore_ascii_case(name));

    match idx {
        Some(i) => {
            if config.blocklists[i].enabled {
                println!(
                    "Blocklist '{}' is already enabled",
                    config.blocklists[i].name
                );
            } else {
                let blocklist_name = config.blocklists[i].name.clone();
                config.blocklists[i].enabled = true;
                config.save(config_path)?;
                println!("[OK] Enabled blocklist '{}'", blocklist_name);
                println!("     Run 'oustip update' to apply changes");
            }
        }
        None => {
            println!("Blocklist '{}' not found.", name);
            println!();
            println!("Available blocklists:");
            for b in &config.blocklists {
                println!("  - {}", b.name);
            }
            anyhow::bail!("Blocklist not found");
        }
    }

    Ok(())
}

/// Disable a blocklist source
async fn disable_blocklist(name: &str, config_path: &Path) -> Result<()> {
    check_root()?;

    // Acquire lock to prevent concurrent config modifications
    let _lock = LockGuard::acquire()?;

    // Load config
    let mut config = Config::load(config_path)?;

    // Find blocklist index by name
    let idx = config
        .blocklists
        .iter()
        .position(|b| b.name.eq_ignore_ascii_case(name));

    match idx {
        Some(i) => {
            if !config.blocklists[i].enabled {
                println!(
                    "Blocklist '{}' is already disabled",
                    config.blocklists[i].name
                );
            } else {
                let blocklist_name = config.blocklists[i].name.clone();
                config.blocklists[i].enabled = false;
                config.save(config_path)?;
                println!("[OK] Disabled blocklist '{}'", blocklist_name);
                println!("     Run 'oustip update' to apply changes");
            }
        }
        None => {
            println!("Blocklist '{}' not found.", name);
            anyhow::bail!("Blocklist not found");
        }
    }

    Ok(())
}

/// List all blocklist sources and their status
async fn list_blocklists(config_path: &Path) -> Result<()> {
    let config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        Config::default()
    };

    let state = OustipState::load().unwrap_or_default();

    println!();
    println!("Blocklist Sources ({} total):", config.blocklists.len());
    println!();

    let enabled_count = config.blocklists.iter().filter(|b| b.enabled).count();
    let disabled_count = config.blocklists.len() - enabled_count;

    println!("  Enabled: {}, Disabled: {}", enabled_count, disabled_count);
    println!();

    // Show enabled blocklists
    println!("Enabled:");
    for b in config.blocklists.iter().filter(|b| b.enabled) {
        // Find stats for this blocklist
        let ip_count = state
            .sources
            .iter()
            .find(|s| s.name == b.name)
            .map(|s| s.ip_count)
            .unwrap_or(0);

        if ip_count > 0 {
            println!("  [x] {} ({} IPs)", b.name, format_count(ip_count as usize));
        } else {
            println!("  [x] {}", b.name);
        }
    }

    println!();
    println!("Disabled:");
    for b in config.blocklists.iter().filter(|b| !b.enabled) {
        println!("  [ ] {}", b.name);
    }

    println!();
    println!("Use 'oustip blocklist enable <name>' to enable a source");
    println!("Use 'oustip blocklist show <name>' to view IPs from a source");

    Ok(())
}

/// Show IPs from a specific blocklist with optional DNS resolution
async fn show_blocklist(name: &str, dns: bool, limit: usize, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let state = OustipState::load().unwrap_or_default();

    // Find the blocklist
    let blocklist = config
        .blocklists
        .iter()
        .find(|b| b.name.eq_ignore_ascii_case(name));

    if blocklist.is_none() {
        println!("Blocklist '{}' not found.", name);
        anyhow::bail!("Blocklist not found");
    }

    let blocklist = blocklist.unwrap();

    // Find stats for this blocklist
    let source = state.sources.iter().find(|s| s.name == blocklist.name);

    match source {
        Some(s) => {
            println!();
            println!(
                "Blocklist: {} ({} IPs)",
                s.name,
                format_count(s.ip_count as usize)
            );
            println!();

            if s.ips.is_empty() {
                println!("  (no IPs cached - run 'oustip update' first)");
            } else {
                let display_count = std::cmp::min(limit, s.ips.len());
                for ip in s.ips.iter().take(display_count) {
                    if dns {
                        let hostname = resolve_ip(ip).await;
                        println!("  {} -> {}", ip, hostname);
                    } else {
                        println!("  {}", ip);
                    }
                }

                if s.ips.len() > limit {
                    println!();
                    println!(
                        "  ... and {} more (use --limit to show more)",
                        s.ips.len() - limit
                    );
                }
            }
        }
        None => {
            println!(
                "No data for blocklist '{}'. Run 'oustip update' first.",
                name
            );
        }
    }

    Ok(())
}

/// Resolve IP to hostname via reverse DNS
async fn resolve_ip(ip: &str) -> String {
    use std::net::IpAddr;

    // Parse IP
    let ip_addr: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => {
            // It's a CIDR, extract the IP part
            if let Some(ip_part) = ip.split('/').next() {
                match ip_part.parse() {
                    Ok(addr) => addr,
                    Err(_) => return "(invalid)".to_string(),
                }
            } else {
                return "(invalid)".to_string();
            }
        }
    };

    // Perform reverse DNS lookup
    match tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_addr)).await {
        Ok(Ok(hostname)) => hostname,
        _ => "(no PTR)".to_string(),
    }
}

/// Format number with thousands separator
fn format_count(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
