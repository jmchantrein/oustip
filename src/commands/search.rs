//! IP search command implementation.
//!
//! Search for an IP in allowlist and blocklist sources with DNS resolution.

use anyhow::Result;
use ipnet::IpNet;
use std::net::IpAddr;
use std::path::Path;

use crate::config::Config;
use crate::stats::OustipState;

/// Run the search command
pub async fn run(ip_str: &str, show_dns: bool, config_path: &Path) -> Result<()> {
    // Parse IP address
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip_str))?;

    let ip_net = IpNet::from(ip);

    // Load config and state
    let config = Config::load(config_path)?;
    let state = OustipState::load().unwrap_or_default();

    println!();
    println!("Searching for: {}", ip);

    // DNS resolution
    if show_dns {
        let hostname = resolve_ip(&ip).await;
        println!("DNS (PTR): {}", hostname);
    }

    println!();

    // Check if in allowlist
    let mut in_allowlist = false;
    let mut allowlist_entry = None;

    for entry in &config.allowlist {
        if let Ok(net) = entry.parse::<IpNet>() {
            if net.contains(&ip) {
                in_allowlist = true;
                allowlist_entry = Some(entry.clone());
                break;
            }
        }
    }

    // Check if in any blocklist
    let mut in_blocklist = false;
    let mut blocklist_sources: Vec<String> = Vec::new();

    for source in &state.sources {
        for blocked_ip in &source.ips {
            if let Ok(net) = blocked_ip.parse::<IpNet>() {
                if net.contains(&ip) || ip_net.contains(&net.network()) {
                    in_blocklist = true;
                    if !blocklist_sources.contains(&source.name) {
                        blocklist_sources.push(source.name.clone());
                    }
                }
            }
        }
    }

    // Report findings
    println!("=== Results ===");
    println!();

    if in_allowlist {
        println!("[ALLOWLIST] Found in allowlist:");
        if let Some(entry) = &allowlist_entry {
            println!("  Matching entry: {}", entry);
        }
    } else {
        println!("[ALLOWLIST] Not found in allowlist");
    }

    println!();

    if in_blocklist {
        println!(
            "[BLOCKLIST] Found in {} blocklist(s):",
            blocklist_sources.len()
        );
        for source in &blocklist_sources {
            println!("  - {}", source);
        }
    } else {
        println!("[BLOCKLIST] Not found in any blocklist");
    }

    println!();

    // Warning if in both
    if in_allowlist && in_blocklist {
        println!("=== WARNING ===");
        println!();
        println!("This IP is in BOTH allowlist and blocklist!");
        println!("The allowlist takes precedence, so this IP is NOT blocked.");
        println!();
        println!("Blocklist sources containing this IP:");
        for source in &blocklist_sources {
            println!("  - {}", source);
        }
        println!();
        println!("If this is intentional, you can acknowledge it with:");
        println!("  oustip assume add {}", ip);
    }

    // Check assumed IPs
    if let Some(ref assumed) = state.assumed_ips {
        if assumed.contains(&ip_str.to_string()) {
            println!();
            println!("[INFO] This IP is in the 'assumed' list (acknowledged overlap)");
        }
    }

    Ok(())
}

/// Resolve IP to hostname via reverse DNS
async fn resolve_ip(ip: &IpAddr) -> String {
    let ip_clone = *ip;
    match tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_clone)).await {
        Ok(Ok(hostname)) => hostname,
        _ => "(no PTR record)".to_string(),
    }
}
