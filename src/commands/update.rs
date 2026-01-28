//! Update command implementation.

use anyhow::{Context, Result};
use ipnet::IpNet;
use std::path::Path;
use tracing::{error, info, warn};

use std::net::IpAddr;

use crate::aggregator::{aggregate, count_ips, subtract_allowlist};
use crate::alerts::{AlertManager, AlertTypes};
use crate::config::Config;
use crate::enforcer::{check_root, create_backend};
use crate::fetcher::{format_count, Fetcher};
use crate::lock::LockGuard;
use crate::signal::is_shutdown_requested;
use crate::stats::OustipState;

/// Default failure threshold percentage (50%)
const DEFAULT_FAILURE_THRESHOLD: f64 = 0.5;

/// Run the update command
pub async fn run(preset: Option<String>, dry_run: bool, config_path: &Path) -> Result<()> {
    // Skip root check in dry-run mode (no firewall changes)
    if !dry_run {
        check_root()?;
    }

    // Acquire exclusive lock (skip in dry-run mode)
    let _lock = if !dry_run {
        Some(LockGuard::acquire()?)
    } else {
        None
    };

    // Load config
    let config = Config::load(config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    // Set language from config
    rust_i18n::set_locale(&config.language);

    if dry_run {
        info!("DRY-RUN: Fetching and processing blocklists (no firewall changes)...");
    } else {
        info!("Updating blocklists...");
    }

    // Create fetcher and backend
    let fetcher = Fetcher::new()?;
    let backend = create_backend(config.backend)?;

    // Get enabled blocklists
    let preset_ref = preset.as_deref();
    let enabled_lists = config.get_enabled_blocklists(preset_ref);

    if enabled_lists.is_empty() {
        warn!("No blocklists enabled. Check your configuration.");
        return Ok(());
    }

    // Check for shutdown before long operation
    if is_shutdown_requested() {
        info!("Shutdown requested, aborting update.");
        return Ok(());
    }

    // Fetch all blocklists concurrently
    let results = fetcher.fetch_blocklists(&enabled_lists).await;

    // Check for shutdown after fetch
    if is_shutdown_requested() {
        info!("Shutdown requested, aborting update.");
        return Ok(());
    }

    // Collect successful fetches
    let mut all_ips: Vec<IpNet> = Vec::new();
    let mut source_stats: Vec<(String, usize, Vec<IpNet>)> = Vec::new();
    let mut fetch_errors: Vec<(String, String)> = Vec::new();

    for result in results {
        match result {
            Ok(fetch_result) => {
                source_stats.push((
                    fetch_result.name.clone(),
                    fetch_result.raw_count,
                    fetch_result.ips.clone(),
                ));
                all_ips.extend(fetch_result.ips);
            }
            Err(e) => {
                let source_name = "unknown".to_string();
                error!("Failed to fetch blocklist: {}", e);
                fetch_errors.push((source_name, e.to_string()));
            }
        }
    }

    // Check failure threshold
    let total_sources = enabled_lists.len();
    let failed_sources = fetch_errors.len();
    let failure_rate = failed_sources as f64 / total_sources as f64;

    if failure_rate >= DEFAULT_FAILURE_THRESHOLD {
        let msg = format!(
            "Too many sources failed: {}/{} ({:.0}% failure rate, threshold: {:.0}%)",
            failed_sources,
            total_sources,
            failure_rate * 100.0,
            DEFAULT_FAILURE_THRESHOLD * 100.0
        );
        error!("{}", msg);

        // Send alert for partial failure threshold exceeded
        if let Ok(alert_manager) = AlertManager::new(config.alerts.clone()) {
            let (level, title, alert_msg) = AlertTypes::update_failed(&msg);
            alert_manager.send(level, &title, &alert_msg).await;
        }

        anyhow::bail!(msg);
    }

    if all_ips.is_empty() {
        error!("No IPs fetched from any source!");

        // Send alert for complete failure
        if let Ok(alert_manager) = AlertManager::new(config.alerts.clone()) {
            let (level, title, msg) = AlertTypes::update_failed("No IPs fetched from any source");
            alert_manager.send(level, &title, &msg).await;
        }

        anyhow::bail!("No IPs fetched from any source");
    }

    // Parse manual allowlist
    let mut allowlist: Vec<IpNet> = config
        .allowlist
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    // Fetch auto-allowlist
    let auto_allowlist = fetcher.fetch_auto_allowlist(&config.auto_allowlist).await?;
    allowlist.extend(auto_allowlist);

    info!(
        "Allowlist: {} entries (manual + auto)",
        format_count(allowlist.len())
    );

    // Subtract allowlist from blocklist
    let filtered_ips = subtract_allowlist(&all_ips, &allowlist);
    info!(
        "After allowlist filtering: {} IPs",
        format_count(filtered_ips.len())
    );

    // Aggregate CIDRs
    info!("Aggregating IP ranges...");
    let aggregated = aggregate(&filtered_ips);
    let total_ips = count_ips(&aggregated);

    info!(
        "Aggregated {} entries -> {} optimized ranges ({} IPs)",
        format_count(filtered_ips.len()),
        format_count(aggregated.len()),
        format_count(total_ips as usize)
    );

    if dry_run {
        // Dry-run: show what would happen without applying
        println!();
        println!("[DRY-RUN] Summary:");
        println!("  - Blocklists fetched: {}", source_stats.len());
        println!(
            "  - Total IPs before filtering: {}",
            format_count(all_ips.len())
        );
        println!("  - Allowlist entries: {}", format_count(allowlist.len()));
        println!(
            "  - IPs after filtering: {}",
            format_count(filtered_ips.len())
        );
        println!(
            "  - Optimized CIDR ranges: {}",
            format_count(aggregated.len())
        );
        println!(
            "  - Total IPs covered: {}",
            format_count(total_ips as usize)
        );
        println!();
        println!("[DRY-RUN] No firewall rules applied.");
        if !fetch_errors.is_empty() {
            println!();
            println!("[DRY-RUN] Fetch errors:");
            for (source, error) in &fetch_errors {
                println!("  - {}: {}", source, error);
            }
        }
        return Ok(());
    }

    // Apply firewall rules
    info!("Applying firewall rules...");
    backend.apply_rules(&aggregated, config.mode).await?;

    // Load state for overlap detection and update
    let mut state = OustipState::load().unwrap_or_default();

    // Detect allow+block overlaps BEFORE updating sources (need source_stats reference)
    let overlaps = detect_overlaps(&allowlist, &source_stats, &state).await;

    // Now update state (takes ownership of source_stats)
    state.update_sources(source_stats);
    state.save()?;

    // Send success alert
    if let Ok(alert_manager) = AlertManager::new(config.alerts.clone()) {
        let (level, title, msg) = AlertTypes::update_success(aggregated.len(), total_ips);
        alert_manager.send(level, &title, &msg).await;
    }

    // Send alerts for fetch errors
    if !fetch_errors.is_empty() {
        if let Ok(alert_manager) = AlertManager::new(config.alerts.clone()) {
            for (source, error) in &fetch_errors {
                let (level, title, msg) = AlertTypes::fetch_failed(source, error);
                alert_manager.send(level, &title, &msg).await;
            }
        }
    }

    // Notify about detected overlaps (excluding assumed IPs)
    if !overlaps.is_empty() {
        info!(
            "Detected {} allow+block overlap(s) (not in assume list)",
            overlaps.len()
        );

        if let Ok(alert_manager) = AlertManager::new(config.alerts) {
            let (level, title, msg) = AlertTypes::overlap_detected(&overlaps);
            alert_manager.send(level, &title, &msg).await;
        }

        println!();
        println!(
            "[INFO] {} IP(s) are in both allowlist AND blocklist:",
            overlaps.len()
        );
        for (ip, hostname, sources) in &overlaps {
            println!("  {} ({}) - found in: {}", ip, hostname, sources.join(", "));
        }
        println!();
        println!("  These IPs are NOT blocked (allowlist takes precedence).");
        println!("  To acknowledge and stop these notifications:");
        println!("    oustip assume add <ip>");
    }

    println!();
    println!(
        "[OK] {} entries loaded ({} IPs blocked)",
        format_count(aggregated.len()),
        format_count(total_ips as usize)
    );

    Ok(())
}

/// Detect IPs that are in both allowlist and blocklist (excluding assumed IPs)
/// Returns: Vec<(ip_string, hostname, sources_where_found)>
async fn detect_overlaps(
    allowlist_ips: &[IpNet],
    source_stats: &[(String, usize, Vec<IpNet>)],
    state: &OustipState,
) -> Vec<(String, String, Vec<String>)> {
    let mut overlaps = Vec::new();

    // For each allowlist IP, check if it's in any blocklist source
    for allow_ip in allowlist_ips {
        // Check if this allowlist entry overlaps with any blocklist entry
        let mut found_in_sources: Vec<String> = Vec::new();

        for (source_name, _, source_ips) in source_stats {
            for block_ip in source_ips {
                if networks_overlap(allow_ip, block_ip) && !found_in_sources.contains(source_name) {
                    found_in_sources.push(source_name.clone());
                }
            }
        }

        if !found_in_sources.is_empty() {
            let ip_str = allow_ip.to_string();

            // Skip if this IP is in the assume list
            if state.is_assumed(&ip_str) {
                continue;
            }

            // Also check if the network address (without prefix) is assumed
            let addr_str = allow_ip.addr().to_string();
            if state.is_assumed(&addr_str) {
                continue;
            }

            // Resolve DNS for this IP
            let hostname = resolve_ip_for_overlap(allow_ip.addr()).await;

            overlaps.push((ip_str, hostname, found_in_sources));
        }
    }

    // Limit to first 20 overlaps to avoid notification spam
    overlaps.truncate(20);
    overlaps
}

/// Check if two IP networks overlap
fn networks_overlap(a: &IpNet, b: &IpNet) -> bool {
    // Check if either contains the other's network address
    a.contains(&b.addr()) || b.contains(&a.addr())
}

/// Resolve IP address to hostname via reverse DNS
async fn resolve_ip_for_overlap(ip: IpAddr) -> String {
    match tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip)).await {
        Ok(Ok(hostname)) => hostname,
        _ => "(no PTR)".to_string(),
    }
}
