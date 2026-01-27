//! Update command implementation.

use anyhow::{Context, Result};
use ipnet::IpNet;
use std::path::Path;
use tracing::{error, info, warn};

use crate::aggregator::{aggregate, count_ips, subtract_allowlist};
use crate::alerts::{AlertManager, AlertTypes};
use crate::config::Config;
use crate::enforcer::{check_root, create_backend};
use crate::fetcher::{format_count, Fetcher};
use crate::stats::OustipState;

/// Run the update command
pub async fn run(preset: Option<String>, config_path: &Path) -> Result<()> {
    check_root()?;

    // Load config
    let config = Config::load(config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    // Set language from config
    rust_i18n::set_locale(&config.language);

    info!("Updating blocklists...");

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

    // Fetch all blocklists concurrently
    let results = fetcher.fetch_blocklists(&enabled_lists).await;

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

    // Apply firewall rules
    info!("Applying firewall rules...");
    backend.apply_rules(&aggregated, config.mode).await?;

    // Update state
    let mut state = OustipState::load().unwrap_or_default();
    state.update_sources(source_stats);
    state.save()?;

    // Send success alert
    if let Ok(alert_manager) = AlertManager::new(config.alerts.clone()) {
        let (level, title, msg) = AlertTypes::update_success(aggregated.len(), total_ips);
        alert_manager.send(level, &title, &msg).await;
    }

    // Send alerts for fetch errors
    if !fetch_errors.is_empty() {
        if let Ok(alert_manager) = AlertManager::new(config.alerts) {
            for (source, error) in fetch_errors {
                let (level, title, msg) = AlertTypes::fetch_failed(&source, &error);
                alert_manager.send(level, &title, &msg).await;
            }
        }
    }

    println!();
    println!(
        "[OK] {} entries loaded ({} IPs blocked)",
        format_count(aggregated.len()),
        format_count(total_ips as usize)
    );

    Ok(())
}
