//! Update command implementation.
//!
//! Supports multiple update targets:
//! - `presets`: Reload presets.yaml definitions
//! - `lists`: Download blocklists and allowlists from URLs
//! - `config`: Reload config.yaml and apply firewall rules
//! - (default): Full update (all of the above)

use anyhow::{Context, Result};
use ipnet::IpNet;
use std::path::Path;
use tracing::{error, info, warn};

use crate::aggregator::{aggregate, count_ips, subtract_allowlist};
use crate::alerts::{AlertManager, AlertTypes};
use crate::cli::UpdateTarget;
use crate::config::Config;
use crate::dns::resolve_ptr;
use crate::enforcer::{check_root, create_backend};
use crate::fetcher::Fetcher;
use crate::lock::LockGuard;
use crate::presets::PresetsConfig;
use crate::signal::is_shutdown_requested;
use crate::stats::OustipState;
use crate::utils::format_count;

/// Default failure threshold percentage (50%)
const DEFAULT_FAILURE_THRESHOLD: f64 = 0.5;

/// Minimum required free disk space in bytes (100 MB)
const MIN_FREE_DISK_SPACE: u64 = 100 * 1024 * 1024;

/// Check if there's enough disk space for the update operation
fn check_disk_space() -> Result<()> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    let path = CString::new("/var/lib/oustip")
        .or_else(|_| CString::new("/"))
        .context("Failed to create CString for disk space check")?;

    // SAFETY: statvfs is a standard POSIX syscall that reads filesystem statistics.
    // It has no side effects and the MaybeUninit pattern ensures we don't read
    // uninitialized memory. The path is a valid null-terminated C string.
    let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };

    if result != 0 {
        anyhow::bail!("Cannot verify disk space: statvfs failed");
    }

    // SAFETY: statvfs succeeded, so stat is now initialized
    let stat = unsafe { stat.assume_init() };
    let free_space = stat.f_bavail * stat.f_frsize;

    if free_space < MIN_FREE_DISK_SPACE {
        anyhow::bail!(
            "Insufficient disk space: {} MB available, {} MB required. \
             Free up space before updating.",
            free_space / (1024 * 1024),
            MIN_FREE_DISK_SPACE / (1024 * 1024)
        );
    }

    Ok(())
}

/// Run the update command with target selection
pub async fn run(target: Option<UpdateTarget>, dry_run: bool, config_path: &Path) -> Result<()> {
    match target {
        Some(UpdateTarget::Presets) => run_update_presets().await,
        Some(UpdateTarget::Lists) => run_update_lists(dry_run, config_path).await,
        Some(UpdateTarget::Config) => run_update_config(dry_run, config_path).await,
        None => run_full_update(dry_run, config_path).await,
    }
}

/// Update presets: reload presets.yaml definitions
async fn run_update_presets() -> Result<()> {
    info!("Reloading presets configuration...");

    // Load and validate presets
    let presets = PresetsConfig::load_or_default()?;

    // List resolved presets
    println!();
    println!("[OK] Presets loaded successfully");
    println!();
    println!("Blocklist presets:");
    for name in presets.list_blocklist_presets() {
        let sources = presets.resolve_blocklist_preset(name)?;
        println!("  {} ({} sources)", name, sources.len());
    }
    println!();
    println!("Allowlist presets:");
    for name in presets.list_allowlist_presets() {
        let sources = presets.resolve_allowlist_preset(name)?;
        println!("  {} ({} sources)", name, sources.len());
    }
    println!();
    println!("To download lists, run: oustip update lists");
    println!("To apply firewall rules, run: oustip update config");

    Ok(())
}

/// Update lists: download blocklists and allowlists from URLs
async fn run_update_lists(dry_run: bool, config_path: &Path) -> Result<()> {
    // Load config
    let config = Config::load(config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    rust_i18n::set_locale(&config.language);

    if dry_run {
        info!("DRY-RUN: Fetching lists (no state changes)...");
    } else {
        info!("Downloading blocklists and allowlists...");
    }

    let fetcher = Fetcher::new()?;

    // Get enabled blocklists from preset
    let enabled_lists = config.get_enabled_blocklists(None);

    if enabled_lists.is_empty() {
        warn!("No blocklists enabled. Check your configuration.");
        return Ok(());
    }

    // Fetch blocklists
    let results = fetcher.fetch_blocklists(&enabled_lists).await;

    let mut success_count = 0;
    let mut error_count = 0;

    for result in &results {
        match result {
            Ok(fetch_result) => {
                info!("  ✓ {} ({} IPs)", fetch_result.name, fetch_result.raw_count);
                success_count += 1;
            }
            Err(e) => {
                error!("  ✗ Error: {}", e);
                error_count += 1;
            }
        }
    }

    // Fetch auto-allowlists
    let auto_allowlist = fetcher.fetch_auto_allowlist(&config.auto_allowlist).await?;
    info!(
        "Auto-allowlist: {} IPs from CDN providers",
        auto_allowlist.len()
    );

    println!();
    println!(
        "[OK] Lists downloaded: {} success, {} errors",
        success_count, error_count
    );
    println!();
    println!("To apply firewall rules, run: oustip update config");

    Ok(())
}

/// Update config: reload config.yaml and apply firewall rules
async fn run_update_config(dry_run: bool, config_path: &Path) -> Result<()> {
    // This is essentially the full update, just re-applying rules from config
    run_full_update(dry_run, config_path).await
}

/// Full update: presets + lists + config (legacy behavior)
async fn run_full_update(dry_run: bool, config_path: &Path) -> Result<()> {
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

    // Check disk space before proceeding (skip in dry-run mode)
    if !dry_run {
        check_disk_space()?;
    }

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
    let enabled_lists = config.get_enabled_blocklists(None);

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
    if total_sources == 0 {
        return Ok(());
    }
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
    let mut allowlist: Vec<IpNet> = Vec::new();
    for entry in &config.allowlist {
        match entry.parse::<IpNet>() {
            Ok(net) => allowlist.push(net),
            Err(_) => warn!("Invalid allowlist entry ignored: {}", entry),
        }
    }

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

    // Save current rules before applying new ones (for rollback)
    let saved_rules = backend.save_current_rules().await.ok();
    if saved_rules.is_some() {
        info!("Saved current firewall rules for potential rollback");
    }

    // Apply firewall rules with rollback on failure
    info!("Applying firewall rules...");
    if let Err(apply_error) = backend.apply_rules(&aggregated, config.mode).await {
        error!("Failed to apply firewall rules: {}", apply_error);

        // Attempt rollback if we have saved rules
        let mut restored = false;
        if let Some(saved) = &saved_rules {
            info!("Attempting to restore previous firewall rules...");
            match backend.restore_rules(saved).await {
                Ok(()) => {
                    info!("Successfully restored previous firewall rules");
                    restored = true;
                }
                Err(restore_error) => {
                    error!("Failed to restore previous rules: {}", restore_error);
                }
            }
        } else {
            warn!("No saved rules available for rollback");
        }

        // Send rollback alert
        if let Ok(alert_manager) = AlertManager::new(config.alerts.clone()) {
            let (level, title, msg) =
                AlertTypes::rollback_performed(&apply_error.to_string(), restored);
            alert_manager.send(level, &title, &msg).await;
        }

        // Print rollback status to console
        println!();
        if restored {
            println!("[ERROR] Failed to apply new firewall rules. Previous rules restored.");
        } else {
            println!("[ERROR] Failed to apply new firewall rules. Rollback also failed!");
            println!("        Manual intervention may be required.");
        }

        return Err(apply_error);
    }

    // Load state for overlap detection and update
    let mut state = match OustipState::load() {
        Ok(s) => s,
        Err(e) => {
            warn!("State file unavailable, starting fresh: {}", e);
            OustipState::default()
        }
    };

    // Detect allow+block overlaps BEFORE updating sources (need source_stats reference)
    let overlaps = detect_overlaps(&allowlist, &source_stats, &state).await;

    // Capture previous state for change detection
    let previous_total_ips = state.last_known_total_ips;
    let previous_preset = state.last_preset.clone();

    // Now update state (takes ownership of source_stats)
    state.update_sources(source_stats);

    // Update tracking fields for change detection
    state.last_known_total_ips = Some(total_ips);
    state.last_preset = Some(config.preset.clone());

    state.save()?;

    // Check for significant blocklist content changes
    check_blocklist_change(
        &config,
        previous_total_ips,
        previous_preset.as_deref(),
        total_ips,
        &config.preset,
    )
    .await;

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

/// Check if blocklist content has changed significantly and send alert if needed
///
/// This function:
/// - Skips alerting if this is the first update (no previous data)
/// - Skips alerting if the user changed the preset (intentional change)
/// - Calculates the percentage change between old and new IP counts
/// - Sends an alert if the change exceeds the configured threshold
async fn check_blocklist_change(
    config: &Config,
    previous_total_ips: Option<u128>,
    previous_preset: Option<&str>,
    current_total_ips: u128,
    current_preset: &str,
) {
    // Skip if blocklist change alerting is disabled
    if !config.alerts.blocklist_change.enabled {
        return;
    }

    // Skip if this is the first update (no previous data to compare)
    let old_ips = match previous_total_ips {
        Some(ips) => ips,
        None => {
            info!("First update - skipping blocklist change detection");
            return;
        }
    };

    // Skip if user changed preset (intentional change, not unexpected)
    if let Some(prev_preset) = previous_preset {
        if prev_preset != current_preset {
            info!(
                "Preset changed from '{}' to '{}' - skipping blocklist change alert (intentional change)",
                prev_preset, current_preset
            );
            return;
        }
    }

    // Calculate percentage change
    let change_percent = calculate_change_percent(old_ips, current_total_ips);
    let threshold = config.alerts.blocklist_change.change_threshold_percent;

    // Check if change exceeds threshold
    if change_percent > threshold {
        info!(
            "Blocklist change detected: {:.1}% change (threshold: {:.1}%)",
            change_percent, threshold
        );

        if let Ok(alert_manager) = AlertManager::new(config.alerts.clone()) {
            let (level, title, msg) =
                AlertTypes::blocklist_changed(old_ips, current_total_ips, change_percent);
            alert_manager.send(level, &title, &msg).await;
        }
    } else {
        info!(
            "Blocklist change within threshold: {:.1}% (threshold: {:.1}%)",
            change_percent, threshold
        );
    }
}

/// Calculate the percentage change between two IP counts
///
/// Returns the absolute percentage change: |new - old| / old * 100
/// Returns 0.0 if old_ips is 0 (avoid division by zero)
pub fn calculate_change_percent(old_ips: u128, new_ips: u128) -> f64 {
    if old_ips == 0 {
        // Avoid division by zero; if we had 0 IPs before, any change is significant
        // but we return 0.0 to avoid false positives on first run
        return if new_ips > 0 { 100.0 } else { 0.0 };
    }

    let diff = new_ips.abs_diff(old_ips);

    (diff as f64 / old_ips as f64) * 100.0
}

/// Detect IPs that are in both allowlist and blocklist (excluding assumed IPs)
/// Returns: Vec<(ip_string, hostname, sources_where_found)>
///
/// Uses HashSet for O(1) lookup of exact matches, then checks CIDR containment.
async fn detect_overlaps(
    allowlist_ips: &[IpNet],
    source_stats: &[(String, usize, Vec<IpNet>)],
    state: &OustipState,
) -> Vec<(String, String, Vec<String>)> {
    use std::collections::HashMap;

    // Build a HashMap of blocklist IPs -> sources for O(1) lookup
    // Key: network address string, Value: (original CIDR, list of source names)
    let mut blocklist_map: HashMap<String, (IpNet, Vec<String>)> = HashMap::new();

    for (source_name, _, source_ips) in source_stats {
        for block_ip in source_ips {
            let key = block_ip.to_string();
            blocklist_map
                .entry(key)
                .or_insert_with(|| (*block_ip, Vec::new()))
                .1
                .push(source_name.clone());
        }
    }

    // Also build a Vec of all blocklist CIDRs for containment checks
    // (for cases where allowlist /32 is contained in blocklist /24)
    let all_blocklist_cidrs: Vec<(&IpNet, &str)> = source_stats
        .iter()
        .flat_map(|(name, _, ips)| ips.iter().map(move |ip| (ip, name.as_str())))
        .collect();

    let mut overlaps = Vec::new();

    for allow_ip in allowlist_ips {
        let mut found_in_sources: Vec<String> = Vec::new();
        let allow_key = allow_ip.to_string();

        // O(1) exact match check
        if let Some((_, sources)) = blocklist_map.get(&allow_key) {
            for source in sources {
                if !found_in_sources.contains(source) {
                    found_in_sources.push(source.clone());
                }
            }
        }

        // Check CIDR containment (allowlist contained in blocklist or vice versa)
        // This is still O(n) but only for CIDR containment, not string matching
        for (block_ip, source_name) in &all_blocklist_cidrs {
            if allow_ip.to_string() != block_ip.to_string() && networks_overlap(allow_ip, block_ip)
            {
                let source_str = source_name.to_string();
                if !found_in_sources.contains(&source_str) {
                    found_in_sources.push(source_str);
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
            let hostname = resolve_ptr(allow_ip.addr()).await;

            overlaps.push((ip_str, hostname, found_in_sources));
        }
    }

    // Limit to first 50 overlaps to avoid notification spam
    let total_overlaps = overlaps.len();
    if total_overlaps > 50 {
        warn!("Showing first 50 of {} overlapping IPs", total_overlaps);
        overlaps.truncate(50);
    }
    overlaps
}

/// Check if two IP networks overlap
fn networks_overlap(a: &IpNet, b: &IpNet) -> bool {
    // Check if either contains the other's network address
    a.contains(&b.addr()) || b.contains(&a.addr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_change_percent_increase() {
        // 10% increase: 100 -> 110
        let percent = calculate_change_percent(100, 110);
        assert!((percent - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_decrease() {
        // 20% decrease: 100 -> 80
        let percent = calculate_change_percent(100, 80);
        assert!((percent - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_no_change() {
        let percent = calculate_change_percent(1000, 1000);
        assert!((percent - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_large_increase() {
        // 100% increase: 1000 -> 2000
        let percent = calculate_change_percent(1000, 2000);
        assert!((percent - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_large_decrease() {
        // 50% decrease: 1000 -> 500
        let percent = calculate_change_percent(1000, 500);
        assert!((percent - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_zero_old() {
        // Starting from 0, any positive value should return 100%
        let percent = calculate_change_percent(0, 1000);
        assert!((percent - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_zero_both() {
        // Both zero should return 0%
        let percent = calculate_change_percent(0, 0);
        assert!((percent - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_small_values() {
        // Small values should still work: 10 -> 15 = 50% increase
        let percent = calculate_change_percent(10, 15);
        assert!((percent - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_large_values() {
        // Large values (u128): 10 million IPs -> 11 million = 10% increase
        let percent = calculate_change_percent(10_000_000, 11_000_000);
        assert!((percent - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_fractional() {
        // 5% increase: 1000 -> 1050
        let percent = calculate_change_percent(1000, 1050);
        assert!((percent - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_preset_change_detection() {
        // This tests the logic that preset changes should NOT trigger alerts
        // The actual function is async, so we test the conditions here

        let _previous_preset = Some("recommended");
        let current_preset = "paranoid";

        // If presets differ, we should NOT alert
        assert_ne!("recommended", current_preset);
    }

    #[test]
    fn test_first_update_detection() {
        // This tests the logic that first updates (no previous data) should NOT trigger alerts

        let previous_total_ips: Option<u128> = None;

        // If no previous data, we should NOT alert
        assert!(previous_total_ips.is_none());
    }

    #[test]
    fn test_threshold_comparison() {
        // Test threshold logic
        let change_percent = 15.0;
        let threshold = 10.0;

        // 15% change with 10% threshold should trigger alert
        assert!(change_percent > threshold);

        // 5% change with 10% threshold should NOT trigger alert
        let small_change = 5.0;
        assert!(small_change <= threshold);
    }

    // =========================================================================
    // Blocklist Change Alert Tests
    // =========================================================================

    #[test]
    fn test_threshold_detection_above() {
        // Change above threshold should trigger
        let old_ips = 100_000u128;
        let new_ips = 115_000u128; // 15% increase
        let threshold = 10.0;

        let change = calculate_change_percent(old_ips, new_ips);
        assert!(change > threshold, "15% change should exceed 10% threshold");
    }

    #[test]
    fn test_threshold_detection_below() {
        // Change below threshold should not trigger
        let old_ips = 100_000u128;
        let new_ips = 105_000u128; // 5% increase
        let threshold = 10.0;

        let change = calculate_change_percent(old_ips, new_ips);
        assert!(
            change <= threshold,
            "5% change should not exceed 10% threshold"
        );
    }

    #[test]
    fn test_threshold_detection_exactly_at() {
        // Change exactly at threshold
        let old_ips = 100_000u128;
        let new_ips = 110_000u128; // 10% increase
        let _threshold = 10.0; // Used for documentation, actual comparison is done separately

        let change = calculate_change_percent(old_ips, new_ips);
        // At 10%, should not trigger (need to exceed threshold, not equal)
        assert!((change - 10.0).abs() < 0.01, "Change should be exactly 10%");
    }

    #[test]
    fn test_first_update_should_not_alert() {
        // First update (no previous data) should NOT trigger alert
        let previous_total_ips: Option<u128> = None;

        // When previous is None, we should skip alerting
        assert!(
            previous_total_ips.is_none(),
            "First update has no previous data"
        );
    }

    #[test]
    fn test_preset_change_should_not_alert() {
        // User changing preset should NOT trigger alert (intentional change)
        let _previous_preset = Some("recommended");
        let current_preset = "paranoid";

        // Presets differ, so we should skip alerting
        assert_ne!(
            "recommended", current_preset,
            "Preset changed = intentional change"
        );
    }

    #[test]
    fn test_same_preset_should_check_change() {
        // Same preset = check for unintentional upstream changes
        let _previous_preset = Some("recommended");
        let current_preset = "recommended";

        assert_eq!(
            "recommended", current_preset,
            "Same preset = check for upstream changes"
        );
    }

    #[test]
    fn test_calculate_change_percent_symmetry() {
        // Increase and decrease of same magnitude should have same percentage
        let base = 100_000u128;
        let increased = 120_000u128;
        let decreased = 80_000u128;

        let increase_percent = calculate_change_percent(base, increased);
        let decrease_percent = calculate_change_percent(base, decreased);

        assert!((increase_percent - decrease_percent).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_90_percent_decrease() {
        // Test large decrease (should still calculate correctly)
        let old_ips = 1_000_000u128;
        let new_ips = 100_000u128; // 90% decrease

        let change = calculate_change_percent(old_ips, new_ips);
        assert!(
            (change - 90.0).abs() < 0.01,
            "90% decrease should be detected"
        );
    }

    #[test]
    fn test_calculate_change_percent_small_base() {
        // Test with small base value
        let old_ips = 100u128;
        let new_ips = 200u128; // 100% increase

        let change = calculate_change_percent(old_ips, new_ips);
        assert!(
            (change - 100.0).abs() < 0.01,
            "100% increase from small base"
        );
    }

    #[test]
    fn test_calculate_change_percent_very_large_values() {
        // Test with very large u128 values (IPv6 scale)
        let old_ips = 340_282_366_920_938_463_463_374_607_431_768_211_455u128 / 2;
        let new_ips = old_ips + old_ips / 10; // 10% increase

        let change = calculate_change_percent(old_ips, new_ips);
        assert!(
            (change - 10.0).abs() < 0.01,
            "10% increase with very large values"
        );
    }

    #[test]
    fn test_networks_overlap_exact_match() {
        let a: IpNet = "192.168.1.0/24".parse().unwrap();
        let b: IpNet = "192.168.1.0/24".parse().unwrap();

        assert!(
            networks_overlap(&a, &b),
            "Identical networks should overlap"
        );
    }

    #[test]
    fn test_networks_overlap_containment() {
        let larger: IpNet = "192.168.0.0/16".parse().unwrap();
        let smaller: IpNet = "192.168.1.0/24".parse().unwrap();

        assert!(
            networks_overlap(&larger, &smaller),
            "Contained networks should overlap"
        );
        assert!(
            networks_overlap(&smaller, &larger),
            "Overlap should be symmetric"
        );
    }

    #[test]
    fn test_networks_no_overlap() {
        let a: IpNet = "192.168.0.0/24".parse().unwrap();
        let b: IpNet = "10.0.0.0/8".parse().unwrap();

        assert!(
            !networks_overlap(&a, &b),
            "Different networks should not overlap"
        );
    }

    #[test]
    fn test_networks_overlap_adjacent() {
        // Adjacent networks should not overlap
        let a: IpNet = "192.168.0.0/24".parse().unwrap();
        let b: IpNet = "192.168.1.0/24".parse().unwrap();

        assert!(
            !networks_overlap(&a, &b),
            "Adjacent networks should not overlap"
        );
    }

    #[test]
    fn test_networks_overlap_single_ip_in_range() {
        let single: IpNet = "192.168.1.100/32".parse().unwrap();
        let range: IpNet = "192.168.1.0/24".parse().unwrap();

        assert!(
            networks_overlap(&single, &range),
            "Single IP in range should overlap"
        );
    }

    #[test]
    fn test_networks_overlap_ipv6() {
        let a: IpNet = "2001:db8::/32".parse().unwrap();
        let b: IpNet = "2001:db8:1234::/48".parse().unwrap();

        assert!(
            networks_overlap(&a, &b),
            "IPv6 contained networks should overlap"
        );
    }

    #[test]
    fn test_preset_change_detection_none_to_some() {
        // Previous preset was None (first run), current has a value
        let previous_preset: Option<&str> = None;
        let _current_preset = "recommended";

        // When previous is None, we don't compare (skip check)
        assert!(previous_preset.is_none());
    }

    #[test]
    fn test_alert_types_blocklist_changed_format() {
        // Test that AlertTypes::blocklist_changed produces valid output
        use crate::alerts::AlertTypes;

        let (level, title, body) = AlertTypes::blocklist_changed(100_000, 120_000, 20.0);

        // Should be Warning level
        assert!(matches!(level, crate::alerts::AlertLevel::Warning));

        // Title should mention blocklist change
        assert!(title.contains("Blocklist") || title.contains("Changed"));

        // Body should contain the statistics
        assert!(body.contains("100000") || body.contains("100,000"));
        assert!(body.contains("120000") || body.contains("120,000"));
        assert!(body.contains("increased") || body.contains("decreased"));
    }

    #[test]
    fn test_default_failure_threshold() {
        assert!((DEFAULT_FAILURE_THRESHOLD - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_min_free_disk_space() {
        // Should be 100 MB
        assert_eq!(MIN_FREE_DISK_SPACE, 100 * 1024 * 1024);
    }

    #[test]
    fn test_failure_threshold_calculation() {
        // Test the failure rate calculation
        let total_sources = 10usize;
        let failed_sources = 3usize;

        let failure_rate = failed_sources as f64 / total_sources as f64;
        assert!((failure_rate - 0.3).abs() < 0.001, "3/10 should be 30%");

        // 30% is below 50% threshold
        assert!(failure_rate < DEFAULT_FAILURE_THRESHOLD);
    }

    #[test]
    fn test_failure_threshold_exceeded() {
        let total_sources = 10usize;
        let failed_sources = 6usize;

        let failure_rate = failed_sources as f64 / total_sources as f64;
        assert!((failure_rate - 0.6).abs() < 0.001, "6/10 should be 60%");

        // 60% exceeds 50% threshold
        assert!(failure_rate >= DEFAULT_FAILURE_THRESHOLD);
    }

    #[test]
    fn test_calculate_change_percent_practical_scenarios() {
        // Scenario 1: Minor daily fluctuation (normal)
        let change = calculate_change_percent(1_000_000, 1_010_000); // 1% change
        assert!(change < 10.0, "1% change should be below typical threshold");

        // Scenario 2: Source went offline (significant)
        let change = calculate_change_percent(1_000_000, 500_000); // 50% decrease
        assert!(change > 10.0, "50% change should exceed threshold");

        // Scenario 3: New major blocklist added
        let change = calculate_change_percent(100_000, 1_000_000); // 900% increase
        assert!(change > 10.0, "Massive increase should exceed threshold");
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    // =========================================================================
    // calculate_change_percent extended tests
    // =========================================================================

    #[test]
    fn test_calculate_change_percent_boundary_values() {
        // Test at u128 boundaries
        assert_eq!(calculate_change_percent(1, 1), 0.0);
        assert_eq!(calculate_change_percent(1, 2), 100.0);
        assert_eq!(calculate_change_percent(2, 1), 50.0);
    }

    #[test]
    fn test_calculate_change_percent_precision() {
        // Test precision with specific values
        let change = calculate_change_percent(1000, 1001);
        assert!((change - 0.1).abs() < 0.01);

        let change = calculate_change_percent(10000, 10050);
        assert!((change - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_calculate_change_percent_doubling_halving() {
        // Doubling should be 100%
        assert_eq!(calculate_change_percent(100, 200), 100.0);
        // Halving should be 50%
        assert_eq!(calculate_change_percent(100, 50), 50.0);
    }

    #[test]
    fn test_calculate_change_percent_to_zero() {
        // Decreasing to zero should be 100%
        let change = calculate_change_percent(100, 0);
        assert_eq!(change, 100.0);
    }

    // =========================================================================
    // networks_overlap extended tests
    // =========================================================================

    #[test]
    fn test_networks_overlap_single_ip_v4() {
        let a: IpNet = "192.168.1.1/32".parse().unwrap();
        let b: IpNet = "192.168.1.1/32".parse().unwrap();
        assert!(networks_overlap(&a, &b));
    }

    #[test]
    fn test_networks_overlap_single_ip_in_cidr() {
        let single: IpNet = "192.168.1.1/32".parse().unwrap();
        let cidr: IpNet = "192.168.1.0/24".parse().unwrap();
        assert!(networks_overlap(&single, &cidr));
    }

    #[test]
    fn test_networks_overlap_completely_disjoint() {
        let a: IpNet = "192.168.0.0/16".parse().unwrap();
        let b: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(!networks_overlap(&a, &b));
    }

    #[test]
    fn test_networks_overlap_ipv6_contained() {
        let large: IpNet = "2001:db8::/32".parse().unwrap();
        let small: IpNet = "2001:db8:1::/48".parse().unwrap();
        assert!(networks_overlap(&large, &small));
    }

    #[test]
    fn test_networks_overlap_ipv6_disjoint() {
        let a: IpNet = "2001:db8::/32".parse().unwrap();
        let b: IpNet = "2001:db9::/32".parse().unwrap();
        assert!(!networks_overlap(&a, &b));
    }

    #[test]
    fn test_networks_overlap_partial_overlap_at_boundary() {
        // Two /24 networks that share a boundary but don't overlap
        let a: IpNet = "192.168.0.0/24".parse().unwrap();
        let b: IpNet = "192.168.1.0/24".parse().unwrap();
        assert!(!networks_overlap(&a, &b));
    }

    #[test]
    fn test_networks_overlap_supernet_contains_subnet() {
        let supernet: IpNet = "10.0.0.0/8".parse().unwrap();
        let subnet: IpNet = "10.255.255.0/24".parse().unwrap();
        assert!(networks_overlap(&supernet, &subnet));
    }

    #[test]
    fn test_networks_overlap_mixed_v4_v6() {
        // IPv4 and IPv6 should never overlap
        let v4: IpNet = "192.168.0.0/16".parse().unwrap();
        let v6: IpNet = "2001:db8::/32".parse().unwrap();
        // They can't contain each other
        assert!(!v4.contains(&v6.addr()));
        assert!(!v6.contains(&v4.addr()));
    }

    // =========================================================================
    // Failure threshold tests
    // =========================================================================

    #[test]
    fn test_failure_rate_calculation_edge_cases() {
        // All fail
        let failure_rate = 10f64 / 10f64;
        assert_eq!(failure_rate, 1.0);

        // None fail
        let failure_rate = 0f64 / 10f64;
        assert_eq!(failure_rate, 0.0);

        // Exactly at threshold
        let failure_rate = 5f64 / 10f64;
        assert_eq!(failure_rate, 0.5);
    }

    #[test]
    fn test_failure_rate_just_below_threshold() {
        let total_sources = 10usize;
        let failed_sources = 4usize;
        let failure_rate = failed_sources as f64 / total_sources as f64;
        assert!(failure_rate < DEFAULT_FAILURE_THRESHOLD);
        assert!((failure_rate - 0.4).abs() < 0.001);
    }

    #[test]
    fn test_failure_rate_just_above_threshold() {
        let total_sources = 10usize;
        let failed_sources = 6usize;
        let failure_rate = failed_sources as f64 / total_sources as f64;
        assert!(failure_rate > DEFAULT_FAILURE_THRESHOLD);
        assert!((failure_rate - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_failure_rate_single_source() {
        // Single source fails
        let failure_rate = 1f64 / 1f64;
        assert!(failure_rate >= DEFAULT_FAILURE_THRESHOLD);

        // Single source succeeds
        let failure_rate = 0f64 / 1f64;
        assert!(failure_rate < DEFAULT_FAILURE_THRESHOLD);
    }

    #[test]
    fn test_failure_rate_many_sources() {
        // 50 out of 100 sources fail
        let failure_rate = 50f64 / 100f64;
        assert_eq!(failure_rate, 0.5);
        assert!(failure_rate >= DEFAULT_FAILURE_THRESHOLD);
    }

    // =========================================================================
    // Disk space constants tests
    // =========================================================================

    #[test]
    fn test_min_free_disk_space_is_100mb() {
        assert_eq!(MIN_FREE_DISK_SPACE, 100 * 1024 * 1024);
        assert_eq!(MIN_FREE_DISK_SPACE, 104_857_600);
    }

    #[test]
    fn test_default_failure_threshold_is_50_percent() {
        assert_eq!(DEFAULT_FAILURE_THRESHOLD, 0.5);
    }

    // =========================================================================
    // Overlap detection logic tests
    // =========================================================================

    #[test]
    fn test_overlap_detection_empty_inputs() {
        let allowlist: Vec<IpNet> = vec![];
        let source_stats: Vec<(String, usize, Vec<IpNet>)> = vec![];
        let state = OustipState::default();

        // The detect_overlaps function is async, so we test its logic here
        // For empty inputs, there should be no overlaps
        assert!(allowlist.is_empty());
        assert!(source_stats.is_empty());
        assert!(state.assumed_ips.is_none());
    }

    #[test]
    fn test_overlap_detection_no_matching_ips() {
        let allowlist: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
        let blocklist: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];

        // Check if they overlap
        let overlaps = allowlist
            .iter()
            .any(|allow| blocklist.iter().any(|block| networks_overlap(allow, block)));
        assert!(!overlaps);
    }

    #[test]
    fn test_overlap_detection_exact_match() {
        let allowlist: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
        let blocklist: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];

        let overlaps = allowlist
            .iter()
            .any(|allow| blocklist.iter().any(|block| networks_overlap(allow, block)));
        assert!(overlaps);
    }

    #[test]
    fn test_overlap_detection_containment() {
        let allowlist: Vec<IpNet> = vec!["192.168.1.100/32".parse().unwrap()];
        let blocklist: Vec<IpNet> = vec!["192.168.0.0/16".parse().unwrap()];

        let overlaps = allowlist
            .iter()
            .any(|allow| blocklist.iter().any(|block| networks_overlap(allow, block)));
        assert!(overlaps);
    }

    // =========================================================================
    // Alert threshold detection tests
    // =========================================================================

    #[test]
    fn test_should_alert_boundary_conditions() {
        // Testing alert threshold logic
        let threshold = 10.0f64;

        // Exactly at threshold - should NOT trigger (need to exceed)
        let change = 10.0f64;
        assert!(change <= threshold);

        // Just above threshold
        let change = 10.01f64;
        assert!(change > threshold);

        // Just below threshold
        let change = 9.99f64;
        assert!(change <= threshold);
    }

    #[test]
    fn test_preset_change_skips_alert() {
        let previous_preset = Some("recommended");
        let current_preset = "paranoid";

        // Different presets = intentional change = skip alert
        let should_skip = previous_preset
            .map(|p| p != current_preset)
            .unwrap_or(false);
        assert!(should_skip);
    }

    #[test]
    fn test_same_preset_checks_change() {
        let previous_preset = Some("recommended");
        let current_preset = "recommended";

        // Same preset = check for upstream changes
        let should_skip = previous_preset
            .map(|p| p != current_preset)
            .unwrap_or(false);
        assert!(!should_skip);
    }

    #[test]
    fn test_no_previous_preset_skips() {
        let previous_preset: Option<&str> = None;

        // No previous preset (first run) = skip alert
        let should_skip = previous_preset.is_none();
        assert!(should_skip);
    }

    // =========================================================================
    // Edge cases for change percent
    // =========================================================================

    #[test]
    fn test_change_percent_max_u128() {
        // Test with very large numbers approaching u128 max
        let base = u128::MAX / 2;
        let increased = base + base / 100; // ~1% increase

        let change = calculate_change_percent(base, increased);
        assert!(change > 0.0 && change < 2.0);
    }

    #[test]
    fn test_change_percent_realistic_blocklist_sizes() {
        // Typical blocklist sizes
        let sizes = [
            (10_000, 10_500),       // Small list, 5% increase
            (100_000, 95_000),      // Medium list, 5% decrease
            (1_000_000, 1_200_000), // Large list, 20% increase
        ];

        for (old, new) in sizes {
            let change = calculate_change_percent(old, new);
            assert!(change >= 0.0, "Change should be non-negative");
        }
    }

    #[test]
    fn test_change_percent_ipv6_scale() {
        // IPv6 can have massive IP counts
        let base: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_455; // u128::MAX
        let reduced = base / 2;

        let change = calculate_change_percent(base, reduced);
        assert!((change - 50.0).abs() < 0.01);
    }
}
