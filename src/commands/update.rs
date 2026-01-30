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

    let path = CString::new("/var/lib/oustip").unwrap_or_else(|_| CString::new("/").unwrap());

    // SAFETY: statvfs is a standard POSIX syscall that reads filesystem statistics.
    // It has no side effects and the MaybeUninit pattern ensures we don't read
    // uninitialized memory. The path is a valid null-terminated C string.
    let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };

    if result != 0 {
        // If we can't check disk space, log warning but continue
        warn!("Could not check disk space, continuing anyway");
        return Ok(());
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
    overlaps.truncate(50);
    overlaps
}

/// Check if two IP networks overlap
fn networks_overlap(a: &IpNet, b: &IpNet) -> bool {
    // Check if either contains the other's network address
    a.contains(&b.addr()) || b.contains(&a.addr())
}
