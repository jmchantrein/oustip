//! Assume command implementation.
//!
//! Manage assumed IPs - IPs that are intentionally in both allowlist and blocklist.
//! This prevents repeated INFO notifications for acknowledged overlaps.

use anyhow::Result;

use crate::cli::AssumeAction;
use crate::dns::resolve_ptr_str;
use crate::enforcer::check_root;
use crate::lock::LockGuard;
use crate::stats::OustipState;
use crate::validation::validate_ip;

/// Run the assume command
pub async fn run(action: AssumeAction) -> Result<()> {
    match action {
        AssumeAction::Add { ip } => add_assumed(&ip).await,
        AssumeAction::Del { ip } => remove_assumed(&ip).await,
        AssumeAction::List => list_assumed().await,
    }
}

/// Add an IP to the assumed list
async fn add_assumed(ip_str: &str) -> Result<()> {
    check_root()?;

    // Validate IP
    let _ = validate_ip(ip_str)?;

    // Acquire lock
    let _lock = LockGuard::acquire()?;

    // Load and update state
    let mut state = OustipState::load().unwrap_or_default();

    if state.is_assumed(ip_str) {
        println!("{} is already in the assumed list", ip_str);
        return Ok(());
    }

    state.add_assumed_ip(ip_str);
    state.save()?;

    println!("[OK] Added {} to assumed list", ip_str);
    println!("     This IP will no longer trigger overlap notifications");

    Ok(())
}

/// Remove an IP from the assumed list
async fn remove_assumed(ip_str: &str) -> Result<()> {
    check_root()?;

    // Acquire lock
    let _lock = LockGuard::acquire()?;

    // Load and update state
    let mut state = OustipState::load().unwrap_or_default();

    if !state.is_assumed(ip_str) {
        println!("{} was not in the assumed list", ip_str);
        return Ok(());
    }

    state.remove_assumed_ip(ip_str);
    state.save()?;

    println!("[OK] Removed {} from assumed list", ip_str);

    Ok(())
}

/// List all assumed IPs
async fn list_assumed() -> Result<()> {
    let state = OustipState::load().unwrap_or_default();

    println!();
    println!("Assumed IPs (acknowledged allow+block overlaps):");
    println!();

    match &state.assumed_ips {
        Some(ips) if !ips.is_empty() => {
            for ip in ips {
                // Try to resolve DNS
                let hostname = resolve_ptr_str(ip).await;
                println!("  {} -> {}", ip, hostname);
            }
            println!();
            println!("Total: {} IP(s)", ips.len());
        }
        _ => {
            println!("  (none)");
        }
    }

    println!();
    println!("Use 'oustip assume add <ip>' to add an IP");
    println!("Use 'oustip assume del <ip>' to remove an IP");

    Ok(())
}

// Note: Tests for validate_ip are in src/validation.rs
