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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a temporary state directory and return its path
    fn setup_test_state() -> (TempDir, OustipState) {
        let temp_dir = TempDir::new().unwrap();
        let state = OustipState::default();
        (temp_dir, state)
    }

    #[test]
    fn test_assumed_ip_add_new() {
        let (_temp_dir, mut state) = setup_test_state();

        // Initially empty
        assert!(!state.is_assumed("8.8.8.8"));

        // Add IP
        state.add_assumed_ip("8.8.8.8");
        assert!(state.is_assumed("8.8.8.8"));
    }

    #[test]
    fn test_assumed_ip_add_duplicate() {
        let (_temp_dir, mut state) = setup_test_state();

        state.add_assumed_ip("8.8.8.8");
        state.add_assumed_ip("8.8.8.8"); // Duplicate

        // Should only have one entry
        let count = state.assumed_ips.as_ref().map(|v| v.len()).unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_assumed_ip_remove() {
        let (_temp_dir, mut state) = setup_test_state();

        state.add_assumed_ip("8.8.8.8");
        state.add_assumed_ip("1.1.1.1");

        // Remove one
        state.remove_assumed_ip("8.8.8.8");

        assert!(!state.is_assumed("8.8.8.8"));
        assert!(state.is_assumed("1.1.1.1"));
    }

    #[test]
    fn test_assumed_ip_remove_nonexistent() {
        let (_temp_dir, mut state) = setup_test_state();

        state.add_assumed_ip("8.8.8.8");

        // Remove non-existent IP (should not panic or error)
        state.remove_assumed_ip("1.1.1.1");

        // Original should still be there
        assert!(state.is_assumed("8.8.8.8"));
    }

    #[test]
    fn test_assumed_ip_is_assumed_empty() {
        let state = OustipState::default();
        assert!(!state.is_assumed("8.8.8.8"));
    }

    #[test]
    fn test_assumed_ip_multiple() {
        let (_temp_dir, mut state) = setup_test_state();

        let ips = vec!["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"];

        for ip in &ips {
            state.add_assumed_ip(ip);
        }

        for ip in &ips {
            assert!(state.is_assumed(ip));
        }

        // Count should match
        let count = state.assumed_ips.as_ref().map(|v| v.len()).unwrap_or(0);
        assert_eq!(count, ips.len());
    }

    #[test]
    fn test_assumed_ip_serialization() {
        let (_temp_dir, mut state) = setup_test_state();

        state.add_assumed_ip("8.8.8.8");
        state.add_assumed_ip("1.1.1.1");

        // Serialize to JSON
        let json = serde_json::to_string(&state).unwrap();

        // Deserialize back
        let restored: OustipState = serde_json::from_str(&json).unwrap();

        assert!(restored.is_assumed("8.8.8.8"));
        assert!(restored.is_assumed("1.1.1.1"));
    }

    #[test]
    fn test_validate_ip_valid() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("255.255.255.255").is_ok());
        assert!(validate_ip("0.0.0.0").is_ok());
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("2001:db8::1").is_ok());
    }

    #[test]
    fn test_validate_ip_invalid() {
        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("256.0.0.0").is_err());
        assert!(validate_ip("").is_err());
        assert!(validate_ip("192.168.1.0/24").is_err()); // CIDR not allowed here
        assert!(validate_ip("192.168.1").is_err()); // Incomplete
    }

    #[test]
    fn test_assumed_ip_case_sensitivity() {
        // IPs should match exactly (case doesn't apply to IPv4 but does for normalization)
        let (_temp_dir, mut state) = setup_test_state();

        state.add_assumed_ip("8.8.8.8");

        // Exact match
        assert!(state.is_assumed("8.8.8.8"));

        // Different IP should not match
        assert!(!state.is_assumed("8.8.8.9"));
    }

    #[test]
    fn test_assumed_ip_whitespace_handling() {
        let (_temp_dir, mut state) = setup_test_state();

        // IPs are stored as-is without trimming in the state
        // The validation layer should handle whitespace
        state.add_assumed_ip("8.8.8.8");

        // Only exact match works
        assert!(state.is_assumed("8.8.8.8"));
        // Note: is_assumed does a contains check, so trimmed/whitespace versions won't match
    }

    #[test]
    fn test_state_default_assumed_none() {
        let state = OustipState::default();
        assert!(state.assumed_ips.is_none());
    }

    #[test]
    fn test_state_assumed_becomes_some_on_add() {
        let mut state = OustipState::default();
        assert!(state.assumed_ips.is_none());

        state.add_assumed_ip("8.8.8.8");
        assert!(state.assumed_ips.is_some());
    }

    #[test]
    fn test_assumed_ip_removal_order_independent() {
        let mut state = OustipState::default();

        // Add in one order
        state.add_assumed_ip("1.1.1.1");
        state.add_assumed_ip("2.2.2.2");
        state.add_assumed_ip("3.3.3.3");

        // Remove in different order
        state.remove_assumed_ip("2.2.2.2");
        state.remove_assumed_ip("1.1.1.1");

        // Only 3.3.3.3 should remain
        assert!(!state.is_assumed("1.1.1.1"));
        assert!(!state.is_assumed("2.2.2.2"));
        assert!(state.is_assumed("3.3.3.3"));
    }
}
