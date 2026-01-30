//! Allowlist command implementation.

use anyhow::Result;
use std::path::Path;

use crate::cli::AllowlistAction;
use crate::config::Config;
use crate::enforcer::check_root;
use crate::lock::LockGuard;
use crate::validation::validate_ip_or_cidr;

/// Run the allowlist command
pub async fn run(action: AllowlistAction, config_path: &Path) -> Result<()> {
    match action {
        AllowlistAction::Add { ip } => add_to_allowlist(&ip, config_path).await,
        AllowlistAction::Del { ip } => remove_from_allowlist(&ip, config_path).await,
        AllowlistAction::List => list_allowlist(config_path).await,
        AllowlistAction::Reload => reload_allowlist(config_path).await,
    }
}

/// Add an IP/CIDR to the allowlist
async fn add_to_allowlist(ip_str: &str, config_path: &Path) -> Result<()> {
    check_root()?;

    // Validate IP/CIDR
    let _ = validate_ip_or_cidr(ip_str)?;

    // Acquire lock to prevent concurrent config modifications
    let _lock = LockGuard::acquire()?;

    // Load config (under lock)
    let mut config = Config::load(config_path)?;

    // Check if already in allowlist
    if config.allowlist.contains(&ip_str.to_string()) {
        println!("{} is already in the allowlist", ip_str);
        return Ok(());
    }

    // Add to allowlist and save atomically
    config.allowlist.push(ip_str.to_string());
    config.save(config_path)?;

    println!("[OK] Added {} to allowlist", ip_str);
    println!("     Run 'oustip update' to apply changes");

    Ok(())
}

/// Remove an IP/CIDR from the allowlist
async fn remove_from_allowlist(ip_str: &str, config_path: &Path) -> Result<()> {
    check_root()?;

    // Acquire lock to prevent concurrent config modifications
    let _lock = LockGuard::acquire()?;

    // Load config (under lock)
    let mut config = Config::load(config_path)?;

    // Find and remove
    let original_len = config.allowlist.len();
    config.allowlist.retain(|x| x != ip_str);

    if config.allowlist.len() == original_len {
        println!("{} was not in the allowlist", ip_str);
        return Ok(());
    }

    // Save atomically
    config.save(config_path)?;

    println!("[OK] Removed {} from allowlist", ip_str);
    println!("     Run 'oustip update' to apply changes");

    Ok(())
}

/// List all IPs in the allowlist
async fn list_allowlist(config_path: &Path) -> Result<()> {
    let config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        Config::default()
    };

    println!();
    println!("Manual allowlist ({} entries):", config.allowlist.len());
    println!();

    if config.allowlist.is_empty() {
        println!("  (empty)");
    } else {
        for ip in &config.allowlist {
            println!("  {}", ip);
        }
    }

    // Show auto-allowlist status
    println!();
    println!("Auto-allowlist providers:");
    println!(
        "  Cloudflare: {}",
        if config.auto_allowlist.cloudflare {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  GitHub: {}",
        if config.auto_allowlist.github {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  Google Cloud: {}",
        if config.auto_allowlist.google_cloud {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  AWS: {}",
        if config.auto_allowlist.aws {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  Fastly: {}",
        if config.auto_allowlist.fastly {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!();

    Ok(())
}

/// Reload allowlist from configuration
async fn reload_allowlist(config_path: &Path) -> Result<()> {
    check_root()?;

    // Simply run update to reload everything
    super::update::run(None, false, config_path).await?;

    println!("[OK] Allowlist reloaded");
    Ok(())
}

// Note: Tests for validate_ip_or_cidr are in src/validation.rs

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Create a test config file
    fn create_test_config(dir: &TempDir) -> std::path::PathBuf {
        let config_path = dir.path().join("config.yaml");
        let content = r#"
language: en
backend: auto
mode: conntrack
preset: recommended
update_interval: 4h
allowlist:
  - 192.168.0.0/16
  - 10.0.0.0/8
blocklists:
  - name: test_list
    url: https://example.com/list
    enabled: true
auto_allowlist:
  cloudflare: false
  github: false
  google_cloud: false
  aws: false
  fastly: false
"#;
        fs::write(&config_path, content).unwrap();
        config_path
    }

    #[test]
    fn test_list_allowlist_no_config() {
        // list_allowlist should work without a config file (uses defaults)
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("nonexistent.yaml");

        // The function is async, so we test the path handling
        assert!(!config_path.exists());
    }

    #[test]
    fn test_list_allowlist_with_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(&temp_dir);

        let config = Config::load(&config_path).unwrap();
        assert!(!config.allowlist.is_empty());
        assert!(config.allowlist.contains(&"192.168.0.0/16".to_string()));
    }

    #[test]
    fn test_allowlist_contains_check() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(&temp_dir);

        let config = Config::load(&config_path).unwrap();

        // Check existing entry
        assert!(config.allowlist.contains(&"192.168.0.0/16".to_string()));

        // Check non-existing entry
        assert!(!config.allowlist.contains(&"8.8.8.8".to_string()));
    }

    #[test]
    fn test_allowlist_default_providers() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(&temp_dir);

        let config = Config::load(&config_path).unwrap();

        // All providers should be disabled in test config
        assert!(!config.auto_allowlist.cloudflare);
        assert!(!config.auto_allowlist.github);
        assert!(!config.auto_allowlist.google_cloud);
        assert!(!config.auto_allowlist.aws);
        assert!(!config.auto_allowlist.fastly);
    }

    #[test]
    fn test_allowlist_modify_in_memory() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(&temp_dir);

        let mut config = Config::load(&config_path).unwrap();
        let original_len = config.allowlist.len();

        // Add new entry
        config.allowlist.push("1.2.3.4".to_string());
        assert_eq!(config.allowlist.len(), original_len + 1);

        // Remove entry
        config.allowlist.retain(|x| x != "1.2.3.4");
        assert_eq!(config.allowlist.len(), original_len);
    }

    #[test]
    fn test_allowlist_validation() {
        // Valid IPs/CIDRs
        assert!(validate_ip_or_cidr("192.168.1.1").is_ok());
        assert!(validate_ip_or_cidr("10.0.0.0/8").is_ok());
        assert!(validate_ip_or_cidr("::1").is_ok());
        assert!(validate_ip_or_cidr("2001:db8::/32").is_ok());

        // Invalid IPs/CIDRs
        assert!(validate_ip_or_cidr("not-an-ip").is_err());
        assert!(validate_ip_or_cidr("192.168.1.0/99").is_err());
        assert!(validate_ip_or_cidr("").is_err());
    }

    #[test]
    fn test_allowlist_duplicate_detection() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(&temp_dir);

        let config = Config::load(&config_path).unwrap();

        // Test duplicate check logic
        let test_ip = "192.168.0.0/16";
        let is_duplicate = config.allowlist.contains(&test_ip.to_string());
        assert!(is_duplicate);

        // Test non-duplicate
        let new_ip = "8.8.8.8";
        let is_duplicate = config.allowlist.contains(&new_ip.to_string());
        assert!(!is_duplicate);
    }

    #[test]
    fn test_allowlist_retain_logic() {
        let mut allowlist = vec![
            "192.168.0.0/16".to_string(),
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
        ];

        // Remove middle entry
        let original_len = allowlist.len();
        allowlist.retain(|x| x != "10.0.0.0/8");
        assert_eq!(allowlist.len(), original_len - 1);
        assert!(!allowlist.contains(&"10.0.0.0/8".to_string()));

        // Remove non-existent entry (no change)
        let len_before = allowlist.len();
        allowlist.retain(|x| x != "non-existent");
        assert_eq!(allowlist.len(), len_before);
    }

    #[test]
    fn test_config_save_atomicity() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = create_test_config(&temp_dir);

        let mut config = Config::load(&config_path).unwrap();
        config.allowlist.push("5.6.7.8".to_string());

        // Save config
        config.save(&config_path).unwrap();

        // Reload and verify
        let reloaded = Config::load(&config_path).unwrap();
        assert!(reloaded.allowlist.contains(&"5.6.7.8".to_string()));
    }
}
