//! IPv6 management command implementation.

use anyhow::{Context, Result};
use std::fs;
use std::process::Command;
use tracing::info;

use crate::cli::Ipv6Action;
use crate::enforcer::check_root;

const SYSCTL_CONF: &str = "/etc/sysctl.d/99-oustip-ipv6.conf";

/// Run the ipv6 command
pub async fn run(action: Ipv6Action) -> Result<()> {
    match action {
        Ipv6Action::Disable => disable_ipv6().await,
        Ipv6Action::Enable => enable_ipv6().await,
        Ipv6Action::Status => show_ipv6_status().await,
    }
}

/// Disable IPv6 via sysctl
async fn disable_ipv6() -> Result<()> {
    check_root()?;

    info!("Disabling IPv6...");

    // Create sysctl config file
    let config = r#"# OustIP IPv6 configuration
# Disable IPv6 on all interfaces
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
"#;

    fs::write(SYSCTL_CONF, config).context("Failed to write sysctl config")?;

    // Apply immediately
    Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.disable_ipv6=1"])
        .status()
        .context("Failed to apply sysctl")?;

    Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.default.disable_ipv6=1"])
        .status()
        .context("Failed to apply sysctl")?;

    println!("[OK] IPv6 disabled");
    println!("     Configuration saved to {}", SYSCTL_CONF);
    println!("     This setting persists across reboots.");

    Ok(())
}

/// Enable IPv6 via sysctl
async fn enable_ipv6() -> Result<()> {
    check_root()?;

    info!("Enabling IPv6...");

    // Remove our sysctl config if it exists
    if std::path::Path::new(SYSCTL_CONF).exists() {
        fs::remove_file(SYSCTL_CONF).context("Failed to remove sysctl config")?;
    }

    // Apply immediately
    Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.disable_ipv6=0"])
        .status()
        .context("Failed to apply sysctl")?;

    Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.default.disable_ipv6=0"])
        .status()
        .context("Failed to apply sysctl")?;

    println!("[OK] IPv6 enabled");
    println!("     Note: You may need to restart network services or reboot");
    println!("     for full IPv6 functionality to be restored.");

    Ok(())
}

/// Show IPv6 status
async fn show_ipv6_status() -> Result<()> {
    // Read current sysctl value
    let output = Command::new("sysctl")
        .args(["-n", "net.ipv6.conf.all.disable_ipv6"])
        .output()
        .context("Failed to read sysctl")?;

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();

    println!();
    if value == "1" {
        println!("IPv6: DISABLED");
    } else {
        println!("IPv6: ENABLED");
    }

    // Check if our config file exists
    if std::path::Path::new(SYSCTL_CONF).exists() {
        println!("Managed by: OustIP ({})", SYSCTL_CONF);
    } else {
        println!("Managed by: System default");
    }
    println!();

    Ok(())
}

/// Generate sysctl config content for disabling IPv6
pub fn generate_ipv6_disable_config() -> &'static str {
    r#"# OustIP IPv6 configuration
# Disable IPv6 on all interfaces
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
"#
}

/// Check if sysctl value indicates IPv6 is disabled
pub fn is_ipv6_disabled(sysctl_value: &str) -> bool {
    sysctl_value.trim() == "1"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_sysctl_conf_path() {
        assert_eq!(SYSCTL_CONF, "/etc/sysctl.d/99-oustip-ipv6.conf");
    }

    #[test]
    fn test_sysctl_conf_path_in_sysctl_d() {
        assert!(SYSCTL_CONF.starts_with("/etc/sysctl.d/"));
        assert!(SYSCTL_CONF.ends_with(".conf"));
    }

    #[test]
    fn test_sysctl_conf_has_oustip_prefix() {
        // Config file should be identifiable as oustip's
        assert!(SYSCTL_CONF.contains("oustip"));
    }

    #[test]
    fn test_generate_ipv6_disable_config_contains_settings() {
        let config = generate_ipv6_disable_config();
        assert!(config.contains("net.ipv6.conf.all.disable_ipv6 = 1"));
        assert!(config.contains("net.ipv6.conf.default.disable_ipv6 = 1"));
    }

    #[test]
    fn test_generate_ipv6_disable_config_has_comments() {
        let config = generate_ipv6_disable_config();
        assert!(config.contains("# OustIP"));
        assert!(config.contains("# Disable IPv6"));
    }

    #[test]
    fn test_generate_ipv6_disable_config_format() {
        let config = generate_ipv6_disable_config();

        // Should have proper sysctl format
        assert!(config.contains("="));

        // Should have multiple lines
        assert!(config.contains("\n"));

        // Should start with a comment
        assert!(config.starts_with("#"));
    }

    #[test]
    fn test_generate_ipv6_disable_config_all_and_default() {
        let config = generate_ipv6_disable_config();

        // Both "all" and "default" interfaces should be covered
        assert!(config.contains("conf.all"));
        assert!(config.contains("conf.default"));
    }

    #[test]
    fn test_generate_ipv6_disable_config_is_static() {
        // Multiple calls should return the same content
        let config1 = generate_ipv6_disable_config();
        let config2 = generate_ipv6_disable_config();
        assert_eq!(config1, config2);
    }

    #[test]
    fn test_is_ipv6_disabled_true() {
        assert!(is_ipv6_disabled("1"));
        assert!(is_ipv6_disabled("1\n"));
        assert!(is_ipv6_disabled(" 1 "));
    }

    #[test]
    fn test_is_ipv6_disabled_true_with_tabs() {
        assert!(is_ipv6_disabled("\t1\t"));
        assert!(is_ipv6_disabled("\t1\n"));
    }

    #[test]
    fn test_is_ipv6_disabled_false() {
        assert!(!is_ipv6_disabled("0"));
        assert!(!is_ipv6_disabled("0\n"));
        assert!(!is_ipv6_disabled(" 0 "));
    }

    #[test]
    fn test_is_ipv6_disabled_empty() {
        assert!(!is_ipv6_disabled(""));
    }

    #[test]
    fn test_is_ipv6_disabled_whitespace_only() {
        assert!(!is_ipv6_disabled("   "));
        assert!(!is_ipv6_disabled("\t\n"));
    }

    #[test]
    fn test_is_ipv6_disabled_garbage() {
        assert!(!is_ipv6_disabled("enabled"));
        assert!(!is_ipv6_disabled("disabled"));
        assert!(!is_ipv6_disabled("yes"));
        assert!(!is_ipv6_disabled("no"));
    }

    #[test]
    fn test_is_ipv6_disabled_similar_values() {
        // Values that might be confused with 1
        assert!(!is_ipv6_disabled("01"));
        assert!(!is_ipv6_disabled("10"));
        assert!(!is_ipv6_disabled("11"));
        assert!(!is_ipv6_disabled("true"));
        assert!(!is_ipv6_disabled("false"));
    }

    #[test]
    fn test_is_ipv6_disabled_unicode() {
        // Unicode digits should not match
        assert!(!is_ipv6_disabled("１")); // Full-width 1
        assert!(!is_ipv6_disabled("٠")); // Arabic-Indic 0
    }

    #[test]
    fn test_is_ipv6_disabled_negative() {
        assert!(!is_ipv6_disabled("-1"));
    }

    #[test]
    fn test_is_ipv6_disabled_special_chars() {
        assert!(!is_ipv6_disabled("1!"));
        assert!(!is_ipv6_disabled("@1"));
        assert!(!is_ipv6_disabled("1.0"));
    }

    #[test]
    fn test_sysctl_config_write_simulation() {
        // Simulate writing the config to a temp file
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("99-oustip-ipv6.conf");

        let config = generate_ipv6_disable_config();
        fs::write(&config_path, &config).unwrap();

        // Read back and verify
        let read_config = fs::read_to_string(&config_path).unwrap();
        assert_eq!(read_config, config);

        // Verify content
        assert!(read_config.contains("net.ipv6.conf.all.disable_ipv6 = 1"));
    }

    #[test]
    fn test_sysctl_config_remove_simulation() {
        // Simulate enabling IPv6 (removing config file)
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("99-oustip-ipv6.conf");

        // Create the file
        fs::write(&config_path, generate_ipv6_disable_config()).unwrap();
        assert!(config_path.exists());

        // Remove it (simulating enable_ipv6)
        fs::remove_file(&config_path).unwrap();
        assert!(!config_path.exists());
    }

    #[test]
    fn test_sysctl_config_file_check() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("99-oustip-ipv6.conf");

        // File doesn't exist initially
        assert!(!config_path.exists());

        // Create it
        fs::write(&config_path, generate_ipv6_disable_config()).unwrap();

        // Now it exists
        assert!(config_path.exists());
    }

    #[test]
    fn test_ipv6_config_values() {
        let config = generate_ipv6_disable_config();

        // Count how many disable directives there are
        let count = config.matches("disable_ipv6 = 1").count();
        assert_eq!(count, 2, "Should disable for both 'all' and 'default'");
    }

    #[test]
    fn test_ipv6_config_no_enable_directives() {
        let config = generate_ipv6_disable_config();

        // Should not contain enable (0) directives
        assert!(!config.contains("disable_ipv6 = 0"));
    }
}
