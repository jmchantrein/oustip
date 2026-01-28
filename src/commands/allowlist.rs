//! Allowlist command implementation.

use anyhow::Result;
use ipnet::IpNet;
use std::net::IpAddr;
use std::path::Path;

use crate::cli::AllowlistAction;
use crate::config::Config;
use crate::enforcer::check_root;
use crate::lock::LockGuard;

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
    let _: IpNet = if ip_str.contains('/') {
        ip_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR: {}", ip_str))?
    } else {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip_str))?;
        IpNet::from(ip)
    };

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

/// Validate an IP address or CIDR string and return the parsed IpNet
pub fn validate_ip_or_cidr(ip_str: &str) -> Result<IpNet> {
    if ip_str.contains('/') {
        ip_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR: {}", ip_str))
    } else {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip_str))?;
        Ok(IpNet::from(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip_v4() {
        let result = validate_ip_or_cidr("192.168.1.1");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "192.168.1.1/32");
    }

    #[test]
    fn test_validate_ip_v6() {
        let result = validate_ip_or_cidr("::1");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "::1/128");
    }

    #[test]
    fn test_validate_cidr_v4() {
        let result = validate_ip_or_cidr("192.168.0.0/24");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "192.168.0.0/24");
    }

    #[test]
    fn test_validate_cidr_v6() {
        let result = validate_ip_or_cidr("2001:db8::/32");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_validate_invalid_ip() {
        let result = validate_ip_or_cidr("not.an.ip");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid IP"));
    }

    #[test]
    fn test_validate_invalid_cidr() {
        let result = validate_ip_or_cidr("192.168.1.0/99");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid CIDR"));
    }

    #[test]
    fn test_validate_empty_string() {
        let result = validate_ip_or_cidr("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_garbage_input() {
        let result = validate_ip_or_cidr("hello world");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_cidr_v4_all() {
        let result = validate_ip_or_cidr("0.0.0.0/0");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "0.0.0.0/0");
    }

    #[test]
    fn test_validate_cidr_single_host() {
        let result = validate_ip_or_cidr("10.0.0.1/32");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "10.0.0.1/32");
    }
}
