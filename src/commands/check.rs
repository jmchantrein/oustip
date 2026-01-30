//! Check command implementation.

use anyhow::Result;
use std::path::Path;

use crate::config::Config;
use crate::enforcer::create_backend;
use crate::validation::validate_ip_or_cidr;

/// Run the check command
pub async fn run(ip_str: &str, config_path: &Path) -> Result<()> {
    // Parse IP address using centralized validation
    let ip_net = validate_ip_or_cidr(ip_str)?;

    // Load config
    let config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        Config::default()
    };

    let backend = create_backend(config.backend)?;

    // Check if blocked
    let is_blocked = backend.is_blocked(&ip_net).await?;

    println!();
    if is_blocked {
        println!("IP {} is BLOCKED", ip_str);
        // TODO: Could add source detection by checking which list contains the IP
    } else {
        println!("IP {} is NOT blocked", ip_str);
    }
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::validation::validate_ip_or_cidr;

    #[test]
    fn test_validate_ip_v4() {
        let result = validate_ip_or_cidr("192.168.1.1").unwrap();
        assert_eq!(result.to_string(), "192.168.1.1/32");
    }

    #[test]
    fn test_validate_ip_v4_cidr() {
        let result = validate_ip_or_cidr("192.168.0.0/24").unwrap();
        assert_eq!(result.to_string(), "192.168.0.0/24");
    }

    #[test]
    fn test_validate_ip_v6() {
        let result = validate_ip_or_cidr("::1").unwrap();
        assert_eq!(result.to_string(), "::1/128");
    }

    #[test]
    fn test_validate_ip_v6_cidr() {
        let result = validate_ip_or_cidr("2001:db8::/32").unwrap();
        assert_eq!(result.to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_validate_ip_invalid() {
        let result = validate_ip_or_cidr("not-an-ip");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid"));
    }

    #[test]
    fn test_validate_ip_invalid_cidr() {
        let result = validate_ip_or_cidr("192.168.1.1/99");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ip_empty() {
        let result = validate_ip_or_cidr("");
        assert!(result.is_err());
    }
}
