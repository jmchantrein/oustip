//! Check command implementation.

use anyhow::Result;
use ipnet::IpNet;
use std::net::IpAddr;
use std::path::Path;

use crate::config::Config;
use crate::enforcer::create_backend;

/// Run the check command
pub async fn run(ip_str: &str, config_path: &Path) -> Result<()> {
    // Parse IP address
    let ip_net: IpNet = if ip_str.contains('/') {
        ip_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR: {}", ip_str))?
    } else {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip_str))?;
        IpNet::from(ip)
    };

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

/// Parse an IP string to IpNet (used for testing and reusability)
pub fn parse_ip(ip_str: &str) -> Result<IpNet> {
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
    fn test_parse_ip_v4() {
        let result = parse_ip("192.168.1.1").unwrap();
        assert_eq!(result.to_string(), "192.168.1.1/32");
    }

    #[test]
    fn test_parse_ip_v4_cidr() {
        let result = parse_ip("192.168.0.0/24").unwrap();
        assert_eq!(result.to_string(), "192.168.0.0/24");
    }

    #[test]
    fn test_parse_ip_v6() {
        let result = parse_ip("::1").unwrap();
        assert_eq!(result.to_string(), "::1/128");
    }

    #[test]
    fn test_parse_ip_v6_cidr() {
        let result = parse_ip("2001:db8::/32").unwrap();
        assert_eq!(result.to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_parse_ip_invalid() {
        let result = parse_ip("not-an-ip");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid"));
    }

    #[test]
    fn test_parse_ip_invalid_cidr() {
        let result = parse_ip("192.168.1.1/99");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ip_empty() {
        let result = parse_ip("");
        assert!(result.is_err());
    }
}
