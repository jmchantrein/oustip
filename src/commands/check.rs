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
