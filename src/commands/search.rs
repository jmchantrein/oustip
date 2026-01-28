//! IP search command implementation.
//!
//! Search for an IP in allowlist and blocklist sources with DNS resolution.

use anyhow::Result;
use ipnet::IpNet;
use std::net::IpAddr;
use std::path::Path;

use crate::config::Config;
use crate::dns::resolve_ptr;
use crate::stats::OustipState;

/// Run the search command
pub async fn run(ip_str: &str, show_dns: bool, config_path: &Path) -> Result<()> {
    // Parse IP address
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip_str))?;

    let ip_net = IpNet::from(ip);

    // Load config and state
    let config = Config::load(config_path)?;
    let state = OustipState::load().unwrap_or_default();

    println!();
    println!("Searching for: {}", ip);

    // DNS resolution
    if show_dns {
        let hostname = resolve_ptr(ip).await;
        println!("DNS (PTR): {}", hostname);
    }

    println!();

    // Check if in allowlist
    let mut in_allowlist = false;
    let mut allowlist_entry = None;

    for entry in &config.allowlist {
        if let Ok(net) = entry.parse::<IpNet>() {
            if net.contains(&ip) {
                in_allowlist = true;
                allowlist_entry = Some(entry.clone());
                break;
            }
        }
    }

    // Check if in any blocklist
    let mut in_blocklist = false;
    let mut blocklist_sources: Vec<String> = Vec::new();

    for source in &state.sources {
        for blocked_ip in &source.ips {
            if let Ok(net) = blocked_ip.parse::<IpNet>() {
                if net.contains(&ip) || ip_net.contains(&net.network()) {
                    in_blocklist = true;
                    if !blocklist_sources.contains(&source.name) {
                        blocklist_sources.push(source.name.clone());
                    }
                }
            }
        }
    }

    // Report findings
    println!("=== Results ===");
    println!();

    if in_allowlist {
        println!("[ALLOWLIST] Found in allowlist:");
        if let Some(entry) = &allowlist_entry {
            println!("  Matching entry: {}", entry);
        }
    } else {
        println!("[ALLOWLIST] Not found in allowlist");
    }

    println!();

    if in_blocklist {
        println!(
            "[BLOCKLIST] Found in {} blocklist(s):",
            blocklist_sources.len()
        );
        for source in &blocklist_sources {
            println!("  - {}", source);
        }
    } else {
        println!("[BLOCKLIST] Not found in any blocklist");
    }

    println!();

    // Warning if in both
    if in_allowlist && in_blocklist {
        println!("=== WARNING ===");
        println!();
        println!("This IP is in BOTH allowlist and blocklist!");
        println!("The allowlist takes precedence, so this IP is NOT blocked.");
        println!();
        println!("Blocklist sources containing this IP:");
        for source in &blocklist_sources {
            println!("  - {}", source);
        }
        println!();
        println!("If this is intentional, you can acknowledge it with:");
        println!("  oustip assume add {}", ip);
    }

    // Check assumed IPs
    if let Some(ref assumed) = state.assumed_ips {
        if assumed.contains(&ip_str.to_string()) {
            println!();
            println!("[INFO] This IP is in the 'assumed' list (acknowledged overlap)");
        }
    }

    Ok(())
}

/// Check if an IP is contained in a CIDR network
pub fn ip_in_network(ip: IpAddr, network: &str) -> bool {
    if let Ok(net) = network.parse::<IpNet>() {
        net.contains(&ip)
    } else {
        false
    }
}

/// Find matching blocklist sources for an IP
pub fn find_blocklist_sources(ip: IpAddr, sources: &[crate::stats::SourceStats]) -> Vec<String> {
    let ip_net = IpNet::from(ip);
    let mut result = Vec::new();

    for source in sources {
        for blocked_ip in &source.ips {
            if let Ok(net) = blocked_ip.parse::<IpNet>() {
                if (net.contains(&ip) || ip_net.contains(&net.network()))
                    && !result.contains(&source.name)
                {
                    result.push(source.name.clone());
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_network_contained() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(ip_in_network(ip, "192.168.0.0/16"));
        assert!(ip_in_network(ip, "192.168.1.0/24"));
        assert!(ip_in_network(ip, "192.168.1.100/32"));
    }

    #[test]
    fn test_ip_in_network_not_contained() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(!ip_in_network(ip, "10.0.0.0/8"));
        assert!(!ip_in_network(ip, "192.168.2.0/24"));
    }

    #[test]
    fn test_ip_in_network_invalid() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(!ip_in_network(ip, "invalid"));
        assert!(!ip_in_network(ip, ""));
    }

    #[test]
    fn test_find_blocklist_sources_empty() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let sources: Vec<crate::stats::SourceStats> = vec![];
        let result = find_blocklist_sources(ip, &sources);
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_blocklist_sources_found() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let sources = vec![crate::stats::SourceStats {
            name: "test_list".to_string(),
            raw_count: 1,
            ip_count: 256,
            ips: vec!["192.168.1.0/24".to_string()],
        }];
        let result = find_blocklist_sources(ip, &sources);
        assert_eq!(result, vec!["test_list"]);
    }

    #[test]
    fn test_find_blocklist_sources_not_found() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let sources = vec![crate::stats::SourceStats {
            name: "test_list".to_string(),
            raw_count: 1,
            ip_count: 256,
            ips: vec!["192.168.1.0/24".to_string()],
        }];
        let result = find_blocklist_sources(ip, &sources);
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_blocklist_sources_multiple() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let sources = vec![
            crate::stats::SourceStats {
                name: "list1".to_string(),
                raw_count: 1,
                ip_count: 256,
                ips: vec!["10.0.0.0/8".to_string()],
            },
            crate::stats::SourceStats {
                name: "list2".to_string(),
                raw_count: 1,
                ip_count: 256,
                ips: vec!["10.0.0.0/24".to_string()],
            },
        ];
        let result = find_blocklist_sources(ip, &sources);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"list1".to_string()));
        assert!(result.contains(&"list2".to_string()));
    }

    #[test]
    fn test_ip_parsing() {
        assert!("192.168.1.1".parse::<IpAddr>().is_ok());
        assert!("::1".parse::<IpAddr>().is_ok());
        assert!("invalid".parse::<IpAddr>().is_err());
    }
}
