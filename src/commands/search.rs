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
use crate::validation::validate_ip;

/// Run the search command
pub async fn run(ip_str: &str, show_dns: bool, config_path: &Path) -> Result<()> {
    // Parse IP address using centralized validation
    let ip = validate_ip(ip_str)?;
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
        use crate::validation::validate_ip;
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("invalid").is_err());
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    // =========================================================================
    // ip_in_network comprehensive tests
    // =========================================================================

    #[test]
    fn test_ip_in_network_exact_match() {
        let ip: IpAddr = "192.168.1.0".parse().unwrap();
        // Network address itself should match
        assert!(ip_in_network(ip, "192.168.1.0/32"));
        assert!(ip_in_network(ip, "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_in_network_broadcast() {
        let ip: IpAddr = "192.168.1.255".parse().unwrap();
        // Broadcast address should be in network
        assert!(ip_in_network(ip, "192.168.1.0/24"));
        // But not in a smaller network
        assert!(!ip_in_network(ip, "192.168.1.0/25"));
    }

    #[test]
    fn test_ip_in_network_boundary() {
        // Test at network boundaries
        let ip: IpAddr = "192.168.1.0".parse().unwrap();
        assert!(ip_in_network(ip, "192.168.1.0/24"));
        assert!(!ip_in_network(ip, "192.168.0.0/24"));

        let ip: IpAddr = "192.168.0.255".parse().unwrap();
        assert!(!ip_in_network(ip, "192.168.1.0/24"));
        assert!(ip_in_network(ip, "192.168.0.0/24"));
    }

    #[test]
    fn test_ip_in_network_host_bits() {
        // Different host bits, same network
        for i in 0..=255u8 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            assert!(ip_in_network(ip, "10.0.0.0/24"));
        }
    }

    #[test]
    fn test_ip_in_network_ipv6_basic() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(ip_in_network(ip, "2001:db8::/32"));
        assert!(!ip_in_network(ip, "2001:db9::/32"));
    }

    #[test]
    fn test_ip_in_network_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(ip_in_network(ip, "::1/128"));
        assert!(!ip_in_network(ip, "::2/128"));
    }

    #[test]
    fn test_ip_in_network_ipv6_full() {
        let ip: IpAddr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap();
        assert!(ip_in_network(ip, "2001:db8::/32"));
        assert!(ip_in_network(ip, "2001:db8:85a3::/48"));
    }

    #[test]
    fn test_ip_in_network_slash_zero() {
        // /0 matches everything
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(ip_in_network(ip, "0.0.0.0/0"));

        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(ip_in_network(ip6, "::/0"));
    }

    #[test]
    fn test_ip_in_network_malformed() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Various malformed network strings
        assert!(!ip_in_network(ip, ""));
        assert!(!ip_in_network(ip, "not-a-network"));
        assert!(!ip_in_network(ip, "192.168.1.0/"));
        assert!(!ip_in_network(ip, "/24"));
        assert!(!ip_in_network(ip, "192.168.1.0/33")); // Invalid prefix
    }

    // =========================================================================
    // find_blocklist_sources comprehensive tests
    // =========================================================================

    #[test]
    fn test_find_blocklist_sources_cidr_containment() {
        let ip: IpAddr = "10.0.5.100".parse().unwrap();
        let sources = vec![
            crate::stats::SourceStats {
                name: "big_list".to_string(),
                raw_count: 1,
                ip_count: 16_777_216,
                ips: vec!["10.0.0.0/8".to_string()],
            },
            crate::stats::SourceStats {
                name: "small_list".to_string(),
                raw_count: 1,
                ip_count: 256,
                ips: vec!["10.0.5.0/24".to_string()],
            },
        ];

        let result = find_blocklist_sources(ip, &sources);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"big_list".to_string()));
        assert!(result.contains(&"small_list".to_string()));
    }

    #[test]
    fn test_find_blocklist_sources_no_duplicates() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let sources = vec![crate::stats::SourceStats {
            name: "duplicate_test".to_string(),
            raw_count: 3,
            ip_count: 768,
            ips: vec![
                "192.168.1.0/24".to_string(),
                "192.168.0.0/16".to_string(),
                "192.0.0.0/8".to_string(),
            ],
        }];

        let result = find_blocklist_sources(ip, &sources);
        // Should only appear once even though multiple ranges contain the IP
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "duplicate_test");
    }

    #[test]
    fn test_find_blocklist_sources_ipv6() {
        let ip: IpAddr = "2001:db8:1:2::100".parse().unwrap();
        let sources = vec![crate::stats::SourceStats {
            name: "ipv6_list".to_string(),
            raw_count: 1,
            ip_count: 1,
            ips: vec!["2001:db8::/32".to_string()],
        }];

        let result = find_blocklist_sources(ip, &sources);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "ipv6_list");
    }

    #[test]
    fn test_find_blocklist_sources_invalid_entries() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let sources = vec![crate::stats::SourceStats {
            name: "mixed_list".to_string(),
            raw_count: 3,
            ip_count: 256,
            ips: vec![
                "invalid-entry".to_string(),
                "8.8.8.0/24".to_string(),
                "also-invalid".to_string(),
            ],
        }];

        let result = find_blocklist_sources(ip, &sources);
        // Should still find the valid entry
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_find_blocklist_sources_single_ip() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let sources = vec![crate::stats::SourceStats {
            name: "exact_match".to_string(),
            raw_count: 1,
            ip_count: 1,
            ips: vec!["1.2.3.4/32".to_string()],
        }];

        let result = find_blocklist_sources(ip, &sources);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_find_blocklist_sources_edge_case_network_address() {
        // Test with the network address itself
        let ip: IpAddr = "10.0.0.0".parse().unwrap();
        let sources = vec![crate::stats::SourceStats {
            name: "network".to_string(),
            raw_count: 1,
            ip_count: 16_777_216,
            ips: vec!["10.0.0.0/8".to_string()],
        }];

        let result = find_blocklist_sources(ip, &sources);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_find_blocklist_sources_order_preservation() {
        let ip: IpAddr = "172.16.1.1".parse().unwrap();
        let sources = vec![
            crate::stats::SourceStats {
                name: "first".to_string(),
                raw_count: 1,
                ip_count: 256,
                ips: vec!["172.16.1.0/24".to_string()],
            },
            crate::stats::SourceStats {
                name: "second".to_string(),
                raw_count: 1,
                ip_count: 1024,
                ips: vec!["172.16.0.0/20".to_string()],
            },
        ];

        let result = find_blocklist_sources(ip, &sources);
        assert_eq!(result.len(), 2);
        // Order should be preserved
        assert_eq!(result[0], "first");
        assert_eq!(result[1], "second");
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn test_ipv4_mapped_ipv6() {
        // IPv4-mapped IPv6 addresses
        let ip: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        // This is technically IPv6, so it won't match IPv4 networks directly
        assert!(!ip_in_network(ip, "192.168.1.0/24"));
    }

    #[test]
    fn test_ip_in_network_various_prefixes() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Test various prefix lengths
        assert!(ip_in_network(ip, "192.168.1.100/32"));
        assert!(ip_in_network(ip, "192.168.1.0/24"));
        assert!(ip_in_network(ip, "192.168.0.0/16"));
        assert!(ip_in_network(ip, "192.0.0.0/8"));
        assert!(ip_in_network(ip, "0.0.0.0/0"));
    }

    #[test]
    fn test_find_sources_many_lists() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap();

        // Create many source lists, only some contain the IP
        let sources: Vec<crate::stats::SourceStats> = (0..100)
            .map(|i| crate::stats::SourceStats {
                name: format!("list_{}", i),
                raw_count: 1,
                ip_count: 256,
                ips: if i % 10 == 0 {
                    vec!["1.1.1.0/24".to_string()]
                } else {
                    vec![format!("{}.0.0.0/8", i + 2)]
                },
            })
            .collect();

        let result = find_blocklist_sources(ip, &sources);
        assert_eq!(result.len(), 10); // Every 10th list should match
    }

    #[test]
    fn test_find_sources_empty_ips() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let sources = vec![crate::stats::SourceStats {
            name: "empty".to_string(),
            raw_count: 0,
            ip_count: 0,
            ips: vec![],
        }];

        let result = find_blocklist_sources(ip, &sources);
        assert!(result.is_empty());
    }

    // =========================================================================
    // IPv6 comprehensive tests
    // =========================================================================

    #[test]
    fn test_ipv6_link_local() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(ip_in_network(ip, "fe80::/10"));
        assert!(!ip_in_network(ip, "2001:db8::/32"));
    }

    #[test]
    fn test_ipv6_unique_local() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(ip_in_network(ip, "fc00::/7"));
    }

    #[test]
    fn test_ipv6_various_prefixes() {
        let ip: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();

        assert!(ip_in_network(ip, "2001:db8:abcd:1234::1/128"));
        assert!(ip_in_network(ip, "2001:db8:abcd:1234::/64"));
        assert!(ip_in_network(ip, "2001:db8:abcd::/48"));
        assert!(ip_in_network(ip, "2001:db8::/32"));
        assert!(ip_in_network(ip, "2001::/16"));
        assert!(ip_in_network(ip, "::/0"));
    }
}
