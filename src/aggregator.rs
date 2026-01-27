//! CIDR aggregation for optimizing blocklists.

use ipnet::{IpNet, Ipv4Net};
use std::collections::HashSet;

/// Aggregate a list of IPs/CIDRs into optimized CIDR ranges.
///
/// This reduces the number of entries by merging contiguous ranges.
/// For example: [192.168.0.0/25, 192.168.0.128/25] -> [192.168.0.0/24]
pub fn aggregate(nets: &[IpNet]) -> Vec<IpNet> {
    // Separate IPv4 and IPv6
    let v4_nets: Vec<Ipv4Net> = nets
        .iter()
        .filter_map(|n| match n {
            IpNet::V4(v4) => Some(*v4),
            _ => None,
        })
        .collect();

    // Use ipnet's native aggregate function
    let aggregated_v4 = Ipv4Net::aggregate(&v4_nets);

    aggregated_v4.into_iter().map(IpNet::V4).collect()
}

/// Remove allowlisted IPs from a blocklist.
///
/// This handles CIDR overlaps: if a blocklist entry is fully contained
/// in an allowlist entry, it's removed. Partial overlaps are not handled
/// (the blocklist entry is kept).
pub fn subtract_allowlist(blocklist: &[IpNet], allowlist: &[IpNet]) -> Vec<IpNet> {
    blocklist
        .iter()
        .filter(|blocked| {
            !allowlist.iter().any(|allowed| contains(allowed, blocked))
        })
        .cloned()
        .collect()
}

/// Check if `container` fully contains `contained`.
fn contains(container: &IpNet, contained: &IpNet) -> bool {
    match (container, contained) {
        (IpNet::V4(c), IpNet::V4(t)) => c.contains(t),
        (IpNet::V6(c), IpNet::V6(t)) => c.contains(t),
        _ => false,
    }
}

/// Deduplicate a list of IPs/CIDRs.
pub fn deduplicate(nets: &[IpNet]) -> Vec<IpNet> {
    let set: HashSet<_> = nets.iter().cloned().collect();
    set.into_iter().collect()
}

/// Calculate the total number of individual IPs covered by a list of CIDRs.
pub fn count_ips(nets: &[IpNet]) -> u128 {
    nets.iter()
        .map(|net| {
            let prefix_len = net.prefix_len();
            let max_prefix = match net {
                IpNet::V4(_) => 32,
                IpNet::V6(_) => 128,
            };
            1u128 << (max_prefix - prefix_len)
        })
        .sum()
}

/// Calculate what percentage of the public IPv4 space is covered.
/// Public IPv4 space is approximately 3.7 billion addresses.
pub fn coverage_percent(ip_count: u128) -> f64 {
    const PUBLIC_IPV4_APPROX: f64 = 3_700_000_000.0;
    (ip_count as f64 / PUBLIC_IPV4_APPROX) * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_contiguous() {
        let nets: Vec<IpNet> = vec![
            "192.168.0.0/25".parse().unwrap(),
            "192.168.0.128/25".parse().unwrap(),
        ];
        let aggregated = aggregate(&nets);
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0], "192.168.0.0/24".parse::<IpNet>().unwrap());
    }

    #[test]
    fn test_aggregate_non_contiguous() {
        let nets: Vec<IpNet> = vec![
            "192.168.0.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let aggregated = aggregate(&nets);
        assert_eq!(aggregated.len(), 2);
    }

    #[test]
    fn test_subtract_allowlist() {
        let blocklist: Vec<IpNet> = vec![
            "192.168.0.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
            "8.8.8.0/24".parse().unwrap(),
        ];
        let allowlist: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
        ];
        let result = subtract_allowlist(&blocklist, &allowlist);
        assert_eq!(result.len(), 2);
        assert!(!result.iter().any(|n| n.to_string() == "10.0.0.0/8"));
    }

    #[test]
    fn test_count_ips() {
        let nets: Vec<IpNet> = vec![
            "192.168.0.0/24".parse().unwrap(), // 256 IPs
            "10.0.0.0/8".parse().unwrap(),     // 16,777,216 IPs
        ];
        let count = count_ips(&nets);
        assert_eq!(count, 256 + 16_777_216);
    }

    #[test]
    fn test_deduplicate() {
        let nets: Vec<IpNet> = vec![
            "192.168.0.0/24".parse().unwrap(),
            "192.168.0.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let deduped = deduplicate(&nets);
        assert_eq!(deduped.len(), 2);
    }
}
