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
        .filter(|blocked| !allowlist.iter().any(|allowed| contains(allowed, blocked)))
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
///
/// Uses saturating arithmetic to prevent overflow on large prefixes like /0.
pub fn count_ips(nets: &[IpNet]) -> u128 {
    nets.iter()
        .map(|net| {
            let prefix_len = net.prefix_len();
            let max_prefix = match net {
                IpNet::V4(_) => 32,
                IpNet::V6(_) => 128,
            };
            let shift = max_prefix - prefix_len;
            // Prevent overflow: 1 << 128 would overflow u128
            // Cap at u128::MAX for /0 IPv6 networks
            if shift >= 128 {
                u128::MAX
            } else {
                1u128 << shift
            }
        })
        .fold(0u128, |acc, count| acc.saturating_add(count))
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
        let allowlist: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
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

    #[test]
    fn test_count_ips_overflow_protection() {
        // Test that large networks don't cause overflow
        let nets: Vec<IpNet> = vec![
            "0.0.0.0/0".parse().unwrap(), // Entire IPv4 space
        ];
        let count = count_ips(&nets);
        assert_eq!(count, 1u128 << 32); // 2^32 = 4,294,967,296
    }

    #[test]
    fn test_aggregate_empty() {
        let nets: Vec<IpNet> = vec![];
        let aggregated = aggregate(&nets);
        assert!(aggregated.is_empty());
    }

    #[test]
    fn test_subtract_allowlist_empty() {
        let blocklist: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let allowlist: Vec<IpNet> = vec![];
        let result = subtract_allowlist(&blocklist, &allowlist);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_subtract_allowlist_contained() {
        // Smaller blocklist entry contained in larger allowlist entry
        let blocklist: Vec<IpNet> = vec!["10.0.1.0/24".parse().unwrap()];
        let allowlist: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let result = subtract_allowlist(&blocklist, &allowlist);
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy to generate valid IPv4 CIDR strings
    fn ipv4_cidr_strategy() -> impl Strategy<Value = IpNet> {
        (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255, 0u8..=32).prop_map(|(a, b, c, d, prefix)| {
            let ip_str = format!("{}.{}.{}.{}/{}", a, b, c, d, prefix);
            ip_str.parse::<IpNet>().unwrap()
        })
    }

    /// Strategy to generate valid IPv4 CIDR vectors
    fn ipv4_cidr_vec_strategy(max_size: usize) -> impl Strategy<Value = Vec<IpNet>> {
        prop::collection::vec(ipv4_cidr_strategy(), 0..max_size)
    }

    proptest! {
        /// Aggregation should never increase the number of entries
        #[test]
        fn prop_aggregate_reduces_or_maintains_size(nets in ipv4_cidr_vec_strategy(100)) {
            let aggregated = aggregate(&nets);
            prop_assert!(aggregated.len() <= nets.len());
        }

        /// Aggregation result should contain no duplicates
        #[test]
        fn prop_aggregate_no_duplicates(nets in ipv4_cidr_vec_strategy(50)) {
            let aggregated = aggregate(&nets);
            let set: HashSet<_> = aggregated.iter().collect();
            prop_assert_eq!(set.len(), aggregated.len());
        }

        /// Deduplication should reduce or maintain size
        #[test]
        fn prop_deduplicate_reduces_size(nets in ipv4_cidr_vec_strategy(100)) {
            let deduped = deduplicate(&nets);
            prop_assert!(deduped.len() <= nets.len());
        }

        /// Deduplication result should have no duplicates
        #[test]
        fn prop_deduplicate_unique(nets in ipv4_cidr_vec_strategy(50)) {
            let deduped = deduplicate(&nets);
            let set: HashSet<_> = deduped.iter().collect();
            prop_assert_eq!(set.len(), deduped.len());
        }

        /// Count IPs should be deterministic
        #[test]
        fn prop_count_ips_deterministic(nets in ipv4_cidr_vec_strategy(20)) {
            let count1 = count_ips(&nets);
            let count2 = count_ips(&nets);
            prop_assert_eq!(count1, count2);
        }

        /// Subtraction should never add entries
        #[test]
        fn prop_subtract_reduces_size(
            blocklist in ipv4_cidr_vec_strategy(50),
            allowlist in ipv4_cidr_vec_strategy(10)
        ) {
            let result = subtract_allowlist(&blocklist, &allowlist);
            prop_assert!(result.len() <= blocklist.len());
        }

        /// Empty allowlist should not change blocklist
        #[test]
        fn prop_subtract_empty_allowlist_identity(blocklist in ipv4_cidr_vec_strategy(50)) {
            let allowlist: Vec<IpNet> = vec![];
            let result = subtract_allowlist(&blocklist, &allowlist);
            prop_assert_eq!(result.len(), blocklist.len());
        }

        /// Coverage percent should be non-negative
        #[test]
        fn prop_coverage_non_negative(nets in ipv4_cidr_vec_strategy(20)) {
            let count = count_ips(&nets);
            let coverage = coverage_percent(count);
            prop_assert!(coverage >= 0.0);
        }
    }
}
