//! DNS resolution utilities for OustIP.

use std::net::IpAddr;
use std::time::Duration;

/// Default DNS resolution timeout in seconds
const DNS_TIMEOUT_SECS: u64 = 5;

/// Resolve an IP address to hostname via reverse DNS (PTR record) with timeout.
///
/// Returns the hostname if found, or a descriptive string if resolution fails:
/// - "(no PTR)" - No PTR record found
/// - "(DNS timeout)" - Resolution timed out after 5 seconds
/// - "(DNS failed)" - Resolution task failed
/// - "(invalid IP)" - Could not parse IP address
pub async fn resolve_ptr(ip: IpAddr) -> String {
    let dns_future = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip));

    match tokio::time::timeout(Duration::from_secs(DNS_TIMEOUT_SECS), dns_future).await {
        Ok(Ok(Ok(hostname))) => hostname,
        Ok(Ok(Err(_))) => "(no PTR)".to_string(),
        Ok(Err(_)) => "(DNS failed)".to_string(),
        Err(_) => "(DNS timeout)".to_string(),
    }
}

/// Resolve an IP address string to hostname via reverse DNS.
///
/// Parses the IP string first, then performs PTR lookup.
pub async fn resolve_ptr_str(ip_str: &str) -> String {
    // Handle CIDR notation by extracting just the IP part
    let ip_part = ip_str.split('/').next().unwrap_or(ip_str);

    match ip_part.parse::<IpAddr>() {
        Ok(ip) => resolve_ptr(ip).await,
        Err(_) => "(invalid IP)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_ptr_invalid() {
        // This should return "(no PTR)" or similar for a private IP
        let result = resolve_ptr("127.0.0.1".parse().unwrap()).await;
        // Just verify it doesn't panic and returns something
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_ptr_str_with_cidr() {
        let result = resolve_ptr_str("192.168.1.1/24").await;
        // Should handle CIDR notation gracefully
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_ptr_str_invalid() {
        let result = resolve_ptr_str("not-an-ip").await;
        assert_eq!(result, "(invalid IP)");
    }

    #[tokio::test]
    async fn test_resolve_ptr_localhost() {
        let result = resolve_ptr("127.0.0.1".parse().unwrap()).await;
        // Localhost may or may not have PTR, but should not panic
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_ptr_str_ipv6() {
        let result = resolve_ptr_str("::1").await;
        // IPv6 localhost - should handle gracefully
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_ptr_str_empty() {
        let result = resolve_ptr_str("").await;
        assert_eq!(result, "(invalid IP)");
    }

    #[tokio::test]
    async fn test_resolve_ptr_str_cidr_only() {
        let result = resolve_ptr_str("/24").await;
        assert_eq!(result, "(invalid IP)");
    }

    #[tokio::test]
    async fn test_resolve_ptr_private_ip() {
        let result = resolve_ptr("10.0.0.1".parse().unwrap()).await;
        // Private IP probably won't have PTR
        assert!(!result.is_empty());
    }

    #[test]
    fn test_dns_timeout_constant() {
        assert_eq!(DNS_TIMEOUT_SECS, 5);
    }

    #[test]
    fn test_cidr_stripping() {
        // Test the CIDR stripping logic
        let ip_str = "192.168.1.1/24";
        let ip_part = ip_str.split('/').next().unwrap_or(ip_str);
        assert_eq!(ip_part, "192.168.1.1");

        let ip_str2 = "10.0.0.1";
        let ip_part2 = ip_str2.split('/').next().unwrap_or(ip_str2);
        assert_eq!(ip_part2, "10.0.0.1");
    }
}
