//! Centralized validation functions for OustIP.
//!
//! This module provides unified validation for:
//! - IP addresses and CIDR ranges
//! - Time intervals (systemd timer format)
//! - Presets

use anyhow::{bail, Result};
use ipnet::IpNet;
use std::net::IpAddr;

/// Valid preset values for blocklist configurations
pub const VALID_PRESETS: &[&str] = &["minimal", "recommended", "full", "paranoid"];

/// Validate an IP address string and return the parsed IpAddr.
///
/// # Examples
/// ```
/// use oustip::validation::validate_ip;
/// assert!(validate_ip("192.168.1.1").is_ok());
/// assert!(validate_ip("::1").is_ok());
/// assert!(validate_ip("invalid").is_err());
/// ```
pub fn validate_ip(ip_str: &str) -> Result<IpAddr> {
    ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip_str))
}

/// Validate an IP address or CIDR string and return the parsed IpNet.
///
/// If the input is a plain IP address (without /prefix), it will be converted
/// to a /32 (IPv4) or /128 (IPv6) network.
///
/// # Examples
/// ```
/// use oustip::validation::validate_ip_or_cidr;
/// assert!(validate_ip_or_cidr("192.168.1.1").is_ok());
/// assert!(validate_ip_or_cidr("192.168.0.0/24").is_ok());
/// assert!(validate_ip_or_cidr("invalid").is_err());
/// ```
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

/// Timer interval validation (e.g., "4h", "30m", "1d").
///
/// Returns `true` if the interval is valid.
/// Requires ASCII-only input to prevent Unicode-related edge cases.
///
/// Valid suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
///
/// # Examples
/// ```
/// use oustip::validation::is_valid_interval;
/// assert!(is_valid_interval("4h"));
/// assert!(is_valid_interval("30m"));
/// assert!(!is_valid_interval("4x"));
/// assert!(!is_valid_interval(""));
/// ```
pub fn is_valid_interval(interval: &str) -> bool {
    // Reject non-ASCII to prevent Unicode edge cases with split_at
    if !interval.is_ascii() || interval.len() < 2 {
        return false;
    }

    // Safe to use chars() since we verified ASCII-only
    let suffix = interval.chars().last().unwrap();
    let num_part = &interval[..interval.len() - 1];

    matches!(suffix, 's' | 'm' | 'h' | 'd') && num_part.parse::<u32>().is_ok()
}

/// Validate timer interval format with detailed error messages.
///
/// Accepts formats like: 30s, 5m, 4h, 1d
/// Requires ASCII-only input to prevent Unicode-related edge cases.
///
/// # Errors
/// Returns an error with a descriptive message if the interval is invalid.
///
/// # Examples
/// ```
/// use oustip::validation::validate_interval;
/// assert!(validate_interval("4h").is_ok());
/// assert!(validate_interval("invalid").is_err());
/// ```
pub fn validate_interval(interval: &str) -> Result<()> {
    if interval.is_empty() {
        bail!("Timer interval cannot be empty");
    }

    // Reject non-ASCII to prevent Unicode edge cases
    if !interval.is_ascii() {
        bail!(
            "Invalid timer interval '{}'. Only ASCII characters allowed",
            interval
        );
    }

    if interval.len() < 2 {
        bail!(
            "Invalid timer interval '{}'. Use format like '4h', '30m', '1d'",
            interval
        );
    }

    // Safe to use chars() since we verified ASCII-only
    let suffix = interval.chars().last().unwrap();
    let num_part = &interval[..interval.len() - 1];

    // Validate suffix
    if !matches!(suffix, 's' | 'm' | 'h' | 'd') {
        bail!(
            "Invalid timer interval '{}'. Suffix must be s, m, h, or d",
            interval
        );
    }

    // Validate number part
    if num_part.parse::<u32>().is_err() {
        bail!(
            "Invalid timer interval '{}'. Number part must be a positive integer",
            interval
        );
    }

    Ok(())
}

/// Validate preset value.
///
/// # Errors
/// Returns an error if the preset is not one of: minimal, recommended, full, paranoid
///
/// # Examples
/// ```
/// use oustip::validation::validate_preset;
/// assert!(validate_preset("recommended").is_ok());
/// assert!(validate_preset("invalid").is_err());
/// ```
pub fn validate_preset(preset: &str) -> Result<()> {
    if !VALID_PRESETS.contains(&preset) {
        bail!(
            "Invalid preset '{}'. Valid values: {}",
            preset,
            VALID_PRESETS.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // IP validation tests
    #[test]
    fn test_validate_ip_v4_valid() {
        let result = validate_ip("192.168.1.1");
        assert!(result.is_ok());
        assert!(result.unwrap().is_ipv4());
    }

    #[test]
    fn test_validate_ip_v6_valid() {
        let result = validate_ip("::1");
        assert!(result.is_ok());
        assert!(result.unwrap().is_ipv6());
    }

    #[test]
    fn test_validate_ip_v6_full() {
        let result = validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        assert!(result.is_ok());
        assert!(result.unwrap().is_ipv6());
    }

    #[test]
    fn test_validate_ip_invalid() {
        let result = validate_ip("not-an-ip");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid IP"));
    }

    #[test]
    fn test_validate_ip_empty() {
        let result = validate_ip("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ip_with_cidr_fails() {
        // CIDR notation should fail for single IP validation
        let result = validate_ip("192.168.1.0/24");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ip_localhost() {
        let result = validate_ip("127.0.0.1");
        assert!(result.is_ok());
        assert!(result.unwrap().is_loopback());
    }

    #[test]
    fn test_validate_ip_broadcast() {
        let result = validate_ip("255.255.255.255");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_ip_zero() {
        let result = validate_ip("0.0.0.0");
        assert!(result.is_ok());
    }

    // IP/CIDR validation tests
    #[test]
    fn test_validate_ip_or_cidr_v4() {
        let result = validate_ip_or_cidr("192.168.1.1");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "192.168.1.1/32");
    }

    #[test]
    fn test_validate_ip_or_cidr_v6() {
        let result = validate_ip_or_cidr("::1");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "::1/128");
    }

    #[test]
    fn test_validate_ip_or_cidr_cidr_v4() {
        let result = validate_ip_or_cidr("192.168.0.0/24");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "192.168.0.0/24");
    }

    #[test]
    fn test_validate_ip_or_cidr_cidr_v6() {
        let result = validate_ip_or_cidr("2001:db8::/32");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_validate_ip_or_cidr_invalid_ip() {
        let result = validate_ip_or_cidr("not.an.ip");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid IP"));
    }

    #[test]
    fn test_validate_ip_or_cidr_invalid_cidr() {
        let result = validate_ip_or_cidr("192.168.1.0/99");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid CIDR"));
    }

    #[test]
    fn test_validate_ip_or_cidr_empty() {
        let result = validate_ip_or_cidr("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ip_or_cidr_all() {
        let result = validate_ip_or_cidr("0.0.0.0/0");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "0.0.0.0/0");
    }

    #[test]
    fn test_validate_ip_or_cidr_single_host() {
        let result = validate_ip_or_cidr("10.0.0.1/32");
        assert!(result.is_ok());
        let net = result.unwrap();
        assert_eq!(net.to_string(), "10.0.0.1/32");
    }

    // is_valid_interval tests
    #[test]
    fn test_is_valid_interval_valid() {
        assert!(is_valid_interval("4h"));
        assert!(is_valid_interval("30m"));
        assert!(is_valid_interval("1d"));
        assert!(is_valid_interval("60s"));
        assert!(is_valid_interval("12h"));
    }

    #[test]
    fn test_is_valid_interval_invalid() {
        assert!(!is_valid_interval(""));
        assert!(!is_valid_interval("h"));
        assert!(!is_valid_interval("4"));
        assert!(!is_valid_interval("4x"));
        assert!(!is_valid_interval("abc"));
    }

    #[test]
    fn test_is_valid_interval_unicode_rejected() {
        // Full-width digit 4 (non-ASCII)
        assert!(!is_valid_interval("４h"));
        // Planck constant symbol (non-ASCII h-like)
        assert!(!is_valid_interval("4ℎ"));
    }

    // validate_interval tests
    #[test]
    fn test_validate_interval_valid() {
        assert!(validate_interval("30s").is_ok());
        assert!(validate_interval("5m").is_ok());
        assert!(validate_interval("4h").is_ok());
        assert!(validate_interval("1d").is_ok());
        assert!(validate_interval("100s").is_ok());
    }

    #[test]
    fn test_validate_interval_invalid_suffix() {
        assert!(validate_interval("30x").is_err());
        assert!(validate_interval("5w").is_err()); // weeks not supported
        assert!(validate_interval("4y").is_err()); // years not supported
    }

    #[test]
    fn test_validate_interval_invalid_number() {
        assert!(validate_interval("abch").is_err());
        assert!(validate_interval("-5h").is_err());
        assert!(validate_interval("3.5h").is_err()); // no decimals
    }

    #[test]
    fn test_validate_interval_empty() {
        assert!(validate_interval("").is_err());
    }

    #[test]
    fn test_validate_interval_too_short() {
        assert!(validate_interval("h").is_err());
        assert!(validate_interval("5").is_err());
    }

    #[test]
    fn test_validate_interval_unicode() {
        assert!(validate_interval("５h").is_err()); // fullwidth 5
        assert!(validate_interval("4ℎ").is_err()); // unicode h
    }

    #[test]
    fn test_validate_interval_injection_attempts() {
        assert!(validate_interval("4h; rm -rf /").is_err());
        assert!(validate_interval("$(whoami)h").is_err());
        assert!(validate_interval("4h\nExec=malicious").is_err());
    }

    // validate_preset tests
    #[test]
    fn test_validate_preset_valid() {
        assert!(validate_preset("minimal").is_ok());
        assert!(validate_preset("recommended").is_ok());
        assert!(validate_preset("full").is_ok());
        assert!(validate_preset("paranoid").is_ok());
    }

    #[test]
    fn test_validate_preset_invalid() {
        assert!(validate_preset("invalid").is_err());
        assert!(validate_preset("").is_err());
        assert!(validate_preset("MINIMAL").is_err()); // case sensitive
        assert!(validate_preset("custom").is_err());
    }

    #[test]
    fn test_validate_preset_injection_attempts() {
        assert!(validate_preset("minimal; rm -rf /").is_err());
        assert!(validate_preset("$(whoami)").is_err());
        assert!(validate_preset("`ls`").is_err());
    }

    #[test]
    fn test_valid_presets_constant() {
        assert!(VALID_PRESETS.contains(&"minimal"));
        assert!(VALID_PRESETS.contains(&"recommended"));
        assert!(VALID_PRESETS.contains(&"full"));
        assert!(VALID_PRESETS.contains(&"paranoid"));
        assert_eq!(VALID_PRESETS.len(), 4);
    }
}
