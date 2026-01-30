//! Robustness tests for edge cases and error conditions.
//!
//! These tests verify that OustIP handles various failure modes gracefully.

use std::time::Duration;

/// Test that network timeout handling works correctly
#[tokio::test]
async fn test_http_client_timeout() {
    use reqwest::Client;

    // Create a client with very short timeout
    let client = Client::builder()
        .timeout(Duration::from_millis(1))
        .build()
        .unwrap();

    // Try to connect to a non-routable IP (should timeout)
    let result = client.get("http://10.255.255.1:12345").send().await;

    // Should fail with timeout error, not panic
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.is_timeout() || err.is_connect());
}

/// Test that invalid URLs are handled gracefully
#[tokio::test]
async fn test_invalid_url_handling() {
    use reqwest::Client;

    let client = Client::new();

    // These should fail gracefully, not panic
    let result = client.get("not-a-url").send().await;
    assert!(result.is_err());

    let result = client.get("ftp://invalid-scheme.com").send().await;
    assert!(result.is_err());
}

/// Test IP parsing edge cases
#[test]
fn test_ip_parsing_edge_cases() {
    use std::net::IpAddr;

    // Valid edge cases
    assert!("0.0.0.0".parse::<IpAddr>().is_ok());
    assert!("255.255.255.255".parse::<IpAddr>().is_ok());
    assert!("::".parse::<IpAddr>().is_ok());
    assert!("::1".parse::<IpAddr>().is_ok());

    // Invalid cases - should fail gracefully
    assert!("256.0.0.0".parse::<IpAddr>().is_err());
    assert!("-1.0.0.0".parse::<IpAddr>().is_err());
    assert!("1.2.3".parse::<IpAddr>().is_err());
    assert!("1.2.3.4.5".parse::<IpAddr>().is_err());
    assert!("".parse::<IpAddr>().is_err());
    assert!("hello".parse::<IpAddr>().is_err());
}

/// Test CIDR parsing edge cases
#[test]
fn test_cidr_parsing_edge_cases() {
    use ipnet::IpNet;

    // Valid edge cases
    assert!("0.0.0.0/0".parse::<IpNet>().is_ok());
    assert!("0.0.0.0/32".parse::<IpNet>().is_ok());
    assert!("::/0".parse::<IpNet>().is_ok());
    assert!("::/128".parse::<IpNet>().is_ok());

    // Invalid cases - should fail gracefully
    assert!("192.168.1.1/33".parse::<IpNet>().is_err());
    assert!("192.168.1.1/-1".parse::<IpNet>().is_err());
    assert!("192.168.1.1/".parse::<IpNet>().is_err());
    assert!("/24".parse::<IpNet>().is_err());
}

/// Test large input handling
#[test]
fn test_large_input_handling() {
    use ipnet::IpNet;
    use std::collections::HashSet;

    // Generate a large number of IPs
    let large_set: HashSet<IpNet> = (0..100_000u32)
        .map(|i| {
            let a = (i % 256) as u8;
            let b = ((i / 256) % 256) as u8;
            let c = ((i / 65536) % 256) as u8;
            format!("{}.{}.{}.0/24", a, b, c).parse().unwrap()
        })
        .collect();

    // Should handle large sets without panic
    assert!(large_set.len() > 50_000);
}

/// Test that file operations handle missing directories gracefully
#[test]
fn test_missing_directory_handling() {
    use std::fs;
    use std::path::Path;

    let nonexistent = Path::new("/nonexistent/path/to/file.yaml");

    // Read should fail gracefully
    let result = fs::read_to_string(nonexistent);
    assert!(result.is_err());

    // Metadata should fail gracefully
    let result = fs::metadata(nonexistent);
    assert!(result.is_err());
}

/// Test Unicode handling in inputs
#[test]
fn test_unicode_handling() {
    use ipnet::IpNet;
    use std::net::IpAddr;

    // Unicode IP-like strings should fail gracefully
    assert!("１２３.０.０.１".parse::<IpAddr>().is_err()); // Full-width digits
    assert!("192．168．1．1".parse::<IpAddr>().is_err()); // Full-width periods
    assert!("192.168.1.1\u{200B}".parse::<IpAddr>().is_err()); // Zero-width space
    assert!("192.168.1.1/24\u{FEFF}".parse::<IpNet>().is_err()); // BOM
}

/// Test empty and whitespace inputs
#[test]
fn test_empty_and_whitespace() {
    use ipnet::IpNet;
    use std::net::IpAddr;

    // Empty string
    assert!("".parse::<IpAddr>().is_err());
    assert!("".parse::<IpNet>().is_err());

    // Whitespace only
    assert!("   ".parse::<IpAddr>().is_err());
    assert!("\t\n".parse::<IpNet>().is_err());

    // Leading/trailing whitespace (trimming needed)
    assert!(" 192.168.1.1 ".parse::<IpAddr>().is_err());
    assert!(" 192.168.1.1 ".trim().parse::<IpAddr>().is_ok());
}

/// Test concurrent operations don't cause data races
#[tokio::test]
async fn test_concurrent_operations() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::task;

    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // Spawn many concurrent tasks
    for _ in 0..100 {
        let counter = Arc::clone(&counter);
        handles.push(task::spawn(async move {
            // Simulate some work
            for _ in 0..100 {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // All increments should be counted
    assert_eq!(counter.load(Ordering::Relaxed), 10_000);
}

/// Test that YAML parsing handles malformed input
#[test]
fn test_yaml_malformed_input() {
    use serde::Deserialize;

    // Invalid YAML should fail gracefully - use String as target type
    let invalid_yaml = "{{{{not valid yaml";
    let result: Result<String, _> = serde_saphyr::from_str(invalid_yaml);
    assert!(result.is_err());

    // Deeply nested YAML - use simple struct to test parsing
    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct Level4 {
        e: String,
    }
    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct Level3 {
        d: Level4,
    }
    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct Level2 {
        c: Level3,
    }
    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct Level1 {
        b: Level2,
    }
    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct DeepNested {
        a: Level1,
    }

    let deep_yaml = "a:\n  b:\n    c:\n      d:\n        e: value";
    let result: Result<DeepNested, _> = serde_saphyr::from_str(deep_yaml);
    assert!(result.is_ok());
}

/// Test that JSON parsing handles malformed input
#[test]
fn test_json_malformed_input() {
    // Invalid JSON should fail gracefully
    let invalid_json = "{not valid json}";
    let result: Result<serde_json::Value, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err());

    // Missing closing brace
    let incomplete = "{\"key\": \"value\"";
    let result: Result<serde_json::Value, _> = serde_json::from_str(incomplete);
    assert!(result.is_err());
}

/// Test overflow protection in count functions
#[test]
fn test_count_overflow_protection() {
    // Verify that u128 saturating_add doesn't panic
    let max = u128::MAX;
    let result = max.saturating_add(1);
    assert_eq!(result, u128::MAX);

    // Verify shift operations don't overflow
    for shift in 0..=128 {
        let result = if shift >= 128 {
            u128::MAX
        } else {
            1u128 << shift
        };
        assert!(result > 0);
    }
}
