//! Resilience tests - verify error handling and recovery.
//!
//! These tests check that oustip handles error conditions gracefully
//! and provides useful error messages.

use std::path::Path;
use std::time::Instant;

use crate::config::Config;
use crate::fetcher::parse_blocklist;

use super::output::{DiagnosticResult, Severity, TestCategory};

/// Run all resilience tests
pub async fn run_tests(_config_path: &Path) -> Vec<DiagnosticResult> {
    vec![
        test_empty_blocklist_parsing(),
        test_malformed_content_parsing(),
        test_unicode_content_handling(),
        test_large_input_handling(),
        test_special_characters_handling(),
        test_config_missing_fields(),
        test_invalid_ip_formats(),
        test_memory_safety_large_cidr(),
    ]
}

/// Test: Empty blocklist parsing
fn test_empty_blocklist_parsing() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "resilience_empty_blocklist";
    let test_name = "Empty blocklist handling";

    let empty_content = "";
    let result = parse_blocklist(empty_content);

    if result.is_empty() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Resilience,
            "Empty content handled correctly (returns empty list)",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Resilience,
            Severity::Warning,
            "Empty content not handled correctly",
            "Empty result",
            &format!("{} entries", result.len()),
            "Parsing empty content should return an empty list, not generate fake entries.",
            "This indicates a bug in the parser. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Malformed content parsing
fn test_malformed_content_parsing() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "resilience_malformed_content";
    let test_name = "Malformed content handling";

    let malformed_content = r#"
not-an-ip
definitely not an IP address
123.456.789.012
192.168.1.1/99
random garbage !@#$%^&*()
<script>alert('xss')</script>
'; DROP TABLE ips; --
192.168.1.1
"#;

    // Should not panic and should parse only valid entry
    let result = std::panic::catch_unwind(|| parse_blocklist(malformed_content));

    match result {
        Ok(parsed) => {
            // Should have parsed only the valid IP (192.168.1.1)
            if parsed.len() == 1 && parsed[0].to_string().contains("192.168.1.1") {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    "Malformed content handled correctly (invalid entries skipped)",
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::warning(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    &format!("Unexpected parse result: {} entries", parsed.len()),
                    "The parser handled malformed content but the result count is unexpected.",
                    "Review the parsing logic for edge cases.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        Err(_) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Resilience,
            Severity::Critical,
            "Parser panicked on malformed content",
            "Graceful handling of invalid input",
            "Panic/crash",
            "The blocklist parser crashed when processing malformed content. This could cause \
             oustip to crash when fetching blocklists from the internet.",
            "This is a critical bug. The parser should gracefully skip invalid lines. Report this issue.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Unicode content handling
fn test_unicode_content_handling() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "resilience_unicode";
    let test_name = "Unicode content handling";

    let unicode_content = r#"
# Comentário em português
192.168.1.1
# 日本語コメント
10.0.0.0/8
# Ру́сский коммента́рий
172.16.0.0/12
# Emoji test 🔥🚀
8.8.8.8
"#;

    let result = std::panic::catch_unwind(|| parse_blocklist(unicode_content));

    match result {
        Ok(parsed) => {
            if parsed.len() == 4 {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    "Unicode content handled correctly (4 IPs parsed)",
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::warning(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    &format!("Unicode content parsed {} entries (expected 4)", parsed.len()),
                    "The parser may have issues with Unicode comment lines.",
                    "Review Unicode handling in the parser.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        Err(_) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Resilience,
            Severity::Critical,
            "Parser panicked on Unicode content",
            "Graceful handling",
            "Panic/crash",
            "The blocklist parser crashed when processing Unicode content.",
            "This is a critical bug. Report this issue.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Large input handling
fn test_large_input_handling() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "resilience_large_input";
    let test_name = "Large input handling";

    // Generate a large blocklist (10,000 entries)
    let mut large_content = String::with_capacity(200_000);
    for i in 0..10_000u32 {
        let a = ((i / 256) % 256) as u8;
        let b = (i % 256) as u8;
        large_content.push_str(&format!("10.{}.{}.0/24\n", a, b));
    }

    let parse_start = Instant::now();
    let result = std::panic::catch_unwind(|| parse_blocklist(&large_content));
    let parse_duration = parse_start.elapsed();

    match result {
        Ok(parsed) => {
            if parsed.len() == 10_000 {
                // Check performance (should complete in reasonable time)
                if parse_duration.as_secs() < 5 {
                    DiagnosticResult::pass(
                        test_id,
                        test_name,
                        TestCategory::Resilience,
                        &format!(
                            "Large input (10K entries) handled in {}ms",
                            parse_duration.as_millis()
                        ),
                        start.elapsed().as_millis() as u64,
                    )
                } else {
                    DiagnosticResult::warning(
                        test_id,
                        test_name,
                        TestCategory::Resilience,
                        &format!(
                            "Large input parsed but slow ({}s)",
                            parse_duration.as_secs()
                        ),
                        "Parsing 10,000 entries took longer than expected. This may cause \
                         delays during blocklist updates.",
                        "Consider optimizing the parser or using smaller blocklists.",
                        start.elapsed().as_millis() as u64,
                    )
                }
            } else {
                DiagnosticResult::warning(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    &format!("Large input: {} of 10,000 entries parsed", parsed.len()),
                    "Some entries were not parsed correctly.",
                    "Review the parser for edge cases with large inputs.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        Err(_) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Resilience,
            Severity::Critical,
            "Parser panicked on large input",
            "Graceful handling",
            "Panic/crash",
            "The parser crashed when processing a large blocklist. Real blocklists can have \
             hundreds of thousands of entries.",
            "This is a critical bug. Report this issue.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Special characters handling
fn test_special_characters_handling() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "resilience_special_chars";
    let test_name = "Special characters handling";

    let special_content = r#"
192.168.1.1
	10.0.0.0/8
  172.16.0.0/12
192.168.2.1;comment
8.8.8.8 # inline comment
"#;

    let result = std::panic::catch_unwind(|| parse_blocklist(special_content));

    match result {
        Ok(parsed) => {
            // Should parse at least the clean entries
            if !parsed.is_empty() {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    &format!(
                        "Special characters handled ({} entries parsed)",
                        parsed.len()
                    ),
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::warning(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    "No entries parsed from content with special characters",
                    "The parser may be too strict with whitespace handling.",
                    "Review whitespace and special character handling in the parser.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        Err(_) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Resilience,
            Severity::Critical,
            "Parser panicked on special characters",
            "Graceful handling",
            "Panic/crash",
            "The parser crashed when processing content with special characters.",
            "This is a critical bug. Report this issue.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Config with missing optional fields
fn test_config_missing_fields() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "resilience_config_missing_fields";
    let test_name = "Config default values";

    // Test that Config::default() works and has sensible defaults
    let config = Config::default();

    let mut issues = Vec::new();

    if config.preset.is_empty() {
        issues.push("preset is empty");
    }
    if config.update_interval.is_empty() {
        issues.push("update_interval is empty");
    }
    if config.blocklists.is_empty() {
        issues.push("no default blocklists");
    }
    if config.allowlist.is_empty() {
        issues.push("no default allowlist");
    }

    if issues.is_empty() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Resilience,
            &format!(
                "Config defaults valid (preset={}, {} blocklists, {} allowlist entries)",
                config.preset,
                config.blocklists.len(),
                config.allowlist.len()
            ),
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::warning(
            test_id,
            test_name,
            TestCategory::Resilience,
            &format!("Config default issues: {}", issues.join(", ")),
            "Some default config values are missing or empty.",
            "Review the Config::default() implementation.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Invalid IP format handling
fn test_invalid_ip_formats() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "resilience_invalid_ip_formats";
    let test_name = "Invalid IP format handling";

    let invalid_ips = [
        "256.1.1.1",
        "192.168.1",
        "192.168.1.1.1",
        "-1.1.1.1",
        "192.168.1.1/33",
        "::gggg",
        "2001:db8:::1",
    ];

    let mut parse_failures = 0;
    let mut panic_count = 0;

    for ip in &invalid_ips {
        let result = std::panic::catch_unwind(|| ip.parse::<ipnet::IpNet>());
        match result {
            Ok(Err(_)) => parse_failures += 1, // Expected: parse error
            Ok(Ok(_)) => {} // Unexpected but not critical
            Err(_) => panic_count += 1, // Critical: panic
        }
    }

    if panic_count > 0 {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Resilience,
            Severity::Critical,
            &format!("{} panics on invalid IP formats", panic_count),
            "Graceful error handling",
            &format!("{} panics", panic_count),
            "The IP parser panicked on invalid input instead of returning an error.",
            "This is a critical bug in error handling. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Resilience,
            &format!(
                "Invalid IP formats handled gracefully ({} correctly rejected)",
                parse_failures
            ),
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Memory safety with large CIDR
fn test_memory_safety_large_cidr() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "resilience_memory_large_cidr";
    let test_name = "Memory safety with large CIDR";

    // Test that counting IPs in large CIDRs doesn't cause overflow
    let large_cidrs: Vec<ipnet::IpNet> = vec![
        "0.0.0.0/0".parse().unwrap(),   // Entire IPv4 space
        "0.0.0.0/1".parse().unwrap(),   // Half of IPv4
        "::/0".parse().unwrap(),        // Entire IPv6 space (huge!)
    ];

    let result = std::panic::catch_unwind(|| {
        use crate::aggregator::count_ips;
        count_ips(&large_cidrs)
    });

    match result {
        Ok(count) => {
            // Should handle without overflow (uses u128)
            if count > 0 {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    "Large CIDR ranges handled without overflow",
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::warning(
                    test_id,
                    test_name,
                    TestCategory::Resilience,
                    "Large CIDR count returned 0 (possible underflow)",
                    "The IP count for large CIDRs returned 0, which may indicate an issue.",
                    "Review the count_ips implementation for edge cases.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        Err(_) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Resilience,
            Severity::Critical,
            "Panic when counting IPs in large CIDR",
            "Safe handling",
            "Panic (likely overflow)",
            "The IP counting function panicked on large CIDR ranges, likely due to integer overflow.",
            "Use saturating arithmetic or u128 for IP counting. Report this issue.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_blocklist() {
        let result = test_empty_blocklist_parsing();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_malformed_content() {
        let result = test_malformed_content_parsing();
        // Should pass or warn, not fail critically
        assert_ne!(
            result.severity,
            Severity::Critical,
            "Malformed content should not cause critical failure"
        );
    }

    #[test]
    fn test_unicode() {
        let result = test_unicode_content_handling();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_large_input() {
        let result = test_large_input_handling();
        // Should complete without critical failure
        assert_ne!(
            result.severity,
            Severity::Critical,
            "Large input should not cause critical failure"
        );
    }

    #[test]
    fn test_config_defaults() {
        let result = test_config_missing_fields();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_invalid_formats() {
        let result = test_invalid_ip_formats();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_memory_safety() {
        let result = test_memory_safety_large_cidr();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }
}
