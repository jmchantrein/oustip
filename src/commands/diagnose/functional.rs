//! Functional tests - verify feature correctness.
//!
//! These tests verify that oustip's core functionality works correctly,
//! including IP checking, CIDR aggregation, and blocklist parsing.

use std::path::Path;
use std::time::Instant;

use ipnet::IpNet;

use crate::aggregator::{aggregate, count_ips, deduplicate, subtract_allowlist};
use crate::config::Config;
use crate::fetcher::parse_blocklist;

use super::output::{DiagnosticResult, Severity, TestCategory};

/// Run all functional tests
pub async fn run_tests(config_path: &Path) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    // Load config (some tests need it)
    let config = Config::load(config_path).ok();

    // Core functionality tests (don't need config)
    results.push(test_ip_parsing());
    results.push(test_cidr_parsing());
    results.push(test_cidr_aggregation());
    results.push(test_allowlist_subtraction());
    results.push(test_blocklist_parsing());
    results.push(test_ip_counting());

    // Config-dependent tests
    if let Some(ref cfg) = config {
        results.push(test_allowlist_parsing(cfg));
    }

    results
}

/// Test: IP address parsing
fn test_ip_parsing() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "functional_ip_parsing";
    let test_name = "IP address parsing";

    let test_cases = [
        ("192.168.1.1", true),
        ("10.0.0.1", true),
        ("8.8.8.8", true),
        ("255.255.255.255", true),
        ("0.0.0.0", true),
        ("2001:db8::1", true),
        ("::1", true),
        ("invalid", false),
        ("256.1.1.1", false),
        ("192.168.1", false),
    ];

    let mut failures = Vec::new();

    for (ip, should_parse) in &test_cases {
        let parsed = ip.parse::<std::net::IpAddr>().is_ok();
        if parsed != *should_parse {
            failures.push(format!(
                "'{}' parsed={} expected={}",
                ip, parsed, should_parse
            ));
        }
    }

    if failures.is_empty() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Functional,
            &format!("All {} IP parsing tests passed", test_cases.len()),
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Functional,
            Severity::Critical,
            "IP parsing test failures",
            "All test cases should pass",
            &failures.join("; "),
            "The IP address parser is not working correctly. This is a critical internal error \
             that would prevent oustip from processing blocklists correctly.",
            "This indicates a bug in the system's IP parsing library. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: CIDR notation parsing
fn test_cidr_parsing() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "functional_cidr_parsing";
    let test_name = "CIDR notation parsing";

    let test_cases = [
        ("192.168.0.0/24", true, 24),
        ("10.0.0.0/8", true, 8),
        ("172.16.0.0/12", true, 12),
        ("0.0.0.0/0", true, 0),
        ("192.168.1.1/32", true, 32),
        ("2001:db8::/32", true, 32),
        ("192.168.0.0/33", false, 0),  // Invalid prefix for IPv4
        ("invalid/24", false, 0),
        ("192.168.0.0", false, 0),  // No prefix
    ];

    let mut failures = Vec::new();

    for (cidr, should_parse, expected_prefix) in &test_cases {
        match cidr.parse::<IpNet>() {
            Ok(net) => {
                if !should_parse {
                    failures.push(format!("'{}' should not parse but did", cidr));
                } else if net.prefix_len() != *expected_prefix {
                    failures.push(format!(
                        "'{}' prefix={} expected={}",
                        cidr,
                        net.prefix_len(),
                        expected_prefix
                    ));
                }
            }
            Err(_) => {
                if *should_parse {
                    failures.push(format!("'{}' should parse but didn't", cidr));
                }
            }
        }
    }

    if failures.is_empty() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Functional,
            &format!("All {} CIDR parsing tests passed", test_cases.len()),
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Functional,
            Severity::Critical,
            "CIDR parsing test failures",
            "All test cases should pass",
            &failures.join("; "),
            "The CIDR parser is not working correctly. This would prevent oustip from \
             correctly processing blocklist entries.",
            "This indicates a bug in the ipnet library. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: CIDR aggregation
fn test_cidr_aggregation() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "functional_cidr_aggregation";
    let test_name = "CIDR aggregation";

    // Test case: Two /25 subnets should aggregate to one /24
    let input: Vec<IpNet> = vec![
        "192.168.0.0/25".parse().unwrap(),
        "192.168.0.128/25".parse().unwrap(),
    ];

    let aggregated = aggregate(&input);

    if aggregated.len() == 1 && aggregated[0].to_string() == "192.168.0.0/24" {
        // Test another case: non-contiguous should not aggregate
        let input2: Vec<IpNet> = vec![
            "192.168.0.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let aggregated2 = aggregate(&input2);

        if aggregated2.len() == 2 {
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Functional,
                "CIDR aggregation working correctly",
                start.elapsed().as_millis() as u64,
            )
        } else {
            DiagnosticResult::fail(
                test_id,
                test_name,
                TestCategory::Functional,
                Severity::Warning,
                "Non-contiguous aggregation incorrect",
                "2 separate networks",
                &format!("{} networks", aggregated2.len()),
                "Non-contiguous CIDR ranges were incorrectly aggregated.",
                "This may indicate a bug in the aggregation algorithm.",
                start.elapsed().as_millis() as u64,
            )
        }
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Functional,
            Severity::Critical,
            "CIDR aggregation failed",
            "192.168.0.0/24 (aggregated from two /25)",
            &aggregated
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            "The CIDR aggregation algorithm is not working correctly. This would result in \
             more firewall rules than necessary and reduced performance.",
            "This indicates a bug in the aggregation code. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Allowlist subtraction
fn test_allowlist_subtraction() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "functional_allowlist_subtraction";
    let test_name = "Allowlist subtraction";

    let blocklist: Vec<IpNet> = vec![
        "192.168.0.0/24".parse().unwrap(),
        "10.0.0.0/8".parse().unwrap(),
        "8.8.8.0/24".parse().unwrap(),
    ];

    let allowlist: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];

    let result = subtract_allowlist(&blocklist, &allowlist);

    // Should have removed 10.0.0.0/8
    let has_10 = result.iter().any(|n| n.to_string().starts_with("10."));

    if !has_10 && result.len() == 2 {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Functional,
            "Allowlist subtraction working correctly",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Functional,
            Severity::Critical,
            "Allowlist subtraction failed",
            "2 entries (10.0.0.0/8 removed)",
            &format!(
                "{} entries: {}",
                result.len(),
                result
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "The allowlist subtraction is not working correctly. This could cause allowlisted \
             IPs to be incorrectly blocked.",
            "This indicates a bug in the subtraction algorithm. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Blocklist parsing
fn test_blocklist_parsing() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "functional_blocklist_parsing";
    let test_name = "Blocklist parsing";

    let sample_content = r#"# FireHOL Level 1 blocklist
# Comment line

192.168.1.1
10.0.0.0/8
# Another comment
172.16.0.0/12
invalid-entry
8.8.8.8
"#;

    let parsed = parse_blocklist(sample_content);

    // Should parse 4 valid entries (skip comments and invalid)
    if parsed.len() == 4 {
        // Verify specific entries
        let has_192 = parsed.iter().any(|n| n.to_string().contains("192.168.1.1"));
        let has_10 = parsed.iter().any(|n| n.to_string().contains("10.0.0.0"));

        if has_192 && has_10 {
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Functional,
                "Blocklist parsing working correctly (4/6 lines parsed, comments/invalid skipped)",
                start.elapsed().as_millis() as u64,
            )
        } else {
            DiagnosticResult::fail(
                test_id,
                test_name,
                TestCategory::Functional,
                Severity::Critical,
                "Blocklist parsing missing expected entries",
                "192.168.1.1 and 10.0.0.0/8 present",
                &format!(
                    "Parsed: {}",
                    parsed
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "The blocklist parser is not correctly extracting IP addresses.",
                "This indicates a bug in the parser. Report this issue.",
                start.elapsed().as_millis() as u64,
            )
        }
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Functional,
            Severity::Critical,
            "Blocklist parsing returned wrong count",
            "4 valid entries",
            &format!("{} entries", parsed.len()),
            "The blocklist parser is not correctly filtering comments and invalid entries.",
            "This indicates a bug in the parser. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: IP counting
fn test_ip_counting() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "functional_ip_counting";
    let test_name = "IP counting";

    let nets: Vec<IpNet> = vec![
        "192.168.0.0/24".parse().unwrap(), // 256 IPs
        "10.0.0.0/8".parse().unwrap(),     // 16,777,216 IPs
    ];

    let count = count_ips(&nets);
    let expected = 256u128 + 16_777_216u128;

    if count == expected {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Functional,
            &format!("IP counting correct ({} IPs)", count),
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Functional,
            Severity::Warning,
            "IP counting incorrect",
            &expected.to_string(),
            &count.to_string(),
            "The IP counting function returned an incorrect value. This affects statistics \
             but not blocking functionality.",
            "This indicates a bug in the counting algorithm. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Allowlist parsing from config
fn test_allowlist_parsing(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "functional_allowlist_config";
    let test_name = "Config allowlist parsing";

    let mut valid_count = 0;
    let mut invalid_entries = Vec::new();

    for entry in &config.allowlist {
        if entry.parse::<IpNet>().is_ok() || entry.parse::<std::net::IpAddr>().is_ok() {
            valid_count += 1;
        } else {
            invalid_entries.push(entry.clone());
        }
    }

    if invalid_entries.is_empty() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Functional,
            &format!("All {} allowlist entries are valid", valid_count),
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::warning(
            test_id,
            test_name,
            TestCategory::Functional,
            &format!(
                "{} of {} allowlist entries are invalid",
                invalid_entries.len(),
                config.allowlist.len()
            ),
            &format!(
                "Invalid entries will be ignored: {}. This may cause unexpected blocking.",
                invalid_entries.join(", ")
            ),
            "Fix or remove the invalid entries from the allowlist in config.yaml.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Deduplication
#[allow(dead_code)]
fn test_deduplication() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "functional_deduplication";
    let test_name = "IP deduplication";

    let input: Vec<IpNet> = vec![
        "192.168.0.0/24".parse().unwrap(),
        "192.168.0.0/24".parse().unwrap(), // Duplicate
        "10.0.0.0/8".parse().unwrap(),
        "10.0.0.0/8".parse().unwrap(), // Duplicate
        "10.0.0.0/8".parse().unwrap(), // Another duplicate
    ];

    let deduped = deduplicate(&input);

    if deduped.len() == 2 {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Functional,
            "Deduplication working correctly (5 -> 2 entries)",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Functional,
            Severity::Warning,
            "Deduplication incorrect",
            "2 unique entries",
            &format!("{} entries", deduped.len()),
            "The deduplication function did not correctly remove duplicates.",
            "This indicates a bug in the deduplication code. Report this issue.",
            start.elapsed().as_millis() as u64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_parsing_result() {
        let result = test_ip_parsing();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_cidr_parsing_result() {
        let result = test_cidr_parsing();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_aggregation_result() {
        let result = test_cidr_aggregation();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_subtraction_result() {
        let result = test_allowlist_subtraction();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_blocklist_parsing_result() {
        let result = test_blocklist_parsing();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_ip_counting_result() {
        let result = test_ip_counting();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }
}
