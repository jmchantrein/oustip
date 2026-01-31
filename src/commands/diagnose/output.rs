//! Output structures for LLM-friendly diagnostic reporting.
//!
//! This module defines the structured output format designed to be
//! easily parsed and understood by LLMs for automated troubleshooting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Test category for grouping related diagnostics
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestCategory {
    /// Smoke tests - basic functionality verification
    Smoke,
    /// Config tests - configuration validation
    Config,
    /// Connectivity tests - external service availability
    Connectivity,
    /// Backend tests - firewall backend verification
    Backend,
    /// Functional tests - feature correctness
    Functional,
    /// Resilience tests - error handling verification
    Resilience,
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestCategory::Smoke => write!(f, "Smoke"),
            TestCategory::Config => write!(f, "Config"),
            TestCategory::Connectivity => write!(f, "Connectivity"),
            TestCategory::Backend => write!(f, "Backend"),
            TestCategory::Functional => write!(f, "Functional"),
            TestCategory::Resilience => write!(f, "Resilience"),
        }
    }
}

/// Test status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    /// Test passed successfully
    Passed,
    /// Test failed
    Failed,
    /// Test was skipped (prerequisite not met)
    Skipped,
    /// Test passed with warnings
    Warning,
}

/// Severity level for failed tests
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Critical - system cannot function correctly
    Critical,
    /// Warning - system can function but may have issues
    Warning,
    /// Info - informational only
    Info,
}

/// Individual diagnostic test result
///
/// Designed to provide comprehensive context for LLM-based troubleshooting:
/// - Clear test identification
/// - Expected vs actual values
/// - Human-readable diagnosis
/// - Actionable suggestions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticResult {
    /// Unique test identifier (e.g., "smoke_config_exists")
    pub test_id: String,

    /// Human-readable test name
    pub test_name: String,

    /// Test category
    pub category: TestCategory,

    /// Test status
    pub status: TestStatus,

    /// Severity if failed
    pub severity: Severity,

    /// Brief message describing the result
    pub message: String,

    /// What was expected (for failures)
    pub expected: String,

    /// What was actually observed (for failures)
    pub actual: String,

    /// Diagnosis explaining why the test failed
    /// Written to help an LLM understand the root cause
    pub diagnosis: String,

    /// Suggested fix or next steps
    /// Written as actionable instructions an LLM can follow
    pub suggestion: String,

    /// Test duration in milliseconds
    pub duration_ms: u64,

    /// Additional context data (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl DiagnosticResult {
    /// Create a passing test result
    pub fn pass(
        test_id: &str,
        test_name: &str,
        category: TestCategory,
        message: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            test_id: test_id.to_string(),
            test_name: test_name.to_string(),
            category,
            status: TestStatus::Passed,
            severity: Severity::Info,
            message: message.to_string(),
            expected: String::new(),
            actual: String::new(),
            diagnosis: String::new(),
            suggestion: String::new(),
            duration_ms,
            context: None,
        }
    }

    /// Create a failing test result with full diagnostic information
    pub fn fail(
        test_id: &str,
        test_name: &str,
        category: TestCategory,
        severity: Severity,
        message: &str,
        expected: &str,
        actual: &str,
        diagnosis: &str,
        suggestion: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            test_id: test_id.to_string(),
            test_name: test_name.to_string(),
            category,
            status: TestStatus::Failed,
            severity,
            message: message.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
            diagnosis: diagnosis.to_string(),
            suggestion: suggestion.to_string(),
            duration_ms,
            context: None,
        }
    }

    /// Create a skipped test result
    pub fn skip(
        test_id: &str,
        test_name: &str,
        category: TestCategory,
        reason: &str,
    ) -> Self {
        Self {
            test_id: test_id.to_string(),
            test_name: test_name.to_string(),
            category,
            status: TestStatus::Skipped,
            severity: Severity::Info,
            message: reason.to_string(),
            expected: String::new(),
            actual: String::new(),
            diagnosis: String::new(),
            suggestion: String::new(),
            duration_ms: 0,
            context: None,
        }
    }

    /// Create a warning result (passed with concerns)
    pub fn warning(
        test_id: &str,
        test_name: &str,
        category: TestCategory,
        message: &str,
        diagnosis: &str,
        suggestion: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            test_id: test_id.to_string(),
            test_name: test_name.to_string(),
            category,
            status: TestStatus::Warning,
            severity: Severity::Warning,
            message: message.to_string(),
            expected: String::new(),
            actual: String::new(),
            diagnosis: diagnosis.to_string(),
            suggestion: suggestion.to_string(),
            duration_ms,
            context: None,
        }
    }

    /// Add context data to the result
    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }
}

/// Summary statistics for the diagnostic run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticSummary {
    /// Total number of tests run
    pub total: usize,
    /// Number of passed tests
    pub passed: usize,
    /// Number of failed tests
    pub failed: usize,
    /// Number of skipped tests
    pub skipped: usize,
    /// Number of warnings
    pub warnings: usize,
    /// Number of critical failures
    pub critical_failures: usize,
}

impl DiagnosticSummary {
    /// Create summary from results
    pub fn from_results(results: &[DiagnosticResult]) -> Self {
        let total = results.len();
        let passed = results.iter().filter(|r| r.status == TestStatus::Passed).count();
        let failed = results.iter().filter(|r| r.status == TestStatus::Failed).count();
        let skipped = results.iter().filter(|r| r.status == TestStatus::Skipped).count();
        let warnings = results.iter().filter(|r| r.status == TestStatus::Warning).count();
        let critical_failures = results
            .iter()
            .filter(|r| r.status == TestStatus::Failed && r.severity == Severity::Critical)
            .count();

        Self {
            total,
            passed,
            failed,
            skipped,
            warnings,
            critical_failures,
        }
    }
}

/// Complete diagnostic report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Report version for compatibility
    pub version: String,

    /// Timestamp when the diagnostic was run
    pub timestamp: DateTime<Utc>,

    /// Total duration in milliseconds
    pub duration_ms: u64,

    /// OustIP version being tested
    pub oustip_version: String,

    /// Summary statistics
    pub summary: DiagnosticSummary,

    /// Individual test results
    pub results: Vec<DiagnosticResult>,

    /// System information (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_info: Option<SystemInfo>,
}

impl DiagnosticReport {
    /// Create a new diagnostic report
    pub fn new(results: Vec<DiagnosticResult>, duration_ms: u64) -> Self {
        let summary = DiagnosticSummary::from_results(&results);
        Self {
            version: "1.0".to_string(),
            timestamp: Utc::now(),
            duration_ms,
            oustip_version: env!("CARGO_PKG_VERSION").to_string(),
            summary,
            results,
            system_info: None,
        }
    }

    /// Add system information to the report
    pub fn with_system_info(mut self, info: SystemInfo) -> Self {
        self.system_info = Some(info);
        self
    }

    /// Check if there are any critical failures
    pub fn has_critical_failures(&self) -> bool {
        self.summary.critical_failures > 0
    }
}

/// System information for context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system
    pub os: String,
    /// Kernel version
    pub kernel: String,
    /// Hostname
    pub hostname: String,
    /// Is running as root
    pub is_root: bool,
    /// Available firewall backends
    pub available_backends: Vec<String>,
}

impl SystemInfo {
    /// Collect system information
    pub fn collect() -> Self {
        let is_root = unsafe { libc::geteuid() == 0 };

        let kernel = std::fs::read_to_string("/proc/version")
            .ok()
            .and_then(|v| v.split_whitespace().nth(2).map(String::from))
            .unwrap_or_else(|| "unknown".to_string());

        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let os = std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            })
            .unwrap_or_else(|| "Linux".to_string());

        // Check available backends
        let mut available_backends = Vec::new();
        if std::process::Command::new("nft")
            .arg("--version")
            .output()
            .is_ok()
        {
            available_backends.push("nftables".to_string());
        }
        if std::process::Command::new("iptables")
            .arg("--version")
            .output()
            .is_ok()
        {
            available_backends.push("iptables".to_string());
        }

        Self {
            os,
            kernel,
            hostname,
            is_root,
            available_backends,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostic_result_pass() {
        let result = DiagnosticResult::pass(
            "test_id",
            "Test Name",
            TestCategory::Smoke,
            "Test passed",
            100,
        );
        assert_eq!(result.status, TestStatus::Passed);
        assert_eq!(result.test_id, "test_id");
        assert!(result.diagnosis.is_empty());
    }

    #[test]
    fn test_diagnostic_result_fail() {
        let result = DiagnosticResult::fail(
            "test_id",
            "Test Name",
            TestCategory::Config,
            Severity::Critical,
            "Test failed",
            "expected value",
            "actual value",
            "The test failed because...",
            "Try fixing by...",
            150,
        );
        assert_eq!(result.status, TestStatus::Failed);
        assert_eq!(result.severity, Severity::Critical);
        assert!(!result.diagnosis.is_empty());
    }

    #[test]
    fn test_diagnostic_result_skip() {
        let result = DiagnosticResult::skip(
            "test_id",
            "Test Name",
            TestCategory::Backend,
            "Prerequisite not met",
        );
        assert_eq!(result.status, TestStatus::Skipped);
        assert_eq!(result.duration_ms, 0);
    }

    #[test]
    fn test_diagnostic_summary() {
        let results = vec![
            DiagnosticResult::pass("t1", "Test 1", TestCategory::Smoke, "ok", 10),
            DiagnosticResult::pass("t2", "Test 2", TestCategory::Smoke, "ok", 10),
            DiagnosticResult::fail(
                "t3", "Test 3", TestCategory::Config, Severity::Critical,
                "fail", "", "", "", "", 10
            ),
            DiagnosticResult::skip("t4", "Test 4", TestCategory::Backend, "skip"),
        ];

        let summary = DiagnosticSummary::from_results(&results);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.critical_failures, 1);
    }

    #[test]
    fn test_diagnostic_report_has_critical_failures() {
        let results = vec![
            DiagnosticResult::fail(
                "t1", "Test 1", TestCategory::Config, Severity::Critical,
                "fail", "", "", "", "", 10
            ),
        ];
        let report = DiagnosticReport::new(results, 100);
        assert!(report.has_critical_failures());
    }

    #[test]
    fn test_diagnostic_report_no_critical_failures() {
        let results = vec![
            DiagnosticResult::pass("t1", "Test 1", TestCategory::Smoke, "ok", 10),
            DiagnosticResult::fail(
                "t2", "Test 2", TestCategory::Config, Severity::Warning,
                "fail", "", "", "", "", 10
            ),
        ];
        let report = DiagnosticReport::new(results, 100);
        assert!(!report.has_critical_failures());
    }

    #[test]
    fn test_test_category_display() {
        assert_eq!(format!("{}", TestCategory::Smoke), "Smoke");
        assert_eq!(format!("{}", TestCategory::Connectivity), "Connectivity");
    }

    #[test]
    fn test_diagnostic_result_with_context() {
        let result = DiagnosticResult::pass("t1", "Test", TestCategory::Smoke, "ok", 10)
            .with_context(serde_json::json!({"key": "value"}));
        assert!(result.context.is_some());
    }

    #[test]
    fn test_diagnostic_report_serialization() {
        let results = vec![
            DiagnosticResult::pass("t1", "Test 1", TestCategory::Smoke, "ok", 10),
        ];
        let report = DiagnosticReport::new(results, 100);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"version\":\"1.0\""));
        assert!(json.contains("\"test_id\":\"t1\""));
    }
}
