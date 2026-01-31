//! Diagnostic command for exhaustive runtime testing.
//!
//! This module provides comprehensive runtime diagnostics for oustip,
//! implementing industry-standard testing practices:
//!
//! - **Smoke Testing**: Verify critical functionality works
//! - **Sanity Testing**: Ensure configuration coherence
//! - **Connectivity Testing**: Check external service availability
//! - **Integration Testing**: Verify component interactions
//! - **Resilience Testing**: Test error handling and recovery
//!
//! The output is designed to be LLM-friendly, providing structured
//! diagnostic information that can be used for automated troubleshooting.

pub mod backend;
pub mod config;
pub mod connectivity;
pub mod functional;
pub mod output;
pub mod resilience;
pub mod runner;
pub mod smoke;

use anyhow::Result;
use std::path::Path;

pub use output::{DiagnosticReport, DiagnosticResult, Severity, TestCategory, TestStatus};
pub use runner::DiagnosticRunner;

/// Run the diagnose command
pub async fn run(
    config_path: &Path,
    json: bool,
    category: Option<String>,
    verbose: bool,
) -> Result<()> {
    let runner = DiagnosticRunner::new(config_path, verbose);
    let report = runner.run_all(category.as_deref()).await;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_readable(&report);
    }

    // Exit with non-zero code if any critical tests failed
    if report.has_critical_failures() {
        std::process::exit(1);
    }

    Ok(())
}

/// Print human-readable diagnostic report
fn print_human_readable(report: &DiagnosticReport) {
    println!("=== OustIP Diagnostic Report ===");
    println!("Timestamp: {}", report.timestamp);
    println!("Duration: {}ms", report.duration_ms);
    println!();

    // Summary
    println!("Summary:");
    println!(
        "  Total: {} | Passed: {} | Failed: {} | Skipped: {}",
        report.summary.total, report.summary.passed, report.summary.failed, report.summary.skipped
    );
    println!();

    // Group results by category
    let mut by_category: std::collections::HashMap<TestCategory, Vec<&DiagnosticResult>> =
        std::collections::HashMap::new();

    for result in &report.results {
        by_category
            .entry(result.category.clone())
            .or_default()
            .push(result);
    }

    // Print each category
    for category in &[
        TestCategory::Smoke,
        TestCategory::Config,
        TestCategory::Connectivity,
        TestCategory::Backend,
        TestCategory::Functional,
        TestCategory::Resilience,
    ] {
        if let Some(results) = by_category.get(category) {
            println!("[{}]", category);
            for result in results {
                let icon = match result.status {
                    TestStatus::Passed => "[OK]",
                    TestStatus::Failed => "[FAIL]",
                    TestStatus::Skipped => "[SKIP]",
                    TestStatus::Warning => "[WARN]",
                };
                let severity_icon = match result.severity {
                    Severity::Critical => "!!!",
                    Severity::Warning => "!",
                    Severity::Info => "",
                };
                println!(
                    "  {} {}{}: {}",
                    icon, severity_icon, result.test_name, result.message
                );
                if result.status == TestStatus::Failed {
                    println!("      Expected: {}", result.expected);
                    println!("      Actual:   {}", result.actual);
                    if !result.diagnosis.is_empty() {
                        println!("      Diagnosis: {}", result.diagnosis);
                    }
                    if !result.suggestion.is_empty() {
                        println!("      Suggestion: {}", result.suggestion);
                    }
                }
            }
            println!();
        }
    }

    // Overall status
    let status = if report.has_critical_failures() {
        "UNHEALTHY - Critical issues detected"
    } else if report.summary.failed > 0 {
        "DEGRADED - Some tests failed"
    } else {
        "HEALTHY - All tests passed"
    };
    println!("Overall Status: {}", status);
}
