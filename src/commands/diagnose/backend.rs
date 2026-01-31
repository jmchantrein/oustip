//! Backend tests - verify firewall backend availability and functionality.
//!
//! These tests check that the configured firewall backend (nftables or iptables)
//! is available and functioning correctly.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::config::{Backend, Config};
use crate::enforcer::create_backend;

use super::output::{DiagnosticResult, Severity, TestCategory};

/// Run all backend tests
pub async fn run_tests(config_path: &Path) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    // Load config
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(_) => {
            results.push(DiagnosticResult::skip(
                "backend_all",
                "Backend tests",
                TestCategory::Backend,
                "Config file could not be loaded (see smoke tests)",
            ));
            return results;
        }
    };

    // Test backend availability
    results.push(test_nftables_available());
    results.push(test_iptables_available());

    // Test root privileges (needed for firewall operations)
    results.push(test_root_privileges());

    // Test configured backend
    results.push(test_configured_backend(&config).await);

    // Test backend initialization
    results.push(test_backend_initialization(&config).await);

    // Test oustip rules exist (if firewall is active)
    results.push(test_oustip_rules_exist(&config).await);

    results
}

/// Test: nftables availability
fn test_nftables_available() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "backend_nftables_available";
    let test_name = "nftables availability";

    match Command::new("nft").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let version_line = version.lines().next().unwrap_or("unknown");
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Backend,
                &format!("nftables available: {}", version_line.trim()),
                start.elapsed().as_millis() as u64,
            )
        }
        Ok(_) => DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Backend,
            "nftables installed but version check failed (may need root)",
            start.elapsed().as_millis() as u64,
        ),
        Err(_) => DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Backend,
            "nftables not installed (iptables can be used instead)",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: iptables availability
fn test_iptables_available() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "backend_iptables_available";
    let test_name = "iptables availability";

    match Command::new("iptables").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let version_line = version.lines().next().unwrap_or("unknown");
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Backend,
                &format!("iptables available: {}", version_line.trim()),
                start.elapsed().as_millis() as u64,
            )
        }
        Ok(_) => DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Backend,
            "iptables installed but version check failed (may need root)",
            start.elapsed().as_millis() as u64,
        ),
        Err(_) => DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Backend,
            "iptables not installed (nftables can be used instead)",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Root privileges
fn test_root_privileges() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "backend_root_privileges";
    let test_name = "Root privileges";

    let is_root = unsafe { libc::geteuid() == 0 };

    if is_root {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Backend,
            "Running as root (UID 0)",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::warning(
            test_id,
            test_name,
            TestCategory::Backend,
            &format!("Not running as root (UID {})", unsafe { libc::geteuid() }),
            "Firewall operations require root privileges. Without root, oustip cannot \
             apply or verify firewall rules. Some tests will be skipped.",
            "Run 'sudo oustip diagnose' to perform full diagnostics with root privileges.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Configured backend works
async fn test_configured_backend(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "backend_configured";
    let test_name = "Configured backend";

    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        return DiagnosticResult::skip(
            test_id,
            test_name,
            TestCategory::Backend,
            "Requires root privileges (see backend_root_privileges)",
        );
    }

    let backend_name = match config.backend {
        Backend::Auto => "auto",
        Backend::Nftables => "nftables",
        Backend::Iptables => "iptables",
    };

    match create_backend(config.backend) {
        Ok(_) => DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Backend,
            &format!("Backend '{}' initialized successfully", backend_name),
            start.elapsed().as_millis() as u64,
        ),
        Err(e) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Backend,
            Severity::Critical,
            &format!("Backend '{}' failed to initialize", backend_name),
            "Backend should initialize",
            &e.to_string(),
            &format!(
                "The configured backend '{}' could not be initialized: {}. \
                 This means oustip cannot manage firewall rules.",
                backend_name, e
            ),
            "Check that the required firewall tools are installed. For nftables: 'apt install nftables'. \
             For iptables: 'apt install iptables ipset'. Or change backend to 'auto' in the config.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Backend initialization (can we create rules?)
async fn test_backend_initialization(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "backend_init";
    let test_name = "Backend initialization";

    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        return DiagnosticResult::skip(
            test_id,
            test_name,
            TestCategory::Backend,
            "Requires root privileges",
        );
    }

    let backend = match create_backend(config.backend) {
        Ok(b) => b,
        Err(_) => {
            return DiagnosticResult::skip(
                test_id,
                test_name,
                TestCategory::Backend,
                "Backend creation failed (see backend_configured)",
            );
        }
    };

    // Check if backend can query state
    match backend.is_active().await {
        Ok(active) => {
            let status = if active { "active" } else { "inactive" };
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Backend,
                &format!("Backend operational (rules {})", status),
                start.elapsed().as_millis() as u64,
            )
        }
        Err(e) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Backend,
            Severity::Warning,
            "Cannot query backend state",
            "Backend should report state",
            &e.to_string(),
            &format!(
                "The backend was initialized but cannot query its state: {}. \
                 This may indicate permission issues or kernel module problems.",
                e
            ),
            "Check kernel modules are loaded. For nftables: 'modprobe nf_tables'. \
             For iptables: 'modprobe ip_tables'. Check dmesg for related errors.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: OustIP rules exist
async fn test_oustip_rules_exist(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "backend_rules_exist";
    let test_name = "OustIP firewall rules";

    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        return DiagnosticResult::skip(
            test_id,
            test_name,
            TestCategory::Backend,
            "Requires root privileges",
        );
    }

    let backend = match create_backend(config.backend) {
        Ok(b) => b,
        Err(_) => {
            return DiagnosticResult::skip(
                test_id,
                test_name,
                TestCategory::Backend,
                "Backend creation failed",
            );
        }
    };

    match backend.is_active().await {
        Ok(true) => {
            // Rules are active, check entry count
            match backend.entry_count().await {
                Ok(count) => DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Backend,
                    &format!("OustIP rules active ({} blocked entries)", count),
                    start.elapsed().as_millis() as u64,
                ),
                Err(_) => DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Backend,
                    "OustIP rules active (entry count unavailable)",
                    start.elapsed().as_millis() as u64,
                ),
            }
        }
        Ok(false) => DiagnosticResult::warning(
            test_id,
            test_name,
            TestCategory::Backend,
            "OustIP rules not active",
            "No oustip firewall rules are currently applied. This means no IPs are being blocked. \
             This is expected if oustip hasn't been run yet or was disabled.",
            "Run 'oustip update' to fetch blocklists and apply rules, or 'oustip enable' to \
             reapply existing rules.",
            start.elapsed().as_millis() as u64,
        ),
        Err(e) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Backend,
            Severity::Warning,
            "Cannot check rule status",
            "Should be able to check rules",
            &e.to_string(),
            &format!("Failed to check if oustip rules are active: {}", e),
            "This may indicate backend issues. Try 'oustip status' for more details.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nftables_check() {
        let result = test_nftables_available();
        // Should not fail - either available or gracefully handled
        assert_ne!(
            result.status,
            super::super::output::TestStatus::Failed,
            "nftables check should not hard fail"
        );
    }

    #[test]
    fn test_iptables_check() {
        let result = test_iptables_available();
        // Should not fail - either available or gracefully handled
        assert_ne!(
            result.status,
            super::super::output::TestStatus::Failed,
            "iptables check should not hard fail"
        );
    }

    #[test]
    fn test_root_privileges_check() {
        let result = test_root_privileges();
        // Just verify it runs without panic
        assert!(!result.test_id.is_empty());
    }
}
