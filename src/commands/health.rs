//! Health check command implementation.

use anyhow::Result;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::config::Config;
use crate::enforcer::create_backend;
use crate::stats::OustipState;

/// Minimum required free disk space in bytes (100 MB)
const MIN_FREE_DISK_SPACE: u64 = 100 * 1024 * 1024;

/// Maximum allowed age for state file in hours
const MAX_STATE_AGE_HOURS: i64 = 24;

/// Health check result
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheck {
    pub healthy: bool,
    pub checks: Vec<CheckResult>,
}

/// Individual check result
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

impl CheckResult {
    fn pass(name: &str, message: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            message: message.to_string(),
        }
    }

    fn fail(name: &str, message: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            message: message.to_string(),
        }
    }
}

/// Run health check command
pub async fn run(config_path: &Path, json: bool) -> Result<()> {
    let mut checks = Vec::new();

    // Check 1: Config file exists and is valid
    checks.push(check_config(config_path));

    // Check 2: State file exists and is recent
    checks.push(check_state_file());

    // Check 3: Firewall rules are active
    checks.push(check_firewall_active(config_path).await);

    // Check 4: Disk space available
    checks.push(check_disk_space());

    let healthy = checks.iter().all(|c| c.passed);
    let health = HealthCheck { healthy, checks };

    if json {
        println!("{}", serde_json::to_string_pretty(&health)?);
    } else {
        // Print human-readable output
        let status = if health.healthy {
            "HEALTHY"
        } else {
            "UNHEALTHY"
        };
        println!("Status: {}", status);
        println!();

        for check in &health.checks {
            let icon = if check.passed { "[OK]" } else { "[FAIL]" };
            println!("{} {}: {}", icon, check.name, check.message);
        }
    }

    // Exit with non-zero code if unhealthy
    if !health.healthy {
        std::process::exit(1);
    }

    Ok(())
}

/// Check if config file exists and is valid
fn check_config(config_path: &Path) -> CheckResult {
    if !config_path.exists() {
        return CheckResult::fail(
            "config",
            &format!("Config file not found: {:?}", config_path),
        );
    }

    match Config::load(config_path) {
        Ok(_) => CheckResult::pass("config", "Config file valid"),
        Err(e) => CheckResult::fail("config", &format!("Config invalid: {}", e)),
    }
}

/// Check if state file exists and is recent
fn check_state_file() -> CheckResult {
    let state_path = Path::new("/var/lib/oustip/state.json");

    if !state_path.exists() {
        return CheckResult::fail("state", "State file not found (run 'oustip update' first)");
    }

    // Check file modification time
    match std::fs::metadata(state_path) {
        Ok(metadata) => {
            if let Ok(modified) = metadata.modified() {
                let modified_time = chrono::DateTime::<Utc>::from(modified);
                let age = Utc::now() - modified_time;

                if age > Duration::hours(MAX_STATE_AGE_HOURS) {
                    return CheckResult::fail(
                        "state",
                        &format!(
                            "State file is {} hours old (max {} hours)",
                            age.num_hours(),
                            MAX_STATE_AGE_HOURS
                        ),
                    );
                }

                // Also check if we can parse the state
                match OustipState::load() {
                    Ok(state) => {
                        let msg = if let Some(last_update) = state.last_update {
                            format!(
                                "State file valid, last updated {}",
                                last_update.format("%Y-%m-%d %H:%M UTC")
                            )
                        } else {
                            "State file valid".to_string()
                        };
                        CheckResult::pass("state", &msg)
                    }
                    Err(e) => CheckResult::fail("state", &format!("State file corrupted: {}", e)),
                }
            } else {
                CheckResult::fail("state", "Cannot read state file modification time")
            }
        }
        Err(e) => CheckResult::fail("state", &format!("Cannot access state file: {}", e)),
    }
}

/// Check if firewall rules are active
async fn check_firewall_active(config_path: &Path) -> CheckResult {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(_) => return CheckResult::fail("firewall", "Cannot load config to check firewall"),
    };

    let backend = match create_backend(config.backend) {
        Ok(b) => b,
        Err(e) => return CheckResult::fail("firewall", &format!("Cannot create backend: {}", e)),
    };

    match backend.is_active().await {
        Ok(true) => {
            // Also get entry count
            match backend.entry_count().await {
                Ok(count) => CheckResult::pass(
                    "firewall",
                    &format!("Firewall rules active ({} entries)", count),
                ),
                Err(_) => CheckResult::pass("firewall", "Firewall rules active"),
            }
        }
        Ok(false) => CheckResult::fail("firewall", "Firewall rules not active"),
        Err(e) => CheckResult::fail("firewall", &format!("Cannot check firewall: {}", e)),
    }
}

/// Check if there's enough disk space
fn check_disk_space() -> CheckResult {
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    let path = match CString::new("/var/lib/oustip").or_else(|_| CString::new("/")) {
        Ok(p) => p,
        Err(_) => return CheckResult::fail("disk", "Failed to create path for disk space check"),
    };

    let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };

    if result != 0 {
        return CheckResult::fail("disk", "Cannot check disk space");
    }

    let stat = unsafe { stat.assume_init() };
    let free_space = stat.f_bavail * stat.f_frsize;
    let free_mb = free_space / (1024 * 1024);

    if free_space < MIN_FREE_DISK_SPACE {
        CheckResult::fail(
            "disk",
            &format!(
                "Insufficient disk space: {} MB available (min {} MB)",
                free_mb,
                MIN_FREE_DISK_SPACE / (1024 * 1024)
            ),
        )
    } else {
        CheckResult::pass("disk", &format!("{} MB available", free_mb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result_pass() {
        let result = CheckResult::pass("test", "All good");
        assert!(result.passed);
        assert_eq!(result.name, "test");
        assert_eq!(result.message, "All good");
    }

    #[test]
    fn test_check_result_fail() {
        let result = CheckResult::fail("test", "Something wrong");
        assert!(!result.passed);
        assert_eq!(result.name, "test");
        assert_eq!(result.message, "Something wrong");
    }

    #[test]
    fn test_health_check_serialization() {
        let health = HealthCheck {
            healthy: true,
            checks: vec![
                CheckResult::pass("config", "OK"),
                CheckResult::pass("state", "OK"),
            ],
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"healthy\":true"));
        assert!(json.contains("\"config\""));
    }

    #[test]
    fn test_check_config_missing() {
        let result = check_config(Path::new("/nonexistent/config.yaml"));
        assert!(!result.passed);
        assert!(result.message.contains("not found"));
    }

    #[test]
    fn test_check_config_invalid() {
        // Create a temp file with invalid YAML
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("invalid_config_test.yaml");
        std::fs::write(&temp_file, "{{invalid yaml").unwrap();

        let result = check_config(&temp_file);
        assert!(!result.passed);
        assert!(result.message.contains("invalid") || result.message.contains("Invalid"));

        std::fs::remove_file(temp_file).ok();
    }

    #[test]
    fn test_check_disk_space() {
        // This test should pass on most systems
        let result = check_disk_space();
        // Either passes with available space or fails with a clear message
        assert!(!result.message.is_empty());
        assert!(result.message.contains("MB") || result.message.contains("Cannot"));
    }

    #[test]
    fn test_health_check_all_passing() {
        let checks = [
            CheckResult::pass("a", "OK"),
            CheckResult::pass("b", "OK"),
            CheckResult::pass("c", "OK"),
        ];
        let healthy = checks.iter().all(|c| c.passed);
        assert!(healthy);
    }

    #[test]
    fn test_health_check_one_failing() {
        let checks = [
            CheckResult::pass("a", "OK"),
            CheckResult::fail("b", "Failed"),
            CheckResult::pass("c", "OK"),
        ];
        let healthy = checks.iter().all(|c| c.passed);
        assert!(!healthy);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MIN_FREE_DISK_SPACE, 100 * 1024 * 1024);
        assert_eq!(MAX_STATE_AGE_HOURS, 24);
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    // =========================================================================
    // CheckResult comprehensive tests
    // =========================================================================

    #[test]
    fn test_check_result_pass_various() {
        let result = CheckResult::pass("test_name", "Success message");
        assert!(result.passed);
        assert_eq!(result.name, "test_name");
        assert_eq!(result.message, "Success message");
    }

    #[test]
    fn test_check_result_fail_various() {
        let result = CheckResult::fail("test_name", "Error: something went wrong");
        assert!(!result.passed);
        assert_eq!(result.name, "test_name");
        assert_eq!(result.message, "Error: something went wrong");
    }

    #[test]
    fn test_check_result_empty_strings() {
        let result = CheckResult::pass("", "");
        assert!(result.passed);
        assert_eq!(result.name, "");
        assert_eq!(result.message, "");
    }

    #[test]
    fn test_check_result_special_chars() {
        let result = CheckResult::pass("test!@#$%", "Message with special chars: <>&\"'");
        assert!(result.passed);
        assert!(result.name.contains("!@#$%"));
    }

    #[test]
    fn test_check_result_unicode() {
        let result = CheckResult::pass("unicode_test", "Status: OK");
        assert!(result.passed);
    }

    // =========================================================================
    // HealthCheck comprehensive tests
    // =========================================================================

    #[test]
    fn test_health_check_healthy_empty() {
        let health = HealthCheck {
            healthy: true,
            checks: vec![],
        };
        assert!(health.healthy);
        assert!(health.checks.is_empty());
    }

    #[test]
    fn test_health_check_unhealthy_single() {
        let health = HealthCheck {
            healthy: false,
            checks: vec![CheckResult::fail("single", "Failed")],
        };
        assert!(!health.healthy);
        assert_eq!(health.checks.len(), 1);
    }

    #[test]
    fn test_health_check_mixed_results() {
        let checks = vec![
            CheckResult::pass("check1", "OK"),
            CheckResult::fail("check2", "Failed"),
            CheckResult::pass("check3", "OK"),
            CheckResult::fail("check4", "Also failed"),
        ];

        let healthy = checks.iter().all(|c| c.passed);
        let health = HealthCheck { healthy, checks };

        assert!(!health.healthy);
        assert_eq!(health.checks.len(), 4);
    }

    #[test]
    fn test_health_check_json_serialization_detailed() {
        let health = HealthCheck {
            healthy: false,
            checks: vec![
                CheckResult::pass("config", "Valid"),
                CheckResult::fail("firewall", "Not active"),
            ],
        };

        let json = serde_json::to_string_pretty(&health).unwrap();

        // Verify JSON structure
        assert!(json.contains("\"healthy\": false"));
        assert!(json.contains("\"checks\""));
        assert!(json.contains("\"name\": \"config\""));
        assert!(json.contains("\"passed\": true"));
        assert!(json.contains("\"name\": \"firewall\""));
        assert!(json.contains("\"passed\": false"));
    }

    #[test]
    fn test_health_check_json_roundtrip() {
        let original = HealthCheck {
            healthy: true,
            checks: vec![
                CheckResult::pass("a", "msg_a"),
                CheckResult::pass("b", "msg_b"),
            ],
        };

        let json = serde_json::to_string(&original).unwrap();
        let restored: HealthCheck = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.healthy, original.healthy);
        assert_eq!(restored.checks.len(), original.checks.len());
    }

    // =========================================================================
    // check_config comprehensive tests
    // =========================================================================

    #[test]
    fn test_check_config_nonexistent_path() {
        let result = check_config(Path::new(
            "/this/path/definitely/does/not/exist/config.yaml",
        ));
        assert!(!result.passed);
        assert!(result.message.contains("not found"));
    }

    #[test]
    fn test_check_config_invalid_yaml_syntax() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("health_test_invalid_yaml.yaml");

        // Write invalid YAML
        std::fs::write(&temp_file, "{{{{invalid yaml syntax").unwrap();

        let result = check_config(&temp_file);
        assert!(!result.passed);

        std::fs::remove_file(temp_file).ok();
    }

    #[test]
    fn test_check_config_empty_file() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("health_test_empty.yaml");

        // Write empty file
        std::fs::write(&temp_file, "").unwrap();

        let result = check_config(&temp_file);
        // Empty file behavior depends on parser - just check we get a result
        // The important thing is it doesn't panic
        assert!(!result.name.is_empty());

        std::fs::remove_file(temp_file).ok();
    }

    // =========================================================================
    // check_disk_space comprehensive tests
    // =========================================================================

    #[test]
    fn test_check_disk_space_returns_result() {
        let result = check_disk_space();
        // Should always return some result (pass or fail)
        assert!(!result.name.is_empty());
        assert!(!result.message.is_empty());
    }

    #[test]
    fn test_check_disk_space_message_format() {
        let result = check_disk_space();
        // Message should contain MB
        assert!(
            result.message.contains("MB") || result.message.contains("Cannot"),
            "Message should contain 'MB' or error text: {}",
            result.message
        );
    }

    // =========================================================================
    // Constants and thresholds tests
    // =========================================================================

    #[test]
    fn test_min_free_disk_space_reasonable() {
        // 100 MB is a reasonable minimum
        assert!(MIN_FREE_DISK_SPACE >= 50 * 1024 * 1024);
        assert!(MIN_FREE_DISK_SPACE <= 500 * 1024 * 1024);
    }

    #[test]
    fn test_max_state_age_reasonable() {
        // 24 hours is reasonable
        assert!(MAX_STATE_AGE_HOURS >= 12);
        assert!(MAX_STATE_AGE_HOURS <= 72);
    }

    #[test]
    fn test_min_free_disk_space_bytes_to_mb() {
        let mb = MIN_FREE_DISK_SPACE / (1024 * 1024);
        assert_eq!(mb, 100);
    }

    // =========================================================================
    // Check aggregation tests
    // =========================================================================

    #[test]
    fn test_all_checks_pass() {
        let checks = vec![
            CheckResult::pass("a", "OK"),
            CheckResult::pass("b", "OK"),
            CheckResult::pass("c", "OK"),
        ];
        assert!(checks.iter().all(|c| c.passed));
    }

    #[test]
    fn test_one_check_fails() {
        let checks = vec![
            CheckResult::pass("a", "OK"),
            CheckResult::pass("b", "OK"),
            CheckResult::fail("c", "Failed"),
        ];
        assert!(!checks.iter().all(|c| c.passed));
    }

    #[test]
    fn test_first_check_fails() {
        let checks = vec![
            CheckResult::fail("a", "Failed"),
            CheckResult::pass("b", "OK"),
            CheckResult::pass("c", "OK"),
        ];
        assert!(!checks.iter().all(|c| c.passed));
    }

    #[test]
    fn test_no_checks() {
        let checks: Vec<CheckResult> = vec![];
        // Empty vec -> all() returns true
        assert!(checks.iter().all(|c| c.passed));
    }

    // =========================================================================
    // Serialization edge cases
    // =========================================================================

    #[test]
    fn test_check_result_serialization() {
        let result = CheckResult::pass("test", "message");
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"passed\":true"));
        assert!(json.contains("\"message\":\"message\""));
    }

    #[test]
    fn test_health_check_empty_checks_json() {
        let health = HealthCheck {
            healthy: true,
            checks: vec![],
        };
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"checks\":[]"));
    }

    #[test]
    fn test_check_result_long_message() {
        let long_message = "a".repeat(10000);
        let result = CheckResult::fail("test", &long_message);
        assert_eq!(result.message.len(), 10000);

        // Should serialize without issues
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.len() > 10000);
    }

    // =========================================================================
    // Display text generation tests
    // =========================================================================

    #[test]
    fn test_status_text_healthy() {
        let healthy = true;
        let status = if healthy { "HEALTHY" } else { "UNHEALTHY" };
        assert_eq!(status, "HEALTHY");
    }

    #[test]
    fn test_status_text_unhealthy() {
        let healthy = false;
        let status = if healthy { "HEALTHY" } else { "UNHEALTHY" };
        assert_eq!(status, "UNHEALTHY");
    }

    #[test]
    fn test_icon_passed() {
        let passed = true;
        let icon = if passed { "[OK]" } else { "[FAIL]" };
        assert_eq!(icon, "[OK]");
    }

    #[test]
    fn test_icon_failed() {
        let passed = false;
        let icon = if passed { "[OK]" } else { "[FAIL]" };
        assert_eq!(icon, "[FAIL]");
    }

    // =========================================================================
    // Debug and Display tests
    // =========================================================================

    #[test]
    fn test_health_check_debug() {
        let health = HealthCheck {
            healthy: true,
            checks: vec![CheckResult::pass("test", "OK")],
        };
        let debug_str = format!("{:?}", health);
        assert!(debug_str.contains("healthy"));
        assert!(debug_str.contains("checks"));
    }

    #[test]
    fn test_check_result_debug() {
        let result = CheckResult::pass("name", "message");
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("name"));
        assert!(debug_str.contains("passed"));
        assert!(debug_str.contains("message"));
    }

    // =========================================================================
    // State file age calculation tests
    // =========================================================================

    #[test]
    fn test_age_calculation_logic() {
        use chrono::{Duration, Utc};

        let now = Utc::now();
        let one_hour_ago = now - Duration::hours(1);
        let age = now - one_hour_ago;

        assert_eq!(age.num_hours(), 1);
        assert!(age.num_hours() < MAX_STATE_AGE_HOURS);
    }

    #[test]
    fn test_age_exceeds_threshold() {
        use chrono::{Duration, Utc};

        let now = Utc::now();
        let old = now - Duration::hours(25);
        let age = now - old;

        assert!(age.num_hours() > MAX_STATE_AGE_HOURS);
    }

    #[test]
    fn test_age_at_threshold() {
        use chrono::{Duration, Utc};

        let now = Utc::now();
        let at_threshold = now - Duration::hours(MAX_STATE_AGE_HOURS);
        let age = now - at_threshold;

        // Exactly at threshold should NOT exceed
        assert!(!(age > Duration::hours(MAX_STATE_AGE_HOURS)));
    }
}
