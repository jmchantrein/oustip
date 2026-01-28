//! Health check command implementation.

use anyhow::Result;
use chrono::{Duration, Utc};
use serde::Serialize;
use std::path::Path;

use crate::config::Config;
use crate::enforcer::create_backend;
use crate::stats::OustipState;

/// Minimum required free disk space in bytes (100 MB)
const MIN_FREE_DISK_SPACE: u64 = 100 * 1024 * 1024;

/// Maximum allowed age for state file in hours
const MAX_STATE_AGE_HOURS: i64 = 24;

/// Health check result
#[derive(Debug, Serialize)]
pub struct HealthCheck {
    pub healthy: bool,
    pub checks: Vec<CheckResult>,
}

/// Individual check result
#[derive(Debug, Serialize)]
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

    let path = CString::new("/var/lib/oustip").unwrap_or_else(|_| CString::new("/").unwrap());

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
