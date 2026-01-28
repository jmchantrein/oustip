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
