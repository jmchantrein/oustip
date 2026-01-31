//! Smoke tests - verify basic functionality works.
//!
//! These are the first tests to run and check that the most critical
//! components are working. If smoke tests fail, deeper tests are likely
//! to fail as well.

use std::path::Path;
use std::time::Instant;

use crate::config::Config;

use super::output::{DiagnosticResult, Severity, TestCategory};

/// Run all smoke tests
pub async fn run_tests(config_path: &Path) -> Vec<DiagnosticResult> {
    vec![
        test_config_file_exists(config_path),
        test_config_file_readable(config_path),
        test_config_file_parseable(config_path),
        test_state_directory_exists(),
        test_state_directory_writable(),
        test_binary_version(),
    ]
}

/// Test: Config file exists
fn test_config_file_exists(config_path: &Path) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "smoke_config_exists";
    let test_name = "Config file exists";

    if config_path.exists() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Smoke,
            &format!("Config file found at {:?}", config_path),
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Smoke,
            Severity::Critical,
            "Config file not found",
            &format!("Config file at {:?}", config_path),
            "File does not exist",
            "The oustip configuration file is missing. This is required for oustip to function. \
             The file should contain YAML configuration for blocklists, allowlists, and alert settings.",
            &format!(
                "Run 'oustip install' to create the default configuration, or manually create \
                 {:?} with valid YAML content. You can use 'oustip install --preset recommended' \
                 for a good starting configuration.",
                config_path
            ),
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Config file is readable
fn test_config_file_readable(config_path: &Path) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "smoke_config_readable";
    let test_name = "Config file is readable";

    if !config_path.exists() {
        return DiagnosticResult::skip(
            test_id,
            test_name,
            TestCategory::Smoke,
            "Config file does not exist (see smoke_config_exists)",
        );
    }

    match std::fs::read_to_string(config_path) {
        Ok(content) => DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Smoke,
            &format!("Config file readable ({} bytes)", content.len()),
            start.elapsed().as_millis() as u64,
        ),
        Err(e) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Smoke,
            Severity::Critical,
            "Config file cannot be read",
            "File should be readable by current user",
            &format!("Read error: {}", e),
            &format!(
                "The config file exists but cannot be read. This is typically a permissions issue. \
                 Error details: {}",
                e
            ),
            &format!(
                "Check file permissions with 'ls -la {:?}'. The file should be readable by the \
                 user running oustip. If running as root, ensure the file has at least 0644 permissions. \
                 Run 'chmod 644 {:?}' to fix permissions.",
                config_path, config_path
            ),
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Config file is valid YAML and parseable
fn test_config_file_parseable(config_path: &Path) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "smoke_config_parseable";
    let test_name = "Config file is valid YAML";

    if !config_path.exists() {
        return DiagnosticResult::skip(
            test_id,
            test_name,
            TestCategory::Smoke,
            "Config file does not exist (see smoke_config_exists)",
        );
    }

    match Config::load(config_path) {
        Ok(_) => DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Smoke,
            "Config file parsed successfully",
            start.elapsed().as_millis() as u64,
        ),
        Err(e) => {
            let error_str = e.to_string();

            // Provide specific diagnosis based on error type
            let (diagnosis, suggestion) = if error_str.contains("Invalid preset") {
                (
                    format!(
                        "The config file has an invalid preset value. {}",
                        error_str
                    ),
                    "Edit the config file and set 'preset' to one of: minimal, recommended, full, paranoid. \
                     Example: preset: recommended".to_string()
                )
            } else if error_str.contains("Invalid update_interval") {
                (
                    format!(
                        "The update_interval format is invalid. {}",
                        error_str
                    ),
                    "Edit the config file and set 'update_interval' to a valid format like '4h', '30m', or '1d'. \
                     Example: update_interval: 4h".to_string()
                )
            } else if error_str.contains("HTTPS") {
                (
                    format!(
                        "A blocklist URL uses HTTP instead of HTTPS. {}",
                        error_str
                    ),
                    "All blocklist URLs must use HTTPS for security. Edit the config file and change \
                     any 'http://' URLs to 'https://'.".to_string()
                )
            } else if error_str.contains("parse") || error_str.contains("YAML") {
                (
                    format!(
                        "The config file contains invalid YAML syntax. {}",
                        error_str
                    ),
                    "Check the YAML syntax in the config file. Common issues: incorrect indentation, \
                     missing colons after keys, unquoted special characters. Use a YAML validator or \
                     regenerate the config with 'oustip install --preset recommended'.".to_string()
                )
            } else {
                (
                    format!("Config validation failed: {}", error_str),
                    "Review the error message and fix the corresponding field in the config file. \
                     Consider regenerating with 'oustip install' if issues persist."
                        .to_string(),
                )
            };

            DiagnosticResult::fail(
                test_id,
                test_name,
                TestCategory::Smoke,
                Severity::Critical,
                "Config file is invalid",
                "Valid YAML configuration",
                &error_str,
                &diagnosis,
                &suggestion,
                start.elapsed().as_millis() as u64,
            )
        }
    }
}

/// Test: State directory exists
fn test_state_directory_exists() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "smoke_state_dir_exists";
    let test_name = "State directory exists";
    let state_dir = Path::new("/var/lib/oustip");

    if state_dir.exists() && state_dir.is_dir() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Smoke,
            "State directory /var/lib/oustip exists",
            start.elapsed().as_millis() as u64,
        )
    } else if state_dir.exists() {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Smoke,
            Severity::Critical,
            "Path exists but is not a directory",
            "/var/lib/oustip should be a directory",
            "Path exists but is a file",
            "The path /var/lib/oustip exists but is not a directory. OustIP needs this directory \
             to store state information including cached blocklists and statistics.",
            "Remove the file at /var/lib/oustip and create a directory: \
             'rm /var/lib/oustip && mkdir -p /var/lib/oustip'",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Smoke,
            Severity::Warning,
            "State directory does not exist",
            "/var/lib/oustip directory",
            "Directory not found",
            "The state directory /var/lib/oustip does not exist. This directory is created during \
             installation and stores blocklist cache and state information. Without it, oustip \
             cannot persist state between runs.",
            "Create the directory with: 'mkdir -p /var/lib/oustip'. If you haven't installed oustip \
             yet, run 'oustip install' which will create this directory automatically.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: State directory is writable
fn test_state_directory_writable() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "smoke_state_dir_writable";
    let test_name = "State directory is writable";
    let state_dir = Path::new("/var/lib/oustip");

    if !state_dir.exists() {
        return DiagnosticResult::skip(
            test_id,
            test_name,
            TestCategory::Smoke,
            "State directory does not exist (see smoke_state_dir_exists)",
        );
    }

    // Try to create a temp file in the directory
    let test_file = state_dir.join(".diagnose_test");
    match std::fs::write(&test_file, "test") {
        Ok(_) => {
            // Clean up
            let _ = std::fs::remove_file(&test_file);
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Smoke,
                "State directory is writable",
                start.elapsed().as_millis() as u64,
            )
        }
        Err(e) => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Smoke,
            Severity::Critical,
            "State directory is not writable",
            "Directory should be writable by current user",
            &format!("Write error: {}", e),
            &format!(
                "The state directory /var/lib/oustip exists but is not writable. This prevents \
                 oustip from saving state information. Error: {}",
                e
            ),
            "Check directory permissions with 'ls -la /var/lib/oustip'. If running as root, \
             ensure the directory is owned by root with 'chown root:root /var/lib/oustip' and \
             has proper permissions with 'chmod 755 /var/lib/oustip'.",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Binary version is accessible
fn test_binary_version() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "smoke_binary_version";
    let test_name = "Binary version check";

    let version = env!("CARGO_PKG_VERSION");

    if version.is_empty() {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Smoke,
            Severity::Warning,
            "Version information unavailable",
            "Valid version string",
            "Empty version",
            "The binary version information is not available. This may indicate a build issue.",
            "Rebuild oustip from source with 'cargo build --release'.",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Smoke,
            &format!("OustIP version {}", version),
            start.elapsed().as_millis() as u64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_smoke_config_exists_pass() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");
        std::fs::write(&config_path, "preset: recommended\nupdate_interval: 4h").unwrap();

        let result = test_config_file_exists(&config_path);
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_smoke_config_exists_fail() {
        let result = test_config_file_exists(Path::new("/nonexistent/path/config.yaml"));
        assert_eq!(result.status, super::super::output::TestStatus::Failed);
        assert_eq!(result.severity, Severity::Critical);
    }

    #[test]
    fn test_smoke_config_readable_skip_when_missing() {
        let result = test_config_file_readable(Path::new("/nonexistent/path/config.yaml"));
        assert_eq!(result.status, super::super::output::TestStatus::Skipped);
    }

    #[test]
    fn test_smoke_binary_version() {
        let result = test_binary_version();
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
        assert!(result.message.contains(env!("CARGO_PKG_VERSION")));
    }
}
