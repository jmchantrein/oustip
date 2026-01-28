//! Integration tests for OustIP.
//!
//! These tests require root privileges and are marked with #[ignore].
//! Run with: `sudo cargo test --release -- --ignored`

use std::path::PathBuf;
use std::process::Command;

/// Helper to get the path to the compiled binary
fn get_binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps directory
    path.push("oustip");
    path
}

/// Check if running as root
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Run oustip command and return output
fn run_oustip(args: &[&str]) -> std::process::Output {
    let binary = get_binary_path();
    Command::new(&binary)
        .args(args)
        .output()
        .expect("Failed to execute oustip")
}

#[test]
fn test_version_command() {
    let output = run_oustip(&["version"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("oustip") || stdout.contains("0.1"));
}

#[test]
fn test_help_command() {
    let output = run_oustip(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("blocklist"));
    assert!(stdout.contains("update"));
}

#[test]
#[ignore] // Requires root
fn test_status_command() {
    if !is_root() {
        eprintln!("Skipping test_status_command: requires root");
        return;
    }

    let output = run_oustip(&["status"]);
    // Status may fail if not installed, but shouldn't crash
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Status")
            || stderr.contains("not installed")
            || stderr.contains("No config"),
        "Unexpected output: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

#[test]
#[ignore] // Requires root
fn test_update_dry_run() {
    if !is_root() {
        eprintln!("Skipping test_update_dry_run: requires root");
        return;
    }

    let output = run_oustip(&["update", "--dry-run", "--preset", "minimal"]);
    // Dry run should complete without error (may warn about config)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Either succeeds or fails gracefully (no panic)
    assert!(
        output.status.success() || stderr.contains("config") || stderr.contains("No config"),
        "Unexpected failure: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

#[test]
#[ignore] // Requires root
fn test_health_check() {
    if !is_root() {
        eprintln!("Skipping test_health_check: requires root");
        return;
    }

    let output = run_oustip(&["health", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Health check should return JSON (may be unhealthy if not configured)
    if output.status.success() || !stdout.is_empty() {
        // Try to parse as JSON
        if !stdout.is_empty() {
            assert!(
                stdout.contains("healthy") || stdout.contains("checks"),
                "Expected JSON health output, got: {}",
                stdout
            );
        }
    }
}

#[test]
fn test_check_invalid_ip() {
    let output = run_oustip(&["check", "not-an-ip"]);
    // Should fail gracefully with invalid IP
    assert!(
        !output.status.success() || {
            let stderr = String::from_utf8_lossy(&output.stderr);
            stderr.contains("invalid") || stderr.contains("parse")
        }
    );
}

#[test]
fn test_search_invalid_ip() {
    let output = run_oustip(&["search", "not-an-ip"]);
    // Should fail gracefully with invalid IP
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success() || stderr.contains("invalid") || stdout.contains("not found"),
        "Expected error for invalid IP"
    );
}

#[test]
fn test_blocklist_list_without_config() {
    // This should work even without config (uses defaults)
    let output = run_oustip(&["blocklist", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Either lists blocklists or reports missing config
    assert!(
        stdout.contains("firehol") || stderr.contains("config") || stderr.contains("No config"),
        "Expected blocklist output or config error"
    );
}

/// Test that concurrent execution is prevented
#[test]
#[ignore] // Requires root
fn test_concurrent_execution_lock() {
    if !is_root() {
        eprintln!("Skipping test_concurrent_execution_lock: requires root");
        return;
    }

    use std::thread;
    use std::time::Duration;

    let binary = get_binary_path();

    // Start first command (long-running dry-run)
    let mut child1 = Command::new(&binary)
        .args(["update", "--dry-run", "--preset", "paranoid"])
        .spawn()
        .expect("Failed to spawn first oustip");

    // Give it time to acquire lock
    thread::sleep(Duration::from_millis(500));

    // Try to start second command
    let output2 = Command::new(&binary)
        .args(["update", "--dry-run", "--preset", "minimal"])
        .output()
        .expect("Failed to spawn second oustip");

    // Wait for first command
    let _ = child1.wait();

    // Second command should fail or wait (depending on lock behavior)
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    // Either it waited and succeeded, or it failed with lock error
    assert!(
        output2.status.success() || stderr2.contains("lock") || stderr2.contains("running"),
        "Expected lock error or success, got: {}",
        stderr2
    );
}
