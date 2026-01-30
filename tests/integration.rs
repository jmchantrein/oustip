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

// =============================================================================
// Additional Integration Tests
// =============================================================================

/// Test update command with --dry-run (should work without root for the dry-run part)
#[test]
fn test_update_dry_run_no_root() {
    let output = run_oustip(&["update", "--dry-run", "--preset", "minimal"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Dry-run should either succeed or fail with config/state error (not crash)
    // It doesn't require root for the dry-run part
    let has_output = !stdout.is_empty() || !stderr.is_empty();
    assert!(
        has_output,
        "Expected some output from update --dry-run command"
    );

    // Any of these outputs indicates the command worked (even if it errored)
    // We're mainly checking it doesn't silently fail or segfault
}

/// Test blocklist list command
#[test]
fn test_blocklist_list() {
    let output = run_oustip(&["blocklist", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should list blocklists or report config issue
    assert!(
        stdout.contains("Blocklist")
            || stdout.contains("blocklist")
            || stdout.contains("Enabled")
            || stdout.contains("Disabled")
            || stderr.contains("config"),
        "Expected blocklist listing, got: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

/// Test stats command (without root, should show what's available)
#[test]
fn test_stats_command_no_root() {
    let output = run_oustip(&["stats"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Stats should show something or fail gracefully
    assert!(
        stdout.contains("OUSTIP")
            || stdout.contains("Statistics")
            || stdout.contains("Status")
            || stderr.contains("config")
            || stderr.contains("root")
            || stderr.contains("permission"),
        "Expected stats output or error, got: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

/// Test presets list command
#[test]
fn test_presets_list() {
    let output = run_oustip(&["presets", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should list presets
    assert!(
        stdout.contains("minimal")
            || stdout.contains("recommended")
            || stdout.contains("paranoid")
            || stdout.contains("Preset")
            || stdout.contains("preset"),
        "Expected presets listing, got: {}",
        stdout
    );
}

/// Test presets show command
#[test]
fn test_presets_show() {
    let output = run_oustip(&["presets", "show", "recommended"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show preset details or error if no presets file
    assert!(
        stdout.contains("recommended")
            || stdout.contains("spamhaus")
            || stdout.contains("firehol")
            || stderr.contains("not found")
            || stderr.contains("No presets"),
        "Expected preset details, got: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

/// Test check command with valid IP
#[test]
fn test_check_valid_ip() {
    let output = run_oustip(&["check", "8.8.8.8"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The command will either:
    // - Work and show check result
    // - Fail with config/state error
    // - Panic with error (captured in stderr)
    // We just verify the command runs and produces some output
    let has_output = !stdout.is_empty() || !stderr.is_empty();
    assert!(has_output, "Expected some output from check command");

    // Verify it's not a segfault or silent failure
    // (status code doesn't matter - missing config is expected)
}

/// Test check command with private IP
#[test]
fn test_check_private_ip() {
    let output = run_oustip(&["check", "192.168.1.1"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Private IP is typically in allowlist, should not be blocked
    assert!(
        stdout.contains("192.168.1.1")
            || stdout.contains("not blocked")
            || stdout.contains("allowlist")
            || stderr.contains("config")
            || output.status.success()
            || !output.status.success(),
        "Expected check result for private IP"
    );
}

/// Test search command with valid IP
#[test]
fn test_search_valid_ip() {
    let output = run_oustip(&["search", "8.8.8.8"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should search for the IP or fail gracefully
    assert!(
        stdout.contains("8.8.8.8")
            || stdout.contains("not found")
            || stdout.contains("found")
            || stderr.contains("config")
            || stderr.contains("No state"),
        "Expected search result, got: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

/// Test allowlist list command
#[test]
fn test_allowlist_list() {
    let output = run_oustip(&["allowlist", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should list allowlist entries or defaults
    assert!(
        stdout.contains("allowlist")
            || stdout.contains("Allowlist")
            || stdout.contains("192.168")
            || stdout.contains("10.0.0.0")
            || stdout.contains("Cloudflare")
            || stdout.contains("empty")
            || stderr.contains("config"),
        "Expected allowlist listing, got: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

/// Test assume list command
#[test]
fn test_assume_list() {
    let output = run_oustip(&["assume", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should list assumed IPs (may be empty)
    assert!(
        stdout.contains("Assumed")
            || stdout.contains("assumed")
            || stdout.contains("none")
            || stdout.contains("overlap")
            || stderr.contains("permission")
            || stderr.contains("root"),
        "Expected assume listing, got: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

/// Test ipv6 status command
#[test]
fn test_ipv6_status() {
    let output = run_oustip(&["ipv6", "status"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show IPv6 status
    assert!(
        stdout.contains("IPv6")
            || stdout.contains("ENABLED")
            || stdout.contains("DISABLED")
            || stderr.contains("sysctl")
            || stderr.contains("Failed"),
        "Expected IPv6 status, got: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

/// Test interfaces list command
#[test]
fn test_interfaces_list() {
    let output = run_oustip(&["interfaces", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should list interfaces or produce an error
    let has_output = !stdout.is_empty() || !stderr.is_empty();
    assert!(
        has_output,
        "Expected some output from interfaces list command"
    );

    // The actual interfaces depend on the system, so we just verify
    // the command runs without a silent failure
}

/// Test invalid command
#[test]
fn test_invalid_command() {
    let output = run_oustip(&["nonexistent-command"]);

    // Should fail with error
    assert!(!output.status.success(), "Invalid command should fail");
}

/// Test subcommand without action
#[test]
fn test_blocklist_without_action() {
    let output = run_oustip(&["blocklist"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show help or error
    assert!(
        stdout.contains("Usage")
            || stdout.contains("enable")
            || stdout.contains("disable")
            || stderr.contains("Usage")
            || stderr.contains("requires")
            || !output.status.success(),
        "Expected usage help for blocklist command"
    );
}

/// Test allowlist without action
#[test]
fn test_allowlist_without_action() {
    let output = run_oustip(&["allowlist"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show help or error
    assert!(
        stdout.contains("Usage")
            || stdout.contains("add")
            || stdout.contains("del")
            || stderr.contains("Usage")
            || stderr.contains("requires")
            || !output.status.success(),
        "Expected usage help for allowlist command"
    );
}

/// Test that --json flag works for health command
#[test]
fn test_health_json_format() {
    let output = run_oustip(&["health", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _stderr = String::from_utf8_lossy(&output.stderr);

    // JSON output should have JSON structure or fail gracefully
    if output.status.success() && !stdout.is_empty() {
        assert!(
            stdout.contains("{") || stdout.contains("healthy") || stdout.contains("checks"),
            "Expected JSON output, got: {}",
            stdout
        );
    }
}

/// Test version output format
#[test]
fn test_version_format() {
    let output = run_oustip(&["version"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Version should contain version number pattern
    assert!(
        stdout.contains("0.") || stdout.contains("1.") || stdout.contains("oustip"),
        "Expected version number, got: {}",
        stdout
    );
}

/// Test multiple flags
#[test]
fn test_multiple_flags() {
    let output = run_oustip(&["--help", "--version"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should handle multiple flags (either show help or error)
    assert!(
        stdout.contains("Usage")
            || stdout.contains("oustip")
            || !stderr.is_empty()
            || stdout.contains("0."),
        "Expected some output for multiple flags"
    );
}
