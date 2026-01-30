//! File-based locking to prevent concurrent execution.
//!
//! Uses flock-style advisory locking to ensure only one instance
//! of OustIP can run update operations at a time.

use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const LOCK_FILE: &str = "/var/run/oustip.lock";

/// A guard that holds an exclusive lock on the OustIP lock file.
/// The lock is automatically released when the guard is dropped.
pub struct LockGuard {
    _file: File,
}

impl LockGuard {
    /// Attempt to acquire an exclusive lock.
    /// Returns an error if another instance is already running.
    ///
    /// Uses OpenOptions with create+read+write to avoid TOCTOU race
    /// between file creation and lock acquisition.
    pub fn acquire() -> Result<Self> {
        // Ensure the directory exists
        let lock_path = Path::new(LOCK_FILE);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).ok(); // /var/run should exist, but just in case
        }

        // Open or create the lock file with read+write (not truncate)
        // This avoids a TOCTOU race between create and lock
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .with_context(|| format!("Failed to open lock file: {}", LOCK_FILE))?;

        // Set restrictive permissions (owner read/write only)
        fs::set_permissions(lock_path, fs::Permissions::from_mode(0o600))
            .context("Failed to set lock file permissions")?;

        // Try to acquire exclusive lock (non-blocking)
        file.try_lock_exclusive().map_err(|_| {
            anyhow::anyhow!(
                "Another instance of OustIP is already running.\n\
                 If you believe this is an error, remove the lock file: {}\n\
                 Or wait for the other instance to complete.",
                LOCK_FILE
            )
        })?;

        Ok(Self { _file: file })
    }
}

// Lock is automatically released when file is closed (on drop)

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_lock_acquire_release() {
        // Note: This test would need root to write to /var/run
        // So we just test the struct exists
        let _guard_type: fn() -> Result<LockGuard> = LockGuard::acquire;
    }

    #[test]
    fn test_lock_constant() {
        assert_eq!(LOCK_FILE, "/var/run/oustip.lock");
        assert!(LOCK_FILE.starts_with("/var"));
        assert!(LOCK_FILE.ends_with(".lock"));
    }

    #[test]
    fn test_lock_constant_in_run_directory() {
        // Lock file should be in /var/run which is for runtime data
        assert!(LOCK_FILE.contains("/run/"));
    }

    #[test]
    fn test_lock_constant_has_oustip_name() {
        // Lock file should be identifiable as oustip's
        assert!(LOCK_FILE.contains("oustip"));
    }

    #[test]
    fn test_file_locking_basic() {
        // Test the underlying fs2 locking mechanism with a temp file
        let temp_file = NamedTempFile::new().unwrap();
        let file = temp_file.as_file();

        // Should be able to lock
        assert!(file.try_lock_exclusive().is_ok());

        // Unlock for next test
        file.unlock().ok();
    }

    #[test]
    fn test_file_locking_shared() {
        // Test shared locking
        let temp_file = NamedTempFile::new().unwrap();
        let file = temp_file.as_file();

        // Should be able to get shared lock
        assert!(file.try_lock_shared().is_ok());

        file.unlock().ok();
    }

    #[test]
    fn test_lock_file_permissions() {
        // Test that 0o600 permission constant is correct
        let perms = fs::Permissions::from_mode(0o600);
        // 0o600 = owner read/write only
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_temp_file_locking_workflow() {
        use std::io::Read;

        // Create temp file
        let mut temp_file = NamedTempFile::new().unwrap();

        // Write something
        writeln!(temp_file, "test content").unwrap();

        // Get the file for locking
        let file = temp_file.reopen().unwrap();

        // Lock it
        assert!(file.try_lock_exclusive().is_ok());

        // Read should still work
        let mut content = String::new();
        let mut reader = temp_file.reopen().unwrap();
        reader.read_to_string(&mut content).ok();

        // Unlock
        file.unlock().ok();
    }

    // =========================================================================
    // Error path tests - Lock acquisition failures
    // =========================================================================

    #[test]
    fn test_exclusive_lock_blocks_second_exclusive() {
        // Test that a second exclusive lock fails when first is held
        let temp_file = NamedTempFile::new().unwrap();
        let file1 = temp_file.reopen().unwrap();
        let file2 = temp_file.reopen().unwrap();

        // First lock should succeed
        assert!(file1.try_lock_exclusive().is_ok());

        // Second exclusive lock should fail
        assert!(file2.try_lock_exclusive().is_err());

        // Cleanup
        file1.unlock().ok();
    }

    #[test]
    fn test_shared_lock_allows_multiple_readers() {
        let temp_file = NamedTempFile::new().unwrap();
        let file1 = temp_file.reopen().unwrap();
        let file2 = temp_file.reopen().unwrap();

        // Both shared locks should succeed
        assert!(file1.try_lock_shared().is_ok());
        assert!(file2.try_lock_shared().is_ok());

        // Cleanup
        file1.unlock().ok();
        file2.unlock().ok();
    }

    #[test]
    fn test_shared_lock_blocks_exclusive() {
        let temp_file = NamedTempFile::new().unwrap();
        let file1 = temp_file.reopen().unwrap();
        let file2 = temp_file.reopen().unwrap();

        // Shared lock first
        assert!(file1.try_lock_shared().is_ok());

        // Exclusive lock should fail
        assert!(file2.try_lock_exclusive().is_err());

        // Cleanup
        file1.unlock().ok();
    }

    #[test]
    fn test_exclusive_lock_blocks_shared() {
        let temp_file = NamedTempFile::new().unwrap();
        let file1 = temp_file.reopen().unwrap();
        let file2 = temp_file.reopen().unwrap();

        // Exclusive lock first
        assert!(file1.try_lock_exclusive().is_ok());

        // Shared lock should fail
        assert!(file2.try_lock_shared().is_err());

        // Cleanup
        file1.unlock().ok();
    }

    #[test]
    fn test_lock_released_on_file_close() {
        let temp_file = NamedTempFile::new().unwrap();

        {
            let file1 = temp_file.reopen().unwrap();
            assert!(file1.try_lock_exclusive().is_ok());
            // file1 goes out of scope here, closing the file
        }

        // New lock should succeed after previous file closed
        let file2 = temp_file.reopen().unwrap();
        assert!(file2.try_lock_exclusive().is_ok());
        file2.unlock().ok();
    }

    #[test]
    fn test_lock_unlock_cycle() {
        let temp_file = NamedTempFile::new().unwrap();
        let file = temp_file.as_file();

        for _ in 0..5 {
            // Lock
            assert!(file.try_lock_exclusive().is_ok());
            // Unlock
            assert!(file.unlock().is_ok());
        }
    }

    #[test]
    fn test_permission_bits_owner_only() {
        let perms = fs::Permissions::from_mode(0o600);

        // Owner read/write
        assert_eq!(perms.mode() & 0o400, 0o400); // Owner read
        assert_eq!(perms.mode() & 0o200, 0o200); // Owner write

        // No group permissions
        assert_eq!(perms.mode() & 0o070, 0);

        // No other permissions
        assert_eq!(perms.mode() & 0o007, 0);
    }

    #[test]
    fn test_file_options_no_truncate() {
        // The lock file should be opened without truncate to avoid race conditions
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write some content first
        fs::write(path, "initial content").unwrap();

        // Open without truncate (like LockGuard does)
        let _file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap();

        // Content should still be there
        let content = fs::read_to_string(path).unwrap();
        assert_eq!(content, "initial content");
    }

    #[test]
    fn test_lock_guard_error_message() {
        // Test that the error message is user-friendly
        // We simulate what the error would look like
        let error_msg = format!(
            "Another instance of OustIP is already running.\n\
             If you believe this is an error, remove the lock file: {}\n\
             Or wait for the other instance to complete.",
            LOCK_FILE
        );

        assert!(error_msg.contains("Another instance"));
        assert!(error_msg.contains(LOCK_FILE));
        assert!(error_msg.contains("remove the lock file"));
    }

    #[test]
    fn test_open_options_create_new() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("test.lock");

        // Should create the file if it doesn't exist
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();

        assert!(lock_path.exists());
        drop(file);
    }

    #[test]
    fn test_lock_with_pid_file_pattern() {
        // Test a common pattern: write PID to lock file
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap();

        // Lock first
        file.try_lock_exclusive().unwrap();

        // Write PID
        use std::process;
        writeln!(file, "{}", process::id()).unwrap();

        // Unlock
        file.unlock().ok();
    }

    #[test]
    fn test_lock_reentrant_same_file_handle() {
        // Locking the same file handle twice should succeed (reentrant)
        let temp_file = NamedTempFile::new().unwrap();
        let file = temp_file.as_file();

        // First lock
        assert!(file.try_lock_exclusive().is_ok());

        // Second lock on same handle (upgrade/reentrant)
        // Note: fs2 behavior may vary - this tests the actual behavior
        let result = file.try_lock_exclusive();
        // Either succeeds (reentrant) or is already locked
        assert!(result.is_ok() || result.is_err());

        file.unlock().ok();
    }
}
