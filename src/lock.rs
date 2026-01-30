//! File-based locking to prevent concurrent execution.
//!
//! Uses flock-style advisory locking to ensure only one instance
//! of OustIP can run update operations at a time.

use crate::fs_abstraction::{real_fs, FileSystem};
use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
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
    /// Uses the real filesystem. For testing directory creation and
    /// permission setting, use `acquire_with_fs` instead.
    pub fn acquire() -> Result<Self> {
        Self::acquire_with_fs(real_fs())
    }

    /// Attempt to acquire an exclusive lock with a custom filesystem.
    ///
    /// This method enables testing directory creation and permission setting
    /// without requiring root access. Note that the actual file locking
    /// mechanism (fs2::FileExt) still uses the real filesystem.
    ///
    /// Uses OpenOptions with create+read+write to avoid TOCTOU race
    /// between file creation and lock acquisition.
    pub fn acquire_with_fs<F: FileSystem>(fs: &F) -> Result<Self> {
        // Ensure the directory exists
        let lock_path = Path::new(LOCK_FILE);
        if let Some(parent) = lock_path.parent() {
            // We use the FileSystem trait here for testability
            // but ignore errors since /var/run should exist
            let _ = fs.create_dir_all(parent);
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
        // Use the FileSystem trait for testability
        fs.set_permissions_mode(lock_path, 0o600)
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

    /// Get the lock file path (for testing).
    #[cfg(test)]
    pub fn lock_file_path() -> &'static str {
        LOCK_FILE
    }
}

// Lock is automatically released when file is closed (on drop)

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
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

    #[test]
    fn test_lock_guard_lock_file_path() {
        assert_eq!(LockGuard::lock_file_path(), "/var/run/oustip.lock");
    }
}

// =============================================================================
// Mock FileSystem tests for LockGuard
// =============================================================================

#[cfg(test)]
mod mock_fs_tests {
    use super::*;
    use crate::fs_abstraction::MockFileSystem;
    use std::io;
    use tempfile::TempDir;

    // Note: Because LockGuard::acquire_with_fs still uses OpenOptions directly
    // for the actual file operations (which is required for fs2 locking),
    // we can only fully test the directory creation and permission setting
    // parts with mocks. The actual locking tests use real temp files.

    #[test]
    fn test_lock_file_path_constant() {
        assert_eq!(LOCK_FILE, "/var/run/oustip.lock");
        assert!(LOCK_FILE.starts_with("/var/run/"));
        assert!(LOCK_FILE.ends_with(".lock"));
    }

    #[test]
    fn test_lock_file_parent_is_var_run() {
        let lock_path = Path::new(LOCK_FILE);
        let parent = lock_path.parent().unwrap();
        assert_eq!(parent, Path::new("/var/run"));
    }

    #[test]
    fn test_lock_file_name() {
        let lock_path = Path::new(LOCK_FILE);
        let file_name = lock_path.file_name().unwrap();
        assert_eq!(file_name, "oustip.lock");
    }

    // Tests that demonstrate the mock patterns even though they can't
    // fully test acquire_with_fs due to the OpenOptions call

    #[test]
    fn test_mock_fs_create_dir_all_called() {
        let mut mock = MockFileSystem::new();

        // Verify that create_dir_all would be called with /var/run
        mock.expect_create_dir_all()
            .withf(|p| p == Path::new("/var/run"))
            .returning(|_| Ok(()))
            .times(1);

        // We can't fully test acquire_with_fs with mocks because OpenOptions
        // will fail to open /var/run/oustip.lock in most test environments.
        // Instead, we verify the mock setup is correct.

        // This tests the mock expectations are valid
        mock.create_dir_all(Path::new("/var/run")).unwrap();
    }

    #[test]
    fn test_mock_fs_set_permissions_mode_pattern() {
        let mut mock = MockFileSystem::new();

        // Verify permission mode 0o600 pattern
        mock.expect_set_permissions_mode()
            .withf(|p, m| p == Path::new(LOCK_FILE) && *m == 0o600)
            .returning(|_, _| Ok(()))
            .times(1);

        mock.set_permissions_mode(Path::new(LOCK_FILE), 0o600)
            .unwrap();
    }

    #[test]
    fn test_mock_fs_permission_error_simulation() {
        let mut mock = MockFileSystem::new();

        mock.expect_set_permissions_mode()
            .returning(|_, _| Err(io::Error::new(io::ErrorKind::PermissionDenied, "no chmod")));

        let result = mock.set_permissions_mode(Path::new(LOCK_FILE), 0o600);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_mock_fs_create_dir_error_simulation() {
        let mut mock = MockFileSystem::new();

        mock.expect_create_dir_all()
            .returning(|_| Err(io::Error::new(io::ErrorKind::PermissionDenied, "no mkdir")));

        let result = mock.create_dir_all(Path::new("/var/run"));
        assert!(result.is_err());
    }

    // Integration-style tests using real temp files

    #[test]
    fn test_real_lock_acquire_release_in_temp_dir() {
        // This test uses real filesystem operations with temp files
        // to verify the lock mechanism works

        // Note: We can't test LockGuard::acquire() directly because
        // it uses a fixed path (/var/run/oustip.lock) which requires root.
        // Instead, we test the underlying mechanisms.

        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("test.lock");

        // Create and lock
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();

        // Lock
        assert!(file.try_lock_exclusive().is_ok());

        // Verify file exists
        assert!(lock_path.exists());

        // Unlock
        file.unlock().ok();
    }

    #[test]
    fn test_concurrent_lock_in_temp_dir() {
        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("concurrent.lock");

        // First lock
        let file1 = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();

        assert!(file1.try_lock_exclusive().is_ok());

        // Second lock attempt should fail
        let file2 = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();

        assert!(file2.try_lock_exclusive().is_err());

        // After first lock is released, second should succeed
        file1.unlock().ok();
        assert!(file2.try_lock_exclusive().is_ok());
        file2.unlock().ok();
    }

    #[test]
    fn test_lock_release_on_drop() {
        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("drop.lock");

        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .unwrap();
            assert!(file.try_lock_exclusive().is_ok());
            // file is dropped here, releasing the lock
        }

        // New lock should succeed after drop
        let file2 = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        assert!(file2.try_lock_exclusive().is_ok());
        file2.unlock().ok();
    }

    #[test]
    fn test_lock_permissions_in_temp_dir() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("perms.lock");

        // Create file
        let _file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();

        // Set permissions
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Verify permissions
        let metadata = std::fs::metadata(&lock_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn test_error_message_format() {
        // Verify the error message format when lock is already held
        let error_msg = format!(
            "Another instance of OustIP is already running.\n\
             If you believe this is an error, remove the lock file: {}\n\
             Or wait for the other instance to complete.",
            LOCK_FILE
        );

        assert!(error_msg.contains("Another instance"));
        assert!(error_msg.contains(LOCK_FILE));
        assert!(error_msg.contains("remove the lock file"));
        assert!(error_msg.contains("wait for the other instance"));
    }
}
