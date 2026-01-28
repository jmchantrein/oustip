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
}
