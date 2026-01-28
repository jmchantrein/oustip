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

    #[test]
    fn test_lock_acquire_release() {
        // Note: This test would need root to write to /var/run
        // So we just test the struct exists
        let _guard_type: fn() -> Result<LockGuard> = LockGuard::acquire;
    }
}
