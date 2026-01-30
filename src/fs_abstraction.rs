//! Filesystem abstraction layer for testability
//!
//! This module provides a trait-based abstraction over filesystem operations,
//! enabling dependency injection for testing without real filesystem access.
//! Uses mockall for automatic mock generation in test builds.

use std::io;
use std::path::Path;

#[cfg(test)]
use mockall::automock;

/// Trait abstracting filesystem operations for dependency injection.
///
/// This trait allows mocking filesystem operations in tests, enabling
/// comprehensive testing of file I/O code paths without touching the
/// real filesystem.
///
/// # Example (production)
/// ```ignore
/// use oustip::fs_abstraction::{FileSystem, real_fs};
///
/// let content = real_fs().read_to_string(Path::new("/etc/oustip/config.yaml"))?;
/// ```
///
/// # Example (testing)
/// ```ignore
/// use oustip::fs_abstraction::MockFileSystem;
/// use std::path::Path;
///
/// let mut mock_fs = MockFileSystem::new();
/// mock_fs.expect_read_to_string()
///     .returning(|_| Ok("test content".to_string()));
/// ```
#[cfg_attr(test, automock)]
pub trait FileSystem: Send + Sync {
    /// Read file contents as a string.
    fn read_to_string(&self, path: &Path) -> io::Result<String>;

    /// Write bytes to a file, creating it if it doesn't exist.
    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()>;

    /// Check if a path exists.
    fn exists(&self, path: &Path) -> bool;

    /// Create a directory and all parent directories.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;

    /// Copy a file from one location to another.
    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64>;

    /// Remove a file.
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// Set Unix file permissions mode (e.g., 0o600).
    fn set_permissions_mode(&self, path: &Path, mode: u32) -> io::Result<()>;

    /// Read file contents as bytes.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Get file metadata.
    fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata>;
}

/// Real filesystem implementation using std::fs.
///
/// This is the production implementation that performs actual
/// filesystem operations.
#[derive(Default, Clone, Copy)]
pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        std::fs::write(path, contents)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
        std::fs::copy(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn set_permissions_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        std::fs::metadata(path)
    }
}

/// Global filesystem instance for production use.
///
/// This static instance avoids allocation overhead for the common case.
static REAL_FS: RealFileSystem = RealFileSystem;

/// Get a reference to the global real filesystem instance.
///
/// Use this function to obtain a filesystem instance for production code.
/// For testing, create a `MockFileSystem` instead.
pub fn real_fs() -> &'static RealFileSystem {
    &REAL_FS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tempfile::TempDir;

    #[test]
    fn test_real_fs_read_write() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let fs = RealFileSystem;

        // Write
        fs.write(&file_path, b"hello world").unwrap();

        // Read
        let content = fs.read_to_string(&file_path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_real_fs_exists() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let fs = RealFileSystem;

        assert!(!fs.exists(&file_path));

        fs.write(&file_path, b"test").unwrap();

        assert!(fs.exists(&file_path));
    }

    #[test]
    fn test_real_fs_create_dir_all() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("a/b/c");

        let fs = RealFileSystem;

        assert!(!fs.exists(&nested_path));

        fs.create_dir_all(&nested_path).unwrap();

        assert!(fs.exists(&nested_path));
    }

    #[test]
    fn test_real_fs_copy() {
        let temp_dir = TempDir::new().unwrap();
        let src = temp_dir.path().join("src.txt");
        let dst = temp_dir.path().join("dst.txt");

        let fs = RealFileSystem;

        fs.write(&src, b"copy me").unwrap();
        let bytes_copied = fs.copy(&src, &dst).unwrap();

        assert_eq!(bytes_copied, 7);
        assert_eq!(fs.read_to_string(&dst).unwrap(), "copy me");
    }

    #[test]
    fn test_real_fs_remove_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("to_remove.txt");

        let fs = RealFileSystem;

        fs.write(&file_path, b"remove me").unwrap();
        assert!(fs.exists(&file_path));

        fs.remove_file(&file_path).unwrap();
        assert!(!fs.exists(&file_path));
    }

    #[test]
    fn test_real_fs_set_permissions_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("perms.txt");

        let fs = RealFileSystem;

        fs.write(&file_path, b"secure").unwrap();
        fs.set_permissions_mode(&file_path, 0o600).unwrap();

        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn test_real_fs_read_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("binary.bin");

        let fs = RealFileSystem;

        let binary_data = vec![0u8, 1, 2, 3, 255, 254, 253];
        fs.write(&file_path, &binary_data).unwrap();

        let read_data = fs.read(&file_path).unwrap();
        assert_eq!(read_data, binary_data);
    }

    #[test]
    fn test_real_fs_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("meta.txt");

        let fs = RealFileSystem;

        fs.write(&file_path, b"metadata test").unwrap();

        let metadata = fs.metadata(&file_path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), 13);
    }

    #[test]
    fn test_real_fs_read_nonexistent() {
        let fs = RealFileSystem;
        let result = fs.read_to_string(Path::new("/nonexistent/path/file.txt"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_real_fs_write_to_nonexistent_dir() {
        let fs = RealFileSystem;
        let result = fs.write(Path::new("/nonexistent/path/file.txt"), b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_real_fs_copy_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let fs = RealFileSystem;

        let result = fs.copy(
            Path::new("/nonexistent/source.txt"),
            &temp_dir.path().join("dst.txt"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_real_fs_remove_nonexistent() {
        let fs = RealFileSystem;
        let result = fs.remove_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_real_fs_static_instance() {
        let fs = real_fs();
        // Should be able to use the static instance
        assert!(!fs.exists(Path::new("/nonexistent/path")));
    }

    #[test]
    fn test_real_fs_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RealFileSystem>();
    }

    #[test]
    fn test_mock_fs_read_to_string() {
        let mut mock = MockFileSystem::new();
        mock.expect_read_to_string()
            .withf(|p| p == Path::new("/test/file.txt"))
            .returning(|_| Ok("mocked content".to_string()));

        let content = mock.read_to_string(Path::new("/test/file.txt")).unwrap();
        assert_eq!(content, "mocked content");
    }

    #[test]
    fn test_mock_fs_error_simulation() {
        let mut mock = MockFileSystem::new();
        mock.expect_read_to_string().returning(|_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "access denied",
            ))
        });

        let result = mock.read_to_string(Path::new("/any/path"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_mock_fs_exists() {
        let mut mock = MockFileSystem::new();
        mock.expect_exists()
            .withf(|p| p == Path::new("/exists"))
            .returning(|_| true);
        mock.expect_exists()
            .withf(|p| p == Path::new("/not_exists"))
            .returning(|_| false);

        assert!(mock.exists(Path::new("/exists")));
        assert!(!mock.exists(Path::new("/not_exists")));
    }

    #[test]
    fn test_mock_fs_write() {
        let mut mock = MockFileSystem::new();
        mock.expect_write()
            .withf(|p, c| p == Path::new("/test.txt") && c == b"hello")
            .returning(|_, _| Ok(()));

        mock.write(Path::new("/test.txt"), b"hello").unwrap();
    }

    #[test]
    fn test_mock_fs_create_dir_all() {
        let mut mock = MockFileSystem::new();
        mock.expect_create_dir_all()
            .withf(|p| p == Path::new("/a/b/c"))
            .returning(|_| Ok(()));

        mock.create_dir_all(Path::new("/a/b/c")).unwrap();
    }

    #[test]
    fn test_mock_fs_copy() {
        let mut mock = MockFileSystem::new();
        mock.expect_copy()
            .withf(|from, to| from == Path::new("/src") && to == Path::new("/dst"))
            .returning(|_, _| Ok(100));

        let bytes = mock.copy(Path::new("/src"), Path::new("/dst")).unwrap();
        assert_eq!(bytes, 100);
    }

    #[test]
    fn test_mock_fs_remove_file() {
        let mut mock = MockFileSystem::new();
        mock.expect_remove_file()
            .withf(|p| p == Path::new("/to_remove"))
            .returning(|_| Ok(()));

        mock.remove_file(Path::new("/to_remove")).unwrap();
    }

    #[test]
    fn test_mock_fs_set_permissions_mode() {
        let mut mock = MockFileSystem::new();
        mock.expect_set_permissions_mode()
            .withf(|p, m| p == Path::new("/file") && *m == 0o600)
            .returning(|_, _| Ok(()));

        mock.set_permissions_mode(Path::new("/file"), 0o600)
            .unwrap();
    }

    #[test]
    fn test_mock_fs_sequence() {
        use mockall::Sequence;

        let mut mock = MockFileSystem::new();
        let mut seq = Sequence::new();

        mock.expect_exists()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| false);

        mock.expect_write()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));

        mock.expect_exists()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| true);

        // Simulate: check if exists, write, check again
        assert!(!mock.exists(Path::new("/test")));
        mock.write(Path::new("/test"), b"data").unwrap();
        assert!(mock.exists(Path::new("/test")));
    }

    #[test]
    fn test_mock_fs_multiple_calls() {
        let mut mock = MockFileSystem::new();

        // Allow any number of calls
        mock.expect_exists().returning(|_| true);

        assert!(mock.exists(Path::new("/a")));
        assert!(mock.exists(Path::new("/b")));
        assert!(mock.exists(Path::new("/c")));
    }
}
