//! Error types for OustIP.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OustipError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Firewall error: {0}")]
    Firewall(String),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("File system error: {0}")]
    FileSystem(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Not installed: {0}")]
    NotInstalled(String),

    #[error("Already installed")]
    AlreadyInstalled,

    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),
}
