//! Signal handling for graceful shutdown.
//!
//! Provides a mechanism to handle SIGINT and SIGTERM signals
//! for clean shutdown during long-running operations.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;

/// Global flag indicating whether a shutdown has been requested.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Check if shutdown has been requested.
#[inline]
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

/// Request a shutdown (can be called from signal handlers or tests).
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

/// Reset shutdown flag (mainly for testing).
#[cfg(test)]
pub fn reset_shutdown() {
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
}

/// A guard that manages signal handlers for graceful shutdown.
/// When created, it spawns a task that listens for SIGINT and SIGTERM.
pub struct ShutdownGuard {
    _marker: (),
}

impl ShutdownGuard {
    /// Create a new shutdown guard and start listening for signals.
    ///
    /// If signal handlers cannot be registered (e.g., in restricted environments),
    /// the guard is still created but signal handling will be disabled.
    pub fn new() -> Self {
        // Spawn signal handler task
        tokio::spawn(async move {
            // Try to register signal handlers - may fail in containers or restricted envs
            let sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("Failed to register SIGINT handler: {}", e);
                    None
                }
            };

            let sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("Failed to register SIGTERM handler: {}", e);
                    None
                }
            };

            // Only proceed if at least one handler was registered
            match (sigint, sigterm) {
                (Some(mut int), Some(mut term)) => {
                    tokio::select! {
                        _ = int.recv() => {
                            info!("Received SIGINT, initiating graceful shutdown...");
                            request_shutdown();
                        }
                        _ = term.recv() => {
                            info!("Received SIGTERM, initiating graceful shutdown...");
                            request_shutdown();
                        }
                    }
                }
                (Some(mut int), None) => {
                    int.recv().await;
                    info!("Received SIGINT, initiating graceful shutdown...");
                    request_shutdown();
                }
                (None, Some(mut term)) => {
                    term.recv().await;
                    info!("Received SIGTERM, initiating graceful shutdown...");
                    request_shutdown();
                }
                (None, None) => {
                    tracing::warn!("No signal handlers registered - graceful shutdown disabled");
                }
            }
        });

        Self { _marker: () }
    }
}

impl Default for ShutdownGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// A token that can be shared across tasks to check for shutdown.
#[derive(Clone)]
pub struct ShutdownToken {
    flag: Arc<AtomicBool>,
}

impl ShutdownToken {
    /// Create a new shutdown token.
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check if shutdown has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed) || is_shutdown_requested()
    }

    /// Request cancellation on this token.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_flag() {
        reset_shutdown();
        assert!(!is_shutdown_requested());
        request_shutdown();
        assert!(is_shutdown_requested());
        reset_shutdown();
    }

    #[test]
    fn test_shutdown_token() {
        let token = ShutdownToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_shutdown_token_clone() {
        let token1 = ShutdownToken::new();
        let token2 = token1.clone();

        assert!(!token1.is_cancelled());
        assert!(!token2.is_cancelled());

        token1.cancel();

        assert!(token1.is_cancelled());
        assert!(token2.is_cancelled());
    }

    #[test]
    fn test_shutdown_token_default() {
        let token = ShutdownToken::default();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn test_shutdown_token_inherits_global() {
        reset_shutdown();
        let token = ShutdownToken::new();
        assert!(!token.is_cancelled());

        request_shutdown();
        assert!(token.is_cancelled());

        reset_shutdown();
    }

    #[test]
    fn test_multiple_cancels() {
        let token = ShutdownToken::new();
        token.cancel();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_reset_global_shutdown() {
        // Reset first in case another test set it
        reset_shutdown();
        assert!(!is_shutdown_requested());
        request_shutdown();
        assert!(is_shutdown_requested());
        reset_shutdown();
        assert!(!is_shutdown_requested());
    }
}
