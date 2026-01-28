//! Firewall enforcement backends (iptables, nftables).

mod iptables;
mod nftables;

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use std::process::Command;
use tracing::warn;

pub use iptables::IptablesBackend;
pub use nftables::NftablesBackend;

use crate::config::{Backend, FilterMode};

/// Warning threshold for large blocklists (500k entries)
const WARN_SET_ENTRIES: usize = 500_000;

/// Warning threshold for very large blocklists (2M entries)
const LARGE_SET_ENTRIES: usize = 2_000_000;

/// Log warnings for large blocklists but allow all sizes
/// Note: No hard limit - all presets must work (including paranoid)
pub fn validate_entry_count(count: usize) -> Result<()> {
    if count > LARGE_SET_ENTRIES {
        warn!(
            "Very large blocklist: {} entries. Estimated kernel memory: ~{} MB. \
             Ensure your system has sufficient memory.",
            count,
            (count * 32) / (1024 * 1024)
        );
    } else if count > WARN_SET_ENTRIES {
        warn!(
            "Large blocklist: {} entries. Estimated kernel memory: ~{} MB",
            count,
            (count * 32) / (1024 * 1024)
        );
    }

    Ok(())
}

/// Statistics from the firewall
#[derive(Debug, Default, Clone)]
pub struct FirewallStats {
    pub packets_blocked: u64,
    pub bytes_blocked: u64,
}

/// Trait for firewall backends
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Apply blocklist rules
    async fn apply_rules(&self, ips: &[IpNet], mode: FilterMode) -> Result<()>;

    /// Remove all OustIP rules (keep other rules intact)
    async fn remove_rules(&self) -> Result<()>;

    /// Get blocking statistics
    async fn get_stats(&self) -> Result<FirewallStats>;

    /// Check if an IP would be blocked
    async fn is_blocked(&self, ip: &IpNet) -> Result<bool>;

    /// Check if OustIP rules are active
    async fn is_active(&self) -> Result<bool>;

    /// Get the number of entries in the blocklist
    async fn entry_count(&self) -> Result<usize>;
}

/// Detect available firewall backend
pub fn detect_backend() -> Result<Backend> {
    // Check nftables first (preferred)
    if Command::new("nft").arg("--version").output().is_ok() {
        return Ok(Backend::Nftables);
    }

    // Fall back to iptables
    if Command::new("iptables").arg("--version").output().is_ok() {
        return Ok(Backend::Iptables);
    }

    anyhow::bail!("No firewall backend available (nft or iptables required)")
}

/// Get the display name for a backend configuration
/// Returns "nftables (auto)" or "iptables (auto)" when auto-detected,
/// or just "nftables"/"iptables" for explicit configuration
pub fn get_backend_display_name(backend: Backend) -> &'static str {
    match backend {
        Backend::Auto => {
            if Command::new("nft").arg("--version").output().is_ok() {
                "nftables (auto)"
            } else {
                "iptables (auto)"
            }
        }
        Backend::Iptables => "iptables",
        Backend::Nftables => "nftables",
    }
}

/// Create a firewall backend based on configuration
pub fn create_backend(backend: Backend) -> Result<Box<dyn FirewallBackend>> {
    let actual_backend = match backend {
        Backend::Auto => detect_backend()?,
        other => other,
    };

    match actual_backend {
        Backend::Nftables => Ok(Box::new(NftablesBackend::new())),
        Backend::Iptables => Ok(Box::new(IptablesBackend::new())),
        Backend::Auto => unreachable!(),
    }
}

/// Command execution timeout in seconds
const CMD_TIMEOUT_SECS: u64 = 30;

/// Execute a command with timeout and return output
pub(crate) fn exec_cmd(program: &str, args: &[&str]) -> Result<String> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let timeout = Duration::from_secs(CMD_TIMEOUT_SECS);

    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn {}", program))?;

    // Wait with timeout
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process completed
                let output = child.wait_with_output()?;
                if status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).to_string());
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("{} failed: {}", program, stderr);
                }
            }
            Ok(None) => {
                // Still running, check timeout
                if start.elapsed() > timeout {
                    // Kill the process
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!("{} timed out after {} seconds", program, CMD_TIMEOUT_SECS);
                }
                // Brief sleep to avoid busy-waiting
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                anyhow::bail!("Error waiting for {}: {}", program, e);
            }
        }
    }
}

/// Check if running as root (effective UID == 0)
///
/// This check verifies that the process has the necessary privileges to
/// manipulate firewall rules. While capability-based checks would be more
/// precise (CAP_NET_ADMIN, CAP_NET_RAW), UID 0 check is simpler and covers
/// the common case of running with sudo.
pub fn check_root() -> Result<()> {
    // SAFETY: geteuid() is a simple syscall that reads the effective user ID.
    // It has no preconditions, never fails, and doesn't modify any state.
    // The returned value is a plain integer that's safe to compare.
    let euid = unsafe { libc::geteuid() };

    if euid != 0 {
        anyhow::bail!(
            "This operation requires root privileges. Please run with sudo.\n\
             Alternatively, ensure the process has CAP_NET_ADMIN and CAP_NET_RAW capabilities."
        )
    }
    Ok(())
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    /// Mock backend for testing
    pub struct MockBackend {
        pub applied_ips: Mutex<Vec<IpNet>>,
        pub active: Mutex<bool>,
    }

    impl Default for MockBackend {
        fn default() -> Self {
            Self {
                applied_ips: Mutex::new(Vec::new()),
                active: Mutex::new(false),
            }
        }
    }

    impl MockBackend {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl FirewallBackend for MockBackend {
        async fn apply_rules(&self, ips: &[IpNet], _mode: FilterMode) -> Result<()> {
            let mut guard = self.applied_ips.lock().unwrap();
            guard.clear();
            guard.extend(ips.iter().cloned());
            *self.active.lock().unwrap() = true;
            Ok(())
        }

        async fn remove_rules(&self) -> Result<()> {
            self.applied_ips.lock().unwrap().clear();
            *self.active.lock().unwrap() = false;
            Ok(())
        }

        async fn get_stats(&self) -> Result<FirewallStats> {
            Ok(FirewallStats::default())
        }

        async fn is_blocked(&self, ip: &IpNet) -> Result<bool> {
            let guard = self.applied_ips.lock().unwrap();
            let result = guard.iter().any(|blocked| match (blocked, ip) {
                (IpNet::V4(b), IpNet::V4(i)) => b.contains(i),
                (IpNet::V6(b), IpNet::V6(i)) => b.contains(i),
                _ => false,
            });
            Ok(result)
        }

        async fn is_active(&self) -> Result<bool> {
            let result = *self.active.lock().unwrap();
            Ok(result)
        }

        async fn entry_count(&self) -> Result<usize> {
            let result = self.applied_ips.lock().unwrap().len();
            Ok(result)
        }
    }
}
