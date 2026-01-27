//! Firewall enforcement backends (iptables, nftables).

mod iptables;
mod nftables;

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use std::process::Command;

pub use iptables::IptablesBackend;
pub use nftables::NftablesBackend;

use crate::config::{Backend, FilterMode};

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

/// Execute a command and return output
pub(crate) fn exec_cmd(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute {}", program))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{} failed: {}", program, stderr)
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

    impl MockBackend {
        pub fn new() -> Self {
            Self {
                applied_ips: Mutex::new(Vec::new()),
                active: Mutex::new(false),
            }
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
