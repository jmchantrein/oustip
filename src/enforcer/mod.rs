//! Firewall enforcement backends (iptables, nftables).

mod iptables;
mod nftables;

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use tracing::warn;

pub use iptables::IptablesBackend;
pub use nftables::NftablesBackend;

use crate::cmd_abstraction::{args_to_strings, CommandExecutor};
use crate::config::{Backend, FilterMode};

// Default paths for firewall commands (most distros use /usr/sbin)
const NFT_PATH_USR_SBIN: &str = "/usr/sbin/nft";
const NFT_PATH_SBIN: &str = "/sbin/nft";
const IPTABLES_PATH_USR_SBIN: &str = "/usr/sbin/iptables";
const IPTABLES_PATH_SBIN: &str = "/sbin/iptables";
const IP6TABLES_PATH_USR_SBIN: &str = "/usr/sbin/ip6tables";
const IP6TABLES_PATH_SBIN: &str = "/sbin/ip6tables";
const IPSET_PATH_USR_SBIN: &str = "/usr/sbin/ipset";
const IPSET_PATH_SBIN: &str = "/sbin/ipset";
const IPTABLES_SAVE_PATH_USR_SBIN: &str = "/usr/sbin/iptables-save";
const IPTABLES_SAVE_PATH_SBIN: &str = "/sbin/iptables-save";
const IP6TABLES_SAVE_PATH_USR_SBIN: &str = "/usr/sbin/ip6tables-save";
const IP6TABLES_SAVE_PATH_SBIN: &str = "/sbin/ip6tables-save";
const IPTABLES_RESTORE_PATH_USR_SBIN: &str = "/usr/sbin/iptables-restore";
const IPTABLES_RESTORE_PATH_SBIN: &str = "/sbin/iptables-restore";
const IP6TABLES_RESTORE_PATH_USR_SBIN: &str = "/usr/sbin/ip6tables-restore";
const IP6TABLES_RESTORE_PATH_SBIN: &str = "/sbin/ip6tables-restore";

// Static storage for resolved command paths
static NFT_PATH: OnceLock<&'static str> = OnceLock::new();
static IPTABLES_PATH: OnceLock<&'static str> = OnceLock::new();
static IP6TABLES_PATH: OnceLock<&'static str> = OnceLock::new();
static IPSET_PATH: OnceLock<&'static str> = OnceLock::new();
static IPTABLES_SAVE_PATH: OnceLock<&'static str> = OnceLock::new();
static IP6TABLES_SAVE_PATH: OnceLock<&'static str> = OnceLock::new();
static IPTABLES_RESTORE_PATH: OnceLock<&'static str> = OnceLock::new();
static IP6TABLES_RESTORE_PATH: OnceLock<&'static str> = OnceLock::new();

/// Find the absolute path for a command, checking /usr/sbin first, then /sbin.
/// Falls back to the bare command name if neither exists (relies on PATH).
fn find_command(name: &str, usr_sbin_path: &str, sbin_path: &str) -> &'static str {
    if Path::new(usr_sbin_path).exists() {
        return usr_sbin_path.to_string().leak();
    }
    if Path::new(sbin_path).exists() {
        return sbin_path.to_string().leak();
    }
    // Fallback to PATH-based lookup
    name.to_string().leak()
}

/// Get the absolute path for nft command
pub(crate) fn nft_path() -> &'static str {
    NFT_PATH.get_or_init(|| find_command("nft", NFT_PATH_USR_SBIN, NFT_PATH_SBIN))
}

/// Get the absolute path for iptables command
pub(crate) fn iptables_path() -> &'static str {
    IPTABLES_PATH
        .get_or_init(|| find_command("iptables", IPTABLES_PATH_USR_SBIN, IPTABLES_PATH_SBIN))
}

/// Get the absolute path for ip6tables command
pub(crate) fn ip6tables_path() -> &'static str {
    IP6TABLES_PATH
        .get_or_init(|| find_command("ip6tables", IP6TABLES_PATH_USR_SBIN, IP6TABLES_PATH_SBIN))
}

/// Get the absolute path for ipset command
pub(crate) fn ipset_path() -> &'static str {
    IPSET_PATH.get_or_init(|| find_command("ipset", IPSET_PATH_USR_SBIN, IPSET_PATH_SBIN))
}

/// Get the absolute path for iptables-save command
pub(crate) fn iptables_save_path() -> &'static str {
    IPTABLES_SAVE_PATH.get_or_init(|| {
        find_command(
            "iptables-save",
            IPTABLES_SAVE_PATH_USR_SBIN,
            IPTABLES_SAVE_PATH_SBIN,
        )
    })
}

/// Get the absolute path for ip6tables-save command
pub(crate) fn ip6tables_save_path() -> &'static str {
    IP6TABLES_SAVE_PATH.get_or_init(|| {
        find_command(
            "ip6tables-save",
            IP6TABLES_SAVE_PATH_USR_SBIN,
            IP6TABLES_SAVE_PATH_SBIN,
        )
    })
}

/// Get the absolute path for iptables-restore command
pub(crate) fn iptables_restore_path() -> &'static str {
    IPTABLES_RESTORE_PATH.get_or_init(|| {
        find_command(
            "iptables-restore",
            IPTABLES_RESTORE_PATH_USR_SBIN,
            IPTABLES_RESTORE_PATH_SBIN,
        )
    })
}

/// Get the absolute path for ip6tables-restore command
pub(crate) fn ip6tables_restore_path() -> &'static str {
    IP6TABLES_RESTORE_PATH.get_or_init(|| {
        find_command(
            "ip6tables-restore",
            IP6TABLES_RESTORE_PATH_USR_SBIN,
            IP6TABLES_RESTORE_PATH_SBIN,
        )
    })
}

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

    /// Save current ruleset for potential rollback
    /// Returns a string representation of the current rules that can be restored later
    async fn save_current_rules(&self) -> Result<String>;

    /// Restore previously saved ruleset
    /// Takes the saved rules string from save_current_rules and restores them
    async fn restore_rules(&self, saved_rules: &str) -> Result<()>;
}

/// Detect available firewall backend
pub fn detect_backend() -> Result<Backend> {
    // Check nftables first (preferred)
    if Command::new(nft_path()).arg("--version").output().is_ok() {
        return Ok(Backend::Nftables);
    }

    // Fall back to iptables
    if Command::new(iptables_path())
        .arg("--version")
        .output()
        .is_ok()
    {
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
            if Command::new(nft_path()).arg("--version").output().is_ok() {
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

/// Execute a command using an injected CommandExecutor.
///
/// This function enables dependency injection for testing, allowing tests
/// to mock command execution without actually running system commands.
pub(crate) fn exec_cmd_with_executor<E: CommandExecutor>(
    executor: &E,
    cmd: &str,
    args: &[&str],
) -> Result<String> {
    let args_vec = args_to_strings(args);
    let output = executor.execute(cmd, &args_vec)?;
    if output.success {
        Ok(output.stdout)
    } else {
        anyhow::bail!("{} failed: {}", cmd, output.stderr)
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
    #[allow(dead_code)]
    pub struct MockBackend {
        pub applied_ips: Mutex<Vec<IpNet>>,
        pub active: Mutex<bool>,
        pub saved_rules: Mutex<Option<String>>,
        pub should_fail_apply: Mutex<bool>,
    }

    impl Default for MockBackend {
        fn default() -> Self {
            Self {
                applied_ips: Mutex::new(Vec::new()),
                active: Mutex::new(false),
                saved_rules: Mutex::new(None),
                should_fail_apply: Mutex::new(false),
            }
        }
    }

    impl MockBackend {
        #[allow(dead_code)]
        pub fn new() -> Self {
            Self::default()
        }

        /// Set whether apply_rules should fail (for testing rollback)
        #[allow(dead_code)]
        pub fn set_should_fail_apply(&self, should_fail: bool) {
            *self.should_fail_apply.lock().unwrap() = should_fail;
        }
    }

    #[async_trait]
    impl FirewallBackend for MockBackend {
        async fn apply_rules(&self, ips: &[IpNet], _mode: FilterMode) -> Result<()> {
            // Check if we should simulate failure
            if *self.should_fail_apply.lock().unwrap() {
                anyhow::bail!("Simulated apply failure for testing");
            }

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

        async fn save_current_rules(&self) -> Result<String> {
            let guard = self.applied_ips.lock().unwrap();
            let ips_str: Vec<String> = guard.iter().map(|ip| ip.to_string()).collect();
            let saved = ips_str.join(",");
            *self.saved_rules.lock().unwrap() = Some(saved.clone());
            Ok(saved)
        }

        async fn restore_rules(&self, saved_rules: &str) -> Result<()> {
            let mut guard = self.applied_ips.lock().unwrap();
            guard.clear();

            if !saved_rules.is_empty() {
                for ip_str in saved_rules.split(',') {
                    if let Ok(ip) = ip_str.parse::<IpNet>() {
                        guard.push(ip);
                    }
                }
            }

            *self.active.lock().unwrap() = !guard.is_empty();
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn test_mock_save_current_rules() {
            let backend = MockBackend::new();

            // Apply some rules
            let ips: Vec<IpNet> = vec![
                "192.168.1.0/24".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
            ];
            backend
                .apply_rules(&ips, FilterMode::Conntrack)
                .await
                .unwrap();

            // Save the rules
            let saved = backend.save_current_rules().await.unwrap();

            // Verify saved rules contain the IPs
            assert!(saved.contains("192.168.1.0/24"));
            assert!(saved.contains("10.0.0.0/8"));
        }

        #[tokio::test]
        async fn test_mock_restore_rules() {
            let backend = MockBackend::new();

            // Restore from a saved string
            let saved = "192.168.1.0/24,10.0.0.0/8";
            backend.restore_rules(saved).await.unwrap();

            // Verify rules were restored
            assert_eq!(backend.entry_count().await.unwrap(), 2);
            assert!(backend.is_active().await.unwrap());
        }

        #[tokio::test]
        async fn test_mock_restore_empty_rules() {
            let backend = MockBackend::new();

            // Apply some rules first
            let ips: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
            backend
                .apply_rules(&ips, FilterMode::Conntrack)
                .await
                .unwrap();

            // Restore empty rules (should clear)
            backend.restore_rules("").await.unwrap();

            // Verify rules were cleared
            assert_eq!(backend.entry_count().await.unwrap(), 0);
            assert!(!backend.is_active().await.unwrap());
        }

        #[tokio::test]
        async fn test_mock_rollback_on_failure() {
            let backend = MockBackend::new();

            // Apply initial rules
            let initial_ips: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
            backend
                .apply_rules(&initial_ips, FilterMode::Conntrack)
                .await
                .unwrap();

            // Save current rules
            let saved = backend.save_current_rules().await.unwrap();

            // Enable failure mode
            backend.set_should_fail_apply(true);

            // Try to apply new rules (should fail)
            let new_ips: Vec<IpNet> = vec!["192.168.0.0/16".parse().unwrap()];
            let result = backend.apply_rules(&new_ips, FilterMode::Conntrack).await;
            assert!(result.is_err());

            // Restore previous rules
            backend.restore_rules(&saved).await.unwrap();

            // Verify original rules are restored
            assert_eq!(backend.entry_count().await.unwrap(), 1);
            assert!(backend
                .is_blocked(&"10.0.0.1/32".parse().unwrap())
                .await
                .unwrap());
        }

        #[tokio::test]
        async fn test_mock_save_restore_ipv6() {
            let backend = MockBackend::new();

            // Apply IPv6 rules
            let ips: Vec<IpNet> = vec![
                "2001:db8::/32".parse().unwrap(),
                "fe80::/10".parse().unwrap(),
            ];
            backend
                .apply_rules(&ips, FilterMode::Conntrack)
                .await
                .unwrap();

            // Save and restore
            let saved = backend.save_current_rules().await.unwrap();
            backend.remove_rules().await.unwrap();
            backend.restore_rules(&saved).await.unwrap();

            // Verify IPv6 rules restored
            assert_eq!(backend.entry_count().await.unwrap(), 2);
        }
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    // =========================================================================
    // validate_entry_count tests
    // =========================================================================

    #[test]
    fn test_validate_entry_count_small() {
        // Small entry counts should always be OK
        assert!(validate_entry_count(0).is_ok());
        assert!(validate_entry_count(100).is_ok());
        assert!(validate_entry_count(1000).is_ok());
        assert!(validate_entry_count(100_000).is_ok());
    }

    #[test]
    fn test_validate_entry_count_at_warning_threshold() {
        // Should pass but log warning
        assert!(validate_entry_count(WARN_SET_ENTRIES).is_ok());
        assert!(validate_entry_count(WARN_SET_ENTRIES + 1).is_ok());
    }

    #[test]
    fn test_validate_entry_count_at_large_threshold() {
        // Should pass but log different warning
        assert!(validate_entry_count(LARGE_SET_ENTRIES).is_ok());
        assert!(validate_entry_count(LARGE_SET_ENTRIES + 1).is_ok());
    }

    #[test]
    fn test_validate_entry_count_extreme() {
        // Even very large counts should pass (no hard limit)
        assert!(validate_entry_count(10_000_000).is_ok());
        assert!(validate_entry_count(100_000_000).is_ok());
    }

    // =========================================================================
    // Constants tests
    // =========================================================================

    #[test]
    fn test_warn_threshold_constant() {
        assert_eq!(WARN_SET_ENTRIES, 500_000);
    }

    #[test]
    fn test_large_threshold_constant() {
        assert_eq!(LARGE_SET_ENTRIES, 2_000_000);
    }

    #[test]
    fn test_cmd_timeout_constant() {
        assert_eq!(CMD_TIMEOUT_SECS, 30);
    }

    // Const assertion for threshold ordering
    const _: () = {
        assert!(LARGE_SET_ENTRIES > WARN_SET_ENTRIES);
    };

    // =========================================================================
    // Path constants tests
    // =========================================================================

    #[test]
    fn test_nft_paths_valid() {
        assert!(NFT_PATH_USR_SBIN.starts_with("/usr/sbin/"));
        assert!(NFT_PATH_SBIN.starts_with("/sbin/"));
    }

    #[test]
    fn test_iptables_paths_valid() {
        assert!(IPTABLES_PATH_USR_SBIN.starts_with("/usr/sbin/"));
        assert!(IPTABLES_PATH_SBIN.starts_with("/sbin/"));
        assert!(IP6TABLES_PATH_USR_SBIN.starts_with("/usr/sbin/"));
        assert!(IP6TABLES_PATH_SBIN.starts_with("/sbin/"));
    }

    #[test]
    fn test_ipset_paths_valid() {
        assert!(IPSET_PATH_USR_SBIN.starts_with("/usr/sbin/"));
        assert!(IPSET_PATH_SBIN.starts_with("/sbin/"));
    }

    #[test]
    fn test_save_restore_paths_valid() {
        assert!(IPTABLES_SAVE_PATH_USR_SBIN.contains("iptables-save"));
        assert!(IPTABLES_RESTORE_PATH_USR_SBIN.contains("iptables-restore"));
        assert!(IP6TABLES_SAVE_PATH_USR_SBIN.contains("ip6tables-save"));
        assert!(IP6TABLES_RESTORE_PATH_USR_SBIN.contains("ip6tables-restore"));
    }

    // =========================================================================
    // FirewallStats tests
    // =========================================================================

    #[test]
    fn test_firewall_stats_default() {
        let stats = FirewallStats::default();
        assert_eq!(stats.packets_blocked, 0);
        assert_eq!(stats.bytes_blocked, 0);
    }

    #[test]
    fn test_firewall_stats_clone() {
        let stats = FirewallStats {
            packets_blocked: 1000,
            bytes_blocked: 50000,
        };
        let cloned = stats.clone();
        assert_eq!(cloned.packets_blocked, stats.packets_blocked);
        assert_eq!(cloned.bytes_blocked, stats.bytes_blocked);
    }

    #[test]
    fn test_firewall_stats_debug() {
        let stats = FirewallStats {
            packets_blocked: 42,
            bytes_blocked: 1337,
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("42"));
        assert!(debug_str.contains("1337"));
    }

    // =========================================================================
    // Backend enum tests
    // =========================================================================

    #[test]
    fn test_backend_display_names() {
        // Note: These tests would need actual nft/iptables installed
        // Here we test the logic without actually running commands

        // When explicitly configured, display name is simple
        let name = match Backend::Nftables {
            Backend::Auto => panic!("Should not be Auto"),
            Backend::Iptables => "iptables",
            Backend::Nftables => "nftables",
        };
        assert_eq!(name, "nftables");

        let name = match Backend::Iptables {
            Backend::Auto => panic!("Should not be Auto"),
            Backend::Iptables => "iptables",
            Backend::Nftables => "nftables",
        };
        assert_eq!(name, "iptables");
    }

    // =========================================================================
    // Memory estimation tests
    // =========================================================================

    #[test]
    fn test_memory_estimation_formula() {
        // Test the memory estimation formula used in warnings
        // ~32 bytes per entry
        let count = 1_000_000usize;
        let estimated_mb = (count * 32) / (1024 * 1024);
        assert!(estimated_mb > 0);
        assert!(estimated_mb < 100); // Should be around 30MB
    }

    #[test]
    fn test_memory_estimation_large() {
        let count = LARGE_SET_ENTRIES;
        let estimated_mb = (count * 32) / (1024 * 1024);
        // 2M entries * 32 bytes = 64MB
        assert!((60..=70).contains(&estimated_mb));
    }

    // =========================================================================
    // Mock backend comprehensive tests
    // =========================================================================

    #[tokio::test]
    async fn test_mock_backend_ipv4_containment() {
        let backend = mock::MockBackend::new();

        // Apply a /24 network
        let ips: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
        backend
            .apply_rules(&ips, FilterMode::Conntrack)
            .await
            .unwrap();

        // Single IP within the /24 should be blocked
        assert!(backend
            .is_blocked(&"192.168.1.100/32".parse().unwrap())
            .await
            .unwrap());
        // IP outside the /24 should not be blocked
        assert!(!backend
            .is_blocked(&"192.168.2.100/32".parse().unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_mock_backend_ipv6_containment() {
        let backend = mock::MockBackend::new();

        let ips: Vec<IpNet> = vec!["2001:db8::/32".parse().unwrap()];
        backend
            .apply_rules(&ips, FilterMode::Conntrack)
            .await
            .unwrap();

        // Address within the /32 should be blocked
        assert!(backend
            .is_blocked(&"2001:db8:1:2::1/128".parse().unwrap())
            .await
            .unwrap());
        // Address outside should not be blocked
        assert!(!backend
            .is_blocked(&"2001:db9::1/128".parse().unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_mock_backend_mixed_v4_v6() {
        let backend = mock::MockBackend::new();

        let ips: Vec<IpNet> = vec![
            "192.168.1.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        backend
            .apply_rules(&ips, FilterMode::Conntrack)
            .await
            .unwrap();

        assert_eq!(backend.entry_count().await.unwrap(), 2);

        // IPv4 should be blocked
        assert!(backend
            .is_blocked(&"192.168.1.1/32".parse().unwrap())
            .await
            .unwrap());
        // IPv6 should be blocked
        assert!(backend
            .is_blocked(&"2001:db8::1/128".parse().unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_mock_backend_reapply_clears_old() {
        let backend = mock::MockBackend::new();

        // First apply
        let ips1: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
        backend
            .apply_rules(&ips1, FilterMode::Conntrack)
            .await
            .unwrap();
        assert!(backend
            .is_blocked(&"192.168.1.1/32".parse().unwrap())
            .await
            .unwrap());

        // Second apply with different IPs
        let ips2: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        backend
            .apply_rules(&ips2, FilterMode::Conntrack)
            .await
            .unwrap();

        // Old IP should no longer be blocked
        assert!(!backend
            .is_blocked(&"192.168.1.1/32".parse().unwrap())
            .await
            .unwrap());
        // New IP should be blocked
        assert!(backend
            .is_blocked(&"10.1.2.3/32".parse().unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_mock_backend_empty_rules() {
        let backend = mock::MockBackend::new();

        // Apply empty rules
        let ips: Vec<IpNet> = vec![];
        backend
            .apply_rules(&ips, FilterMode::Conntrack)
            .await
            .unwrap();

        assert_eq!(backend.entry_count().await.unwrap(), 0);
        // Should still be marked as active even with 0 entries
        assert!(backend.is_active().await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_backend_get_stats_default() {
        let backend = mock::MockBackend::new();
        let stats = backend.get_stats().await.unwrap();

        assert_eq!(stats.packets_blocked, 0);
        assert_eq!(stats.bytes_blocked, 0);
    }

    // =========================================================================
    // find_command logic tests
    // =========================================================================

    #[test]
    fn test_find_command_returns_string() {
        // Test that find_command returns a static str
        // We can't test actual path resolution without mocking the filesystem,
        // but we can test the function signature and return type

        // This tests the fallback case when neither path exists
        // The function should return the bare command name
        let result = find_command("test_cmd", "/nonexistent/path1", "/nonexistent/path2");
        assert_eq!(result, "test_cmd");
    }

    // =========================================================================
    // FilterMode interaction tests
    // =========================================================================

    #[tokio::test]
    async fn test_mock_backend_conntrack_mode() {
        let backend = mock::MockBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/16".parse().unwrap()];

        // Conntrack mode should work the same in mock
        backend
            .apply_rules(&ips, FilterMode::Conntrack)
            .await
            .unwrap();
        assert!(backend.is_active().await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_backend_raw_mode() {
        let backend = mock::MockBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/16".parse().unwrap()];

        // Raw mode should work the same in mock
        backend.apply_rules(&ips, FilterMode::Raw).await.unwrap();
        assert!(backend.is_active().await.unwrap());
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[tokio::test]
    async fn test_mock_backend_single_ip() {
        let backend = mock::MockBackend::new();

        let ips: Vec<IpNet> = vec!["1.2.3.4/32".parse().unwrap()];
        backend
            .apply_rules(&ips, FilterMode::Conntrack)
            .await
            .unwrap();

        // Exact match should be blocked
        assert!(backend
            .is_blocked(&"1.2.3.4/32".parse().unwrap())
            .await
            .unwrap());
        // Adjacent IP should not be blocked
        assert!(!backend
            .is_blocked(&"1.2.3.5/32".parse().unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_mock_backend_large_cidr() {
        let backend = mock::MockBackend::new();

        // /8 blocks millions of IPs
        let ips: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        backend
            .apply_rules(&ips, FilterMode::Conntrack)
            .await
            .unwrap();

        // Various addresses within /8 should be blocked
        assert!(backend
            .is_blocked(&"10.0.0.1/32".parse().unwrap())
            .await
            .unwrap());
        assert!(backend
            .is_blocked(&"10.255.255.255/32".parse().unwrap())
            .await
            .unwrap());
        assert!(backend
            .is_blocked(&"10.128.64.32/32".parse().unwrap())
            .await
            .unwrap());
    }
}
