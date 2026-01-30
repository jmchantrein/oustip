//! iptables backend implementation.

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{debug, info};

use super::{
    exec_cmd, exec_cmd_with_executor, ip6tables_path, ip6tables_restore_path, ip6tables_save_path,
    iptables_path, iptables_restore_path, iptables_save_path, ipset_path, validate_entry_count,
    FirewallBackend, FirewallStats,
};
use crate::cmd_abstraction::CommandExecutor;
use crate::config::FilterMode;

const CHAIN_INPUT: &str = "OUSTIP-INPUT";
const CHAIN_FORWARD: &str = "OUSTIP-FORWARD";
const CHAIN_INPUT_V6: &str = "OUSTIP-INPUT6";
const CHAIN_FORWARD_V6: &str = "OUSTIP-FORWARD6";
const IPSET_NAME: &str = "oustip_blocklist";
const IPSET_NAME_V6: &str = "oustip_blocklist6";

/// iptables backend (uses ipset for efficient IP matching)
pub struct IptablesBackend;

impl IptablesBackend {
    pub fn new() -> Self {
        Self
    }

    /// Create ipsets and populate with IPs using batch restore (supports IPv4 and IPv6)
    /// Uses `ipset restore` with stdin for O(1) complexity instead of O(n) exec calls
    fn create_ipsets(&self, ips: &[IpNet]) -> Result<()> {
        // Separate IPv4 and IPv6
        let v4_ips: Vec<&IpNet> = ips.iter().filter(|ip| matches!(ip, IpNet::V4(_))).collect();
        let v6_ips: Vec<&IpNet> = ips.iter().filter(|ip| matches!(ip, IpNet::V6(_))).collect();

        // Destroy existing sets if any
        if let Err(e) = Command::new(ipset_path()).args(["destroy", IPSET_NAME]).output() {
            debug!("Could not destroy existing ipset {}: {}", IPSET_NAME, e);
        }
        if let Err(e) = Command::new(ipset_path()).args(["destroy", IPSET_NAME_V6]).output() {
            debug!("Could not destroy existing ipset {}: {}", IPSET_NAME_V6, e);
        }

        // Build restore script for atomic batch import
        let mut script = String::new();

        // Create IPv4 set
        script.push_str(&format!("create {} hash:net -exist\n", IPSET_NAME));
        for ip in &v4_ips {
            script.push_str(&format!("add {} {} -exist\n", IPSET_NAME, ip));
        }

        // Create IPv6 set (family inet6)
        script.push_str(&format!("create {} hash:net family inet6 -exist\n", IPSET_NAME_V6));
        for ip in &v6_ips {
            script.push_str(&format!("add {} {} -exist\n", IPSET_NAME_V6, ip));
        }

        // Execute ipset restore with script via stdin
        let mut child = Command::new(ipset_path())
            .arg("restore")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn ipset restore")?;

        // Write script to stdin
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(script.as_bytes())
                .context("Failed to write to ipset stdin")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to wait for ipset")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ipset restore failed: {}", stderr);
        }

        debug!(
            "Created ipsets: {} with {} IPv4 entries, {} with {} IPv6 entries",
            IPSET_NAME,
            v4_ips.len(),
            IPSET_NAME_V6,
            v6_ips.len()
        );
        Ok(())
    }

    /// Create iptables chains (IPv4)
    fn create_chains(&self, mode: FilterMode) -> Result<()> {
        // Create chains (ignore error if already exists)
        let _ = exec_cmd(iptables_path(), &["-N", CHAIN_INPUT]);
        let _ = exec_cmd(iptables_path(), &["-N", CHAIN_FORWARD]);

        // Flush existing rules in our chains
        let _ = exec_cmd(iptables_path(), &["-F", CHAIN_INPUT]);
        let _ = exec_cmd(iptables_path(), &["-F", CHAIN_FORWARD]);

        // Determine target table based on mode
        let table_args: &[&str] = match mode {
            FilterMode::Raw => &["-t", "raw"],
            FilterMode::Conntrack => &[],
        };

        // Add jump rules to our chains (if not already present)
        // Use -C to check, then -I to insert if not present
        let check_input = if table_args.is_empty() {
            Command::new(iptables_path())
                .args(["-C", "INPUT", "-j", CHAIN_INPUT])
                .output()
        } else {
            Command::new(iptables_path())
                .args(table_args)
                .args(["-C", "PREROUTING", "-j", CHAIN_INPUT])
                .output()
        };

        if check_input.map(|o| !o.status.success()).unwrap_or(true) {
            if table_args.is_empty() {
                exec_cmd(iptables_path(), &["-I", "INPUT", "-j", CHAIN_INPUT])?;
                exec_cmd(iptables_path(), &["-I", "FORWARD", "-j", CHAIN_FORWARD])?;
            } else {
                exec_cmd(
                    iptables_path(),
                    &["-t", "raw", "-I", "PREROUTING", "-j", CHAIN_INPUT],
                )?;
            }
        }

        Ok(())
    }

    /// Create ip6tables chains (IPv6)
    fn create_chains_v6(&self, mode: FilterMode) -> Result<()> {
        // Create chains (ignore error if already exists)
        let _ = exec_cmd(ip6tables_path(), &["-N", CHAIN_INPUT_V6]);
        let _ = exec_cmd(ip6tables_path(), &["-N", CHAIN_FORWARD_V6]);

        // Flush existing rules in our chains
        let _ = exec_cmd(ip6tables_path(), &["-F", CHAIN_INPUT_V6]);
        let _ = exec_cmd(ip6tables_path(), &["-F", CHAIN_FORWARD_V6]);

        // Determine target table based on mode
        let table_args: &[&str] = match mode {
            FilterMode::Raw => &["-t", "raw"],
            FilterMode::Conntrack => &[],
        };

        // Add jump rules to our chains (if not already present)
        let check_input = if table_args.is_empty() {
            Command::new(ip6tables_path())
                .args(["-C", "INPUT", "-j", CHAIN_INPUT_V6])
                .output()
        } else {
            Command::new(ip6tables_path())
                .args(table_args)
                .args(["-C", "PREROUTING", "-j", CHAIN_INPUT_V6])
                .output()
        };

        if check_input.map(|o| !o.status.success()).unwrap_or(true) {
            if table_args.is_empty() {
                exec_cmd(ip6tables_path(), &["-I", "INPUT", "-j", CHAIN_INPUT_V6])?;
                exec_cmd(ip6tables_path(), &["-I", "FORWARD", "-j", CHAIN_FORWARD_V6])?;
            } else {
                exec_cmd(
                    ip6tables_path(),
                    &["-t", "raw", "-I", "PREROUTING", "-j", CHAIN_INPUT_V6],
                )?;
            }
        }

        Ok(())
    }

    /// Add blocking rules to our IPv4 chains
    fn add_blocking_rules(&self) -> Result<()> {
        // Log and drop matching packets
        exec_cmd(
            iptables_path(),
            &[
                "-A",
                CHAIN_INPUT,
                "-m",
                "set",
                "--match-set",
                IPSET_NAME,
                "src",
                "-j",
                "LOG",
                "--log-prefix",
                "OustIP-Blocked: ",
                "--log-level",
                "4",
            ],
        )?;
        exec_cmd(
            iptables_path(),
            &[
                "-A",
                CHAIN_INPUT,
                "-m",
                "set",
                "--match-set",
                IPSET_NAME,
                "src",
                "-j",
                "DROP",
            ],
        )?;

        exec_cmd(
            iptables_path(),
            &[
                "-A",
                CHAIN_FORWARD,
                "-m",
                "set",
                "--match-set",
                IPSET_NAME,
                "src",
                "-j",
                "LOG",
                "--log-prefix",
                "OustIP-Blocked: ",
                "--log-level",
                "4",
            ],
        )?;
        exec_cmd(
            iptables_path(),
            &[
                "-A",
                CHAIN_FORWARD,
                "-m",
                "set",
                "--match-set",
                IPSET_NAME,
                "src",
                "-j",
                "DROP",
            ],
        )?;

        debug!("Added iptables IPv4 blocking rules");
        Ok(())
    }

    /// Add blocking rules to our IPv6 chains
    fn add_blocking_rules_v6(&self) -> Result<()> {
        // Log and drop matching packets
        exec_cmd(
            ip6tables_path(),
            &[
                "-A",
                CHAIN_INPUT_V6,
                "-m",
                "set",
                "--match-set",
                IPSET_NAME_V6,
                "src",
                "-j",
                "LOG",
                "--log-prefix",
                "OustIP-Blocked: ",
                "--log-level",
                "4",
            ],
        )?;
        exec_cmd(
            ip6tables_path(),
            &[
                "-A",
                CHAIN_INPUT_V6,
                "-m",
                "set",
                "--match-set",
                IPSET_NAME_V6,
                "src",
                "-j",
                "DROP",
            ],
        )?;

        exec_cmd(
            ip6tables_path(),
            &[
                "-A",
                CHAIN_FORWARD_V6,
                "-m",
                "set",
                "--match-set",
                IPSET_NAME_V6,
                "src",
                "-j",
                "LOG",
                "--log-prefix",
                "OustIP-Blocked: ",
                "--log-level",
                "4",
            ],
        )?;
        exec_cmd(
            ip6tables_path(),
            &[
                "-A",
                CHAIN_FORWARD_V6,
                "-m",
                "set",
                "--match-set",
                IPSET_NAME_V6,
                "src",
                "-j",
                "DROP",
            ],
        )?;

        debug!("Added ip6tables IPv6 blocking rules");
        Ok(())
    }

    /// Check if our IPv4 chains exist
    fn chains_exist(&self) -> bool {
        exec_cmd(iptables_path(), &["-L", CHAIN_INPUT]).is_ok()
    }

    /// Check if our IPv6 chains exist
    fn chains_exist_v6(&self) -> bool {
        exec_cmd(ip6tables_path(), &["-L", CHAIN_INPUT_V6]).is_ok()
    }

    /// Check if IPv4 ipset exists
    fn ipset_exists(&self) -> bool {
        exec_cmd(ipset_path(), &["list", IPSET_NAME]).is_ok()
    }

    /// Check if IPv6 ipset exists
    fn ipset_exists_v6(&self) -> bool {
        exec_cmd(ipset_path(), &["list", IPSET_NAME_V6]).is_ok()
    }

    // =========================================================================
    // Executor-based methods for testability
    // =========================================================================

    /// Check if our IPv4 chains exist (with executor injection)
    pub fn chains_exist_with_executor<E: CommandExecutor>(&self, executor: &E) -> bool {
        exec_cmd_with_executor(executor, iptables_path(), &["-L", CHAIN_INPUT]).is_ok()
    }

    /// Check if our IPv6 chains exist (with executor injection)
    pub fn chains_exist_v6_with_executor<E: CommandExecutor>(&self, executor: &E) -> bool {
        exec_cmd_with_executor(executor, ip6tables_path(), &["-L", CHAIN_INPUT_V6]).is_ok()
    }

    /// Check if IPv4 ipset exists (with executor injection)
    pub fn ipset_exists_with_executor<E: CommandExecutor>(&self, executor: &E) -> bool {
        exec_cmd_with_executor(executor, ipset_path(), &["list", IPSET_NAME]).is_ok()
    }

    /// Check if IPv6 ipset exists (with executor injection)
    pub fn ipset_exists_v6_with_executor<E: CommandExecutor>(&self, executor: &E) -> bool {
        exec_cmd_with_executor(executor, ipset_path(), &["list", IPSET_NAME_V6]).is_ok()
    }

    /// Check if IP is blocked (with executor injection)
    pub fn is_blocked_with_executor<E: CommandExecutor>(&self, executor: &E, ip: &IpNet) -> Result<bool> {
        let ipset_name = match ip {
            IpNet::V4(_) => IPSET_NAME,
            IpNet::V6(_) => IPSET_NAME_V6,
        };
        let result = exec_cmd_with_executor(executor, ipset_path(), &["test", ipset_name, &ip.to_string()]);
        Ok(result.is_ok())
    }

    /// Get stats (with executor injection)
    pub fn get_stats_with_executor<E: CommandExecutor>(&self, executor: &E) -> Result<FirewallStats> {
        let mut stats = FirewallStats::default();

        // Get IPv4 stats from INPUT chain
        if let Ok(output) = exec_cmd_with_executor(executor, iptables_path(), &["-L", CHAIN_INPUT, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        // Get IPv4 stats from FORWARD chain
        if let Ok(output) = exec_cmd_with_executor(executor, iptables_path(), &["-L", CHAIN_FORWARD, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        // Get IPv6 stats from INPUT chain
        if let Ok(output) = exec_cmd_with_executor(executor, ip6tables_path(), &["-L", CHAIN_INPUT_V6, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME_V6) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        // Get IPv6 stats from FORWARD chain
        if let Ok(output) = exec_cmd_with_executor(executor, ip6tables_path(), &["-L", CHAIN_FORWARD_V6, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME_V6) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Get entry count (with executor injection)
    pub fn entry_count_with_executor<E: CommandExecutor>(&self, executor: &E) -> Result<usize> {
        let mut total_count = 0usize;

        // Count IPv4 entries
        if let Ok(output) = exec_cmd_with_executor(executor, ipset_path(), &["list", IPSET_NAME]) {
            total_count += output
                .lines()
                .skip_while(|line| !line.starts_with("Members:"))
                .skip(1)
                .filter(|line| !line.is_empty())
                .count();
        }

        // Count IPv6 entries
        if let Ok(output) = exec_cmd_with_executor(executor, ipset_path(), &["list", IPSET_NAME_V6]) {
            total_count += output
                .lines()
                .skip_while(|line| !line.starts_with("Members:"))
                .skip(1)
                .filter(|line| !line.is_empty())
                .count();
        }

        Ok(total_count)
    }

    /// Check if rules are active (with executor injection)
    pub fn is_active_with_executor<E: CommandExecutor>(&self, executor: &E) -> Result<bool> {
        let v4_active = self.chains_exist_with_executor(executor) && self.ipset_exists_with_executor(executor);
        let v6_active = self.chains_exist_v6_with_executor(executor) && self.ipset_exists_v6_with_executor(executor);
        Ok(v4_active || v6_active)
    }
}

impl Default for IptablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallBackend for IptablesBackend {
    async fn apply_rules(&self, ips: &[IpNet], mode: FilterMode) -> Result<()> {
        // Validate entry count before applying
        validate_entry_count(ips.len())?;

        // Create ipsets first (both IPv4 and IPv6)
        self.create_ipsets(ips)?;

        // Create IPv4 chains and add rules
        self.create_chains(mode)?;
        // Verify IPv4 chains were created
        if !self.chains_exist() {
            anyhow::bail!("Failed to create iptables IPv4 chains");
        }
        self.add_blocking_rules()?;

        // Create IPv6 chains and add rules
        self.create_chains_v6(mode)?;
        // Verify IPv6 chains were created
        if !self.chains_exist_v6() {
            anyhow::bail!("Failed to create ip6tables IPv6 chains");
        }
        self.add_blocking_rules_v6()?;

        let v4_count = ips.iter().filter(|ip| matches!(ip, IpNet::V4(_))).count();
        let v6_count = ips.iter().filter(|ip| matches!(ip, IpNet::V6(_))).count();
        info!(
            "Applied iptables/ip6tables rules with {} entries ({} IPv4, {} IPv6)",
            ips.len(),
            v4_count,
            v6_count
        );
        Ok(())
    }

    async fn remove_rules(&self) -> Result<()> {
        // === Remove IPv4 rules ===
        // Remove jump rules from INPUT/FORWARD
        let _ = exec_cmd(iptables_path(), &["-D", "INPUT", "-j", CHAIN_INPUT]);
        let _ = exec_cmd(iptables_path(), &["-D", "FORWARD", "-j", CHAIN_FORWARD]);

        // Also try raw table
        let _ = exec_cmd(
            iptables_path(),
            &["-t", "raw", "-D", "PREROUTING", "-j", CHAIN_INPUT],
        );

        // Flush and delete our IPv4 chains
        let _ = exec_cmd(iptables_path(), &["-F", CHAIN_INPUT]);
        let _ = exec_cmd(iptables_path(), &["-F", CHAIN_FORWARD]);
        let _ = exec_cmd(iptables_path(), &["-X", CHAIN_INPUT]);
        let _ = exec_cmd(iptables_path(), &["-X", CHAIN_FORWARD]);

        // === Remove IPv6 rules ===
        // Remove jump rules from INPUT/FORWARD
        let _ = exec_cmd(ip6tables_path(), &["-D", "INPUT", "-j", CHAIN_INPUT_V6]);
        let _ = exec_cmd(ip6tables_path(), &["-D", "FORWARD", "-j", CHAIN_FORWARD_V6]);

        // Also try raw table
        let _ = exec_cmd(
            ip6tables_path(),
            &["-t", "raw", "-D", "PREROUTING", "-j", CHAIN_INPUT_V6],
        );

        // Flush and delete our IPv6 chains
        let _ = exec_cmd(ip6tables_path(), &["-F", CHAIN_INPUT_V6]);
        let _ = exec_cmd(ip6tables_path(), &["-F", CHAIN_FORWARD_V6]);
        let _ = exec_cmd(ip6tables_path(), &["-X", CHAIN_INPUT_V6]);
        let _ = exec_cmd(ip6tables_path(), &["-X", CHAIN_FORWARD_V6]);

        // Destroy ipsets (both IPv4 and IPv6)
        let _ = exec_cmd(ipset_path(), &["destroy", IPSET_NAME]);
        let _ = exec_cmd(ipset_path(), &["destroy", IPSET_NAME_V6]);

        info!("Removed iptables/ip6tables rules");
        Ok(())
    }

    async fn get_stats(&self) -> Result<FirewallStats> {
        let mut stats = FirewallStats::default();

        // === Get IPv4 stats ===
        if let Ok(output) = exec_cmd(iptables_path(), &["-L", CHAIN_INPUT, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        if let Ok(output) = exec_cmd(iptables_path(), &["-L", CHAIN_FORWARD, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        // === Get IPv6 stats ===
        if let Ok(output) = exec_cmd(ip6tables_path(), &["-L", CHAIN_INPUT_V6, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME_V6) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        if let Ok(output) = exec_cmd(ip6tables_path(), &["-L", CHAIN_FORWARD_V6, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME_V6) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        Ok(stats)
    }

    async fn is_blocked(&self, ip: &IpNet) -> Result<bool> {
        // Check appropriate ipset based on IP version
        let ipset_name = match ip {
            IpNet::V4(_) => IPSET_NAME,
            IpNet::V6(_) => IPSET_NAME_V6,
        };
        let output = exec_cmd(ipset_path(), &["test", ipset_name, &ip.to_string()]);
        // ipset test returns 0 if member, non-zero if not
        Ok(output.is_ok())
    }

    async fn is_active(&self) -> Result<bool> {
        // Check if either IPv4 or IPv6 rules are active
        let v4_active = self.chains_exist() && self.ipset_exists();
        let v6_active = self.chains_exist_v6() && self.ipset_exists_v6();
        Ok(v4_active || v6_active)
    }

    async fn entry_count(&self) -> Result<usize> {
        let mut total_count = 0usize;

        // Count IPv4 entries
        if let Ok(output) = exec_cmd(ipset_path(), &["list", IPSET_NAME]) {
            total_count += output
                .lines()
                .skip_while(|line| !line.starts_with("Members:"))
                .skip(1)
                .filter(|line| !line.is_empty())
                .count();
        }

        // Count IPv6 entries
        if let Ok(output) = exec_cmd(ipset_path(), &["list", IPSET_NAME_V6]) {
            total_count += output
                .lines()
                .skip_while(|line| !line.starts_with("Members:"))
                .skip(1)
                .filter(|line| !line.is_empty())
                .count();
        }

        Ok(total_count)
    }

    async fn save_current_rules(&self) -> Result<String> {
        let mut saved = String::new();

        // Save ipsets (both IPv4 and IPv6)
        saved.push_str("### IPSET_START ###\n");
        if let Ok(output) = exec_cmd(ipset_path(), &["save", IPSET_NAME]) {
            saved.push_str(&output);
        }
        if let Ok(output) = exec_cmd(ipset_path(), &["save", IPSET_NAME_V6]) {
            saved.push_str(&output);
        }
        saved.push_str("### IPSET_END ###\n");

        // Save iptables rules for our chains
        saved.push_str("### IPTABLES_START ###\n");
        // Save IPv4 rules - use iptables-save and filter for our chains
        if let Ok(output) = exec_cmd(iptables_save_path(), &[]) {
            // Filter to keep only lines related to our chains
            for line in output.lines() {
                if line.contains(CHAIN_INPUT)
                    || line.contains(CHAIN_FORWARD)
                    || line.starts_with("*filter")
                    || line.starts_with("COMMIT")
                    || line.starts_with(":OUSTIP")
                {
                    saved.push_str(line);
                    saved.push('\n');
                }
            }
        }
        saved.push_str("### IPTABLES_END ###\n");

        // Save ip6tables rules for our chains
        saved.push_str("### IP6TABLES_START ###\n");
        if let Ok(output) = exec_cmd(ip6tables_save_path(), &[]) {
            // Filter to keep only lines related to our chains
            for line in output.lines() {
                if line.contains(CHAIN_INPUT_V6)
                    || line.contains(CHAIN_FORWARD_V6)
                    || line.starts_with("*filter")
                    || line.starts_with("COMMIT")
                    || line.starts_with(":OUSTIP")
                {
                    saved.push_str(line);
                    saved.push('\n');
                }
            }
        }
        saved.push_str("### IP6TABLES_END ###\n");

        debug!("Saved current iptables rules ({} bytes)", saved.len());
        Ok(saved)
    }

    async fn restore_rules(&self, saved_rules: &str) -> Result<()> {
        if saved_rules.is_empty() {
            debug!("No saved rules to restore, removing current rules");
            return self.remove_rules().await;
        }

        // Parse the saved rules into sections
        let mut ipset_rules = String::new();
        let mut iptables_rules = String::new();
        let mut ip6tables_rules = String::new();
        let mut current_section = "";

        for line in saved_rules.lines() {
            match line {
                "### IPSET_START ###" => current_section = "ipset",
                "### IPSET_END ###" => current_section = "",
                "### IPTABLES_START ###" => current_section = "iptables",
                "### IPTABLES_END ###" => current_section = "",
                "### IP6TABLES_START ###" => current_section = "ip6tables",
                "### IP6TABLES_END ###" => current_section = "",
                _ => match current_section {
                    "ipset" => {
                        ipset_rules.push_str(line);
                        ipset_rules.push('\n');
                    }
                    "iptables" => {
                        iptables_rules.push_str(line);
                        iptables_rules.push('\n');
                    }
                    "ip6tables" => {
                        ip6tables_rules.push_str(line);
                        ip6tables_rules.push('\n');
                    }
                    _ => {}
                },
            }
        }

        // First, remove current rules to get a clean state
        // (ignore errors as rules might not exist)
        let _ = self.remove_rules().await;

        // Restore ipsets using ipset restore
        if !ipset_rules.trim().is_empty() {
            let mut child = Command::new(ipset_path())
                .arg("restore")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn ipset restore")?;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin
                    .write_all(ipset_rules.as_bytes())
                    .context("Failed to write to ipset stdin")?;
            }

            let output = child
                .wait_with_output()
                .context("Failed to wait for ipset")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                debug!("ipset restore warning (may be expected): {}", stderr);
            }
        }

        // Restore iptables rules
        if !iptables_rules.trim().is_empty() {
            let mut child = Command::new(iptables_restore_path())
                .arg("--noflush")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn iptables-restore")?;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin
                    .write_all(iptables_rules.as_bytes())
                    .context("Failed to write to iptables-restore stdin")?;
            }

            let output = child
                .wait_with_output()
                .context("Failed to wait for iptables-restore")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                debug!("iptables-restore warning (may be expected): {}", stderr);
            }
        }

        // Restore ip6tables rules
        if !ip6tables_rules.trim().is_empty() {
            let mut child = Command::new(ip6tables_restore_path())
                .arg("--noflush")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn ip6tables-restore")?;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin
                    .write_all(ip6tables_rules.as_bytes())
                    .context("Failed to write to ip6tables-restore stdin")?;
            }

            let output = child
                .wait_with_output()
                .context("Failed to wait for ip6tables-restore")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                debug!("ip6tables-restore warning (may be expected): {}", stderr);
            }
        }

        info!("Restored previous iptables rules");
        Ok(())
    }
}

/// Parse iptables -L -v output for counters
/// Format: "  123K  456M DROP  all  --  *  *  0.0.0.0/0  0.0.0.0/0  match-set oustip_blocklist src"
fn parse_iptables_counters(line: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let packets = parse_human_number(parts[0])?;
    let bytes = parse_human_number(parts[1])?;
    Some((packets, bytes))
}

/// Parse human-readable numbers (e.g., "123K", "456M")
fn parse_human_number(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_part, multiplier) = if let Some(stripped) = s.strip_suffix('K') {
        (stripped, 1_000u64)
    } else if let Some(stripped) = s.strip_suffix('M') {
        (stripped, 1_000_000u64)
    } else if let Some(stripped) = s.strip_suffix('G') {
        (stripped, 1_000_000_000u64)
    } else {
        (s, 1u64)
    };

    num_part.parse::<u64>().ok().and_then(|n| n.checked_mul(multiplier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_human_number() {
        assert_eq!(parse_human_number("123"), Some(123));
        assert_eq!(parse_human_number("123K"), Some(123_000));
        assert_eq!(parse_human_number("456M"), Some(456_000_000));
        assert_eq!(parse_human_number("1G"), Some(1_000_000_000));
    }

    #[test]
    fn test_parse_human_number_edge_cases() {
        assert_eq!(parse_human_number("0"), Some(0));
        assert_eq!(parse_human_number("0K"), Some(0));
        assert_eq!(parse_human_number(""), None);
        assert_eq!(parse_human_number("  "), None);
        assert_eq!(parse_human_number("abc"), None);
    }

    #[test]
    fn test_parse_human_number_with_whitespace() {
        assert_eq!(parse_human_number("  123  "), Some(123));
        assert_eq!(parse_human_number("  456K  "), Some(456_000));
    }

    #[test]
    fn test_parse_human_number_overflow() {
        // Test that extremely large numbers that would overflow return None
        // u64::MAX is 18446744073709551615
        // 18446744073709551615K would overflow
        assert_eq!(parse_human_number("18446744073709551615G"), None);
        assert_eq!(parse_human_number("99999999999999999999G"), None);
    }

    #[test]
    fn test_parse_iptables_counters() {
        let line = "  123K  456M DROP  all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set oustip_blocklist src";
        let (packets, bytes) = parse_iptables_counters(line).unwrap();
        assert_eq!(packets, 123_000);
        assert_eq!(bytes, 456_000_000);
    }

    #[test]
    fn test_parse_iptables_counters_small_numbers() {
        let line = "  100  2048 DROP  all  --  *  *  0.0.0.0/0  0.0.0.0/0";
        let (packets, bytes) = parse_iptables_counters(line).unwrap();
        assert_eq!(packets, 100);
        assert_eq!(bytes, 2048);
    }

    #[test]
    fn test_parse_iptables_counters_invalid() {
        assert!(parse_iptables_counters("").is_none());
        assert!(parse_iptables_counters("single").is_none());
    }

    #[test]
    fn test_ipset_name_constant() {
        assert_eq!(IPSET_NAME, "oustip_blocklist");
        assert!(IPSET_NAME.len() < 32); // ipset name limit
    }

    #[test]
    fn test_ipset_name_v6_constant() {
        assert_eq!(IPSET_NAME_V6, "oustip_blocklist6");
        assert!(IPSET_NAME_V6.len() < 32); // ipset name limit
    }

    #[test]
    fn test_chain_constants() {
        assert_eq!(CHAIN_INPUT, "OUSTIP-INPUT");
        assert_eq!(CHAIN_FORWARD, "OUSTIP-FORWARD");
        assert!(CHAIN_INPUT.contains("OUSTIP"));
        assert!(CHAIN_FORWARD.contains("OUSTIP"));
    }

    #[test]
    fn test_chain_v6_constants() {
        assert_eq!(CHAIN_INPUT_V6, "OUSTIP-INPUT6");
        assert_eq!(CHAIN_FORWARD_V6, "OUSTIP-FORWARD6");
        assert!(CHAIN_INPUT_V6.contains("OUSTIP"));
        assert!(CHAIN_FORWARD_V6.contains("OUSTIP"));
    }

    #[test]
    fn test_iptables_backend_new() {
        let backend = IptablesBackend::new();
        // Just verify it can be created without panicking
        let _ = backend;
    }

    // Note: save_current_rules and restore_rules require actual iptables/ipset binaries
    // and root privileges. These are integration tests that would need to be
    // run in a privileged environment. Unit tests for the logic are below.

    #[test]
    fn test_save_rules_section_markers() {
        // Test that the section markers are correctly formatted
        let markers = vec![
            "### IPSET_START ###",
            "### IPSET_END ###",
            "### IPTABLES_START ###",
            "### IPTABLES_END ###",
            "### IP6TABLES_START ###",
            "### IP6TABLES_END ###",
        ];

        for marker in markers {
            assert!(marker.starts_with("###"));
            assert!(marker.ends_with("###"));
        }
    }

    #[test]
    fn test_restore_rules_section_parsing() {
        // Test that restore_rules correctly parses sections
        let saved_rules = "\
### IPSET_START ###
create oustip_blocklist hash:net
add oustip_blocklist 192.168.1.0/24
### IPSET_END ###
### IPTABLES_START ###
*filter
:OUSTIP-INPUT - [0:0]
-A OUSTIP-INPUT -m set --match-set oustip_blocklist src -j DROP
COMMIT
### IPTABLES_END ###
### IP6TABLES_START ###
*filter
:OUSTIP-INPUT6 - [0:0]
COMMIT
### IP6TABLES_END ###
";

        // Parse the sections (same logic as in restore_rules)
        let mut ipset_rules = String::new();
        let mut iptables_rules = String::new();
        let mut ip6tables_rules = String::new();
        let mut current_section = "";

        for line in saved_rules.lines() {
            match line {
                "### IPSET_START ###" => current_section = "ipset",
                "### IPSET_END ###" => current_section = "",
                "### IPTABLES_START ###" => current_section = "iptables",
                "### IPTABLES_END ###" => current_section = "",
                "### IP6TABLES_START ###" => current_section = "ip6tables",
                "### IP6TABLES_END ###" => current_section = "",
                _ => match current_section {
                    "ipset" => {
                        ipset_rules.push_str(line);
                        ipset_rules.push('\n');
                    }
                    "iptables" => {
                        iptables_rules.push_str(line);
                        iptables_rules.push('\n');
                    }
                    "ip6tables" => {
                        ip6tables_rules.push_str(line);
                        ip6tables_rules.push('\n');
                    }
                    _ => {}
                },
            }
        }

        // Verify ipset section
        assert!(ipset_rules.contains("create oustip_blocklist"));
        assert!(ipset_rules.contains("192.168.1.0/24"));
        assert!(!ipset_rules.contains("### IPSET"));

        // Verify iptables section
        assert!(iptables_rules.contains("*filter"));
        assert!(iptables_rules.contains("OUSTIP-INPUT"));
        assert!(iptables_rules.contains("COMMIT"));
        assert!(!iptables_rules.contains("### IPTABLES"));

        // Verify ip6tables section
        assert!(ip6tables_rules.contains("*filter"));
        assert!(ip6tables_rules.contains("OUSTIP-INPUT6"));
        assert!(!ip6tables_rules.contains("### IP6TABLES"));
    }

    #[test]
    fn test_restore_rules_empty_sections() {
        // Test with empty saved rules
        let saved_rules = "";

        let mut ipset_rules = String::new();
        let mut current_section = "";

        for line in saved_rules.lines() {
            match line {
                "### IPSET_START ###" => current_section = "ipset",
                "### IPSET_END ###" => current_section = "",
                _ => {
                    if current_section == "ipset" {
                        ipset_rules.push_str(line);
                        ipset_rules.push('\n');
                    }
                }
            }
        }

        assert!(ipset_rules.is_empty());
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    // =========================================================================
    // parse_human_number comprehensive tests
    // =========================================================================

    #[test]
    fn test_parse_human_number_lowercase_suffix() {
        // Lowercase suffixes should not work (iptables uses uppercase)
        assert_eq!(parse_human_number("123k"), None);
        assert_eq!(parse_human_number("456m"), None);
        assert_eq!(parse_human_number("1g"), None);
    }

    #[test]
    fn test_parse_human_number_large_multiplied_values() {
        // Test values that are large but don't overflow
        assert_eq!(parse_human_number("999K"), Some(999_000));
        assert_eq!(parse_human_number("999M"), Some(999_000_000));
        assert_eq!(parse_human_number("9G"), Some(9_000_000_000));
    }

    #[test]
    fn test_parse_human_number_boundary_overflow() {
        // Test overflow at boundary
        // u64::MAX = 18446744073709551615
        // 18446744073709551615 / 1000 = 18446744073709551 (still valid for K)
        assert_eq!(parse_human_number("18446744073709551K"), Some(18446744073709551000));
        // But 18446744073709552K would overflow
        assert_eq!(parse_human_number("18446744073709552K"), None);
    }

    #[test]
    fn test_parse_human_number_with_leading_zeros() {
        assert_eq!(parse_human_number("000123"), Some(123));
        assert_eq!(parse_human_number("00100K"), Some(100_000));
    }

    #[test]
    fn test_parse_human_number_only_suffix() {
        // Just a suffix with no number
        assert_eq!(parse_human_number("K"), None);
        assert_eq!(parse_human_number("M"), None);
        assert_eq!(parse_human_number("G"), None);
    }

    #[test]
    fn test_parse_human_number_decimal() {
        // Decimal numbers are not supported
        assert_eq!(parse_human_number("1.5K"), None);
        assert_eq!(parse_human_number("123.456"), None);
    }

    #[test]
    fn test_parse_human_number_multiple_suffixes() {
        // Multiple suffixes should fail
        assert_eq!(parse_human_number("123KM"), None);
        assert_eq!(parse_human_number("123KK"), None);
    }

    #[test]
    fn test_parse_human_number_suffix_only_chars() {
        // Characters that aren't suffixes
        assert_eq!(parse_human_number("123B"), None); // B is not a valid suffix
        assert_eq!(parse_human_number("123T"), None); // T is not a valid suffix
    }

    #[test]
    fn test_parse_human_number_negative() {
        // Negative numbers
        assert_eq!(parse_human_number("-123"), None);
        assert_eq!(parse_human_number("-1K"), None);
    }

    // =========================================================================
    // parse_iptables_counters comprehensive tests
    // =========================================================================

    #[test]
    fn test_parse_iptables_counters_typical_format() {
        // Typical iptables -L -v -n format
        let line = "   12K  3456K DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set oustip_blocklist src";
        let result = parse_iptables_counters(line);
        assert!(result.is_some());
        let (packets, bytes) = result.unwrap();
        assert_eq!(packets, 12_000);
        assert_eq!(bytes, 3_456_000);
    }

    #[test]
    fn test_parse_iptables_counters_no_suffix() {
        let line = "  100  2048 DROP  all  --  *  *  0.0.0.0/0  0.0.0.0/0";
        let result = parse_iptables_counters(line);
        assert!(result.is_some());
        let (packets, bytes) = result.unwrap();
        assert_eq!(packets, 100);
        assert_eq!(bytes, 2048);
    }

    #[test]
    fn test_parse_iptables_counters_mixed_suffixes() {
        let line = "  100K  5G DROP  all";
        let result = parse_iptables_counters(line);
        assert!(result.is_some());
        let (packets, bytes) = result.unwrap();
        assert_eq!(packets, 100_000);
        assert_eq!(bytes, 5_000_000_000);
    }

    #[test]
    fn test_parse_iptables_counters_zero_values() {
        let line = "    0     0 DROP  all";
        let result = parse_iptables_counters(line);
        assert!(result.is_some());
        let (packets, bytes) = result.unwrap();
        assert_eq!(packets, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_parse_iptables_counters_whitespace_only() {
        let line = "       ";
        let result = parse_iptables_counters(line);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_iptables_counters_header_line() {
        // Header line from iptables -L -v -n
        let line = "pkts bytes target     prot opt in     out     source               destination";
        let result = parse_iptables_counters(line);
        // Should fail because "pkts" is not a number
        assert!(result.is_none());
    }

    // =========================================================================
    // Constants tests
    // =========================================================================

    #[test]
    fn test_chain_names_unique() {
        // IPv4 and IPv6 chain names should be different
        assert_ne!(CHAIN_INPUT, CHAIN_INPUT_V6);
        assert_ne!(CHAIN_FORWARD, CHAIN_FORWARD_V6);
    }

    #[test]
    fn test_chain_names_contain_oustip() {
        // All chain names should contain OUSTIP for easy identification
        assert!(CHAIN_INPUT.contains("OUSTIP"));
        assert!(CHAIN_FORWARD.contains("OUSTIP"));
        assert!(CHAIN_INPUT_V6.contains("OUSTIP"));
        assert!(CHAIN_FORWARD_V6.contains("OUSTIP"));
    }

    #[test]
    fn test_ipset_names_unique() {
        assert_ne!(IPSET_NAME, IPSET_NAME_V6);
    }

    #[test]
    fn test_ipset_names_under_limit() {
        // ipset name limit is 31 characters
        assert!(IPSET_NAME.len() <= 31);
        assert!(IPSET_NAME_V6.len() <= 31);
    }

    // =========================================================================
    // IptablesBackend struct tests
    // =========================================================================

    #[test]
    fn test_iptables_backend_default() {
        let backend = IptablesBackend::default();
        let _ = backend;
    }

    #[test]
    fn test_iptables_backend_new() {
        let backend = IptablesBackend::new();
        let _ = backend;
    }

    // =========================================================================
    // Section marker tests
    // =========================================================================

    #[test]
    fn test_section_markers_format() {
        // Test that section markers follow expected format
        let markers = [
            "### IPSET_START ###",
            "### IPSET_END ###",
            "### IPTABLES_START ###",
            "### IPTABLES_END ###",
            "### IP6TABLES_START ###",
            "### IP6TABLES_END ###",
        ];

        for marker in markers {
            // Each marker starts and ends with ###
            assert!(marker.starts_with("###"));
            assert!(marker.ends_with("###"));
            // Has content between
            assert!(marker.len() > 6);
        }
    }

    #[test]
    fn test_section_parsing_order_independence() {
        // Sections should be parseable regardless of order
        let saved_rules = r#"
### IPTABLES_START ###
*filter
COMMIT
### IPTABLES_END ###
### IPSET_START ###
create oustip_blocklist hash:net
### IPSET_END ###
"#;

        let mut ipset_rules = String::new();
        let mut iptables_rules = String::new();
        let mut current_section = "";

        for line in saved_rules.lines() {
            match line {
                "### IPSET_START ###" => current_section = "ipset",
                "### IPSET_END ###" => current_section = "",
                "### IPTABLES_START ###" => current_section = "iptables",
                "### IPTABLES_END ###" => current_section = "",
                _ => match current_section {
                    "ipset" => {
                        ipset_rules.push_str(line);
                        ipset_rules.push('\n');
                    }
                    "iptables" => {
                        iptables_rules.push_str(line);
                        iptables_rules.push('\n');
                    }
                    _ => {}
                },
            }
        }

        assert!(ipset_rules.contains("create oustip_blocklist"));
        assert!(iptables_rules.contains("*filter"));
    }

    // =========================================================================
    // Overflow protection tests
    // =========================================================================

    #[test]
    fn test_parse_human_number_m_overflow() {
        // Large number with M suffix that would overflow
        // 18446744073710 * 1_000_000 overflows u64
        let result = parse_human_number("18446744073710M");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_human_number_g_overflow() {
        // Large number with G suffix that would overflow
        // 18446744074 * 1_000_000_000 overflows u64
        let result = parse_human_number("18446744074G");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_human_number_max_safe_values() {
        // Maximum safe values for each suffix
        assert!(parse_human_number("18446744073709551K").is_some());
        assert!(parse_human_number("18446744073709M").is_some());
        assert!(parse_human_number("18446744073G").is_some());
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn test_parse_iptables_counters_single_field() {
        // Single field should fail
        let result = parse_iptables_counters("123");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_iptables_counters_invalid_first() {
        // First field invalid, second valid
        let result = parse_iptables_counters("abc 123");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_iptables_counters_valid_first_invalid_second() {
        // First field valid, second invalid
        let result = parse_iptables_counters("123 abc");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_human_number_spaces_around_suffix() {
        // Suffix with space before it
        assert_eq!(parse_human_number("123 K"), None);
    }

    #[test]
    fn test_parse_human_number_unicode() {
        // Unicode digits shouldn't be parsed
        assert_eq!(parse_human_number("\u{0661}\u{0662}\u{0663}"), None); // Arabic digits
    }

    // =========================================================================
    // IPv6 specific tests
    // =========================================================================

    #[test]
    fn test_ipv6_chain_names_contain_6() {
        // IPv6 chain names should contain "6"
        assert!(CHAIN_INPUT_V6.contains("6"));
        assert!(CHAIN_FORWARD_V6.contains("6"));
    }

    #[test]
    fn test_ipv6_ipset_name_contains_6() {
        assert!(IPSET_NAME_V6.contains("6"));
    }

    // =========================================================================
    // Section content extraction tests
    // =========================================================================

    #[test]
    fn test_extract_ipset_section() {
        let saved_rules = r#"
### IPSET_START ###
create oustip_blocklist hash:net
add oustip_blocklist 192.168.1.0/24
add oustip_blocklist 10.0.0.0/8
### IPSET_END ###
"#;

        let mut ipset_rules = String::new();
        let mut in_section = false;

        for line in saved_rules.lines() {
            match line {
                "### IPSET_START ###" => in_section = true,
                "### IPSET_END ###" => in_section = false,
                _ if in_section => {
                    ipset_rules.push_str(line);
                    ipset_rules.push('\n');
                }
                _ => {}
            }
        }

        assert!(ipset_rules.contains("create oustip_blocklist"));
        assert!(ipset_rules.contains("192.168.1.0/24"));
        assert!(ipset_rules.contains("10.0.0.0/8"));
    }

    #[test]
    fn test_extract_iptables_section() {
        let saved_rules = r#"
### IPTABLES_START ###
*filter
:OUSTIP-INPUT - [0:0]
-A OUSTIP-INPUT -m set --match-set oustip_blocklist src -j DROP
COMMIT
### IPTABLES_END ###
"#;

        let mut iptables_rules = String::new();
        let mut in_section = false;

        for line in saved_rules.lines() {
            match line {
                "### IPTABLES_START ###" => in_section = true,
                "### IPTABLES_END ###" => in_section = false,
                _ if in_section => {
                    iptables_rules.push_str(line);
                    iptables_rules.push('\n');
                }
                _ => {}
            }
        }

        assert!(iptables_rules.contains("*filter"));
        assert!(iptables_rules.contains("OUSTIP-INPUT"));
        assert!(iptables_rules.contains("COMMIT"));
    }
}

// =============================================================================
// MockCommandExecutor-based tests
// =============================================================================
#[cfg(test)]
mod mock_executor_tests {
    use super::*;
    use anyhow::Result;
    use mockall::automock;

    /// Command output for testing
    #[derive(Debug, Clone, Default)]
    struct CmdOutput {
        stdout: String,
        stderr: String,
        success: bool,
    }

    /// Trait for command execution (test-only)
    #[automock]
    trait CmdExecutor: Send + Sync {
        fn execute(&self, cmd: &str, args: &[String]) -> Result<CmdOutput>;
        fn execute_with_stdin(&self, cmd: &str, args: &[String], stdin: &str) -> Result<CmdOutput>;
    }

    fn args_to_vec(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn success_output(stdout: &str) -> CmdOutput {
        CmdOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            success: true,
        }
    }

    fn failure_output(stderr: &str) -> CmdOutput {
        CmdOutput {
            stdout: String::new(),
            stderr: stderr.to_string(),
            success: false,
        }
    }

    fn args_has(args: &[String], val: &str) -> bool {
        args.iter().any(|a| a == val)
    }

    // Helper functions for executor-based operations
    fn exec_cmd_mock<E: CmdExecutor>(executor: &E, cmd: &str, args: &[&str]) -> Result<String> {
        let args_vec = args_to_vec(args);
        let output = executor.execute(cmd, &args_vec)?;
        if output.success {
            Ok(output.stdout)
        } else {
            anyhow::bail!("{} failed: {}", cmd, output.stderr)
        }
    }

    fn chains_exist_mock<E: CmdExecutor>(executor: &E) -> bool {
        exec_cmd_mock(executor, iptables_path(), &["-L", CHAIN_INPUT]).is_ok()
    }

    fn chains_exist_v6_mock<E: CmdExecutor>(executor: &E) -> bool {
        exec_cmd_mock(executor, ip6tables_path(), &["-L", CHAIN_INPUT_V6]).is_ok()
    }

    fn ipset_exists_mock<E: CmdExecutor>(executor: &E) -> bool {
        exec_cmd_mock(executor, ipset_path(), &["list", IPSET_NAME]).is_ok()
    }

    fn ipset_exists_v6_mock<E: CmdExecutor>(executor: &E) -> bool {
        exec_cmd_mock(executor, ipset_path(), &["list", IPSET_NAME_V6]).is_ok()
    }

    fn is_blocked_mock<E: CmdExecutor>(executor: &E, ip: &IpNet) -> Result<bool> {
        let ipset_name = match ip {
            IpNet::V4(_) => IPSET_NAME,
            IpNet::V6(_) => IPSET_NAME_V6,
        };
        let result = exec_cmd_mock(executor, ipset_path(), &["test", ipset_name, &ip.to_string()]);
        Ok(result.is_ok())
    }

    fn get_stats_mock<E: CmdExecutor>(executor: &E) -> Result<FirewallStats> {
        let mut stats = FirewallStats::default();

        // Get IPv4 stats from INPUT chain
        if let Ok(output) = exec_cmd_mock(executor, iptables_path(), &["-L", CHAIN_INPUT, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        // Get IPv4 stats from FORWARD chain
        if let Ok(output) = exec_cmd_mock(executor, iptables_path(), &["-L", CHAIN_FORWARD, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        // Get IPv6 stats
        if let Ok(output) = exec_cmd_mock(executor, ip6tables_path(), &["-L", CHAIN_INPUT_V6, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME_V6) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        Ok(stats)
    }

    fn entry_count_mock<E: CmdExecutor>(executor: &E) -> Result<usize> {
        let mut total_count = 0usize;

        // Count IPv4 entries
        if let Ok(output) = exec_cmd_mock(executor, ipset_path(), &["list", IPSET_NAME]) {
            total_count += output
                .lines()
                .skip_while(|line| !line.starts_with("Members:"))
                .skip(1)
                .filter(|line| !line.is_empty())
                .count();
        }

        // Count IPv6 entries
        if let Ok(output) = exec_cmd_mock(executor, ipset_path(), &["list", IPSET_NAME_V6]) {
            total_count += output
                .lines()
                .skip_while(|line| !line.starts_with("Members:"))
                .skip(1)
                .filter(|line| !line.is_empty())
                .count();
        }

        Ok(total_count)
    }

    fn is_active_mock<E: CmdExecutor>(executor: &E) -> Result<bool> {
        let v4_active = chains_exist_mock(executor) && ipset_exists_mock(executor);
        let v6_active = chains_exist_v6_mock(executor) && ipset_exists_v6_mock(executor);
        Ok(v4_active || v6_active)
    }

    // =========================================================================
    // Mock tests for chains_exist
    // =========================================================================

    #[test]
    fn test_chains_exist_v4_success() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("iptables") && args_has(args, "-L") && args_has(args, CHAIN_INPUT))
            .times(1)
            .returning(|_, _| Ok(success_output("Chain OUSTIP-INPUT...")));

        assert!(chains_exist_mock(&mock));
    }

    #[test]
    fn test_chains_exist_v4_not_found() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(1)
            .returning(|_, _| Ok(failure_output("iptables: No chain by that name")));

        assert!(!chains_exist_mock(&mock));
    }

    #[test]
    fn test_chains_exist_v6_success() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ip6tables") && args_has(args, "-L") && args_has(args, CHAIN_INPUT_V6))
            .times(1)
            .returning(|_, _| Ok(success_output("Chain OUSTIP-INPUT6...")));

        assert!(chains_exist_v6_mock(&mock));
    }

    #[test]
    fn test_chains_exist_v6_not_found() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(1)
            .returning(|_, _| Ok(failure_output("ip6tables: No chain by that name")));

        assert!(!chains_exist_v6_mock(&mock));
    }

    // =========================================================================
    // Mock tests for ipset_exists
    // =========================================================================

    #[test]
    fn test_ipset_exists_v4_success() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, "list") && args_has(args, IPSET_NAME))
            .times(1)
            .returning(|_, _| Ok(success_output("Name: oustip_blocklist\nType: hash:net\nMembers:\n192.168.1.0/24")));

        assert!(ipset_exists_mock(&mock));
    }

    #[test]
    fn test_ipset_exists_v4_not_found() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(1)
            .returning(|_, _| Ok(failure_output("ipset: The set with the given name does not exist")));

        assert!(!ipset_exists_mock(&mock));
    }

    #[test]
    fn test_ipset_exists_v6_success() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, "list") && args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| Ok(success_output("Name: oustip_blocklist6\nType: hash:net")));

        assert!(ipset_exists_v6_mock(&mock));
    }

    // =========================================================================
    // Mock tests for is_blocked
    // =========================================================================

    #[test]
    fn test_is_blocked_ipv4_found() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, "test") && args_has(args, IPSET_NAME))
            .times(1)
            .returning(|_, _| Ok(success_output("192.168.1.0/24 is in set oustip_blocklist")));

        let ip: IpNet = "192.168.1.0/24".parse().unwrap();
        let result = is_blocked_mock(&mock, &ip);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_is_blocked_ipv4_not_found() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(1)
            .returning(|_, _| Ok(failure_output("10.0.0.0/8 is NOT in set oustip_blocklist")));

        let ip: IpNet = "10.0.0.0/8".parse().unwrap();
        let result = is_blocked_mock(&mock, &ip);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_is_blocked_ipv6_found() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, "test") && args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| Ok(success_output("2001:db8::/32 is in set oustip_blocklist6")));

        let ip: IpNet = "2001:db8::/32".parse().unwrap();
        let result = is_blocked_mock(&mock, &ip);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_is_blocked_ipv6_not_found() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(1)
            .returning(|_, _| Ok(failure_output("2001:db9::/32 is NOT in set oustip_blocklist6")));

        let ip: IpNet = "2001:db9::/32".parse().unwrap();
        let result = is_blocked_mock(&mock, &ip);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // =========================================================================
    // Mock tests for get_stats
    // =========================================================================

    #[test]
    fn test_get_stats_ipv4_only() {
        let mut mock = MockCmdExecutor::new();

        // Mock INPUT chain stats
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("iptables") && args_has(args, CHAIN_INPUT) && args_has(args, "-v"))
            .times(1)
            .returning(|_, _| {
                Ok(success_output(
                    "Chain OUSTIP-INPUT (1 references)\n\
                     pkts bytes target     prot opt in     out     source               destination\n\
                       100  5000 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set oustip_blocklist src\n\
                       100  5000 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set oustip_blocklist src"
                ))
            });

        // Mock FORWARD chain stats
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("iptables") && args_has(args, CHAIN_FORWARD) && args_has(args, "-v"))
            .times(1)
            .returning(|_, _| {
                Ok(success_output(
                    "Chain OUSTIP-FORWARD (1 references)\n\
                     pkts bytes target     prot opt in     out     source               destination\n\
                        50  2500 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set oustip_blocklist src"
                ))
            });

        // Mock IPv6 chains (return failure - no IPv6)
        mock.expect_execute()
            .withf(|cmd, _| cmd.ends_with("ip6tables"))
            .times(1)
            .returning(|_, _| Ok(failure_output("chain not found")));

        let result = get_stats_mock(&mock);
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.packets_blocked, 150); // 100 + 50
        assert_eq!(stats.bytes_blocked, 7500);  // 5000 + 2500
    }

    #[test]
    fn test_get_stats_no_rules() {
        let mut mock = MockCmdExecutor::new();

        // All chains fail (no rules)
        mock.expect_execute()
            .times(3)
            .returning(|_, _| Ok(failure_output("chain not found")));

        let result = get_stats_mock(&mock);
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.packets_blocked, 0);
        assert_eq!(stats.bytes_blocked, 0);
    }

    #[test]
    fn test_get_stats_with_suffixes() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("iptables") && args_has(args, CHAIN_INPUT))
            .times(1)
            .returning(|_, _| {
                Ok(success_output(
                    "  10K  500M DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set oustip_blocklist src"
                ))
            });

        mock.expect_execute()
            .times(2)
            .returning(|_, _| Ok(failure_output("chain not found")));

        let result = get_stats_mock(&mock);
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.packets_blocked, 10_000);
        assert_eq!(stats.bytes_blocked, 500_000_000);
    }

    // =========================================================================
    // Mock tests for entry_count
    // =========================================================================

    #[test]
    fn test_entry_count_ipv4_only() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, IPSET_NAME) && !args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| {
                Ok(success_output(
                    "Name: oustip_blocklist\n\
                     Type: hash:net\n\
                     Revision: 6\n\
                     Header: family inet hashsize 1024 maxelem 65536\n\
                     Size in memory: 568\n\
                     References: 2\n\
                     Number of entries: 3\n\
                     Members:\n\
                     192.168.1.0/24\n\
                     10.0.0.0/8\n\
                     172.16.0.0/12"
                ))
            });

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| Ok(failure_output("set not found")));

        let result = entry_count_mock(&mock);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn test_entry_count_mixed_v4_v6() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, IPSET_NAME) && !args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| {
                Ok(success_output(
                    "Name: oustip_blocklist\n\
                     Members:\n\
                     192.168.1.0/24\n\
                     10.0.0.0/8"
                ))
            });

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| {
                Ok(success_output(
                    "Name: oustip_blocklist6\n\
                     Members:\n\
                     2001:db8::/32"
                ))
            });

        let result = entry_count_mock(&mock);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3); // 2 IPv4 + 1 IPv6
    }

    #[test]
    fn test_entry_count_empty_sets() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(2)
            .returning(|_, _| {
                Ok(success_output(
                    "Name: oustip_blocklist\n\
                     Members:"
                ))
            });

        let result = entry_count_mock(&mock);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_entry_count_no_sets() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(2)
            .returning(|_, _| Ok(failure_output("set not found")));

        let result = entry_count_mock(&mock);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    // =========================================================================
    // Mock tests for is_active
    // =========================================================================

    #[test]
    fn test_is_active_both_present() {
        let mut mock = MockCmdExecutor::new();

        // is_active_mock checks:
        // 1. chains_exist_mock (iptables -L OUSTIP-INPUT)
        // 2. ipset_exists_mock (ipset list oustip_blocklist)
        // 3. chains_exist_v6_mock (ip6tables -L OUSTIP-INPUT6) - always called
        // 4. ipset_exists_v6_mock (ipset list oustip_blocklist6) - only if v6 chain exists

        // IPv4 chain exists
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("iptables") && args_has(args, "-L") && args_has(args, CHAIN_INPUT))
            .times(1)
            .returning(|_, _| Ok(success_output("Chain OUSTIP-INPUT")));

        // IPv4 ipset exists
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, IPSET_NAME) && !args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| Ok(success_output("Name: oustip_blocklist")));

        // IPv6 chain check (still happens even if v4 is active)
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ip6tables") && args_has(args, "-L"))
            .times(1)
            .returning(|_, _| Ok(failure_output("chain not found")));

        // Since v6 chain doesn't exist, ipset_exists_v6_mock is NOT called (short-circuit &&)

        let result = is_active_mock(&mock);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_is_active_v4_only() {
        let mut mock = MockCmdExecutor::new();

        // IPv4 chain exists
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("iptables") && args_has(args, "-L"))
            .times(1)
            .returning(|_, _| Ok(success_output("Chain OUSTIP-INPUT")));

        // IPv4 ipset exists
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, IPSET_NAME) && !args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| Ok(success_output("Name: oustip_blocklist")));

        // IPv6 chain doesn't exist (short-circuits so ipset6 check is skipped)
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ip6tables") && args_has(args, "-L"))
            .times(1)
            .returning(|_, _| Ok(failure_output("chain not found")));

        let result = is_active_mock(&mock);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_is_active_none() {
        let mut mock = MockCmdExecutor::new();

        // IPv4 chain doesn't exist (short-circuits so ipset check is skipped)
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("iptables") && args_has(args, "-L"))
            .times(1)
            .returning(|_, _| Ok(failure_output("chain not found")));

        // IPv6 chain doesn't exist (short-circuits so ipset6 check is skipped)
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ip6tables") && args_has(args, "-L"))
            .times(1)
            .returning(|_, _| Ok(failure_output("chain not found")));

        let result = is_active_mock(&mock);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_is_active_chain_exists_but_no_ipset() {
        let mut mock = MockCmdExecutor::new();

        // IPv4 chain exists
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("iptables") && args_has(args, "-L"))
            .times(1)
            .returning(|_, _| Ok(success_output("Chain OUSTIP-INPUT")));

        // IPv4 ipset does NOT exist
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ipset") && args_has(args, IPSET_NAME) && !args_has(args, IPSET_NAME_V6))
            .times(1)
            .returning(|_, _| Ok(failure_output("set not found")));

        // IPv6 chain does NOT exist (short-circuits so ipset6 check is skipped)
        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("ip6tables") && args_has(args, "-L"))
            .times(1)
            .returning(|_, _| Ok(failure_output("chain not found")));

        let result = is_active_mock(&mock);
        assert!(result.is_ok());
        // Not active because chain exists but ipset doesn't (for v4), and v6 chain doesn't exist
        assert!(!result.unwrap());
    }
}
