//! iptables backend implementation.

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{debug, info};

use super::{
    exec_cmd, ip6tables_path, ip6tables_restore_path, ip6tables_save_path, iptables_path,
    iptables_restore_path, iptables_save_path, ipset_path, validate_entry_count, FirewallBackend,
    FirewallStats,
};
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
        let _ = Command::new(ipset_path()).args(["destroy", IPSET_NAME]).output();
        let _ = Command::new(ipset_path()).args(["destroy", IPSET_NAME_V6]).output();

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
        self.add_blocking_rules()?;

        // Create IPv6 chains and add rules
        self.create_chains_v6(mode)?;
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
