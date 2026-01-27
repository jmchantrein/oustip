//! iptables backend implementation.

use anyhow::Result;
use async_trait::async_trait;
use ipnet::IpNet;
use std::process::Command;
use tracing::{debug, info};

use super::{exec_cmd, FirewallBackend, FirewallStats};
use crate::config::FilterMode;

const CHAIN_INPUT: &str = "OUSTIP-INPUT";
const CHAIN_FORWARD: &str = "OUSTIP-FORWARD";
const IPSET_NAME: &str = "oustip_blocklist";

/// iptables backend (uses ipset for efficient IP matching)
pub struct IptablesBackend;

impl IptablesBackend {
    pub fn new() -> Self {
        Self
    }

    /// Create ipset and populate with IPs
    fn create_ipset(&self, ips: &[IpNet]) -> Result<()> {
        // Destroy existing set if any
        let _ = Command::new("ipset")
            .args(["destroy", IPSET_NAME])
            .output();

        // Create new set (hash:net for CIDR support)
        exec_cmd("ipset", &["create", IPSET_NAME, "hash:net", "-exist"])?;

        // Add IPs in batches for efficiency
        for ip in ips {
            let _ = exec_cmd("ipset", &["add", IPSET_NAME, &ip.to_string(), "-exist"]);
        }

        debug!("Created ipset {} with {} entries", IPSET_NAME, ips.len());
        Ok(())
    }

    /// Create iptables chains
    fn create_chains(&self, mode: FilterMode) -> Result<()> {
        // Create chains (ignore error if already exists)
        let _ = exec_cmd("iptables", &["-N", CHAIN_INPUT]);
        let _ = exec_cmd("iptables", &["-N", CHAIN_FORWARD]);

        // Flush existing rules in our chains
        let _ = exec_cmd("iptables", &["-F", CHAIN_INPUT]);
        let _ = exec_cmd("iptables", &["-F", CHAIN_FORWARD]);

        // Determine target table based on mode
        let table_args: &[&str] = match mode {
            FilterMode::Raw => &["-t", "raw"],
            FilterMode::Conntrack => &[],
        };

        // Add jump rules to our chains (if not already present)
        // Use -C to check, then -I to insert if not present
        let check_input = if table_args.is_empty() {
            Command::new("iptables")
                .args(["-C", "INPUT", "-j", CHAIN_INPUT])
                .output()
        } else {
            Command::new("iptables")
                .args(table_args)
                .args(["-C", "PREROUTING", "-j", CHAIN_INPUT])
                .output()
        };

        if check_input.map(|o| !o.status.success()).unwrap_or(true) {
            if table_args.is_empty() {
                exec_cmd("iptables", &["-I", "INPUT", "-j", CHAIN_INPUT])?;
                exec_cmd("iptables", &["-I", "FORWARD", "-j", CHAIN_FORWARD])?;
            } else {
                exec_cmd("iptables", &["-t", "raw", "-I", "PREROUTING", "-j", CHAIN_INPUT])?;
            }
        }

        Ok(())
    }

    /// Add blocking rules to our chains
    fn add_blocking_rules(&self) -> Result<()> {
        // Log and drop matching packets
        exec_cmd(
            "iptables",
            &[
                "-A", CHAIN_INPUT,
                "-m", "set", "--match-set", IPSET_NAME, "src",
                "-j", "LOG", "--log-prefix", "OustIP-Blocked: ", "--log-level", "4",
            ],
        )?;
        exec_cmd(
            "iptables",
            &[
                "-A", CHAIN_INPUT,
                "-m", "set", "--match-set", IPSET_NAME, "src",
                "-j", "DROP",
            ],
        )?;

        exec_cmd(
            "iptables",
            &[
                "-A", CHAIN_FORWARD,
                "-m", "set", "--match-set", IPSET_NAME, "src",
                "-j", "LOG", "--log-prefix", "OustIP-Blocked: ", "--log-level", "4",
            ],
        )?;
        exec_cmd(
            "iptables",
            &[
                "-A", CHAIN_FORWARD,
                "-m", "set", "--match-set", IPSET_NAME, "src",
                "-j", "DROP",
            ],
        )?;

        debug!("Added iptables blocking rules");
        Ok(())
    }

    /// Check if our chains exist
    fn chains_exist(&self) -> bool {
        exec_cmd("iptables", &["-L", CHAIN_INPUT]).is_ok()
    }

    /// Check if ipset exists
    fn ipset_exists(&self) -> bool {
        exec_cmd("ipset", &["list", IPSET_NAME]).is_ok()
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
        // Create ipset first
        self.create_ipset(ips)?;

        // Create chains and add rules
        self.create_chains(mode)?;
        self.add_blocking_rules()?;

        info!("Applied iptables rules with {} entries", ips.len());
        Ok(())
    }

    async fn remove_rules(&self) -> Result<()> {
        // Remove jump rules from INPUT/FORWARD
        let _ = exec_cmd("iptables", &["-D", "INPUT", "-j", CHAIN_INPUT]);
        let _ = exec_cmd("iptables", &["-D", "FORWARD", "-j", CHAIN_FORWARD]);

        // Also try raw table
        let _ = exec_cmd("iptables", &["-t", "raw", "-D", "PREROUTING", "-j", CHAIN_INPUT]);

        // Flush and delete our chains
        let _ = exec_cmd("iptables", &["-F", CHAIN_INPUT]);
        let _ = exec_cmd("iptables", &["-F", CHAIN_FORWARD]);
        let _ = exec_cmd("iptables", &["-X", CHAIN_INPUT]);
        let _ = exec_cmd("iptables", &["-X", CHAIN_FORWARD]);

        // Destroy ipset
        let _ = exec_cmd("ipset", &["destroy", IPSET_NAME]);

        info!("Removed iptables rules");
        Ok(())
    }

    async fn get_stats(&self) -> Result<FirewallStats> {
        let mut stats = FirewallStats::default();

        // Get stats from our chains
        if let Ok(output) = exec_cmd("iptables", &["-L", CHAIN_INPUT, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME) {
                    if let Some((packets, bytes)) = parse_iptables_counters(line) {
                        stats.packets_blocked += packets;
                        stats.bytes_blocked += bytes;
                    }
                }
            }
        }

        if let Ok(output) = exec_cmd("iptables", &["-L", CHAIN_FORWARD, "-v", "-n"]) {
            for line in output.lines() {
                if line.contains("DROP") && line.contains(IPSET_NAME) {
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
        let output = exec_cmd("ipset", &["test", IPSET_NAME, &ip.to_string()]);
        // ipset test returns 0 if member, non-zero if not
        Ok(output.is_ok())
    }

    async fn is_active(&self) -> Result<bool> {
        Ok(self.chains_exist() && self.ipset_exists())
    }

    async fn entry_count(&self) -> Result<usize> {
        let output = exec_cmd("ipset", &["list", IPSET_NAME])?;

        // Count lines after "Members:" header
        let count = output
            .lines()
            .skip_while(|line| !line.starts_with("Members:"))
            .skip(1)
            .filter(|line| !line.is_empty())
            .count();

        Ok(count)
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

    num_part.parse::<u64>().ok().map(|n| n * multiplier)
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
    fn test_parse_iptables_counters() {
        let line = "  123K  456M DROP  all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set oustip_blocklist src";
        let (packets, bytes) = parse_iptables_counters(line).unwrap();
        assert_eq!(packets, 123_000);
        assert_eq!(bytes, 456_000_000);
    }
}
