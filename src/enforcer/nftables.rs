//! nftables backend implementation.

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{debug, info};

use super::{exec_cmd, validate_entry_count, FirewallBackend, FirewallStats};
use crate::config::FilterMode;

const TABLE_NAME: &str = "oustip";
const SET_NAME: &str = "blocklist";

/// Validate that an IP/CIDR string is safe for nftables script inclusion.
/// This is a defense-in-depth check - IpNet::to_string() should already be safe,
/// but we explicitly validate to prevent any potential injection.
fn is_safe_nft_element(s: &str) -> bool {
    // Only allow: digits, dots (IPv4), colons (IPv6), slashes (CIDR), a-f (IPv6 hex)
    s.chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == ':' || c == '/' || ('a'..='f').contains(&c))
}

/// nftables backend
pub struct NftablesBackend;

impl NftablesBackend {
    pub fn new() -> Self {
        Self
    }

    /// Generate nftables script for applying rules
    fn generate_apply_script(&self, ips: &[IpNet], mode: FilterMode) -> String {
        let mut script = String::new();

        // Flush existing table if it exists
        script.push_str(&format!("table ip {} {{\n", TABLE_NAME));
        script.push_str("}\n");
        script.push_str(&format!("delete table ip {}\n", TABLE_NAME));

        // Create table and set
        script.push_str(&format!("table ip {} {{\n", TABLE_NAME));
        script.push_str(&format!("    set {} {{\n", SET_NAME));
        script.push_str("        type ipv4_addr\n");
        script.push_str("        flags interval\n");

        // Add elements with defensive validation
        if !ips.is_empty() {
            script.push_str("        elements = { ");
            let elements: Vec<String> = ips
                .iter()
                .map(|ip| ip.to_string())
                .filter(|s| is_safe_nft_element(s)) // Defense in depth
                .collect();
            script.push_str(&elements.join(", "));
            script.push_str(" }\n");
        }

        script.push_str("    }\n\n");

        // Create chains based on mode
        let (hook, priority) = match mode {
            FilterMode::Raw => ("prerouting", -300), // Before conntrack
            FilterMode::Conntrack => ("prerouting", -1), // After conntrack
        };

        // Input chain (packets destined for this host)
        script.push_str(&format!(
            "    chain input {{\n        type filter hook input priority {}; policy accept;\n",
            priority
        ));
        script.push_str(&format!(
            "        ip saddr @{} counter log prefix \"OustIP-Blocked: \" drop\n",
            SET_NAME
        ));
        script.push_str("    }\n\n");

        // Forward chain (packets being routed through)
        script.push_str(&format!(
            "    chain forward {{\n        type filter hook forward priority {}; policy accept;\n",
            priority
        ));
        script.push_str(&format!(
            "        ip saddr @{} counter log prefix \"OustIP-Blocked: \" drop\n",
            SET_NAME
        ));
        script.push_str("    }\n");

        // Prerouting chain for raw mode
        if mode == FilterMode::Raw {
            script.push_str(&format!(
                "\n    chain prerouting {{\n        type filter hook {} priority {}; policy accept;\n",
                hook, priority
            ));
            script.push_str(&format!(
                "        ip saddr @{} counter log prefix \"OustIP-Blocked: \" drop\n",
                SET_NAME
            ));
            script.push_str("    }\n");
        }

        script.push_str("}\n");
        script
    }

    /// Generate nftables script for removing rules
    fn generate_remove_script(&self) -> String {
        // Check if table exists before deleting
        format!(
            "table ip {} {{\n}}\ndelete table ip {}\n",
            TABLE_NAME, TABLE_NAME
        )
    }

    /// Execute nft with stdin script
    fn exec_nft_script(&self, script: &str) -> Result<()> {
        debug!("Executing nft script:\n{}", script);

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn nft")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nft failed: {}", stderr);
        }

        Ok(())
    }

    /// Parse counter values from nft output
    fn parse_counters(&self, output: &str) -> FirewallStats {
        let mut stats = FirewallStats::default();

        // Look for counter lines like: counter packets 123 bytes 456
        for line in output.lines() {
            if line.contains("counter") && line.contains("packets") {
                if let Some(packets) = extract_number_after(line, "packets") {
                    stats.packets_blocked += packets;
                }
                if let Some(bytes) = extract_number_after(line, "bytes") {
                    stats.bytes_blocked += bytes;
                }
            }
        }

        stats
    }
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallBackend for NftablesBackend {
    async fn apply_rules(&self, ips: &[IpNet], mode: FilterMode) -> Result<()> {
        // Validate entry count before applying
        validate_entry_count(ips.len())?;

        let script = self.generate_apply_script(ips, mode);
        self.exec_nft_script(&script)?;
        info!("Applied nftables rules with {} entries", ips.len());
        Ok(())
    }

    async fn remove_rules(&self) -> Result<()> {
        // Check if table exists first
        let check = Command::new("nft")
            .args(["list", "table", "ip", TABLE_NAME])
            .output();

        if let Ok(output) = check {
            if output.status.success() {
                let script = self.generate_remove_script();
                self.exec_nft_script(&script)?;
                info!("Removed nftables rules");
            }
        }
        Ok(())
    }

    async fn get_stats(&self) -> Result<FirewallStats> {
        let output = exec_cmd("nft", &["list", "table", "ip", TABLE_NAME])?;
        Ok(self.parse_counters(&output))
    }

    async fn is_blocked(&self, ip: &IpNet) -> Result<bool> {
        let output = exec_cmd("nft", &["list", "set", "ip", TABLE_NAME, SET_NAME])?;
        let ip_str = ip.to_string();
        Ok(output.contains(&ip_str))
    }

    async fn is_active(&self) -> Result<bool> {
        let result = Command::new("nft")
            .args(["list", "table", "ip", TABLE_NAME])
            .output();

        match result {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    async fn entry_count(&self) -> Result<usize> {
        let output = exec_cmd("nft", &["list", "set", "ip", TABLE_NAME, SET_NAME])?;

        // Count elements in the set
        // Format: elements = { 1.2.3.4/24, 5.6.7.8/16, ... }
        let count: usize = output
            .lines()
            .filter(|line| line.contains("elements"))
            .map(|line| {
                // Extract the part between { and }
                if let Some(start) = line.find('{') {
                    if let Some(end) = line.find('}') {
                        let elements = &line[start + 1..end];
                        return elements.split(',').filter(|s| !s.trim().is_empty()).count();
                    }
                }
                0
            })
            .sum();

        Ok(count)
    }
}

/// Extract a number after a keyword in a string
fn extract_number_after(s: &str, keyword: &str) -> Option<u64> {
    let idx = s.find(keyword)?;
    let after = &s[idx + keyword.len()..];
    let num_str: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_apply_script() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec![
            "192.168.0.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        assert!(script.contains("table ip oustip"));
        assert!(script.contains("set blocklist"));
        assert!(script.contains("192.168.0.0/24"));
        assert!(script.contains("10.0.0.0/8"));
        assert!(script.contains("OustIP-Blocked"));
    }

    #[test]
    fn test_parse_counters() {
        let backend = NftablesBackend::new();
        let output = r#"
table ip oustip {
    chain input {
        counter packets 123 bytes 4567 log prefix "OustIP-Blocked: " drop
    }
}
"#;
        let stats = backend.parse_counters(output);
        assert_eq!(stats.packets_blocked, 123);
        assert_eq!(stats.bytes_blocked, 4567);
    }

    #[test]
    fn test_extract_number_after() {
        assert_eq!(
            extract_number_after("packets 123 bytes", "packets"),
            Some(123)
        );
        assert_eq!(extract_number_after("bytes 456", "bytes"), Some(456));
        assert_eq!(extract_number_after("no number here", "packets"), None);
    }

    #[test]
    fn test_is_safe_nft_element() {
        // Valid IPv4
        assert!(is_safe_nft_element("192.168.1.0/24"));
        assert!(is_safe_nft_element("10.0.0.1"));
        assert!(is_safe_nft_element("0.0.0.0/0"));

        // Valid IPv6
        assert!(is_safe_nft_element("2001:db8::/32"));
        assert!(is_safe_nft_element("::1"));
        assert!(is_safe_nft_element("fe80::1"));

        // Invalid - potential injection attempts
        assert!(!is_safe_nft_element("192.168.1.0/24; drop"));
        assert!(!is_safe_nft_element("10.0.0.1 }"));
        assert!(!is_safe_nft_element("{ 1.2.3.4"));
        assert!(!is_safe_nft_element("1.2.3.4\n"));
        assert!(!is_safe_nft_element("$(whoami)"));
    }

    #[test]
    fn test_is_safe_nft_element_more_injections() {
        // More injection attempts
        assert!(!is_safe_nft_element("`id`"));
        assert!(!is_safe_nft_element("1.2.3.4|cat /etc/passwd"));
        assert!(!is_safe_nft_element("1.2.3.4 #comment"));
        assert!(!is_safe_nft_element("1.2.3.4\r"));
        // Empty string is vacuously safe (all 0 chars are valid)
        // but would be rejected by IpNet parsing anyway
        assert!(is_safe_nft_element(""));
    }

    #[test]
    fn test_generate_apply_script_raw_mode() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Raw);

        assert!(script.contains("table ip oustip"));
        assert!(script.contains("type filter hook prerouting"));
    }

    #[test]
    fn test_generate_apply_script_conntrack_mode() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        assert!(script.contains("type filter hook input"));
        assert!(script.contains("type filter hook forward"));
    }

    #[test]
    fn test_generate_apply_script_empty_ips() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec![];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should still create valid table structure
        assert!(script.contains("table ip oustip"));
        assert!(script.contains("set blocklist"));
    }

    #[test]
    fn test_parse_counters_no_match() {
        let backend = NftablesBackend::new();
        let output = "table ip oustip {\n}\n";
        let stats = backend.parse_counters(output);
        assert_eq!(stats.packets_blocked, 0);
        assert_eq!(stats.bytes_blocked, 0);
    }

    #[test]
    fn test_parse_counters_large_numbers() {
        let backend = NftablesBackend::new();
        let output = r#"counter packets 1234567890 bytes 9876543210"#;
        let stats = backend.parse_counters(output);
        assert_eq!(stats.packets_blocked, 1234567890);
        assert_eq!(stats.bytes_blocked, 9876543210);
    }

    #[test]
    fn test_extract_number_after_edge_cases() {
        assert_eq!(extract_number_after("", "packets"), None);
        assert_eq!(extract_number_after("packets", "packets"), None);
        assert_eq!(extract_number_after("packets abc", "packets"), None);
        assert_eq!(extract_number_after("packets 0", "packets"), Some(0));
    }

    #[test]
    fn test_nftables_backend_new() {
        let backend = NftablesBackend::new();
        // Verify it can be created
        let _ = backend;
    }

    #[test]
    fn test_generate_remove_script() {
        let backend = NftablesBackend::new();
        let script = backend.generate_remove_script();
        assert!(script.contains("delete table ip oustip"));
    }
}
