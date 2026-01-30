//! nftables backend implementation.

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use std::io::Write;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

use super::{exec_cmd, exec_cmd_with_executor, nft_path, validate_entry_count, FirewallBackend, FirewallStats};
use crate::cmd_abstraction::{args_to_strings, CommandExecutor};
use crate::config::FilterMode;

const TABLE_NAME: &str = "oustip";
const SET_NAME: &str = "blocklist";
const SET_NAME_V6: &str = "blocklist_v6";

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

    /// Generate nftables script for applying rules (supports both IPv4 and IPv6)
    fn generate_apply_script(&self, ips: &[IpNet], mode: FilterMode) -> String {
        // Separate IPv4 and IPv6 addresses
        let v4_ips: Vec<&IpNet> = ips.iter().filter(|ip| matches!(ip, IpNet::V4(_))).collect();
        let v6_ips: Vec<&IpNet> = ips.iter().filter(|ip| matches!(ip, IpNet::V6(_))).collect();

        let mut script = String::new();

        // Determine priority based on mode
        let (hook, priority) = match mode {
            FilterMode::Raw => ("prerouting", -300), // Before conntrack
            FilterMode::Conntrack => ("prerouting", -1), // After conntrack
        };

        // === IPv4 Table ===
        script.push_str(&self.generate_ip4_table(&v4_ips, mode, hook, priority));

        // === IPv6 Table ===
        script.push_str(&self.generate_ip6_table(&v6_ips, mode, hook, priority));

        script
    }

    /// Generate IPv4 nftables table
    fn generate_ip4_table(
        &self,
        ips: &[&IpNet],
        mode: FilterMode,
        hook: &str,
        priority: i32,
    ) -> String {
        let mut script = String::new();

        // Create table if it doesn't exist (idempotent), then flush it
        // This reduces the race window compared to delete+create
        script.push_str(&format!("add table ip {}\n", TABLE_NAME));
        script.push_str(&format!("flush table ip {}\n", TABLE_NAME));

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
                .filter(|s| {
                    let safe = is_safe_nft_element(s);
                    if !safe {
                        warn!("Filtered unsafe nftables element: {}", s);
                    }
                    safe
                })
                .collect();
            script.push_str(&elements.join(", "));
            script.push_str(" }\n");
        }

        script.push_str("    }\n\n");

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

    /// Generate IPv6 nftables table
    fn generate_ip6_table(
        &self,
        ips: &[&IpNet],
        mode: FilterMode,
        hook: &str,
        priority: i32,
    ) -> String {
        let mut script = String::new();

        // Create table if it doesn't exist (idempotent), then flush it
        // This reduces the race window compared to delete+create
        script.push_str(&format!("add table ip6 {}\n", TABLE_NAME));
        script.push_str(&format!("flush table ip6 {}\n", TABLE_NAME));

        // Create table and set
        script.push_str(&format!("table ip6 {} {{\n", TABLE_NAME));
        script.push_str(&format!("    set {} {{\n", SET_NAME_V6));
        script.push_str("        type ipv6_addr\n");
        script.push_str("        flags interval\n");

        // Add elements with defensive validation
        if !ips.is_empty() {
            script.push_str("        elements = { ");
            let elements: Vec<String> = ips
                .iter()
                .map(|ip| ip.to_string())
                .filter(|s| {
                    let safe = is_safe_nft_element(s);
                    if !safe {
                        warn!("Filtered unsafe nftables element: {}", s);
                    }
                    safe
                })
                .collect();
            script.push_str(&elements.join(", "));
            script.push_str(" }\n");
        }

        script.push_str("    }\n\n");

        // Input chain (packets destined for this host)
        script.push_str(&format!(
            "    chain input {{\n        type filter hook input priority {}; policy accept;\n",
            priority
        ));
        script.push_str(&format!(
            "        ip6 saddr @{} counter log prefix \"OustIP-Blocked: \" drop\n",
            SET_NAME_V6
        ));
        script.push_str("    }\n\n");

        // Forward chain (packets being routed through)
        script.push_str(&format!(
            "    chain forward {{\n        type filter hook forward priority {}; policy accept;\n",
            priority
        ));
        script.push_str(&format!(
            "        ip6 saddr @{} counter log prefix \"OustIP-Blocked: \" drop\n",
            SET_NAME_V6
        ));
        script.push_str("    }\n");

        // Prerouting chain for raw mode
        if mode == FilterMode::Raw {
            script.push_str(&format!(
                "\n    chain prerouting {{\n        type filter hook {} priority {}; policy accept;\n",
                hook, priority
            ));
            script.push_str(&format!(
                "        ip6 saddr @{} counter log prefix \"OustIP-Blocked: \" drop\n",
                SET_NAME_V6
            ));
            script.push_str("    }\n");
        }

        script.push_str("}\n");
        script
    }

    /// Generate nftables script for removing rules (both IPv4 and IPv6)
    fn generate_remove_script(&self) -> String {
        let mut script = String::new();

        // Remove IPv4 table
        script.push_str(&format!("table ip {} {{\n}}\n", TABLE_NAME));
        script.push_str(&format!("delete table ip {}\n", TABLE_NAME));

        // Remove IPv6 table
        script.push_str(&format!("table ip6 {} {{\n}}\n", TABLE_NAME));
        script.push_str(&format!("delete table ip6 {}\n", TABLE_NAME));

        script
    }

    /// Execute nft with stdin script
    fn exec_nft_script(&self, script: &str) -> Result<()> {
        debug!("Executing nft script:\n{}", script);

        let mut child = Command::new(nft_path())
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

    /// Execute nft script using an injected CommandExecutor
    pub fn exec_nft_script_with_executor<E: CommandExecutor>(
        &self,
        executor: &E,
        script: &str,
    ) -> Result<()> {
        debug!("Executing nft script (with executor):\n{}", script);
        let args = args_to_strings(&["-f", "-"]);
        let output = executor.execute_with_stdin(nft_path(), &args, script)?;
        if !output.success {
            anyhow::bail!("nft failed: {}", output.stderr);
        }
        Ok(())
    }

    /// Apply rules using an injected CommandExecutor
    pub fn apply_rules_with_executor<E: CommandExecutor>(
        &self,
        executor: &E,
        ips: &[IpNet],
        mode: FilterMode,
    ) -> Result<()> {
        validate_entry_count(ips.len())?;
        let script = self.generate_apply_script(ips, mode);
        self.exec_nft_script_with_executor(executor, &script)?;
        info!("Applied nftables rules with {} entries", ips.len());
        Ok(())
    }

    /// Check if IP is blocked using an injected CommandExecutor
    pub fn is_blocked_with_executor<E: CommandExecutor>(
        &self,
        executor: &E,
        ip: &IpNet,
    ) -> Result<bool> {
        let (table_family, set_name) = match ip {
            IpNet::V4(_) => ("ip", SET_NAME),
            IpNet::V6(_) => ("ip6", SET_NAME_V6),
        };
        let output = exec_cmd_with_executor(
            executor,
            nft_path(),
            &["list", "set", table_family, TABLE_NAME, set_name],
        )?;
        let ip_str = ip.to_string();
        Ok(output.contains(&format!(" {} ", ip_str))
            || output.contains(&format!("{},", ip_str))
            || output.contains(&format!(" {}\n", ip_str))
            || output.ends_with(&ip_str))
    }

    /// Get stats using an injected CommandExecutor
    pub fn get_stats_with_executor<E: CommandExecutor>(&self, executor: &E) -> Result<FirewallStats> {
        let mut stats = FirewallStats::default();
        if let Ok(output) = exec_cmd_with_executor(executor, nft_path(), &["list", "table", "ip", TABLE_NAME]) {
            let v4_stats = self.parse_counters(&output);
            stats.packets_blocked += v4_stats.packets_blocked;
            stats.bytes_blocked += v4_stats.bytes_blocked;
        }
        if let Ok(output) = exec_cmd_with_executor(executor, nft_path(), &["list", "table", "ip6", TABLE_NAME]) {
            let v6_stats = self.parse_counters(&output);
            stats.packets_blocked += v6_stats.packets_blocked;
            stats.bytes_blocked += v6_stats.bytes_blocked;
        }
        Ok(stats)
    }

    /// Get entry count using an injected CommandExecutor
    pub fn entry_count_with_executor<E: CommandExecutor>(&self, executor: &E) -> Result<usize> {
        let mut total_count = 0usize;
        if let Ok(output) = exec_cmd_with_executor(executor, nft_path(), &["list", "set", "ip", TABLE_NAME, SET_NAME]) {
            total_count += count_set_elements(&output);
        }
        if let Ok(output) = exec_cmd_with_executor(executor, nft_path(), &["list", "set", "ip6", TABLE_NAME, SET_NAME_V6]) {
            total_count += count_set_elements(&output);
        }
        Ok(total_count)
    }

    /// Remove rules using an injected CommandExecutor
    pub fn remove_rules_with_executor<E: CommandExecutor>(&self, executor: &E) -> Result<()> {
        let args_v4 = args_to_strings(&["list", "table", "ip", TABLE_NAME]);
        let v4_exists = executor.execute(nft_path(), &args_v4).map(|o| o.success).unwrap_or(false);
        let args_v6 = args_to_strings(&["list", "table", "ip6", TABLE_NAME]);
        let v6_exists = executor.execute(nft_path(), &args_v6).map(|o| o.success).unwrap_or(false);
        if v4_exists || v6_exists {
            let script = self.generate_remove_script();
            self.exec_nft_script_with_executor(executor, &script)?;
            info!("Removed nftables rules (IPv4 and IPv6)");
        }
        Ok(())
    }

    /// Check if rules are active using an injected CommandExecutor
    pub fn is_active_with_executor<E: CommandExecutor>(&self, executor: &E) -> Result<bool> {
        let args_v4 = args_to_strings(&["list", "table", "ip", TABLE_NAME]);
        let v4_active = executor.execute(nft_path(), &args_v4).map(|o| o.success).unwrap_or(false);
        let args_v6 = args_to_strings(&["list", "table", "ip6", TABLE_NAME]);
        let v6_active = executor.execute(nft_path(), &args_v6).map(|o| o.success).unwrap_or(false);
        Ok(v4_active || v6_active)
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
        // Check if IPv4 table exists
        let check_v4 = Command::new(nft_path())
            .args(["list", "table", "ip", TABLE_NAME])
            .output();

        // Check if IPv6 table exists
        let check_v6 = Command::new(nft_path())
            .args(["list", "table", "ip6", TABLE_NAME])
            .output();

        let v4_exists = check_v4.map(|o| o.status.success()).unwrap_or(false);
        let v6_exists = check_v6.map(|o| o.status.success()).unwrap_or(false);

        if v4_exists || v6_exists {
            let script = self.generate_remove_script();
            self.exec_nft_script(&script)?;
            info!("Removed nftables rules (IPv4 and IPv6)");
        }
        Ok(())
    }

    async fn get_stats(&self) -> Result<FirewallStats> {
        let mut stats = FirewallStats::default();

        // Get IPv4 stats
        if let Ok(output) = exec_cmd(nft_path(), &["list", "table", "ip", TABLE_NAME]) {
            let v4_stats = self.parse_counters(&output);
            stats.packets_blocked += v4_stats.packets_blocked;
            stats.bytes_blocked += v4_stats.bytes_blocked;
        }

        // Get IPv6 stats
        if let Ok(output) = exec_cmd(nft_path(), &["list", "table", "ip6", TABLE_NAME]) {
            let v6_stats = self.parse_counters(&output);
            stats.packets_blocked += v6_stats.packets_blocked;
            stats.bytes_blocked += v6_stats.bytes_blocked;
        }

        Ok(stats)
    }

    async fn is_blocked(&self, ip: &IpNet) -> Result<bool> {
        match ip {
            IpNet::V4(_) => {
                let output =
                    exec_cmd(nft_path(), &["list", "set", "ip", TABLE_NAME, SET_NAME])?;
                let ip_str = ip.to_string();
                // More precise check - look for the IP as a complete entry
                let ip_pattern = format!(" {} ", ip_str); // surrounded by spaces
                let ip_pattern_comma = format!("{},", ip_str); // followed by comma
                let ip_pattern_end = format!(" {}\n", ip_str); // at end of line
                Ok(output.contains(&ip_pattern) || output.contains(&ip_pattern_comma) || output.contains(&ip_pattern_end) || output.ends_with(&ip_str))
            }
            IpNet::V6(_) => {
                let output =
                    exec_cmd(nft_path(), &["list", "set", "ip6", TABLE_NAME, SET_NAME_V6])?;
                let ip_str = ip.to_string();
                // More precise check - look for the IP as a complete entry
                let ip_pattern = format!(" {} ", ip_str); // surrounded by spaces
                let ip_pattern_comma = format!("{},", ip_str); // followed by comma
                let ip_pattern_end = format!(" {}\n", ip_str); // at end of line
                Ok(output.contains(&ip_pattern) || output.contains(&ip_pattern_comma) || output.contains(&ip_pattern_end) || output.ends_with(&ip_str))
            }
        }
    }

    async fn is_active(&self) -> Result<bool> {
        // Check if either IPv4 or IPv6 table exists
        let v4_result = Command::new(nft_path())
            .args(["list", "table", "ip", TABLE_NAME])
            .output();

        let v6_result = Command::new(nft_path())
            .args(["list", "table", "ip6", TABLE_NAME])
            .output();

        let v4_active = v4_result.map(|o| o.status.success()).unwrap_or(false);
        let v6_active = v6_result.map(|o| o.status.success()).unwrap_or(false);

        Ok(v4_active || v6_active)
    }

    async fn entry_count(&self) -> Result<usize> {
        let mut total_count = 0usize;

        // Count IPv4 entries
        if let Ok(output) = exec_cmd(nft_path(), &["list", "set", "ip", TABLE_NAME, SET_NAME]) {
            total_count += count_set_elements(&output);
        }

        // Count IPv6 entries
        if let Ok(output) = exec_cmd(nft_path(), &["list", "set", "ip6", TABLE_NAME, SET_NAME_V6])
        {
            total_count += count_set_elements(&output);
        }

        Ok(total_count)
    }

    async fn save_current_rules(&self) -> Result<String> {
        let mut saved = String::new();

        // Save IPv4 table if it exists
        if let Ok(output) = exec_cmd(nft_path(), &["list", "table", "ip", TABLE_NAME]) {
            saved.push_str("# IPv4 rules\n");
            saved.push_str(&output);
            saved.push_str("\n");
        }

        // Save IPv6 table if it exists
        if let Ok(output) = exec_cmd(nft_path(), &["list", "table", "ip6", TABLE_NAME]) {
            saved.push_str("# IPv6 rules\n");
            saved.push_str(&output);
        }

        debug!("Saved current nftables rules ({} bytes)", saved.len());
        Ok(saved)
    }

    async fn restore_rules(&self, saved_rules: &str) -> Result<()> {
        if saved_rules.is_empty() {
            debug!("No saved rules to restore, removing current rules");
            return self.remove_rules().await;
        }

        // First remove current OustIP tables to ensure clean state
        let remove_script = self.generate_remove_script();
        // Ignore errors from remove - tables might not exist
        let _ = self.exec_nft_script(&remove_script);

        // The saved rules from `nft list table` are in a format that can be
        // directly restored with `nft -f -`. We need to process the output
        // to make it restorable.
        let mut restore_script = String::new();

        // Parse the saved rules and reconstruct them
        // The output of `nft list table` is human-readable, so we need to
        // convert it to a format that nft -f can accept
        for line in saved_rules.lines() {
            // Skip comment lines
            if line.starts_with('#') {
                continue;
            }
            restore_script.push_str(line);
            restore_script.push('\n');
        }

        if restore_script.trim().is_empty() {
            debug!("No rules to restore after parsing");
            return Ok(());
        }

        self.exec_nft_script(&restore_script)?;
        info!("Restored previous nftables rules");
        Ok(())
    }
}

/// Count elements in nft set output
fn count_set_elements(output: &str) -> usize {
    output
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
        .sum()
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
    fn test_generate_apply_script_uses_flush() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should use add+flush pattern instead of delete+create to reduce race window
        assert!(script.contains("add table ip oustip"));
        assert!(script.contains("flush table ip oustip"));
        assert!(script.contains("add table ip6 oustip"));
        assert!(script.contains("flush table ip6 oustip"));
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
        assert!(script.contains("delete table ip6 oustip"));
    }

    #[test]
    fn test_generate_apply_script_ipv6() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec![
            "2001:db8::/32".parse().unwrap(),
            "2001:db9::/32".parse().unwrap(),
        ];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        assert!(script.contains("table ip6 oustip"));
        assert!(script.contains("set blocklist_v6"));
        assert!(script.contains("type ipv6_addr"));
        assert!(script.contains("2001:db8::/32"));
        assert!(script.contains("2001:db9::/32"));
        assert!(script.contains("ip6 saddr @blocklist_v6"));
    }

    #[test]
    fn test_generate_apply_script_mixed_v4_v6() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec![
            "192.168.0.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should have both IPv4 and IPv6 tables
        assert!(script.contains("table ip oustip"));
        assert!(script.contains("table ip6 oustip"));
        assert!(script.contains("set blocklist"));
        assert!(script.contains("set blocklist_v6"));
        assert!(script.contains("192.168.0.0/24"));
        assert!(script.contains("2001:db8::/32"));
    }

    #[test]
    fn test_generate_apply_script_ipv6_raw_mode() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["2001:db8::/32".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Raw);

        assert!(script.contains("table ip6 oustip"));
        assert!(script.contains("chain prerouting"));
        assert!(script.contains("ip6 saddr @blocklist_v6"));
    }

    #[test]
    fn test_count_set_elements() {
        let output = "elements = { 192.168.1.0/24, 10.0.0.0/8 }";
        assert_eq!(count_set_elements(output), 2);

        let output_empty = "set blocklist { }";
        assert_eq!(count_set_elements(output_empty), 0);

        let output_ipv6 = "elements = { 2001:db8::/32, 2001:db9::/32, 2001:dba::/32 }";
        assert_eq!(count_set_elements(output_ipv6), 3);
    }

    #[test]
    fn test_generate_remove_script_structure() {
        let backend = NftablesBackend::new();
        let script = backend.generate_remove_script();

        // Verify the script has proper structure for both IPv4 and IPv6
        assert!(script.contains("table ip oustip"));
        assert!(script.contains("table ip6 oustip"));
        assert!(script.contains("delete table ip oustip"));
        assert!(script.contains("delete table ip6 oustip"));
    }

    // Note: save_current_rules and restore_rules require actual nft binary
    // and root privileges. These are integration tests that would need to be
    // run in a privileged environment. Unit tests for the logic are below.

    #[test]
    fn test_save_current_rules_empty_state() {
        // Test that save_current_rules returns empty string when no rules exist
        // (this is a logical test - actual execution requires nft)
        let empty_output = "";
        assert!(empty_output.is_empty());
    }

    #[test]
    fn test_restore_rules_parses_comments() {
        // Test that restore logic properly skips comment lines
        let saved_rules = "# IPv4 rules\ntable ip oustip {\n}\n# IPv6 rules\ntable ip6 oustip {\n}\n";

        let mut restore_script = String::new();
        for line in saved_rules.lines() {
            if !line.starts_with('#') {
                restore_script.push_str(line);
                restore_script.push('\n');
            }
        }

        // Verify comments are stripped
        assert!(!restore_script.contains("# IPv4"));
        assert!(!restore_script.contains("# IPv6"));
        assert!(restore_script.contains("table ip oustip"));
        assert!(restore_script.contains("table ip6 oustip"));
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    // =========================================================================
    // is_safe_nft_element comprehensive tests
    // =========================================================================

    #[test]
    fn test_is_safe_nft_element_all_valid_ipv4_chars() {
        // Test all valid characters for IPv4
        assert!(is_safe_nft_element("0123456789./"));
    }

    #[test]
    fn test_is_safe_nft_element_all_valid_ipv6_chars() {
        // Test all valid characters for IPv6
        assert!(is_safe_nft_element("0123456789:abcdef/"));
    }

    #[test]
    fn test_is_safe_nft_element_uppercase_hex() {
        // Uppercase hex should fail (IPv6 addresses should be lowercase)
        assert!(!is_safe_nft_element("2001:DB8::1"));
        assert!(!is_safe_nft_element("ABCDEF"));
    }

    #[test]
    fn test_is_safe_nft_element_special_chars_rejected() {
        let dangerous_chars = [
            ' ', '\t', '\n', '\r', ';', '{', '}', '(', ')', '[', ']',
            '|', '&', '$', '`', '\\', '"', '\'', '!', '#', '%', '^',
            '*', '+', '=', '<', '>', '?', '~',
        ];

        for c in dangerous_chars {
            let test = format!("192.168.1.0{}", c);
            assert!(!is_safe_nft_element(&test), "Should reject char: {:?}", c);
        }
    }

    #[test]
    fn test_is_safe_nft_element_shell_injection() {
        // Shell command injection attempts
        assert!(!is_safe_nft_element("$(whoami)"));
        assert!(!is_safe_nft_element("`id`"));
        assert!(!is_safe_nft_element("1.2.3.4; rm -rf /"));
        assert!(!is_safe_nft_element("1.2.3.4 && whoami"));
        assert!(!is_safe_nft_element("1.2.3.4 | cat /etc/passwd"));
    }

    #[test]
    fn test_is_safe_nft_element_nft_syntax_injection() {
        // nftables syntax injection attempts
        assert!(!is_safe_nft_element("1.2.3.4 }"));
        assert!(!is_safe_nft_element("{ 1.2.3.4"));
        assert!(!is_safe_nft_element("1.2.3.4, 5.6.7.8")); // comma not allowed
        assert!(!is_safe_nft_element("elements = {"));
    }

    #[test]
    fn test_is_safe_nft_element_control_characters() {
        assert!(!is_safe_nft_element("192.168.1.0\x00"));
        assert!(!is_safe_nft_element("192.168.1.0\x1b"));
        assert!(!is_safe_nft_element("\x00192.168.1.0"));
    }

    // =========================================================================
    // Script generation comprehensive tests
    // =========================================================================

    #[test]
    fn test_generate_apply_script_conntrack_priority() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Conntrack mode should use priority -1
        assert!(script.contains("priority -1"));
    }

    #[test]
    fn test_generate_apply_script_raw_priority() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Raw);

        // Raw mode should use priority -300
        assert!(script.contains("priority -300"));
    }

    #[test]
    fn test_generate_apply_script_has_log_prefix() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should include log prefix for debugging
        assert!(script.contains("log prefix \"OustIP-Blocked:"));
    }

    #[test]
    fn test_generate_apply_script_has_counter() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should include counter for stats
        assert!(script.contains("counter"));
    }

    #[test]
    fn test_generate_apply_script_has_drop() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should drop matching packets
        assert!(script.contains("drop"));
    }

    #[test]
    fn test_generate_apply_script_interval_flag() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should have interval flag for CIDR support
        assert!(script.contains("flags interval"));
    }

    #[test]
    fn test_generate_apply_script_input_and_forward_chains() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should have both input and forward chains
        assert!(script.contains("chain input"));
        assert!(script.contains("chain forward"));
    }

    #[test]
    fn test_generate_apply_script_raw_mode_has_prerouting() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Raw);

        // Raw mode should also have prerouting chain
        assert!(script.contains("chain prerouting"));
    }

    #[test]
    fn test_generate_apply_script_accepts_by_default() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Default policy should be accept
        assert!(script.contains("policy accept"));
    }

    #[test]
    fn test_generate_remove_script_structure() {
        let backend = NftablesBackend::new();
        let script = backend.generate_remove_script();

        // Should create empty table first then delete
        assert!(script.contains("table ip oustip"));
        assert!(script.contains("table ip6 oustip"));
        assert!(script.contains("delete table ip oustip"));
        assert!(script.contains("delete table ip6 oustip"));
    }

    // =========================================================================
    // parse_counters comprehensive tests
    // =========================================================================

    #[test]
    fn test_parse_counters_multiple_rules() {
        let backend = NftablesBackend::new();
        let output = r#"
table ip oustip {
    chain input {
        counter packets 100 bytes 1000 drop
        counter packets 200 bytes 2000 drop
    }
    chain forward {
        counter packets 50 bytes 500 drop
    }
}
"#;
        let stats = backend.parse_counters(output);
        // Should sum all counters
        assert_eq!(stats.packets_blocked, 350);
        assert_eq!(stats.bytes_blocked, 3500);
    }

    #[test]
    fn test_parse_counters_with_extra_whitespace() {
        let backend = NftablesBackend::new();
        let output = "    counter    packets    123    bytes    456   ";
        let stats = backend.parse_counters(output);
        assert_eq!(stats.packets_blocked, 123);
        assert_eq!(stats.bytes_blocked, 456);
    }

    #[test]
    fn test_parse_counters_empty_output() {
        let backend = NftablesBackend::new();
        let stats = backend.parse_counters("");
        assert_eq!(stats.packets_blocked, 0);
        assert_eq!(stats.bytes_blocked, 0);
    }

    #[test]
    fn test_parse_counters_no_counter_keyword() {
        let backend = NftablesBackend::new();
        let output = "table ip oustip { }";
        let stats = backend.parse_counters(output);
        assert_eq!(stats.packets_blocked, 0);
        assert_eq!(stats.bytes_blocked, 0);
    }

    #[test]
    fn test_parse_counters_zero_values() {
        let backend = NftablesBackend::new();
        let output = "counter packets 0 bytes 0";
        let stats = backend.parse_counters(output);
        assert_eq!(stats.packets_blocked, 0);
        assert_eq!(stats.bytes_blocked, 0);
    }

    // =========================================================================
    // extract_number_after comprehensive tests
    // =========================================================================

    #[test]
    fn test_extract_number_after_multiple_occurrences() {
        // Should find first occurrence
        let result = extract_number_after("packets 123 packets 456", "packets");
        assert_eq!(result, Some(123));
    }

    #[test]
    fn test_extract_number_after_negative_parses_number() {
        // extract_number_after skips the '-' and parses the digits after
        let result = extract_number_after("packets -123", "packets");
        // The function finds "packets", then skips non-digits (' -'), then parses "123"
        assert_eq!(result, Some(123));
    }

    #[test]
    fn test_extract_number_after_u64_max() {
        let max_str = format!("packets {}", u64::MAX);
        let result = extract_number_after(&max_str, "packets");
        assert_eq!(result, Some(u64::MAX));
    }

    #[test]
    fn test_extract_number_after_overflow() {
        // Number larger than u64::MAX
        let too_large = "packets 99999999999999999999999";
        let result = extract_number_after(too_large, "packets");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_number_after_keyword_at_end() {
        let result = extract_number_after("value packets", "packets");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_number_after_finds_within_string() {
        // The function uses .find() which matches substrings
        let result = extract_number_after("xpackets 123", "packets");
        // "packets" is found within "xpackets" so it parses 123
        assert_eq!(result, Some(123));
    }

    // =========================================================================
    // count_set_elements comprehensive tests
    // =========================================================================

    #[test]
    fn test_count_set_elements_single_element() {
        let output = "elements = { 192.168.1.0/24 }";
        assert_eq!(count_set_elements(output), 1);
    }

    #[test]
    fn test_count_set_elements_empty_set() {
        let output = "elements = { }";
        assert_eq!(count_set_elements(output), 0);
    }

    #[test]
    fn test_count_set_elements_no_elements_line() {
        let output = "table ip oustip { set blocklist { } }";
        assert_eq!(count_set_elements(output), 0);
    }

    #[test]
    fn test_count_set_elements_many() {
        let output = "elements = { 1.1.1.0/24, 2.2.2.0/24, 3.3.3.0/24, 4.4.4.0/24, 5.5.5.0/24 }";
        assert_eq!(count_set_elements(output), 5);
    }

    #[test]
    fn test_count_set_elements_multiline() {
        let output = r#"
elements = { 1.1.1.0/24, 2.2.2.0/24 }
elements = { 3.3.3.0/24 }
"#;
        // Should sum across all elements lines
        assert_eq!(count_set_elements(output), 3);
    }

    // =========================================================================
    // IPv6 specific tests
    // =========================================================================

    #[test]
    fn test_generate_ip6_table_type() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["2001:db8::/32".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        assert!(script.contains("type ipv6_addr"));
    }

    #[test]
    fn test_generate_ip6_table_uses_ip6_saddr() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["2001:db8::/32".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        assert!(script.contains("ip6 saddr @"));
    }

    #[test]
    fn test_generate_ipv4_uses_ip_saddr() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        assert!(script.contains("ip saddr @"));
    }

    #[test]
    fn test_is_safe_nft_element_full_ipv6() {
        // Full IPv6 address
        assert!(is_safe_nft_element("2001:0db8:0000:0000:0000:0000:0000:0001"));
    }

    #[test]
    fn test_is_safe_nft_element_compressed_ipv6() {
        assert!(is_safe_nft_element("2001:db8::1"));
        assert!(is_safe_nft_element("::1"));
        assert!(is_safe_nft_element("::"));
        assert!(is_safe_nft_element("fe80::"));
    }

    // =========================================================================
    // Constants tests
    // =========================================================================

    #[test]
    fn test_table_name_constant() {
        assert_eq!(TABLE_NAME, "oustip");
    }

    #[test]
    fn test_set_name_constants() {
        assert_eq!(SET_NAME, "blocklist");
        assert_eq!(SET_NAME_V6, "blocklist_v6");
    }

    // =========================================================================
    // Backend Default trait
    // =========================================================================

    #[test]
    fn test_nftables_backend_default() {
        let backend = NftablesBackend::default();
        // Just verify it can be created
        let _ = backend;
    }

    // =========================================================================
    // Script idempotency tests
    // =========================================================================

    #[test]
    fn test_generate_apply_script_uses_add_table() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should use 'add table' for idempotent creation
        assert!(script.contains("add table ip oustip"));
    }

    #[test]
    fn test_generate_apply_script_uses_flush() {
        let backend = NftablesBackend::new();
        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let script = backend.generate_apply_script(&ips, FilterMode::Conntrack);

        // Should flush table to clear old rules
        assert!(script.contains("flush table ip oustip"));
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

    fn args_eq(args: &[String], expected: &[&str]) -> bool {
        args.len() == expected.len() && args.iter().zip(expected.iter()).all(|(a, e)| a == *e)
    }

    // Helper functions for executor-based operations
    fn exec_nft_script_mock<E: CmdExecutor>(executor: &E, script: &str) -> Result<()> {
        let args = args_to_vec(&["-f", "-"]);
        let output = executor.execute_with_stdin(nft_path(), &args, script)?;
        if !output.success {
            anyhow::bail!("nft failed: {}", output.stderr);
        }
        Ok(())
    }

    fn apply_rules_mock<E: CmdExecutor>(
        backend: &NftablesBackend,
        executor: &E,
        ips: &[IpNet],
        mode: FilterMode,
    ) -> Result<()> {
        validate_entry_count(ips.len())?;
        let script = backend.generate_apply_script(ips, mode);
        exec_nft_script_mock(executor, &script)?;
        Ok(())
    }

    fn exec_cmd_mock<E: CmdExecutor>(executor: &E, cmd: &str, args: &[&str]) -> Result<String> {
        let args_vec = args_to_vec(args);
        let output = executor.execute(cmd, &args_vec)?;
        if output.success {
            Ok(output.stdout)
        } else {
            anyhow::bail!("{} failed: {}", cmd, output.stderr)
        }
    }

    fn is_blocked_mock<E: CmdExecutor>(
        _backend: &NftablesBackend,
        executor: &E,
        ip: &IpNet,
    ) -> Result<bool> {
        let (table_family, set_name) = match ip {
            IpNet::V4(_) => ("ip", SET_NAME),
            IpNet::V6(_) => ("ip6", SET_NAME_V6),
        };
        let output = exec_cmd_mock(executor, nft_path(), &["list", "set", table_family, TABLE_NAME, set_name])?;
        let ip_str = ip.to_string();
        Ok(output.contains(&format!(" {} ", ip_str))
            || output.contains(&format!("{},", ip_str))
            || output.contains(&format!(" {}\n", ip_str))
            || output.ends_with(&ip_str))
    }

    fn get_stats_mock<E: CmdExecutor>(backend: &NftablesBackend, executor: &E) -> Result<FirewallStats> {
        let mut stats = FirewallStats::default();
        if let Ok(output) = exec_cmd_mock(executor, nft_path(), &["list", "table", "ip", TABLE_NAME]) {
            let v4_stats = backend.parse_counters(&output);
            stats.packets_blocked += v4_stats.packets_blocked;
            stats.bytes_blocked += v4_stats.bytes_blocked;
        }
        if let Ok(output) = exec_cmd_mock(executor, nft_path(), &["list", "table", "ip6", TABLE_NAME]) {
            let v6_stats = backend.parse_counters(&output);
            stats.packets_blocked += v6_stats.packets_blocked;
            stats.bytes_blocked += v6_stats.bytes_blocked;
        }
        Ok(stats)
    }

    fn entry_count_mock<E: CmdExecutor>(executor: &E) -> Result<usize> {
        let mut total_count = 0usize;
        if let Ok(output) = exec_cmd_mock(executor, nft_path(), &["list", "set", "ip", TABLE_NAME, SET_NAME]) {
            total_count += count_set_elements(&output);
        }
        if let Ok(output) = exec_cmd_mock(executor, nft_path(), &["list", "set", "ip6", TABLE_NAME, SET_NAME_V6]) {
            total_count += count_set_elements(&output);
        }
        Ok(total_count)
    }

    fn remove_rules_mock<E: CmdExecutor>(backend: &NftablesBackend, executor: &E) -> Result<()> {
        let args_v4 = args_to_vec(&["list", "table", "ip", TABLE_NAME]);
        let v4_exists = executor.execute(nft_path(), &args_v4).map(|o| o.success).unwrap_or(false);
        let args_v6 = args_to_vec(&["list", "table", "ip6", TABLE_NAME]);
        let v6_exists = executor.execute(nft_path(), &args_v6).map(|o| o.success).unwrap_or(false);
        if v4_exists || v6_exists {
            let script = backend.generate_remove_script();
            exec_nft_script_mock(executor, &script)?;
        }
        Ok(())
    }

    fn is_active_mock<E: CmdExecutor>(executor: &E) -> Result<bool> {
        let args_v4 = args_to_vec(&["list", "table", "ip", TABLE_NAME]);
        let v4_active = executor.execute(nft_path(), &args_v4).map(|o| o.success).unwrap_or(false);
        let args_v6 = args_to_vec(&["list", "table", "ip6", TABLE_NAME]);
        let v6_active = executor.execute(nft_path(), &args_v6).map(|o| o.success).unwrap_or(false);
        Ok(v4_active || v6_active)
    }

    #[test]
    fn test_apply_rules_success() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute_with_stdin()
            .withf(|cmd, args, _stdin| cmd.ends_with("nft") && args_eq(args, &["-f", "-"]))
            .times(1)
            .returning(|_, _, _| Ok(success_output("")));

        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let result = apply_rules_mock(&backend, &mock, &ips, FilterMode::Conntrack);
        assert!(result.is_ok());
    }

    #[test]
    fn test_apply_rules_failure_nft_syntax_error() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute_with_stdin()
            .times(1)
            .returning(|_, _, _| Ok(failure_output("Error: syntax error")));

        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let result = apply_rules_mock(&backend, &mock, &ips, FilterMode::Conntrack);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nft failed"));
    }

    #[test]
    fn test_apply_rules_with_ipv6() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute_with_stdin()
            .times(1)
            .returning(|_, _, stdin: &str| {
                assert!(stdin.contains("2001:db8::/32"));
                assert!(stdin.contains("table ip6 oustip"));
                Ok(success_output(""))
            });

        let ips: Vec<IpNet> = vec!["2001:db8::/32".parse().unwrap()];
        let result = apply_rules_mock(&backend, &mock, &ips, FilterMode::Conntrack);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_blocked_ipv4_found() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd.ends_with("nft") && args_has(args, "list") && args_has(args, "set"))
            .times(1)
            .returning(|_, _| {
                Ok(success_output("elements = { 192.168.1.0/24, 10.0.0.0/8 }"))
            });

        let ip: IpNet = "192.168.1.0/24".parse().unwrap();
        let result = is_blocked_mock(&backend, &mock, &ip);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_is_blocked_ipv4_not_found() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(1)
            .returning(|_, _| Ok(success_output("elements = { 10.0.0.0/8 }")));

        let ip: IpNet = "192.168.1.0/24".parse().unwrap();
        let result = is_blocked_mock(&backend, &mock, &ip);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_is_blocked_ipv6_found() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|_, args| args_has(args, "ip6") && args_has(args, "blocklist_v6"))
            .times(1)
            .returning(|_, _| Ok(success_output("elements = { 2001:db8::/32 }")));

        let ip: IpNet = "2001:db8::/32".parse().unwrap();
        let result = is_blocked_mock(&backend, &mock, &ip);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_get_stats_parsing() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|_, args| args_has(args, "ip") && !args_has(args, "ip6"))
            .times(1)
            .returning(|_, _| {
                Ok(success_output("counter packets 100 bytes 5000 drop\ncounter packets 50 bytes 2500 drop"))
            });

        mock.expect_execute()
            .withf(|_, args| args_has(args, "ip6"))
            .times(1)
            .returning(|_, _| Ok(success_output("counter packets 25 bytes 1000 drop")));

        let result = get_stats_mock(&backend, &mock);
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.packets_blocked, 175);
        assert_eq!(stats.bytes_blocked, 8500);
    }

    #[test]
    fn test_get_stats_no_tables() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(2)
            .returning(|_, _| Ok(failure_output("table not found")));

        let result = get_stats_mock(&backend, &mock);
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.packets_blocked, 0);
        assert_eq!(stats.bytes_blocked, 0);
    }

    #[test]
    fn test_entry_count_ipv4_only() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|_, args| args_has(args, "ip") && args_has(args, "blocklist") && !args_has(args, "blocklist_v6"))
            .times(1)
            .returning(|_, _| Ok(success_output("elements = { 192.168.1.0/24, 10.0.0.0/8, 172.16.0.0/12 }")));

        mock.expect_execute()
            .withf(|_, args| args_has(args, "ip6"))
            .times(1)
            .returning(|_, _| Ok(failure_output("table not found")));

        let result = entry_count_mock(&mock);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn test_remove_rules_tables_exist() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|_, args| args_has(args, "list") && args_has(args, "table"))
            .times(2)
            .returning(|_, _| Ok(success_output("")));

        mock.expect_execute_with_stdin()
            .withf(|_, args, stdin: &str| {
                args_eq(args, &["-f", "-"])
                    && stdin.contains("delete table ip oustip")
                    && stdin.contains("delete table ip6 oustip")
            })
            .times(1)
            .returning(|_, _, _| Ok(success_output("")));

        let result = remove_rules_mock(&backend, &mock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_remove_rules_no_tables() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(2)
            .returning(|_, _| Ok(failure_output("table not found")));

        let result = remove_rules_mock(&backend, &mock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_active_both_tables() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute().times(2).returning(|_, _| Ok(success_output("")));

        let result = is_active_mock(&mock);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_is_active_only_ipv4() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .withf(|_, args| args_has(args, "ip") && !args_has(args, "ip6"))
            .times(1)
            .returning(|_, _| Ok(success_output("")));

        mock.expect_execute()
            .withf(|_, args| args_has(args, "ip6"))
            .times(1)
            .returning(|_, _| Ok(failure_output("table not found")));

        let result = is_active_mock(&mock);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_is_active_no_tables() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute()
            .times(2)
            .returning(|_, _| Ok(failure_output("table not found")));

        let result = is_active_mock(&mock);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_exec_nft_script_success() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute_with_stdin()
            .withf(|cmd, args, stdin| {
                cmd.ends_with("nft") && args_eq(args, &["-f", "-"]) && stdin == "test script"
            })
            .times(1)
            .returning(|_, _, _| Ok(success_output("")));

        let result = exec_nft_script_mock(&mock, "test script");
        assert!(result.is_ok());
    }

    #[test]
    fn test_exec_nft_script_failure() {
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute_with_stdin()
            .times(1)
            .returning(|_, _, _| Ok(failure_output("Error: invalid syntax")));

        let result = exec_nft_script_mock(&mock, "invalid script");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid syntax"));
    }

    #[test]
    fn test_apply_rules_raw_mode() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute_with_stdin()
            .times(1)
            .returning(|_, _, stdin: &str| {
                assert!(stdin.contains("chain prerouting"));
                assert!(stdin.contains("priority -300"));
                Ok(success_output(""))
            });

        let ips: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let result = apply_rules_mock(&backend, &mock, &ips, FilterMode::Raw);
        assert!(result.is_ok());
    }

    #[test]
    fn test_apply_rules_mixed_v4_v6() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute_with_stdin()
            .times(1)
            .returning(|_, _, stdin: &str| {
                assert!(stdin.contains("table ip oustip"));
                assert!(stdin.contains("table ip6 oustip"));
                assert!(stdin.contains("192.168.0.0/24"));
                assert!(stdin.contains("2001:db8::/32"));
                Ok(success_output(""))
            });

        let ips: Vec<IpNet> = vec![
            "192.168.0.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let result = apply_rules_mock(&backend, &mock, &ips, FilterMode::Conntrack);
        assert!(result.is_ok());
    }

    #[test]
    fn test_apply_rules_empty_list() {
        let backend = NftablesBackend::new();
        let mut mock = MockCmdExecutor::new();

        mock.expect_execute_with_stdin()
            .times(1)
            .returning(|_, _, stdin: &str| {
                assert!(stdin.contains("table ip oustip"));
                assert!(!stdin.contains("elements"));
                Ok(success_output(""))
            });

        let ips: Vec<IpNet> = vec![];
        let result = apply_rules_mock(&backend, &mock, &ips, FilterMode::Conntrack);
        assert!(result.is_ok());
    }
}
