//! Config validation tests - deep configuration verification.
//!
//! These tests go beyond basic parsing to verify that the configuration
//! values are correct, consistent, and likely to work in practice.

use std::path::Path;
use std::time::Instant;

use crate::config::{Backend, Config, FilterMode};
use crate::presets::PresetsConfig;

use super::output::{DiagnosticResult, Severity, TestCategory};

/// Run all config validation tests
pub async fn run_tests(config_path: &Path) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    // Load config first (needed for other tests)
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(_) => {
            // Config loading already tested in smoke tests
            results.push(DiagnosticResult::skip(
                "config_all",
                "Config validation",
                TestCategory::Config,
                "Config file could not be loaded (see smoke tests)",
            ));
            return results;
        }
    };

    results.push(test_preset_validity(&config));
    results.push(test_update_interval(&config));
    results.push(test_blocklist_urls(&config));
    results.push(test_allowlist_validity(&config));
    results.push(test_alert_config(&config));
    results.push(test_backend_config(&config));
    results.push(test_mode_config(&config));
    results.push(test_presets_file_exists());
    results.push(test_interface_config(&config));

    results
}

/// Test: Preset is valid
fn test_preset_validity(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_preset_valid";
    let test_name = "Preset configuration";

    let valid_presets = ["minimal", "recommended", "full", "paranoid"];

    if valid_presets.contains(&config.preset.as_str()) {
        let blocklist_count = config.get_enabled_blocklists(None).len();
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Config,
            &format!(
                "Preset '{}' is valid ({} blocklists enabled)",
                config.preset, blocklist_count
            ),
            start.elapsed().as_millis() as u64,
        )
    } else if config.preset.is_empty() {
        DiagnosticResult::warning(
            test_id,
            test_name,
            TestCategory::Config,
            "No preset specified, using individual blocklist flags",
            "When no preset is specified, oustip uses the 'enabled' flag on each blocklist. \
             This is valid but harder to maintain than using a preset.",
            "Consider using a preset like 'recommended' for easier management: preset: recommended",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Config,
            Severity::Warning,
            &format!("Unknown preset '{}'", config.preset),
            "One of: minimal, recommended, full, paranoid",
            &config.preset,
            &format!(
                "The preset '{}' is not recognized. Valid presets are: {}. \
                 With an invalid preset, oustip falls back to individual blocklist flags.",
                config.preset,
                valid_presets.join(", ")
            ),
            "Change the preset to a valid value. Recommended: 'preset: recommended' \
             for balanced protection, or 'preset: paranoid' for maximum protection.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Update interval is reasonable
fn test_update_interval(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_update_interval";
    let test_name = "Update interval configuration";

    let interval = &config.update_interval;

    // Parse interval to check reasonableness
    let (value, unit) = if let Some(stripped) = interval.strip_suffix('h') {
        (stripped.parse::<u32>().ok(), "hours")
    } else if let Some(stripped) = interval.strip_suffix('m') {
        (stripped.parse::<u32>().ok(), "minutes")
    } else if let Some(stripped) = interval.strip_suffix('d') {
        (stripped.parse::<u32>().ok(), "days")
    } else if let Some(stripped) = interval.strip_suffix('s') {
        (stripped.parse::<u32>().ok(), "seconds")
    } else {
        (None, "unknown")
    };

    match value {
        Some(v) => {
            // Convert to hours for comparison
            let hours = match unit {
                "hours" => v,
                "minutes" => v / 60,
                "days" => v * 24,
                "seconds" => v / 3600,
                _ => 0,
            };

            if hours == 0 && unit == "minutes" && v < 30 {
                DiagnosticResult::warning(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    &format!("Update interval {} is very frequent", interval),
                    "Updating more frequently than every 30 minutes may cause unnecessary load \
                     on blocklist servers and could result in rate limiting.",
                    "Consider using at least '30m' or '1h' for the update interval.",
                    start.elapsed().as_millis() as u64,
                )
            } else if hours > 48 {
                DiagnosticResult::warning(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    &format!("Update interval {} is quite long", interval),
                    "Updating less frequently than every 48 hours means your blocklist may be \
                     outdated. New threats are added to blocklists regularly.",
                    "Consider using '4h' to '24h' for a good balance of freshness and server load.",
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    &format!("Update interval '{}' is reasonable", interval),
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        None => DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Config,
            Severity::Warning,
            "Cannot parse update interval",
            "Valid interval like '4h', '30m', '1d'",
            interval,
            "The update_interval could not be parsed. It should be a number followed by \
             a unit: 's' for seconds, 'm' for minutes, 'h' for hours, 'd' for days.",
            "Set update_interval to a valid value like: update_interval: 4h",
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Test: Blocklist URLs are valid
fn test_blocklist_urls(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_blocklist_urls";
    let test_name = "Blocklist URL validation";

    let enabled_lists = config.get_enabled_blocklists(None);

    if enabled_lists.is_empty() {
        return DiagnosticResult::warning(
            test_id,
            test_name,
            TestCategory::Config,
            "No blocklists are enabled",
            "Without any blocklists enabled, oustip will not block any IP addresses. \
             This defeats the purpose of the application.",
            "Enable blocklists by setting a preset (preset: recommended) or enabling \
             individual lists with 'enabled: true'.",
            start.elapsed().as_millis() as u64,
        );
    }

    let mut issues = Vec::new();

    for list in &enabled_lists {
        // Check URL scheme
        if !list.url.starts_with("https://") {
            issues.push(format!("{}: URL must use HTTPS", list.name));
        }

        // Check URL format
        if reqwest::Url::parse(&list.url).is_err() {
            issues.push(format!("{}: Invalid URL format", list.name));
        }
    }

    if issues.is_empty() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Config,
            &format!("{} blocklist URLs validated", enabled_lists.len()),
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Config,
            Severity::Warning,
            &format!("{} blocklist URL issues found", issues.len()),
            "All URLs should be valid HTTPS URLs",
            &issues.join("; "),
            "Some blocklist URLs have issues. Invalid URLs will fail to fetch during updates.",
            "Fix the URLs in the config file or presets.yaml. Ensure all URLs start with 'https://'.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Allowlist entries are valid
fn test_allowlist_validity(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_allowlist_valid";
    let test_name = "Allowlist validation";

    let mut valid_count = 0;
    let mut invalid_entries = Vec::new();

    for entry in &config.allowlist {
        if entry.parse::<ipnet::IpNet>().is_ok() || entry.parse::<std::net::IpAddr>().is_ok() {
            valid_count += 1;
        } else {
            invalid_entries.push(entry.clone());
        }
    }

    if invalid_entries.is_empty() {
        let rfc1918 = config
            .allowlist
            .iter()
            .any(|e| e.contains("192.168") || e.contains("10.0") || e.contains("172.16"));

        if rfc1918 {
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Config,
                &format!(
                    "{} valid allowlist entries (includes RFC1918 private ranges)",
                    valid_count
                ),
                start.elapsed().as_millis() as u64,
            )
        } else {
            DiagnosticResult::warning(
                test_id,
                test_name,
                TestCategory::Config,
                &format!("{} valid entries, but RFC1918 ranges not found", valid_count),
                "The allowlist does not include RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, \
                 192.168.0.0/16). This could block legitimate local network traffic.",
                "Add RFC1918 ranges to the allowlist to prevent blocking local network traffic.",
                start.elapsed().as_millis() as u64,
            )
        }
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Config,
            Severity::Warning,
            &format!("{} invalid allowlist entries", invalid_entries.len()),
            "Valid IP addresses or CIDR ranges",
            &invalid_entries.join(", "),
            "Some allowlist entries are not valid IP addresses or CIDR ranges. These will be \
             ignored during processing.",
            "Fix or remove the invalid entries. Valid formats: '192.168.1.1' (single IP) or \
             '192.168.0.0/16' (CIDR range).",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Alert configuration
fn test_alert_config(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_alerts";
    let test_name = "Alert configuration";

    let alerts = &config.alerts;
    let mut enabled_alerts = Vec::new();
    let mut issues = Vec::new();

    if alerts.gotify.enabled {
        enabled_alerts.push("Gotify");
        if alerts.gotify.url.is_empty() {
            issues.push("Gotify enabled but URL is empty");
        }
        if alerts.gotify.token.is_empty() && alerts.gotify.token_env.is_none() {
            issues.push("Gotify enabled but no token configured");
        }
    }

    if alerts.email.enabled {
        enabled_alerts.push("Email");
        if alerts.email.smtp_host.is_empty() {
            issues.push("Email enabled but SMTP host is empty");
        }
        if alerts.email.from.is_empty() || alerts.email.to.is_empty() {
            issues.push("Email enabled but from/to addresses are empty");
        }
    }

    if alerts.webhook.enabled {
        enabled_alerts.push("Webhook");
        if alerts.webhook.url.is_empty() {
            issues.push("Webhook enabled but URL is empty");
        }
    }

    if enabled_alerts.is_empty() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Config,
            "No alerts configured (optional feature)",
            start.elapsed().as_millis() as u64,
        )
    } else if issues.is_empty() {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Config,
            &format!("Alerts configured: {}", enabled_alerts.join(", ")),
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::fail(
            test_id,
            test_name,
            TestCategory::Config,
            Severity::Warning,
            "Alert configuration has issues",
            "Complete alert configuration",
            &issues.join("; "),
            "Some alerts are enabled but missing required configuration. They will fail to send.",
            "Complete the configuration for each enabled alert type, or disable alerts you don't need.",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Backend configuration
fn test_backend_config(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_backend";
    let test_name = "Backend configuration";

    let backend_str = match config.backend {
        Backend::Auto => "auto",
        Backend::Nftables => "nftables",
        Backend::Iptables => "iptables",
    };

    // Check if the specified backend is available
    let nft_available = std::process::Command::new("nft")
        .arg("--version")
        .output()
        .is_ok();
    let ipt_available = std::process::Command::new("iptables")
        .arg("--version")
        .output()
        .is_ok();

    match config.backend {
        Backend::Auto => {
            if nft_available {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    "Backend: auto (nftables available, will be used)",
                    start.elapsed().as_millis() as u64,
                )
            } else if ipt_available {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    "Backend: auto (iptables available, will be used)",
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::fail(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    Severity::Critical,
                    "No firewall backend available",
                    "nftables or iptables installed",
                    "Neither nft nor iptables found",
                    "OustIP requires either nftables or iptables to function. Neither is available on this system.",
                    "Install nftables (recommended): 'apt install nftables' or 'dnf install nftables'. \
                     Alternatively, install iptables: 'apt install iptables ipset'.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        Backend::Nftables => {
            if nft_available {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    "Backend: nftables (available)",
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::fail(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    Severity::Critical,
                    "nftables backend configured but not available",
                    "nft command available",
                    "nft command not found",
                    "The config specifies nftables backend, but the 'nft' command is not available.",
                    "Install nftables: 'apt install nftables' or 'dnf install nftables'. \
                     Or change backend to 'auto' or 'iptables' in the config.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
        Backend::Iptables => {
            if ipt_available {
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    &format!("Backend: {} (available)", backend_str),
                    start.elapsed().as_millis() as u64,
                )
            } else {
                DiagnosticResult::fail(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    Severity::Critical,
                    "iptables backend configured but not available",
                    "iptables command available",
                    "iptables command not found",
                    "The config specifies iptables backend, but the 'iptables' command is not available.",
                    "Install iptables: 'apt install iptables ipset' or 'dnf install iptables ipset'. \
                     Or change backend to 'auto' or 'nftables' in the config.",
                    start.elapsed().as_millis() as u64,
                )
            }
        }
    }
}

/// Test: Filter mode configuration
fn test_mode_config(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_mode";
    let test_name = "Filter mode configuration";

    let mode_str = match config.mode {
        FilterMode::Raw => "raw",
        FilterMode::Conntrack => "conntrack",
    };

    match config.mode {
        FilterMode::Raw => {
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Config,
                &format!(
                    "Filter mode: {} (blocks before connection tracking, highest performance)",
                    mode_str
                ),
                start.elapsed().as_millis() as u64,
            )
        }
        FilterMode::Conntrack => {
            DiagnosticResult::pass(
                test_id,
                test_name,
                TestCategory::Config,
                &format!(
                    "Filter mode: {} (allows responses to LAN-initiated connections)",
                    mode_str
                ),
                start.elapsed().as_millis() as u64,
            )
        }
    }
}

/// Test: Presets file exists
fn test_presets_file_exists() -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_presets_file";
    let test_name = "Presets file exists";
    let presets_path = Path::new("/etc/oustip/presets.yaml");

    if presets_path.exists() {
        match PresetsConfig::load(presets_path) {
            Ok(presets) => {
                let blocklist_count = presets.list_blocklist_presets().len();
                let allowlist_count = presets.list_allowlist_presets().len();
                DiagnosticResult::pass(
                    test_id,
                    test_name,
                    TestCategory::Config,
                    &format!(
                        "Presets file valid ({} blocklist, {} allowlist presets)",
                        blocklist_count, allowlist_count
                    ),
                    start.elapsed().as_millis() as u64,
                )
            }
            Err(e) => DiagnosticResult::fail(
                test_id,
                test_name,
                TestCategory::Config,
                Severity::Warning,
                "Presets file exists but is invalid",
                "Valid YAML presets file",
                &e.to_string(),
                "The presets.yaml file exists but could not be parsed. Built-in presets will be used.",
                "Fix the YAML syntax in /etc/oustip/presets.yaml or delete it to use built-in presets.",
                start.elapsed().as_millis() as u64,
            ),
        }
    } else {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Config,
            "Presets file not present (using built-in presets)",
            start.elapsed().as_millis() as u64,
        )
    }
}

/// Test: Interface-based configuration
fn test_interface_config(config: &Config) -> DiagnosticResult {
    let start = Instant::now();
    let test_id = "config_interfaces";
    let test_name = "Interface configuration";

    if !config.is_interface_based() {
        return DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Config,
            "Using legacy mode (no per-interface configuration)",
            start.elapsed().as_millis() as u64,
        );
    }

    let interfaces = config.get_interfaces().unwrap();

    if interfaces.is_empty() {
        return DiagnosticResult::warning(
            test_id,
            test_name,
            TestCategory::Config,
            "Interface mode enabled but no interfaces configured",
            "The 'interfaces' section is present but empty. No firewall rules will be applied.",
            "Add interface configurations or remove the 'interfaces' section to use legacy mode.",
            start.elapsed().as_millis() as u64,
        );
    }

    let wan_count = config.get_wan_interfaces().len();
    let lan_count = config.get_lan_interfaces().len();
    let trusted_count = config.get_trusted_interfaces().len();

    if wan_count == 0 {
        DiagnosticResult::warning(
            test_id,
            test_name,
            TestCategory::Config,
            &format!(
                "{} interfaces configured but no WAN interface",
                interfaces.len()
            ),
            "No WAN interface is configured. Without a WAN interface, incoming traffic will not be filtered.",
            "Add a WAN interface configuration with blocklist_preset to filter incoming traffic.",
            start.elapsed().as_millis() as u64,
        )
    } else {
        DiagnosticResult::pass(
            test_id,
            test_name,
            TestCategory::Config,
            &format!(
                "Interface mode: {} WAN, {} LAN, {} trusted",
                wan_count, lan_count, trusted_count
            ),
            start.elapsed().as_millis() as u64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_validity_recommended() {
        let config = Config {
            preset: "recommended".to_string(),
            ..Default::default()
        };
        let result = test_preset_validity(&config);
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_preset_validity_invalid() {
        let config = Config {
            preset: "invalid_preset".to_string(),
            ..Default::default()
        };
        let result = test_preset_validity(&config);
        assert_eq!(result.status, super::super::output::TestStatus::Failed);
    }

    #[test]
    fn test_update_interval_reasonable() {
        let config = Config {
            update_interval: "4h".to_string(),
            ..Default::default()
        };
        let result = test_update_interval(&config);
        assert_eq!(result.status, super::super::output::TestStatus::Passed);
    }

    #[test]
    fn test_update_interval_too_long() {
        let config = Config {
            update_interval: "7d".to_string(),
            ..Default::default()
        };
        let result = test_update_interval(&config);
        assert_eq!(result.status, super::super::output::TestStatus::Warning);
    }
}
