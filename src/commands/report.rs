//! Report command implementation.
//!
//! Generate statistics reports in various formats (text, JSON, email).

use anyhow::Result;
use chrono::{DateTime, Local, Utc};
use serde::Serialize;
use std::path::Path;

use crate::alerts::AlertManager;
use crate::config::Config;
use crate::enforcer::create_backend;
use crate::stats::OustipState;
use crate::utils::{format_bytes, format_count, truncate};

/// Report output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Text,
    Json,
    Markdown,
}

impl std::str::FromStr for ReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" | "txt" => Ok(ReportFormat::Text),
            "json" => Ok(ReportFormat::Json),
            "markdown" | "md" => Ok(ReportFormat::Markdown),
            _ => Err(format!(
                "Unknown format: {}. Use text, json, or markdown",
                s
            )),
        }
    }
}

/// Report data structure for JSON serialization
#[derive(Debug, Serialize)]
pub struct Report {
    pub generated_at: DateTime<Utc>,
    pub hostname: String,
    pub status: StatusInfo,
    pub blocking: BlockingStats,
    pub sources: Vec<SourceInfo>,
    pub top_blocked: Vec<TopBlockedIp>,
}

#[derive(Debug, Serialize)]
pub struct StatusInfo {
    pub active: bool,
    pub backend: String,
    pub entries_in_set: usize,
    pub last_update: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct BlockingStats {
    pub packets_blocked: u64,
    pub bytes_blocked: u64,
    pub bytes_blocked_human: String,
}

#[derive(Debug, Serialize)]
pub struct SourceInfo {
    pub name: String,
    pub ip_count: u128,
    pub raw_count: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct TopBlockedIp {
    pub ip: String,
    pub count: u64,
    pub hostname: Option<String>,
}

// ============================================================================
// Formatter Trait and Implementations
// ============================================================================

/// Trait for formatting reports in different output formats
trait ReportFormatter {
    fn format(&self, report: &Report) -> String;
}

/// Plain text formatter
struct TextFormatter;

impl TextFormatter {
    const BORDER: &'static str =
        "══════════════════════════════════════════════════════════════════";
    const DIVIDER: &'static str =
        " ────────────────────────────────────────────────────────────────";

    fn format_header(&self, report: &Report) -> String {
        let local: DateTime<Local> = report.generated_at.into();
        format!(
            "{}\n OUSTIP REPORT\n{}\n\n Generated: {}\n Hostname:  {}\n\n",
            Self::BORDER,
            Self::BORDER,
            local.format("%Y-%m-%d %H:%M:%S"),
            report.hostname
        )
    }

    fn format_status(&self, status: &StatusInfo) -> String {
        let mut out = format!(" STATUS\n{}\n", Self::DIVIDER);
        out.push_str(&format!(
            " Active:    {}\n",
            if status.active { "YES" } else { "NO" }
        ));
        out.push_str(&format!(" Backend:   {}\n", status.backend));
        out.push_str(&format!(
            " Entries:   {}\n",
            format_count(status.entries_in_set)
        ));
        if let Some(last) = status.last_update {
            let local: DateTime<Local> = last.into();
            out.push_str(&format!(
                " Updated:   {}\n",
                local.format("%Y-%m-%d %H:%M:%S")
            ));
        }
        out.push('\n');
        out
    }

    fn format_blocking(&self, blocking: &BlockingStats) -> String {
        format!(
            " BLOCKING STATISTICS (since boot)\n{}\n Packets:   {}\n Bytes:     {}\n\n",
            Self::DIVIDER,
            format_count(blocking.packets_blocked as usize),
            blocking.bytes_blocked_human
        )
    }

    fn format_sources(&self, sources: &[SourceInfo]) -> String {
        if sources.is_empty() {
            return String::new();
        }
        let mut out = format!(" SOURCES\n{}\n NAME                 IPs          ENTRIES\n", Self::DIVIDER);
        for src in sources {
            out.push_str(&format!(
                " {:<20} {:>12} {:>12}\n",
                truncate(&src.name, 20),
                format_count(src.ip_count as usize),
                format_count(src.raw_count)
            ));
        }
        out.push('\n');
        out
    }

    fn format_top_blocked(&self, top_blocked: &[TopBlockedIp]) -> String {
        if top_blocked.is_empty() {
            return String::new();
        }
        let mut out = format!(
            " TOP BLOCKED IPs (last 24h)\n{}\n IP                          ATTEMPTS\n",
            Self::DIVIDER
        );
        for ip in top_blocked {
            out.push_str(&format!(
                " {:<28} {:>8}\n",
                ip.ip,
                format_count(ip.count as usize)
            ));
        }
        out.push('\n');
        out
    }
}

impl ReportFormatter for TextFormatter {
    fn format(&self, report: &Report) -> String {
        let mut out = self.format_header(report);
        out.push_str(&self.format_status(&report.status));
        out.push_str(&self.format_blocking(&report.blocking));
        out.push_str(&self.format_sources(&report.sources));
        out.push_str(&self.format_top_blocked(&report.top_blocked));
        out.push_str(Self::BORDER);
        out.push('\n');
        out
    }
}

/// Markdown formatter
struct MarkdownFormatter;

impl MarkdownFormatter {
    fn format_header(&self, report: &Report) -> String {
        let local: DateTime<Local> = report.generated_at.into();
        format!(
            "# OustIP Report - {}\n\n**Generated:** {}\n\n",
            report.hostname,
            local.format("%Y-%m-%d %H:%M:%S")
        )
    }

    fn format_status(&self, status: &StatusInfo) -> String {
        let mut out = String::from("## Status\n\n| Metric | Value |\n|--------|-------|\n");
        out.push_str(&format!(
            "| Active | {} |\n",
            if status.active {
                "✅ Yes"
            } else {
                "❌ No"
            }
        ));
        out.push_str(&format!("| Backend | {} |\n", status.backend));
        out.push_str(&format!(
            "| Entries | {} |\n",
            format_count(status.entries_in_set)
        ));
        if let Some(last) = status.last_update {
            let local: DateTime<Local> = last.into();
            out.push_str(&format!(
                "| Last Update | {} |\n",
                local.format("%Y-%m-%d %H:%M:%S")
            ));
        }
        out.push('\n');
        out
    }

    fn format_blocking(&self, blocking: &BlockingStats) -> String {
        format!(
            "## Blocking Statistics\n\n| Metric | Value |\n|--------|-------|\n| Packets Blocked | {} |\n| Bytes Blocked | {} |\n\n",
            format_count(blocking.packets_blocked as usize),
            blocking.bytes_blocked_human
        )
    }

    fn format_sources(&self, sources: &[SourceInfo]) -> String {
        if sources.is_empty() {
            return String::new();
        }
        let mut out =
            String::from("## Sources\n\n| Source | IPs | Entries |\n|--------|-----|--------|\n");
        for src in sources {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                src.name,
                format_count(src.ip_count as usize),
                format_count(src.raw_count)
            ));
        }
        out.push('\n');
        out
    }

    fn format_top_blocked(&self, top_blocked: &[TopBlockedIp]) -> String {
        if top_blocked.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "## Top Blocked IPs (Last 24h)\n\n| IP | Attempts |\n|----|----------|\n",
        );
        for ip in top_blocked {
            out.push_str(&format!(
                "| {} | {} |\n",
                ip.ip,
                format_count(ip.count as usize)
            ));
        }
        out.push('\n');
        out
    }
}

impl ReportFormatter for MarkdownFormatter {
    fn format(&self, report: &Report) -> String {
        let mut out = self.format_header(report);
        out.push_str(&self.format_status(&report.status));
        out.push_str(&self.format_blocking(&report.blocking));
        out.push_str(&self.format_sources(&report.sources));
        out.push_str(&self.format_top_blocked(&report.top_blocked));
        out
    }
}

// ============================================================================
// Log Parser Module
// ============================================================================

mod log_parser {
    use super::TopBlockedIp;
    use std::collections::HashMap;
    use std::process::Command;

    /// Get top blocked IPs from system logs (journalctl or syslog)
    pub async fn get_top_blocked_ips(limit: usize) -> Vec<TopBlockedIp> {
        let log_output = fetch_log_output();
        let ip_counts = parse_ip_counts(&log_output);
        sorted_top_ips(ip_counts, limit)
    }

    fn fetch_log_output() -> String {
        // Try journalctl first (systemd)
        let output = Command::new("journalctl")
            .args([
                "-k", // kernel messages only
                "--no-pager",
                "-o",
                "short",
                "--since",
                "24 hours ago",
                "-g",
                "oustip.*DROP", // grep for our drops
            ])
            .output();

        match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => {
                // Fallback: try reading /var/log/kern.log or /var/log/syslog
                if let Ok(content) = std::fs::read_to_string("/var/log/kern.log") {
                    content
                } else if let Ok(content) = std::fs::read_to_string("/var/log/syslog") {
                    content
                } else {
                    String::new()
                }
            }
        }
    }

    fn parse_ip_counts(log_output: &str) -> HashMap<String, u64> {
        let mut ip_counts: HashMap<String, u64> = HashMap::new();

        for line in log_output.lines() {
            if !line.contains("oustip") && !line.contains("OUSTIP") {
                continue;
            }

            // Extract SRC= IP address
            // nftables log format: ... SRC=1.2.3.4 DST=...
            // iptables log format: ... SRC=1.2.3.4 DST=...
            if let Some(src_start) = line.find("SRC=") {
                let src_part = &line[src_start + 4..];
                if let Some(end) = src_part.find(|c: char| c.is_whitespace()) {
                    let ip = &src_part[..end];
                    // Validate it looks like an IP
                    if ip.contains('.') || ip.contains(':') {
                        *ip_counts.entry(ip.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }

        ip_counts
    }

    fn sorted_top_ips(ip_counts: HashMap<String, u64>, limit: usize) -> Vec<TopBlockedIp> {
        let mut sorted: Vec<_> = ip_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        sorted
            .into_iter()
            .take(limit)
            .map(|(ip, count)| TopBlockedIp {
                ip,
                count,
                hostname: None, // DNS resolution would be slow, skip for now
            })
            .collect()
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Run the report command
pub async fn run(
    format: ReportFormat,
    send_email: bool,
    top_count: usize,
    config_path: &Path,
) -> Result<()> {
    let config = Config::load(config_path)?;
    let report = generate_report(&config, top_count).await?;

    // Output report
    let output = match format {
        ReportFormat::Text => TextFormatter.format(&report),
        ReportFormat::Json => serde_json::to_string_pretty(&report)?,
        ReportFormat::Markdown => MarkdownFormatter.format(&report),
    };

    println!("{}", output);

    // Send via email if requested
    if send_email {
        if let Ok(alert_manager) = AlertManager::new(config.alerts.clone()) {
            let subject = format!(
                "OustIP Report - {} - {}",
                report.hostname,
                Local::now().format("%Y-%m-%d")
            );
            alert_manager
                .send(crate::alerts::AlertLevel::Info, &subject, &output)
                .await;
            println!("\n[OK] Report sent via configured alert channels");
        } else {
            println!("\n[WARN] Could not send report - check alert configuration");
        }
    }

    Ok(())
}

/// Generate report data
async fn generate_report(config: &Config, top_count: usize) -> Result<Report> {
    let state = OustipState::load().unwrap_or_default();
    let backend = create_backend(config.backend)?;
    let fw_stats = backend.get_stats().await.unwrap_or_default();
    let is_active = backend.is_active().await.unwrap_or(false);
    let entry_count = backend.entry_count().await.unwrap_or(0);

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let backend_name = match config.backend {
        crate::config::Backend::Auto => "auto",
        crate::config::Backend::Iptables => "iptables",
        crate::config::Backend::Nftables => "nftables",
    };

    // Get top blocked IPs from logs
    let top_blocked = log_parser::get_top_blocked_ips(top_count).await;

    Ok(Report {
        generated_at: Utc::now(),
        hostname,
        status: StatusInfo {
            active: is_active,
            backend: backend_name.to_string(),
            entries_in_set: entry_count,
            last_update: state.last_update,
        },
        blocking: BlockingStats {
            packets_blocked: fw_stats.packets_blocked,
            bytes_blocked: fw_stats.bytes_blocked,
            bytes_blocked_human: format_bytes(fw_stats.bytes_blocked),
        },
        sources: state
            .sources
            .iter()
            .map(|s| SourceInfo {
                name: s.name.clone(),
                ip_count: s.ip_count,
                raw_count: s.raw_count,
            })
            .collect(),
        top_blocked,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a default report for testing with sensible defaults.
    /// Override specific fields as needed using struct update syntax.
    fn default_report() -> Report {
        Report {
            generated_at: Utc::now(),
            hostname: "test-host".to_string(),
            status: StatusInfo {
                active: true,
                backend: "nftables".to_string(),
                entries_in_set: 1000,
                last_update: None,
            },
            blocking: BlockingStats {
                packets_blocked: 5000,
                bytes_blocked: 1_000_000,
                bytes_blocked_human: "1.0 MB".to_string(),
            },
            sources: vec![],
            top_blocked: vec![],
        }
    }

    #[test]
    fn test_report_format_from_str_text() {
        assert_eq!("text".parse::<ReportFormat>().unwrap(), ReportFormat::Text);
        assert_eq!("txt".parse::<ReportFormat>().unwrap(), ReportFormat::Text);
        assert_eq!("TEXT".parse::<ReportFormat>().unwrap(), ReportFormat::Text);
    }

    #[test]
    fn test_report_format_from_str_json() {
        assert_eq!("json".parse::<ReportFormat>().unwrap(), ReportFormat::Json);
        assert_eq!("JSON".parse::<ReportFormat>().unwrap(), ReportFormat::Json);
    }

    #[test]
    fn test_report_format_from_str_markdown() {
        assert_eq!(
            "markdown".parse::<ReportFormat>().unwrap(),
            ReportFormat::Markdown
        );
        assert_eq!(
            "md".parse::<ReportFormat>().unwrap(),
            ReportFormat::Markdown
        );
        assert_eq!(
            "MARKDOWN".parse::<ReportFormat>().unwrap(),
            ReportFormat::Markdown
        );
    }

    #[test]
    fn test_report_format_from_str_invalid() {
        assert!("xml".parse::<ReportFormat>().is_err());
        assert!("csv".parse::<ReportFormat>().is_err());
        assert!("".parse::<ReportFormat>().is_err());
    }

    #[test]
    fn test_report_serialization() {
        let report = Report {
            status: StatusInfo {
                last_update: Some(Utc::now()),
                ..default_report().status
            },
            sources: vec![SourceInfo {
                name: "firehol".to_string(),
                ip_count: 5000,
                raw_count: 100,
            }],
            top_blocked: vec![TopBlockedIp {
                ip: "1.2.3.4".to_string(),
                count: 100,
                hostname: None,
            }],
            ..default_report()
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("test-host"));
        assert!(json.contains("nftables"));
        assert!(json.contains("firehol"));
    }

    #[test]
    fn test_format_text_contains_sections() {
        let report = Report {
            hostname: "myhost".to_string(),
            status: StatusInfo {
                entries_in_set: 500,
                ..default_report().status
            },
            blocking: BlockingStats {
                packets_blocked: 100,
                bytes_blocked: 5000,
                bytes_blocked_human: "5.0 KB".to_string(),
            },
            ..default_report()
        };

        let text = TextFormatter.format(&report);
        assert!(text.contains("OUSTIP REPORT"));
        assert!(text.contains("myhost"));
        assert!(text.contains("STATUS"));
        assert!(text.contains("BLOCKING STATISTICS"));
        assert!(text.contains("Active:"));
        assert!(text.contains("YES"));
    }

    #[test]
    fn test_format_text_inactive_status() {
        let report = Report {
            hostname: "host".to_string(),
            status: StatusInfo {
                active: false,
                backend: "iptables".to_string(),
                entries_in_set: 0,
                last_update: None,
            },
            blocking: BlockingStats {
                packets_blocked: 0,
                bytes_blocked: 0,
                bytes_blocked_human: "0 B".to_string(),
            },
            ..default_report()
        };

        let text = TextFormatter.format(&report);
        assert!(text.contains("NO"));
    }

    #[test]
    fn test_format_markdown_contains_sections() {
        let report = Report {
            hostname: "markdown-host".to_string(),
            status: StatusInfo {
                last_update: Some(Utc::now()),
                ..default_report().status
            },
            blocking: BlockingStats {
                packets_blocked: 200,
                bytes_blocked: 10000,
                bytes_blocked_human: "10.0 KB".to_string(),
            },
            sources: vec![SourceInfo {
                name: "test-source".to_string(),
                ip_count: 100,
                raw_count: 50,
            }],
            top_blocked: vec![TopBlockedIp {
                ip: "10.0.0.1".to_string(),
                count: 50,
                hostname: None,
            }],
            ..default_report()
        };

        let md = MarkdownFormatter.format(&report);
        assert!(md.contains("# OustIP Report"));
        assert!(md.contains("## Status"));
        assert!(md.contains("## Blocking Statistics"));
        assert!(md.contains("## Sources"));
        assert!(md.contains("## Top Blocked IPs"));
        assert!(md.contains("| Metric | Value |"));
        assert!(md.contains("test-source"));
        assert!(md.contains("10.0.0.1"));
    }

    #[test]
    fn test_format_markdown_active_status_emoji() {
        let report = Report {
            hostname: "host".to_string(),
            status: StatusInfo {
                entries_in_set: 0,
                ..default_report().status
            },
            blocking: BlockingStats {
                packets_blocked: 0,
                bytes_blocked: 0,
                bytes_blocked_human: "0 B".to_string(),
            },
            ..default_report()
        };

        let md = MarkdownFormatter.format(&report);
        assert!(md.contains("Yes"));
    }

    #[test]
    fn test_format_markdown_inactive_status_emoji() {
        let report = Report {
            hostname: "host".to_string(),
            status: StatusInfo {
                active: false,
                entries_in_set: 0,
                ..default_report().status
            },
            blocking: BlockingStats {
                packets_blocked: 0,
                bytes_blocked: 0,
                bytes_blocked_human: "0 B".to_string(),
            },
            ..default_report()
        };

        let md = MarkdownFormatter.format(&report);
        assert!(md.contains("No"));
    }

    #[test]
    fn test_top_blocked_ip_clone() {
        let ip = TopBlockedIp {
            ip: "1.2.3.4".to_string(),
            count: 100,
            hostname: Some("example.com".to_string()),
        };
        let cloned = ip.clone();
        assert_eq!(ip.ip, cloned.ip);
        assert_eq!(ip.count, cloned.count);
        assert_eq!(ip.hostname, cloned.hostname);
    }

    #[test]
    fn test_source_info_serialization() {
        let source = SourceInfo {
            name: "test".to_string(),
            ip_count: 1000,
            raw_count: 50,
        };
        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"ip_count\":1000"));
        assert!(json.contains("\"raw_count\":50"));
    }

    #[test]
    fn test_blocking_stats_serialization() {
        let stats = BlockingStats {
            packets_blocked: 5000,
            bytes_blocked: 1_000_000,
            bytes_blocked_human: "1.0 MB".to_string(),
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"packets_blocked\":5000"));
        assert!(json.contains("\"bytes_blocked\":1000000"));
        assert!(json.contains("\"bytes_blocked_human\":\"1.0 MB\""));
    }

    #[test]
    fn test_status_info_serialization() {
        let status = StatusInfo {
            active: true,
            backend: "nftables".to_string(),
            entries_in_set: 1234,
            last_update: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"backend\":\"nftables\""));
        assert!(json.contains("\"entries_in_set\":1234"));
        assert!(json.contains("\"last_update\":null"));
    }

    #[test]
    fn test_format_text_with_sources() {
        let report = Report {
            hostname: "host".to_string(),
            status: StatusInfo {
                entries_in_set: 100,
                ..default_report().status
            },
            blocking: BlockingStats {
                packets_blocked: 0,
                bytes_blocked: 0,
                bytes_blocked_human: "0 B".to_string(),
            },
            sources: vec![
                SourceInfo {
                    name: "source1".to_string(),
                    ip_count: 500,
                    raw_count: 100,
                },
                SourceInfo {
                    name: "source2".to_string(),
                    ip_count: 1000,
                    raw_count: 200,
                },
            ],
            ..default_report()
        };

        let text = TextFormatter.format(&report);
        assert!(text.contains("SOURCES"));
        assert!(text.contains("source1"));
        assert!(text.contains("source2"));
    }

    #[test]
    fn test_format_text_with_top_blocked() {
        let report = Report {
            hostname: "host".to_string(),
            status: StatusInfo {
                entries_in_set: 100,
                ..default_report().status
            },
            blocking: BlockingStats {
                packets_blocked: 0,
                bytes_blocked: 0,
                bytes_blocked_human: "0 B".to_string(),
            },
            top_blocked: vec![
                TopBlockedIp {
                    ip: "1.1.1.1".to_string(),
                    count: 100,
                    hostname: None,
                },
                TopBlockedIp {
                    ip: "2.2.2.2".to_string(),
                    count: 50,
                    hostname: None,
                },
            ],
            ..default_report()
        };

        let text = TextFormatter.format(&report);
        assert!(text.contains("TOP BLOCKED IPs"));
        assert!(text.contains("1.1.1.1"));
        assert!(text.contains("2.2.2.2"));
    }
}
