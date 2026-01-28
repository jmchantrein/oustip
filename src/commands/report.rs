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
use crate::fetcher::format_count;
use crate::stats::OustipState;
use crate::utils::{format_bytes, truncate};

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
        ReportFormat::Text => format_text(&report),
        ReportFormat::Json => serde_json::to_string_pretty(&report)?,
        ReportFormat::Markdown => format_markdown(&report),
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
    let top_blocked = get_top_blocked_ips(top_count).await;

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

/// Get top blocked IPs from system logs (journalctl or syslog)
async fn get_top_blocked_ips(limit: usize) -> Vec<TopBlockedIp> {
    use std::collections::HashMap;
    use std::process::Command;

    let mut ip_counts: HashMap<String, u64> = HashMap::new();

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

    let log_output = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            // Fallback: try reading /var/log/kern.log or /var/log/syslog
            if let Ok(content) = std::fs::read_to_string("/var/log/kern.log") {
                content
            } else if let Ok(content) = std::fs::read_to_string("/var/log/syslog") {
                content
            } else {
                return Vec::new();
            }
        }
    };

    // Parse log lines for source IPs
    // nftables log format: ... SRC=1.2.3.4 DST=...
    // iptables log format: ... SRC=1.2.3.4 DST=...
    for line in log_output.lines() {
        if !line.contains("oustip") && !line.contains("OUSTIP") {
            continue;
        }

        // Extract SRC= IP address
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

    // Sort by count and take top N
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

/// Format report as plain text
fn format_text(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("══════════════════════════════════════════════════════════════════\n");
    out.push_str(" OUSTIP REPORT\n");
    out.push_str("══════════════════════════════════════════════════════════════════\n\n");

    let local: DateTime<Local> = report.generated_at.into();
    out.push_str(&format!(
        " Generated: {}\n",
        local.format("%Y-%m-%d %H:%M:%S")
    ));
    out.push_str(&format!(" Hostname:  {}\n\n", report.hostname));

    // Status
    out.push_str(" STATUS\n");
    out.push_str(" ────────────────────────────────────────────────────────────────\n");
    out.push_str(&format!(
        " Active:    {}\n",
        if report.status.active { "YES" } else { "NO" }
    ));
    out.push_str(&format!(" Backend:   {}\n", report.status.backend));
    out.push_str(&format!(
        " Entries:   {}\n",
        format_count(report.status.entries_in_set)
    ));
    if let Some(last) = report.status.last_update {
        let local: DateTime<Local> = last.into();
        out.push_str(&format!(
            " Updated:   {}\n",
            local.format("%Y-%m-%d %H:%M:%S")
        ));
    }
    out.push('\n');

    // Blocking stats
    out.push_str(" BLOCKING STATISTICS (since boot)\n");
    out.push_str(" ────────────────────────────────────────────────────────────────\n");
    out.push_str(&format!(
        " Packets:   {}\n",
        format_count(report.blocking.packets_blocked as usize)
    ));
    out.push_str(&format!(
        " Bytes:     {}\n\n",
        report.blocking.bytes_blocked_human
    ));

    // Sources
    if !report.sources.is_empty() {
        out.push_str(" SOURCES\n");
        out.push_str(" ────────────────────────────────────────────────────────────────\n");
        out.push_str(" NAME                 IPs          ENTRIES\n");
        for src in &report.sources {
            out.push_str(&format!(
                " {:<20} {:>12} {:>12}\n",
                truncate(&src.name, 20),
                format_count(src.ip_count as usize),
                format_count(src.raw_count)
            ));
        }
        out.push('\n');
    }

    // Top blocked
    if !report.top_blocked.is_empty() {
        out.push_str(" TOP BLOCKED IPs (last 24h)\n");
        out.push_str(" ────────────────────────────────────────────────────────────────\n");
        out.push_str(" IP                          ATTEMPTS\n");
        for ip in &report.top_blocked {
            out.push_str(&format!(
                " {:<28} {:>8}\n",
                ip.ip,
                format_count(ip.count as usize)
            ));
        }
        out.push('\n');
    }

    out.push_str("══════════════════════════════════════════════════════════════════\n");

    out
}

/// Format report as Markdown
fn format_markdown(report: &Report) -> String {
    let mut out = String::new();

    let local: DateTime<Local> = report.generated_at.into();
    out.push_str(&format!("# OustIP Report - {}\n\n", report.hostname));
    out.push_str(&format!(
        "**Generated:** {}\n\n",
        local.format("%Y-%m-%d %H:%M:%S")
    ));

    // Status
    out.push_str("## Status\n\n");
    out.push_str("| Metric | Value |\n");
    out.push_str("|--------|-------|\n");
    out.push_str(&format!(
        "| Active | {} |\n",
        if report.status.active {
            "✅ Yes"
        } else {
            "❌ No"
        }
    ));
    out.push_str(&format!("| Backend | {} |\n", report.status.backend));
    out.push_str(&format!(
        "| Entries | {} |\n",
        format_count(report.status.entries_in_set)
    ));
    if let Some(last) = report.status.last_update {
        let local: DateTime<Local> = last.into();
        out.push_str(&format!(
            "| Last Update | {} |\n",
            local.format("%Y-%m-%d %H:%M:%S")
        ));
    }
    out.push('\n');

    // Blocking stats
    out.push_str("## Blocking Statistics\n\n");
    out.push_str("| Metric | Value |\n");
    out.push_str("|--------|-------|\n");
    out.push_str(&format!(
        "| Packets Blocked | {} |\n",
        format_count(report.blocking.packets_blocked as usize)
    ));
    out.push_str(&format!(
        "| Bytes Blocked | {} |\n\n",
        report.blocking.bytes_blocked_human
    ));

    // Sources
    if !report.sources.is_empty() {
        out.push_str("## Sources\n\n");
        out.push_str("| Source | IPs | Entries |\n");
        out.push_str("|--------|-----|--------|\n");
        for src in &report.sources {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                src.name,
                format_count(src.ip_count as usize),
                format_count(src.raw_count)
            ));
        }
        out.push('\n');
    }

    // Top blocked
    if !report.top_blocked.is_empty() {
        out.push_str("## Top Blocked IPs (Last 24h)\n\n");
        out.push_str("| IP | Attempts |\n");
        out.push_str("|----|----------|\n");
        for ip in &report.top_blocked {
            out.push_str(&format!(
                "| {} | {} |\n",
                ip.ip,
                format_count(ip.count as usize)
            ));
        }
        out.push('\n');
    }

    out
}
