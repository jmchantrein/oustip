//! CLI argument parsing with clap.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "oustip")]
#[command(author, version, about = "IP Blocklist Manager for Linux Gateways")]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Config file path
    #[arg(short, long, default_value = "/etc/oustip/config.yaml", global = true)]
    pub config: PathBuf,

    /// Quiet mode (for cron/systemd timer)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Verbose mode (debug output)
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Language override (en, fr)
    #[arg(long, global = true)]
    pub lang: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Install OustIP (create config, systemd service, timer)
    Install {
        /// Use a preset configuration (minimal, recommended, full, paranoid)
        #[arg(long)]
        preset: Option<String>,
    },

    /// Update blocklists and apply firewall rules
    Update {
        /// Use a preset configuration (overrides config file)
        #[arg(long)]
        preset: Option<String>,

        /// Dry-run mode: fetch and process but don't apply firewall rules
        #[arg(long)]
        dry_run: bool,
    },

    /// Show blocking statistics
    Stats,

    /// Check if an IP is blocked and by which source
    Check {
        /// IP address to check
        ip: String,
    },

    /// Enable blocking (reapply rules)
    Enable,

    /// Disable blocking (remove rules, keep config)
    Disable,

    /// Show current status
    Status,

    /// Manage allowlist
    Allowlist {
        #[command(subcommand)]
        action: AllowlistAction,
    },

    /// Manage blocklist sources
    Blocklist {
        #[command(subcommand)]
        action: BlocklistAction,
    },

    /// Search for an IP in allow/blocklists with DNS resolution
    Search {
        /// IP address to search
        ip: String,
        /// Show DNS reverse resolution
        #[arg(long, short)]
        dns: bool,
    },

    /// Manage assumed IPs (acknowledged allow+block overlaps)
    Assume {
        #[command(subcommand)]
        action: AssumeAction,
    },

    /// Manage IPv6
    Ipv6 {
        #[command(subcommand)]
        action: Ipv6Action,
    },

    /// Generate a statistics report
    Report {
        /// Output format (text, json, markdown)
        #[arg(long, short, default_value = "text")]
        format: String,
        /// Send report via configured alert channels (email, gotify, webhook)
        #[arg(long)]
        send: bool,
        /// Number of top blocked IPs to include
        #[arg(long, default_value = "10")]
        top: usize,
    },

    /// Run health check (for monitoring)
    Health {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Uninstall OustIP completely
    Uninstall,

    /// Show version
    Version,
}

#[derive(Subcommand)]
pub enum AllowlistAction {
    /// Add IP/CIDR to allowlist
    Add {
        /// IP or CIDR to add
        ip: String,
    },
    /// Remove IP/CIDR from allowlist
    Del {
        /// IP or CIDR to remove
        ip: String,
    },
    /// List all allowlisted IPs
    List,
    /// Reload allowlist from config file
    Reload,
}

#[derive(Subcommand)]
pub enum AssumeAction {
    /// Add an IP to the assumed list (acknowledge allow+block overlap)
    Add {
        /// IP address to assume
        ip: String,
    },
    /// Remove an IP from the assumed list
    Del {
        /// IP address to remove
        ip: String,
    },
    /// List all assumed IPs
    List,
}

#[derive(Subcommand)]
pub enum BlocklistAction {
    /// Enable a blocklist source
    Enable {
        /// Name of the blocklist to enable
        name: String,
    },
    /// Disable a blocklist source
    Disable {
        /// Name of the blocklist to disable
        name: String,
    },
    /// List all blocklist sources and their status
    List,
    /// Show IPs from a specific blocklist with optional DNS
    Show {
        /// Name of the blocklist
        name: String,
        /// Show DNS reverse resolution
        #[arg(long, short)]
        dns: bool,
        /// Limit number of entries to show
        #[arg(long, short, default_value = "20")]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub enum Ipv6Action {
    /// Disable IPv6 via sysctl
    Disable,
    /// Enable IPv6 via sysctl
    Enable,
    /// Show IPv6 status
    Status,
}
