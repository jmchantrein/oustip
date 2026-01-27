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

    /// Manage IPv6
    Ipv6 {
        #[command(subcommand)]
        action: Ipv6Action,
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
pub enum Ipv6Action {
    /// Disable IPv6 via sysctl
    Disable,
    /// Enable IPv6 via sysctl
    Enable,
    /// Show IPv6 status
    Status,
}
