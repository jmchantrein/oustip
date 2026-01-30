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

        /// Headless mode: auto-detect interfaces, no interaction
        #[arg(long)]
        headless: bool,

        /// Use existing config file (skip detection)
        #[arg(long)]
        config_file: Option<PathBuf>,
    },

    /// Update blocklists and apply firewall rules
    Update {
        /// Update target (default: all)
        #[command(subcommand)]
        target: Option<UpdateTarget>,

        /// Dry-run mode: fetch and process but don't apply firewall rules
        #[arg(long)]
        dry_run: bool,
    },

    /// Manage network interfaces
    Interfaces {
        #[command(subcommand)]
        action: InterfacesAction,
    },

    /// Manage presets
    Presets {
        #[command(subcommand)]
        action: PresetsAction,
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

/// Update target for partial updates
#[derive(Subcommand, Clone)]
pub enum UpdateTarget {
    /// Reload presets.yaml definitions
    Presets,
    /// Download blocklists and allowlists from URLs
    Lists,
    /// Reload config.yaml and apply firewall rules
    Config,
}

/// Interface management actions
#[derive(Subcommand)]
pub enum InterfacesAction {
    /// Detect network interfaces and suggest configuration
    Detect,
}

/// Presets management actions
#[derive(Subcommand)]
pub enum PresetsAction {
    /// List all available presets (blocklist and allowlist)
    List {
        /// Show only blocklist presets
        #[arg(long)]
        blocklist: bool,
        /// Show only allowlist presets
        #[arg(long)]
        allowlist: bool,
    },
    /// Show details of a specific preset
    Show {
        /// Preset name
        name: String,
        /// Show blocklist preset (default if ambiguous)
        #[arg(long)]
        blocklist: bool,
        /// Show allowlist preset
        #[arg(long)]
        allowlist: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parses_help() {
        // Verify the CLI structure is valid
        Cli::command().debug_assert();
    }

    #[test]
    fn test_cli_version_command() {
        let cli = Cli::try_parse_from(["oustip", "version"]).unwrap();
        assert!(matches!(cli.command, Commands::Version));
    }

    #[test]
    fn test_cli_update_command() {
        let cli = Cli::try_parse_from(["oustip", "update"]).unwrap();
        match cli.command {
            Commands::Update { target, dry_run } => {
                assert!(target.is_none());
                assert!(!dry_run);
            }
            _ => panic!("Expected Update command"),
        }
    }

    #[test]
    fn test_cli_update_with_target() {
        let cli = Cli::try_parse_from(["oustip", "update", "presets"]).unwrap();
        match cli.command {
            Commands::Update { target, dry_run } => {
                assert!(matches!(target, Some(UpdateTarget::Presets)));
                assert!(!dry_run);
            }
            _ => panic!("Expected Update command"),
        }
    }

    #[test]
    fn test_cli_update_dry_run() {
        let cli = Cli::try_parse_from(["oustip", "update", "--dry-run"]).unwrap();
        match cli.command {
            Commands::Update { dry_run, .. } => {
                assert!(dry_run);
            }
            _ => panic!("Expected Update command"),
        }
    }

    #[test]
    fn test_cli_interfaces_detect() {
        let cli = Cli::try_parse_from(["oustip", "interfaces", "detect"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Interfaces {
                action: InterfacesAction::Detect
            }
        ));
    }

    #[test]
    fn test_cli_presets_list() {
        let cli = Cli::try_parse_from(["oustip", "presets", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Presets {
                action: PresetsAction::List { .. }
            }
        ));
    }

    #[test]
    fn test_cli_check_command() {
        let cli = Cli::try_parse_from(["oustip", "check", "192.168.1.1"]).unwrap();
        match cli.command {
            Commands::Check { ip } => {
                assert_eq!(ip, "192.168.1.1");
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_search_command() {
        let cli = Cli::try_parse_from(["oustip", "search", "8.8.8.8", "--dns"]).unwrap();
        match cli.command {
            Commands::Search { ip, dns } => {
                assert_eq!(ip, "8.8.8.8");
                assert!(dns);
            }
            _ => panic!("Expected Search command"),
        }
    }

    #[test]
    fn test_cli_allowlist_add() {
        let cli = Cli::try_parse_from(["oustip", "allowlist", "add", "10.0.0.0/8"]).unwrap();
        match cli.command {
            Commands::Allowlist {
                action: AllowlistAction::Add { ip },
            } => {
                assert_eq!(ip, "10.0.0.0/8");
            }
            _ => panic!("Expected Allowlist Add command"),
        }
    }

    #[test]
    fn test_cli_blocklist_show() {
        let cli = Cli::try_parse_from([
            "oustip",
            "blocklist",
            "show",
            "firehol_level1",
            "--limit",
            "50",
        ])
        .unwrap();
        match cli.command {
            Commands::Blocklist {
                action: BlocklistAction::Show { name, limit, dns },
            } => {
                assert_eq!(name, "firehol_level1");
                assert_eq!(limit, 50);
                assert!(!dns);
            }
            _ => panic!("Expected Blocklist Show command"),
        }
    }

    #[test]
    fn test_cli_report_command() {
        let cli =
            Cli::try_parse_from(["oustip", "report", "--format", "json", "--top", "20"]).unwrap();
        match cli.command {
            Commands::Report { format, top, send } => {
                assert_eq!(format, "json");
                assert_eq!(top, 20);
                assert!(!send);
            }
            _ => panic!("Expected Report command"),
        }
    }

    #[test]
    fn test_cli_health_command() {
        let cli = Cli::try_parse_from(["oustip", "health", "--json"]).unwrap();
        match cli.command {
            Commands::Health { json } => {
                assert!(json);
            }
            _ => panic!("Expected Health command"),
        }
    }

    #[test]
    fn test_cli_global_options() {
        let cli = Cli::try_parse_from([
            "oustip",
            "-q",
            "-v",
            "--config",
            "/custom/path.yaml",
            "status",
        ])
        .unwrap();
        assert!(cli.quiet);
        assert!(cli.verbose);
        assert_eq!(cli.config.to_str().unwrap(), "/custom/path.yaml");
    }

    #[test]
    fn test_cli_lang_option() {
        let cli = Cli::try_parse_from(["oustip", "--lang", "fr", "status"]).unwrap();
        assert_eq!(cli.lang, Some("fr".to_string()));
    }

    #[test]
    fn test_cli_install_with_preset() {
        let cli = Cli::try_parse_from(["oustip", "install", "--preset", "paranoid"]).unwrap();
        match cli.command {
            Commands::Install {
                preset,
                headless,
                config_file,
            } => {
                assert_eq!(preset, Some("paranoid".to_string()));
                assert!(!headless);
                assert!(config_file.is_none());
            }
            _ => panic!("Expected Install command"),
        }
    }

    #[test]
    fn test_cli_install_headless() {
        let cli = Cli::try_parse_from(["oustip", "install", "--headless"]).unwrap();
        match cli.command {
            Commands::Install { headless, .. } => {
                assert!(headless);
            }
            _ => panic!("Expected Install command"),
        }
    }

    #[test]
    fn test_cli_ipv6_commands() {
        let cli = Cli::try_parse_from(["oustip", "ipv6", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Ipv6 {
                action: Ipv6Action::Status
            }
        ));

        let cli = Cli::try_parse_from(["oustip", "ipv6", "disable"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Ipv6 {
                action: Ipv6Action::Disable
            }
        ));
    }

    #[test]
    fn test_cli_assume_commands() {
        let cli = Cli::try_parse_from(["oustip", "assume", "add", "1.2.3.4"]).unwrap();
        match cli.command {
            Commands::Assume {
                action: AssumeAction::Add { ip },
            } => {
                assert_eq!(ip, "1.2.3.4");
            }
            _ => panic!("Expected Assume Add command"),
        }

        let cli = Cli::try_parse_from(["oustip", "assume", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Assume {
                action: AssumeAction::List
            }
        ));
    }
}
