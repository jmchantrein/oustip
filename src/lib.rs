//! # OustIP - IP Blocklist Manager for Linux Gateways
//!
//! A high-performance tool for blocking malicious IPs on Linux gateways/routers.
//! Written in Rust for memory safety, zero GC pauses, and minimal attack surface.
//!
//! ## Features
//!
//! - **High Performance** - Process millions of IPs with minimal latency (nftables default)
//! - **Memory Safe** - Written in Rust with compile-time guarantees
//! - **Non-Intrusive** - Never modifies existing firewall rules
//! - **Flexible** - Supports both nftables (default) and iptables backends
//! - **Smart Aggregation** - CIDR optimization reduces rule count
//! - **Overlap Detection** - Automatic detection of allow+block overlaps
//! - **Auto-Allowlist** - Automatically whitelist CDN providers
//! - **Alerting** - Gotify, email, and webhook notifications
//! - **Secure** - Environment variable support for credentials, input validation
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        OustIP                               │
//! ├─────────────────────────────────────────────────────────────┤
//! │  CLI (clap)                                                 │
//! │    └── Commands: install, update, status, check, report... │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Config (serde_yaml)                                        │
//! │    └── Presets: minimal, recommended, full, paranoid        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Fetcher (reqwest + rustls)                                 │
//! │    ├── Blocklist sources (FireHOL, Spamhaus, DShield)       │
//! │    └── CDN allowlists (Cloudflare, GitHub, AWS, etc.)       │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Aggregator (ipnet)                                         │
//! │    └── CIDR optimization and allowlist subtraction          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Enforcer (FirewallBackend trait)                           │
//! │    ├── NftablesBackend (recommended)                        │
//! │    └── IptablesBackend (legacy)                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Alerts (gotify, smtp, webhook)                             │
//! │    └── Notifications for overlaps, errors, reports          │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example Usage
//!
//! ```no_run
//! use oustip::config::Config;
//! use oustip::enforcer::{create_backend, check_root};
//! use oustip::fetcher::Fetcher;
//! use oustip::aggregator::aggregate;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Check root privileges
//!     check_root()?;
//!
//!     // Load configuration
//!     let config = Config::load("/etc/oustip/config.yaml")?;
//!
//!     // Fetch blocklists
//!     let fetcher = Fetcher::new()?;
//!     let sources = config.get_enabled_blocklists(None);
//!     let results = fetcher.fetch_blocklists(&sources).await;
//!
//!     // Aggregate IPs
//!     let all_ips: Vec<_> = results
//!         .into_iter()
//!         .filter_map(|r| r.ok())
//!         .flat_map(|r| r.ips)
//!         .collect();
//!     let aggregated = aggregate(&all_ips);
//!
//!     // Apply to firewall
//!     let backend = create_backend(config.backend)?;
//!     backend.apply_rules(&aggregated, config.mode).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Security
//!
//! OustIP is designed with security in mind:
//!
//! - **Input Validation** - All user inputs are validated (presets, intervals, headers)
//! - **Injection Prevention** - Systemd units and HTTP headers are sanitized
//! - **Credential Protection** - Support for environment variables, memory zeroed on drop
//! - **Atomic Operations** - State files written atomically to prevent corruption
//! - **Download Limits** - Blocklist downloads are size-limited (10MB/file, 50MB total)
//! - **HTTPS Only** - All external URLs must use HTTPS
//!
//! ## Modules
//!
//! - [`aggregator`] - CIDR aggregation and allowlist subtraction
//! - [`alerts`] - Alert destinations (Gotify, Email, Webhook)
//! - [`cli`] - Command-line interface definitions
//! - [`commands`] - CLI command implementations
//! - [`config`] - Configuration parsing and validation
//! - [`dns`] - DNS resolution utilities with timeout
//! - [`enforcer`] - Firewall backend abstraction (nftables, iptables)
//! - [`fetcher`] - HTTP client for downloading blocklists
//! - [`installer`] - System installation (systemd units, config)
//! - [`lock`] - File locking for concurrent execution prevention
//! - [`signal`] - Graceful shutdown signal handling
//! - [`stats`] - State persistence and statistics
//! - [`utils`] - Common utility functions (formatting, truncation)

pub mod aggregator;
pub mod alerts;
pub mod cli;
pub mod commands;
pub mod config;
pub mod dns;
pub mod enforcer;
pub mod fetcher;
pub mod installer;
pub mod lock;
pub mod signal;
pub mod stats;
pub mod utils;

pub use cli::{AllowlistAction, Cli, Commands, Ipv6Action};
pub use config::Config;
