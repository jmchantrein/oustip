//! OustIP - IP Blocklist Manager for Linux Gateways
//!
//! A high-performance tool for blocking malicious IPs on Linux gateways/routers.
//! Written in Rust for memory safety, zero GC pauses, and minimal attack surface.

pub mod aggregator;
pub mod alerts;
pub mod cli;
pub mod commands;
pub mod config;
pub mod enforcer;
pub mod fetcher;
pub mod installer;
pub mod lock;
pub mod signal;
pub mod stats;

pub use cli::{AllowlistAction, Cli, Commands, Ipv6Action};
pub use config::Config;
