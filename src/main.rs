//! OustIP - IP Blocklist Manager for Linux Gateways
//!
//! A high-performance tool for blocking malicious IPs on Linux gateways/routers.

use anyhow::Result;
use clap::Parser;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

rust_i18n::i18n!("i18n", fallback = "en");

use oustip::cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging based on verbosity
    let log_level = if cli.verbose {
        Level::DEBUG
    } else if cli.quiet {
        Level::ERROR
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .without_time()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Set language if specified
    if let Some(ref lang) = cli.lang {
        rust_i18n::set_locale(lang);
    }

    // Execute command
    match cli.command {
        Commands::Install { preset } => oustip::commands::install::run(preset, &cli.config).await,
        Commands::Update { preset, dry_run } => {
            oustip::commands::update::run(preset, dry_run, &cli.config).await
        }
        Commands::Stats => oustip::commands::stats::run(&cli.config).await,
        Commands::Check { ip } => oustip::commands::check::run(&ip, &cli.config).await,
        Commands::Enable => oustip::commands::enable::run(&cli.config).await,
        Commands::Disable => oustip::commands::disable::run(&cli.config).await,
        Commands::Status => oustip::commands::status::run(&cli.config).await,
        Commands::Allowlist { action } => {
            oustip::commands::allowlist::run(action, &cli.config).await
        }
        Commands::Blocklist { action } => {
            oustip::commands::blocklist::run(action, &cli.config).await
        }
        Commands::Search { ip, dns } => oustip::commands::search::run(&ip, dns, &cli.config).await,
        Commands::Assume { action } => oustip::commands::assume::run(action).await,
        Commands::Ipv6 { action } => oustip::commands::ipv6::run(action).await,
        Commands::Report { format, send, top } => {
            let fmt = format.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            oustip::commands::report::run(fmt, send, top, &cli.config).await
        }
        Commands::Uninstall => oustip::commands::uninstall::run(&cli.config).await,
        Commands::Version => {
            println!("oustip {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}
