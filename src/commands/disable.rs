//! Disable command implementation.

use anyhow::Result;
use std::path::Path;
use tracing::info;

use crate::config::Config;
use crate::enforcer::{check_root, create_backend};

/// Run the disable command
pub async fn run(config_path: &Path) -> Result<()> {
    check_root()?;

    info!("Disabling OustIP...");

    // Load config to get backend preference
    let config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        Config::default()
    };

    let backend = create_backend(config.backend)?;
    backend.remove_rules().await?;

    println!("[OK] OustIP disabled (rules removed, config preserved)");
    Ok(())
}
