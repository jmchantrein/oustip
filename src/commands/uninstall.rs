//! Uninstall command implementation.

use anyhow::Result;
use std::path::Path;
use tracing::info;

use crate::config::Config;
use crate::enforcer::{check_root, create_backend};
use crate::installer;

/// Run the uninstall command
pub async fn run(config_path: &Path) -> Result<()> {
    check_root()?;

    info!("Uninstalling OustIP...");

    // Remove firewall rules first
    let config = if config_path.exists() {
        Config::load(config_path).ok()
    } else {
        None
    };

    let backend = config
        .map(|c| create_backend(c.backend))
        .unwrap_or_else(|| create_backend(crate::config::Backend::Auto))?;

    info!("Removing firewall rules...");
    backend.remove_rules().await?;

    // Uninstall (remove config, systemd, etc.)
    installer::uninstall()?;

    Ok(())
}
