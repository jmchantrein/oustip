//! Install command implementation.

use anyhow::Result;
use std::path::Path;
use tracing::info;

use crate::enforcer::check_root;
use crate::installer;

/// Run the install command
pub async fn run(preset: Option<String>, _config_path: &Path) -> Result<()> {
    check_root()?;

    info!("Installing OustIP...");
    installer::install(preset.as_deref())?;

    Ok(())
}
