//! Enable command implementation.

use anyhow::Result;
use std::path::Path;
use tracing::info;

use crate::enforcer::check_root;

/// Run the enable command
pub async fn run(config_path: &Path) -> Result<()> {
    check_root()?;

    info!("Enabling OustIP...");

    // Simply run update to reapply rules
    super::update::run(None, false, config_path).await?;

    println!("[OK] OustIP enabled");
    Ok(())
}
