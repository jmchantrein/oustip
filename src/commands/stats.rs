//! Stats command implementation.

use anyhow::Result;
use std::path::Path;

use crate::config::Config;
use crate::stats::display_stats;

/// Run the stats command
pub async fn run(config_path: &Path) -> Result<()> {
    let config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        Config::default()
    };

    display_stats(&config).await
}
