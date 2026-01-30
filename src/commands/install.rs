//! Install command implementation.

use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::config::ConfigV2;
use crate::enforcer::check_root;
use crate::installer;
use crate::interfaces::detect_interfaces;

/// Run the install command
pub async fn run(
    preset: Option<String>,
    headless: bool,
    config_file: Option<PathBuf>,
    _config_path: &Path,
) -> Result<()> {
    check_root()?;

    info!("Installing OustIP...");

    // If config file is provided, use it directly
    if let Some(ref path) = config_file {
        info!("Using provided config file: {:?}", path);
        installer::install_with_config(path)?;
        return Ok(());
    }

    // Auto-detect interfaces
    info!("Detecting network interfaces...");
    let interfaces = detect_interfaces()?;

    if headless {
        // Headless mode: auto-generate config from detected interfaces
        info!("Headless mode: generating config from detected interfaces");
        let config = ConfigV2::from_detected_interfaces(&interfaces);
        installer::install_v2(preset.as_deref(), Some(config))?;
    } else {
        // Interactive mode: show detected interfaces and proceed
        // For now, we'll use the detected interfaces directly
        // In a full implementation, this would prompt for user confirmation
        println!("\nDetected interfaces:");
        for iface in &interfaces {
            println!(
                "  {} -> {} ({})",
                iface.name, iface.suggested_mode, iface.reason
            );
        }
        println!();

        let config = ConfigV2::from_detected_interfaces(&interfaces);
        installer::install_v2(preset.as_deref(), Some(config))?;
    }

    Ok(())
}
