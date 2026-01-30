//! Interface detection command for OustIP.

use anyhow::Result;

use crate::cli::InterfacesAction;
use crate::interfaces::{detect_interfaces, format_detection_report, generate_config_snippet};

/// Run interfaces command
pub async fn run(action: InterfacesAction, lang: Option<&str>) -> Result<()> {
    match action {
        InterfacesAction::Detect => detect(lang).await,
    }
}

/// Detect network interfaces and suggest configuration
async fn detect(lang: Option<&str>) -> Result<()> {
    let interfaces = detect_interfaces()?;

    if interfaces.is_empty() {
        println!("No network interfaces detected (excluding loopback).");
        return Ok(());
    }

    // Print detection report
    let report = format_detection_report(&interfaces, lang.unwrap_or("en"));
    println!("{}", report);

    // Print suggested config snippet
    println!("\nSuggested configuration / Configuration suggérée:");
    println!("─────────────────────────────────────────────────\n");
    let snippet = generate_config_snippet(&interfaces);
    println!("{}", snippet);

    Ok(())
}
