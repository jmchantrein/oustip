//! Presets management command for OustIP.

use anyhow::Result;

use crate::cli::PresetsAction;
use crate::presets::PresetsConfig;

/// Run presets command
pub async fn run(action: PresetsAction, lang: Option<&str>) -> Result<()> {
    match action {
        PresetsAction::List {
            blocklist,
            allowlist,
        } => list(blocklist, allowlist, lang).await,
        PresetsAction::Show {
            name,
            blocklist,
            allowlist,
        } => show(&name, blocklist, allowlist, lang).await,
    }
}

/// List available presets
async fn list(blocklist_only: bool, allowlist_only: bool, lang: Option<&str>) -> Result<()> {
    let presets = PresetsConfig::load_or_default()?;
    let lang = lang.unwrap_or("en");

    let show_blocklist = !allowlist_only || blocklist_only;
    let show_allowlist = !blocklist_only || allowlist_only;

    if show_blocklist {
        println!("Blocklist Presets / Presets de Blocklists:");
        println!("──────────────────────────────────────────\n");

        for name in presets.list_blocklist_presets() {
            if let Some(preset) = presets.blocklist_presets.get(name) {
                let sources = presets.resolve_blocklist_preset(name)?;
                let desc = preset.description.get(lang);
                println!("  {} ({} sources)", name, sources.len());
                println!("    {}", desc);
                if let Some(ref extends) = preset.extends {
                    println!("    extends: {}", extends);
                }
                println!();
            }
        }
    }

    if show_allowlist {
        println!("Allowlist Presets / Presets d'Allowlists:");
        println!("─────────────────────────────────────────\n");

        for name in presets.list_allowlist_presets() {
            if let Some(preset) = presets.allowlist_presets.get(name) {
                let sources = presets.resolve_allowlist_preset(name)?;
                let desc = preset.description.get(lang);
                println!("  {} ({} sources)", name, sources.len());
                println!("    {}", desc);
                if let Some(ref extends) = preset.extends {
                    println!("    extends: {}", extends);
                }
                println!();
            }
        }
    }

    Ok(())
}

/// Show details of a specific preset
async fn show(name: &str, blocklist: bool, allowlist: bool, lang: Option<&str>) -> Result<()> {
    let presets = PresetsConfig::load_or_default()?;
    let lang = lang.unwrap_or("en");

    // Determine which type to show
    let show_blocklist = blocklist || (!allowlist && presets.blocklist_presets.contains_key(name));
    let show_allowlist = allowlist || (!blocklist && presets.allowlist_presets.contains_key(name));

    if show_blocklist {
        if let Some(preset) = presets.blocklist_presets.get(name) {
            println!("Blocklist Preset: {}", name);
            println!("════════════════════════════════\n");
            println!("Description: {}", preset.description.get(lang));

            if let Some(ref extends) = preset.extends {
                println!("Extends: {}", extends);
            }

            let sources = presets.resolve_blocklist_preset(name)?;
            println!("\nSources ({}):", sources.len());

            for source_name in &sources {
                if let Some(source) = presets.blocklist_sources.get(source_name) {
                    println!("  - {} ", source_name);
                    println!("    URL: {}", source.url);
                    println!("    {}", source.description.get(lang));
                }
            }
            println!();
        } else if !show_allowlist {
            anyhow::bail!("Blocklist preset '{}' not found", name);
        }
    }

    if show_allowlist {
        if let Some(preset) = presets.allowlist_presets.get(name) {
            println!("Allowlist Preset: {}", name);
            println!("════════════════════════════════\n");
            println!("Description: {}", preset.description.get(lang));

            if let Some(ref extends) = preset.extends {
                println!("Extends: {}", extends);
            }

            let sources = presets.resolve_allowlist_preset(name)?;
            println!("\nSources ({}):", sources.len());

            for source_name in &sources {
                if let Some(source) = presets.allowlist_sources.get(source_name) {
                    println!("  - {}", source_name);
                    match source {
                        crate::presets::AllowlistSourceDef::Static {
                            ranges,
                            description,
                        } => {
                            println!("    Type: static");
                            println!("    Ranges: {}", ranges.join(", "));
                            println!("    {}", description.get(lang));
                        }
                        crate::presets::AllowlistSourceDef::Dynamic {
                            url,
                            json_path,
                            description,
                            ..
                        } => {
                            println!("    Type: dynamic");
                            println!("    URL: {}", url);
                            if let Some(path) = json_path {
                                println!("    JSON Path: {}", path);
                            }
                            println!("    {}", description.get(lang));
                        }
                    }
                }
            }
            println!();
        } else if !show_blocklist {
            anyhow::bail!("Allowlist preset '{}' not found", name);
        }
    }

    if !show_blocklist && !show_allowlist {
        anyhow::bail!(
            "Preset '{}' not found in blocklist or allowlist presets",
            name
        );
    }

    Ok(())
}
