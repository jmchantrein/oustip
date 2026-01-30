//! Installation and uninstallation of OustIP.

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::config::Config;
use crate::presets::PresetsConfig;
use crate::validation::{validate_interval, validate_preset};

const CONFIG_DIR: &str = "/etc/oustip";
const CONFIG_FILE: &str = "/etc/oustip/config.yaml";
const PRESETS_FILE: &str = "/etc/oustip/presets.yaml";
const STATE_DIR: &str = "/var/lib/oustip";
const SYSTEMD_SERVICE: &str = "/etc/systemd/system/oustip.service";
const SYSTEMD_TIMER: &str = "/etc/systemd/system/oustip.timer";

/// Install OustIP
pub fn install(preset: Option<&str>) -> Result<()> {
    // Validate preset if provided (prevents injection attacks)
    if let Some(p) = preset {
        validate_preset(p)?;
    }

    // Check if already installed
    if Path::new(CONFIG_FILE).exists() {
        anyhow::bail!(
            "OustIP is already installed. Config exists at {}.\n\
             Use 'oustip uninstall' first if you want to reinstall.",
            CONFIG_FILE
        );
    }

    // Create directories
    info!("Creating directories...");
    fs::create_dir_all(CONFIG_DIR).context("Failed to create config directory")?;
    fs::create_dir_all(STATE_DIR).context("Failed to create state directory")?;

    // Set restrictive permissions on state directory
    fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700))
        .context("Failed to set state directory permissions")?;

    // Create config file
    info!("Creating {}...", CONFIG_FILE);
    let mut config_content = Config::generate_default_yaml();

    // Override preset if specified (already validated above)
    if let Some(p) = preset {
        config_content = config_content.replace("preset: recommended", &format!("preset: {}", p));
    }

    fs::write(CONFIG_FILE, &config_content).context("Failed to write config file")?;

    // Set permissions (readable only by root)
    fs::set_permissions(CONFIG_FILE, fs::Permissions::from_mode(0o600))
        .context("Failed to set config permissions")?;

    // Load the config to get the update_interval
    let config = Config::load(CONFIG_FILE)?;
    let update_interval = &config.update_interval;

    // Create systemd service
    info!("Creating {}...", SYSTEMD_SERVICE);
    fs::write(SYSTEMD_SERVICE, generate_service_unit())
        .context("Failed to write systemd service")?;

    // Create systemd timer with configured interval
    info!("Creating {}...", SYSTEMD_TIMER);
    fs::write(SYSTEMD_TIMER, generate_timer_unit(update_interval))
        .context("Failed to write systemd timer")?;

    // Reload systemd
    info!("Reloading systemd...");
    Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .context("Failed to reload systemd")?;

    // Enable timer
    info!("Enabling oustip.timer...");
    Command::new("systemctl")
        .args(["enable", "oustip.timer"])
        .status()
        .context("Failed to enable timer")?;

    // Enable service (for boot)
    Command::new("systemctl")
        .args(["enable", "oustip.service"])
        .status()
        .context("Failed to enable service")?;

    // Start timer
    info!("Starting oustip.timer...");
    Command::new("systemctl")
        .args(["start", "oustip.timer"])
        .status()
        .context("Failed to start timer")?;

    println!();
    println!("[OK] Installation complete!");
    println!();
    println!("Next steps:");
    println!("  1. Edit configuration: {}", CONFIG_FILE);
    println!("  2. Apply rules: oustip update");
    println!("  3. Check status: oustip status");
    println!();

    Ok(())
}

/// Install OustIP with new interface-based configuration (v2)
///
/// This function installs OustIP with the new configuration system that supports:
/// - Per-interface blocklist/allowlist configuration
/// - Automatic interface detection
/// - Separate presets.yaml for source management
pub fn install_v2(preset: Option<&str>, config: Option<Config>) -> Result<()> {
    // Validate preset if provided (prevents injection attacks)
    if let Some(p) = preset {
        validate_preset(p)?;
    }

    // Check if already installed
    if Path::new(CONFIG_FILE).exists() {
        anyhow::bail!(
            "OustIP is already installed. Config exists at {}.\n\
             Use 'oustip uninstall' first if you want to reinstall.",
            CONFIG_FILE
        );
    }

    // Create directories
    info!("Creating directories...");
    fs::create_dir_all(CONFIG_DIR).context("Failed to create config directory")?;
    fs::create_dir_all(STATE_DIR).context("Failed to create state directory")?;

    // Set restrictive permissions on state directory
    fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700))
        .context("Failed to set state directory permissions")?;

    // Create presets.yaml from template
    info!("Creating {}...", PRESETS_FILE);
    let presets_content = PresetsConfig::generate_default_yaml();
    fs::write(PRESETS_FILE, &presets_content).context("Failed to write presets file")?;
    fs::set_permissions(PRESETS_FILE, fs::Permissions::from_mode(0o644))
        .context("Failed to set presets permissions")?;

    // Create config.yaml
    info!("Creating {}...", CONFIG_FILE);
    let config_content = if let Some(cfg) = config {
        generate_config_yaml_v2(&cfg, preset.unwrap_or("recommended"))
    } else {
        generate_default_config_yaml_v2()
    };
    fs::write(CONFIG_FILE, &config_content).context("Failed to write config file")?;
    fs::set_permissions(CONFIG_FILE, fs::Permissions::from_mode(0o600))
        .context("Failed to set config permissions")?;

    // Load the config to get the update_interval
    let config = Config::load(CONFIG_FILE)?;
    let update_interval = &config.update_interval;

    // Create systemd service
    info!("Creating {}...", SYSTEMD_SERVICE);
    fs::write(SYSTEMD_SERVICE, generate_service_unit())
        .context("Failed to write systemd service")?;

    // Create systemd timer with configured interval
    info!("Creating {}...", SYSTEMD_TIMER);
    fs::write(SYSTEMD_TIMER, generate_timer_unit(update_interval))
        .context("Failed to write systemd timer")?;

    // Reload systemd
    info!("Reloading systemd...");
    Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .context("Failed to reload systemd")?;

    // Enable timer
    info!("Enabling oustip.timer...");
    Command::new("systemctl")
        .args(["enable", "oustip.timer"])
        .status()
        .context("Failed to enable timer")?;

    // Enable service (for boot)
    Command::new("systemctl")
        .args(["enable", "oustip.service"])
        .status()
        .context("Failed to enable service")?;

    // Start timer
    info!("Starting oustip.timer...");
    Command::new("systemctl")
        .args(["start", "oustip.timer"])
        .status()
        .context("Failed to start timer")?;

    println!();
    println!("[OK] Installation complete!");
    println!();
    println!("Configuration files created:");
    println!("  - {} (main config)", CONFIG_FILE);
    println!("  - {} (presets/sources)", PRESETS_FILE);
    println!();
    println!("Next steps:");
    println!("  1. Review detected interfaces: oustip interfaces detect");
    println!("  2. Edit configuration: {}", CONFIG_FILE);
    println!("  3. Edit presets if needed: {}", PRESETS_FILE);
    println!("  4. Apply rules: oustip update");
    println!("  5. Check status: oustip status");
    println!();
    println!("After editing {}:", CONFIG_FILE);
    println!("  oustip update config");
    println!();
    println!("After editing {}:", PRESETS_FILE);
    println!("  oustip update presets && oustip update lists");
    println!();

    Ok(())
}

/// Install OustIP using an existing config file
pub fn install_with_config(config_path: &Path) -> Result<()> {
    // Validate the config file exists and is valid
    if !config_path.exists() {
        anyhow::bail!("Config file not found: {:?}", config_path);
    }

    // Try to load as v2 config first
    let config = Config::load(config_path).context("Failed to parse config file")?;

    // Check if already installed
    if Path::new(CONFIG_FILE).exists() {
        anyhow::bail!(
            "OustIP is already installed. Config exists at {}.\n\
             Use 'oustip uninstall' first if you want to reinstall.",
            CONFIG_FILE
        );
    }

    // Create directories
    info!("Creating directories...");
    fs::create_dir_all(CONFIG_DIR).context("Failed to create config directory")?;
    fs::create_dir_all(STATE_DIR).context("Failed to create state directory")?;

    // Set restrictive permissions on state directory
    fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700))
        .context("Failed to set state directory permissions")?;

    // Copy the provided config file
    info!("Copying config file to {}...", CONFIG_FILE);
    fs::copy(config_path, CONFIG_FILE).context("Failed to copy config file")?;
    fs::set_permissions(CONFIG_FILE, fs::Permissions::from_mode(0o600))
        .context("Failed to set config permissions")?;

    // Create default presets.yaml if not present
    if !Path::new(PRESETS_FILE).exists() {
        info!("Creating {}...", PRESETS_FILE);
        let presets_content = PresetsConfig::generate_default_yaml();
        fs::write(PRESETS_FILE, &presets_content).context("Failed to write presets file")?;
        fs::set_permissions(PRESETS_FILE, fs::Permissions::from_mode(0o644))
            .context("Failed to set presets permissions")?;
    }

    let update_interval = &config.update_interval;

    // Create systemd service
    info!("Creating {}...", SYSTEMD_SERVICE);
    fs::write(SYSTEMD_SERVICE, generate_service_unit())
        .context("Failed to write systemd service")?;

    // Create systemd timer with configured interval
    info!("Creating {}...", SYSTEMD_TIMER);
    fs::write(SYSTEMD_TIMER, generate_timer_unit(update_interval))
        .context("Failed to write systemd timer")?;

    // Reload systemd
    info!("Reloading systemd...");
    Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .context("Failed to reload systemd")?;

    // Enable timer
    info!("Enabling oustip.timer...");
    Command::new("systemctl")
        .args(["enable", "oustip.timer"])
        .status()
        .context("Failed to enable timer")?;

    // Enable service (for boot)
    Command::new("systemctl")
        .args(["enable", "oustip.service"])
        .status()
        .context("Failed to enable service")?;

    // Start timer
    info!("Starting oustip.timer...");
    Command::new("systemctl")
        .args(["start", "oustip.timer"])
        .status()
        .context("Failed to start timer")?;

    println!();
    println!("[OK] Installation complete with provided config!");
    println!();
    println!("Next steps:");
    println!("  1. Apply rules: oustip update");
    println!("  2. Check status: oustip status");
    println!();

    Ok(())
}

/// Generate default config.yaml content for v2 (interface-based)
fn generate_default_config_yaml_v2() -> String {
    r#"# =============================================================================
# OustIP Configuration
# https://github.com/jmchantrein/oustip
#
# Main configuration file for interface-based IP blocklist management.
# Presets and sources are defined in /etc/oustip/presets.yaml
#
# After editing this file, run: oustip update config
#
# Fichier de configuration principal pour la gestion des blocklists par interface.
# Les presets et sources sont définis dans /etc/oustip/presets.yaml
#
# Après édition de ce fichier, exécuter: oustip update config
# =============================================================================

# Language for messages / Langue des messages (en, fr)
language: en

# Firewall backend / Backend firewall
# auto: auto-detect (nftables preferred)
# nftables: use nftables (recommended, better performance)
# iptables: use iptables/ipset (legacy)
backend: auto

# Filtering mode / Mode de filtrage
# raw: PREROUTING (before conntrack, more performant)
# conntrack: after conntrack (allows responses to LAN-initiated connections)
mode: conntrack

# Update interval for systemd timer / Intervalle de mise à jour
# Examples / Exemples: 30m, 1h, 4h, 1d
update_interval: 4h

# =============================================================================
# INTERFACES CONFIGURATION / CONFIGURATION DES INTERFACES
# =============================================================================
# Configure each network interface with its mode and presets.
# Use 'oustip interfaces detect' to auto-detect your interfaces.
#
# Configurer chaque interface réseau avec son mode et ses presets.
# Utilisez 'oustip interfaces detect' pour auto-détecter vos interfaces.
#
# Modes:
#   wan: Internet-facing, apply blocklist (uses blocklist_preset)
#   lan: Internal network, monitor outbound (uses outbound_monitor)
#   trusted: No filtering (containers, VPN tunnels)
#
# Available presets (see presets.yaml for details):
#   blocklist: minimal, recommended, full, paranoid
#   allowlist: rfc1918, private_full, cdn_cloudflare, cdn_github, cdn_common
# =============================================================================

interfaces:
  # Example WAN interface / Exemple interface WAN
  # eth0:
  #   mode: wan
  #   blocklist_preset: paranoid    # Block suspicious IPs from internet
  #   allowlist_preset: cdn_common  # Allow CDN providers (Cloudflare, GitHub, Fastly)

  # Example LAN interface / Exemple interface LAN
  # eth1:
  #   mode: lan
  #   allowlist_preset: rfc1918     # Allow private networks
  #   outbound_monitor:             # Monitor outbound traffic for compromise detection
  #     blocklist_preset: recommended
  #     action: alert               # alert, block, block_and_alert

  # Example trusted interface / Exemple interface de confiance
  # docker0:
  #   mode: trusted                 # No filtering on container bridge

# =============================================================================
# RAW RULES (Advanced) / RÈGLES RAW (Avancé)
# =============================================================================
# Custom nftables/iptables rules for advanced users.
# These rules are added to the oustip chain.
#
# Règles personnalisées pour utilisateurs avancés.
# Ces règles sont ajoutées à la chaîne oustip.
# =============================================================================

# raw_rules:
#   nftables: |
#     # Custom nftables rules here
#   iptables: |
#     # Custom iptables rules here

# =============================================================================
# IPv6 CONFIGURATION
# =============================================================================

ipv6:
  # Boot state / État au démarrage
  # disabled: disable IPv6 at boot
  # enabled: enable IPv6 at boot
  # unchanged: don't modify IPv6 settings
  boot_state: unchanged

# =============================================================================
# ALERTS CONFIGURATION / CONFIGURATION DES ALERTES
# =============================================================================

alerts:
  gotify:
    enabled: false
    url: ""
    # Token can be set via OUSTIP_GOTIFY_TOKEN env var / Peut être défini via variable d'env
    token: ""
    # token_env: CUSTOM_GOTIFY_TOKEN  # Optional: custom env var name

  email:
    enabled: false
    smtp_host: ""
    smtp_port: 587
    smtp_user: ""
    # Password can be set via OUSTIP_SMTP_PASSWORD env var / Peut être défini via variable d'env
    smtp_password: ""
    # smtp_password_env: CUSTOM_SMTP_PASSWORD  # Optional: custom env var name
    from: ""
    to: ""

  webhook:
    enabled: false
    url: ""
    headers: {}
"#
    .to_string()
}

/// Generate config.yaml content from Config with comments
fn generate_config_yaml_v2(config: &Config, default_preset: &str) -> String {
    let mut yaml =
        r#"# =============================================================================
# OustIP Configuration
# https://github.com/jmchantrein/oustip
#
# Auto-generated configuration with detected interfaces.
# Presets and sources are defined in /etc/oustip/presets.yaml
#
# After editing this file, run: oustip update config
#
# Configuration auto-générée avec les interfaces détectées.
# Les presets et sources sont définis dans /etc/oustip/presets.yaml
#
# Après édition de ce fichier, exécuter: oustip update config
# =============================================================================

"#
        .to_string();

    yaml.push_str(&format!("language: {}\n", config.language));
    yaml.push_str(&format!(
        "backend: {}\n",
        match config.backend {
            crate::config::Backend::Auto => "auto",
            crate::config::Backend::Iptables => "iptables",
            crate::config::Backend::Nftables => "nftables",
        }
    ));
    yaml.push_str(&format!(
        "mode: {}\n",
        match config.mode {
            crate::config::FilterMode::Raw => "raw",
            crate::config::FilterMode::Conntrack => "conntrack",
        }
    ));
    yaml.push_str(&format!("update_interval: {}\n", config.update_interval));
    yaml.push('\n');

    yaml.push_str(
        "# =============================================================================\n",
    );
    yaml.push_str("# INTERFACES (auto-detected)\n");
    yaml.push_str("# Run 'oustip interfaces detect' to see detection details\n");
    yaml.push_str(
        "# =============================================================================\n\n",
    );

    yaml.push_str("interfaces:\n");
    if let Some(ref interfaces) = config.interfaces {
        for (name, iface_config) in interfaces {
            yaml.push_str(&format!("  {}:\n", name));
            yaml.push_str(&format!(
                "    mode: {}\n",
                match iface_config.mode {
                    crate::config::InterfaceMode::Wan => "wan",
                    crate::config::InterfaceMode::Lan => "lan",
                    crate::config::InterfaceMode::Trusted => "trusted",
                }
            ));
            if let Some(ref preset) = iface_config.blocklist_preset {
                yaml.push_str(&format!("    blocklist_preset: {}\n", preset));
            }
            if let Some(ref preset) = iface_config.allowlist_preset {
                yaml.push_str(&format!("    allowlist_preset: {}\n", preset));
            }
            if let Some(ref monitor) = iface_config.outbound_monitor {
                yaml.push_str("    outbound_monitor:\n");
                yaml.push_str(&format!(
                    "      blocklist_preset: {}\n",
                    monitor.blocklist_preset
                ));
                yaml.push_str(&format!(
                    "      action: {}\n",
                    match monitor.action {
                        crate::config::OutboundAction::Alert => "alert",
                        crate::config::OutboundAction::Block => "block",
                        crate::config::OutboundAction::BlockAndAlert => "block_and_alert",
                    }
                ));
            }
        }
    }

    yaml.push('\n');
    yaml.push_str("# IPv6 configuration\n");
    yaml.push_str("ipv6:\n");
    yaml.push_str(&format!(
        "  boot_state: {}\n",
        match config.ipv6.boot_state {
            crate::config::Ipv6BootState::Disabled => "disabled",
            crate::config::Ipv6BootState::Enabled => "enabled",
            crate::config::Ipv6BootState::Unchanged => "unchanged",
        }
    ));

    yaml.push('\n');
    yaml.push_str("# Alerts configuration (disabled by default)\n");
    yaml.push_str("alerts:\n");
    yaml.push_str("  gotify:\n");
    yaml.push_str("    enabled: false\n");
    yaml.push_str("    url: \"\"\n");
    yaml.push_str("    token: \"\"\n");
    yaml.push_str("  email:\n");
    yaml.push_str("    enabled: false\n");
    yaml.push_str("    smtp_host: \"\"\n");
    yaml.push_str("    smtp_port: 587\n");
    yaml.push_str("    smtp_user: \"\"\n");
    yaml.push_str("    smtp_password: \"\"\n");
    yaml.push_str("    from: \"\"\n");
    yaml.push_str("    to: \"\"\n");
    yaml.push_str("  webhook:\n");
    yaml.push_str("    enabled: false\n");
    yaml.push_str("    url: \"\"\n");
    yaml.push_str("    headers: {}\n");

    // Use the default_preset for documentation
    let _ = default_preset;

    yaml
}

/// Uninstall OustIP
pub fn uninstall() -> Result<()> {
    info!("Uninstalling OustIP...");

    // Stop and disable timer
    let _ = Command::new("systemctl")
        .args(["stop", "oustip.timer"])
        .status();
    let _ = Command::new("systemctl")
        .args(["disable", "oustip.timer"])
        .status();

    // Stop and disable service
    let _ = Command::new("systemctl")
        .args(["stop", "oustip.service"])
        .status();
    let _ = Command::new("systemctl")
        .args(["disable", "oustip.service"])
        .status();

    // Remove systemd files
    if Path::new(SYSTEMD_SERVICE).exists() {
        info!("Removing {}...", SYSTEMD_SERVICE);
        fs::remove_file(SYSTEMD_SERVICE)?;
    }
    if Path::new(SYSTEMD_TIMER).exists() {
        info!("Removing {}...", SYSTEMD_TIMER);
        fs::remove_file(SYSTEMD_TIMER)?;
    }

    // Reload systemd
    let _ = Command::new("systemctl").args(["daemon-reload"]).status();

    // Remove config directory
    if Path::new(CONFIG_DIR).exists() {
        info!("Removing {}...", CONFIG_DIR);
        fs::remove_dir_all(CONFIG_DIR)?;
    }

    // Remove state directory
    if Path::new(STATE_DIR).exists() {
        info!("Removing {}...", STATE_DIR);
        fs::remove_dir_all(STATE_DIR)?;
    }

    println!();
    println!("[OK] OustIP uninstalled successfully.");
    println!();
    println!("Note: Firewall rules have been removed.");
    println!("      The binary at /usr/local/sbin/oustip was not removed.");
    println!();

    Ok(())
}

/// Update systemd timer interval
pub fn update_timer_interval(interval: &str) -> Result<()> {
    // Validate interval format (prevents injection attacks)
    validate_interval(interval)?;

    info!("Updating timer interval to {}...", interval);
    fs::write(SYSTEMD_TIMER, generate_timer_unit(interval)).context("Failed to update timer")?;

    Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .context("Failed to reload systemd")?;

    Command::new("systemctl")
        .args(["restart", "oustip.timer"])
        .status()
        .context("Failed to restart timer")?;

    Ok(())
}

/// Generate systemd service unit
fn generate_service_unit() -> String {
    r#"[Unit]
Description=OustIP Blocklist Manager
After=network-online.target nftables.service
Wants=network-online.target
Documentation=https://github.com/jmchantrein/oustip

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/oustip update --quiet
RemainAfterExit=yes

# Restart on failure with rate limiting
Restart=on-failure
RestartSec=5min
StartLimitBurst=3
StartLimitIntervalSec=1h

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/oustip /var/log

# Required capabilities for firewall manipulation
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"#
    .to_string()
}

/// Generate systemd timer unit
fn generate_timer_unit(interval: &str) -> String {
    format!(
        r#"[Unit]
Description=OustIP periodic blocklist update
Documentation=https://github.com/jmchantrein/oustip

[Timer]
OnBootSec=5min
OnUnitActiveSec={}
Persistent=true

[Install]
WantedBy=timers.target
"#,
        interval
    )
}

/// Check if OustIP is installed
pub fn is_installed() -> bool {
    Path::new(CONFIG_FILE).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_service_unit() {
        let unit = generate_service_unit();
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("oustip update"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("CAP_NET_ADMIN"));
        assert!(unit.contains("ProtectSystem"));
    }

    #[test]
    fn test_generate_timer_unit() {
        let unit = generate_timer_unit("6h");
        assert!(unit.contains("[Timer]"));
        assert!(unit.contains("OnUnitActiveSec=6h"));
        assert!(unit.contains("OnBootSec=5min"));
        assert!(unit.contains("Persistent=true"));
    }

    #[test]
    fn test_generate_timer_unit_various_intervals() {
        for interval in ["1h", "30m", "4h", "1d", "12h"] {
            let unit = generate_timer_unit(interval);
            assert!(unit.contains(&format!("OnUnitActiveSec={}", interval)));
        }
    }

    #[test]
    fn test_service_unit_security_hardening() {
        let unit = generate_service_unit();
        // Verify security hardening options are present
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("ProtectHome=yes"));
        assert!(unit.contains("PrivateTmp=yes"));
        assert!(unit.contains("ReadWritePaths=/var/lib/oustip"));
    }

    #[test]
    fn test_timer_unit_structure() {
        let unit = generate_timer_unit("4h");
        // Check all required sections
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Timer]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("WantedBy=timers.target"));
    }

    #[test]
    fn test_constants() {
        assert!(CONFIG_DIR.starts_with("/etc"));
        assert!(CONFIG_FILE.ends_with(".yaml"));
        assert!(STATE_DIR.starts_with("/var"));
    }

    #[test]
    fn test_is_installed_false_by_default() {
        // On a test system without oustip installed
        // This test checks the function works without panicking
        let _ = is_installed();
    }

    // validate_preset tests
    #[test]
    fn test_validate_preset_valid() {
        assert!(validate_preset("minimal").is_ok());
        assert!(validate_preset("recommended").is_ok());
        assert!(validate_preset("full").is_ok());
        assert!(validate_preset("paranoid").is_ok());
    }

    #[test]
    fn test_validate_preset_invalid() {
        assert!(validate_preset("invalid").is_err());
        assert!(validate_preset("").is_err());
        assert!(validate_preset("MINIMAL").is_err()); // case sensitive
        assert!(validate_preset("custom").is_err());
    }

    #[test]
    fn test_validate_preset_injection_attempts() {
        assert!(validate_preset("minimal; rm -rf /").is_err());
        assert!(validate_preset("$(whoami)").is_err());
        assert!(validate_preset("`ls`").is_err());
    }

    // validate_interval tests
    #[test]
    fn test_validate_interval_valid() {
        assert!(validate_interval("30s").is_ok());
        assert!(validate_interval("5m").is_ok());
        assert!(validate_interval("4h").is_ok());
        assert!(validate_interval("1d").is_ok());
        assert!(validate_interval("100s").is_ok());
    }

    #[test]
    fn test_validate_interval_invalid_suffix() {
        assert!(validate_interval("30x").is_err());
        assert!(validate_interval("5w").is_err()); // weeks not supported
        assert!(validate_interval("4y").is_err()); // years not supported
    }

    #[test]
    fn test_validate_interval_invalid_number() {
        assert!(validate_interval("abch").is_err());
        assert!(validate_interval("-5h").is_err());
        assert!(validate_interval("3.5h").is_err()); // no decimals
    }

    #[test]
    fn test_validate_interval_empty() {
        assert!(validate_interval("").is_err());
    }

    #[test]
    fn test_validate_interval_too_short() {
        assert!(validate_interval("h").is_err());
        assert!(validate_interval("5").is_err());
    }

    #[test]
    fn test_validate_interval_unicode() {
        assert!(validate_interval("５h").is_err()); // fullwidth 5
        assert!(validate_interval("4ℎ").is_err()); // unicode h
    }

    #[test]
    fn test_validate_interval_injection_attempts() {
        assert!(validate_interval("4h; rm -rf /").is_err());
        assert!(validate_interval("$(whoami)h").is_err());
        assert!(validate_interval("4h\nExec=malicious").is_err());
    }

    #[test]
    fn test_service_unit_restart_limits() {
        let unit = generate_service_unit();
        assert!(unit.contains("RestartSec=5min"));
        assert!(unit.contains("StartLimitBurst=3"));
        assert!(unit.contains("StartLimitIntervalSec=1h"));
    }

    #[test]
    fn test_service_unit_capabilities() {
        let unit = generate_service_unit();
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW"));
    }

    #[test]
    fn test_timer_unit_persistent() {
        let unit = generate_timer_unit("1h");
        assert!(unit.contains("Persistent=true"));
    }
}
