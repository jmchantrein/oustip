//! Network interface detection and classification for OustIP.
//!
//! This module provides functionality to detect network interfaces
//! and classify them based on their characteristics (WAN, LAN, container, VPN).

use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

/// Interface mode for firewall rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceMode {
    /// WAN interface - exposed to internet, full blocklist protection
    Wan,
    /// LAN interface - internal network, RFC1918 auto-allowed
    #[default]
    Lan,
    /// Trusted interface - no filtering (VPN, containers)
    Trusted,
}

impl InterfaceMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            InterfaceMode::Wan => "wan",
            InterfaceMode::Lan => "lan",
            InterfaceMode::Trusted => "trusted",
        }
    }
}

impl std::fmt::Display for InterfaceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for InterfaceMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "wan" => Ok(InterfaceMode::Wan),
            "lan" => Ok(InterfaceMode::Lan),
            "trusted" => Ok(InterfaceMode::Trusted),
            _ => anyhow::bail!(
                "Invalid interface mode: {}. Valid values: wan, lan, trusted",
                s
            ),
        }
    }
}

/// Detected interface with its properties
#[derive(Debug, Clone)]
pub struct DetectedInterface {
    /// Interface name (e.g., eth0, wlan0)
    pub name: String,
    /// Suggested mode based on detection
    pub suggested_mode: InterfaceMode,
    /// Reason for the suggested mode
    pub reason: String,
    /// IPv4 addresses assigned to this interface
    pub ipv4_addresses: Vec<String>,
    /// Whether this is the default route interface
    pub is_default_route: bool,
    /// Interface type detected
    pub interface_type: InterfaceType,
}

/// Type of network interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceType {
    /// Physical ethernet interface
    Ethernet,
    /// Wireless interface
    Wireless,
    /// Loopback interface
    Loopback,
    /// Docker bridge
    Docker,
    /// Incus/LXD bridge
    Incus,
    /// Libvirt bridge
    Libvirt,
    /// Generic bridge
    Bridge,
    /// VPN tunnel (OpenVPN, etc.)
    TunTap,
    /// WireGuard VPN
    WireGuard,
    /// VLAN interface
    Vlan,
    /// Virtual ethernet (container)
    Veth,
    /// Unknown type
    Unknown,
}

impl InterfaceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            InterfaceType::Ethernet => "ethernet",
            InterfaceType::Wireless => "wireless",
            InterfaceType::Loopback => "loopback",
            InterfaceType::Docker => "docker",
            InterfaceType::Incus => "incus/lxd",
            InterfaceType::Libvirt => "libvirt",
            InterfaceType::Bridge => "bridge",
            InterfaceType::TunTap => "tun/tap",
            InterfaceType::WireGuard => "wireguard",
            InterfaceType::Vlan => "vlan",
            InterfaceType::Veth => "veth",
            InterfaceType::Unknown => "unknown",
        }
    }
}

/// Detect all network interfaces and classify them
pub fn detect_interfaces() -> Result<Vec<DetectedInterface>> {
    let mut interfaces = Vec::new();

    // Get list of interfaces from /sys/class/net
    let net_path = Path::new("/sys/class/net");
    if !net_path.exists() {
        anyhow::bail!("/sys/class/net not found - are you running on Linux?");
    }

    let default_route_iface = get_default_route_interface();
    let interface_addresses = get_interface_addresses()?;

    for entry in fs::read_dir(net_path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip loopback - it's always implicitly trusted
        if name == "lo" {
            continue;
        }

        let iface_type = detect_interface_type(&name);
        let addresses = interface_addresses.get(&name).cloned().unwrap_or_default();
        let is_default = default_route_iface
            .as_ref()
            .map(|d| d == &name)
            .unwrap_or(false);

        let (suggested_mode, reason) = suggest_mode(&name, iface_type, &addresses, is_default);

        interfaces.push(DetectedInterface {
            name,
            suggested_mode,
            reason,
            ipv4_addresses: addresses,
            is_default_route: is_default,
            interface_type: iface_type,
        });
    }

    // Sort: WAN first, then LAN, then trusted
    interfaces.sort_by(|a, b| {
        let mode_order = |m: &InterfaceMode| match m {
            InterfaceMode::Wan => 0,
            InterfaceMode::Lan => 1,
            InterfaceMode::Trusted => 2,
        };
        mode_order(&a.suggested_mode)
            .cmp(&mode_order(&b.suggested_mode))
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(interfaces)
}

/// Detect interface type based on name and properties
fn detect_interface_type(name: &str) -> InterfaceType {
    // Check by name patterns
    if name == "lo" {
        return InterfaceType::Loopback;
    }

    // Docker interfaces
    if name == "docker0" || name.starts_with("br-") {
        return InterfaceType::Docker;
    }

    // Incus/LXD interfaces
    if name == "incusbr0"
        || name == "lxdbr0"
        || name.starts_with("incus")
        || name.starts_with("lxd")
    {
        return InterfaceType::Incus;
    }

    // Libvirt interfaces
    if name.starts_with("virbr") {
        return InterfaceType::Libvirt;
    }

    // WireGuard
    if name.starts_with("wg") {
        return InterfaceType::WireGuard;
    }

    // TUN/TAP (OpenVPN, etc.)
    if name.starts_with("tun") || name.starts_with("tap") {
        return InterfaceType::TunTap;
    }

    // Virtual ethernet (container)
    if name.starts_with("veth") {
        return InterfaceType::Veth;
    }

    // VLAN interfaces
    if name.contains('.') || name.starts_with("vlan") {
        return InterfaceType::Vlan;
    }

    // Wireless
    if name.starts_with("wlan") || name.starts_with("wlp") || name.starts_with("wifi") {
        return InterfaceType::Wireless;
    }

    // Check if it's a bridge by looking at /sys/class/net/<name>/bridge
    let bridge_path = format!("/sys/class/net/{}/bridge", name);
    if Path::new(&bridge_path).exists() {
        return InterfaceType::Bridge;
    }

    // Physical ethernet (eth*, enp*, eno*, ens*)
    if name.starts_with("eth")
        || name.starts_with("enp")
        || name.starts_with("eno")
        || name.starts_with("ens")
    {
        return InterfaceType::Ethernet;
    }

    InterfaceType::Unknown
}

/// Suggest interface mode based on detected properties
fn suggest_mode(
    name: &str,
    iface_type: InterfaceType,
    addresses: &[String],
    is_default_route: bool,
) -> (InterfaceMode, String) {
    // Container/VPN interfaces are trusted
    match iface_type {
        InterfaceType::Docker => {
            return (
                InterfaceMode::Trusted,
                "Docker bridge - traffic managed by Docker".to_string(),
            );
        }
        InterfaceType::Incus => {
            return (
                InterfaceMode::Trusted,
                "Incus/LXD bridge - traffic managed by Incus".to_string(),
            );
        }
        InterfaceType::Libvirt => {
            return (
                InterfaceMode::Trusted,
                "Libvirt bridge - traffic managed by libvirt".to_string(),
            );
        }
        InterfaceType::WireGuard => {
            return (
                InterfaceMode::Trusted,
                "WireGuard VPN - already filtered at endpoint".to_string(),
            );
        }
        InterfaceType::TunTap => {
            return (
                InterfaceMode::Trusted,
                "VPN tunnel - already filtered at endpoint".to_string(),
            );
        }
        InterfaceType::Veth => {
            return (
                InterfaceMode::Trusted,
                "Container veth - traffic managed by container runtime".to_string(),
            );
        }
        _ => {}
    }

    // Default route = likely WAN
    if is_default_route {
        return (
            InterfaceMode::Wan,
            format!("Default route interface (gateway via {})", name),
        );
    }

    // Check if addresses are RFC1918 (private)
    let has_private_ip = addresses.iter().any(|addr| is_private_ip(addr));

    if has_private_ip {
        let private_addr = addresses.iter().find(|a| is_private_ip(a)).unwrap();
        return (
            InterfaceMode::Lan,
            format!("Has private IP: {}", private_addr),
        );
    }

    // No addresses or public IPs without default route - assume LAN
    if addresses.is_empty() {
        (InterfaceMode::Lan, "No IP address assigned".to_string())
    } else {
        (
            InterfaceMode::Lan,
            format!("Has IP: {}", addresses.first().unwrap()),
        )
    }
}

/// Check if an IP address is in RFC1918 private range
fn is_private_ip(addr: &str) -> bool {
    // Remove CIDR suffix if present
    let ip_str = addr.split('/').next().unwrap_or(addr);

    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 10.0.0.0/8
                if octets[0] == 10 {
                    return true;
                }
                // 172.16.0.0/12
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    return true;
                }
                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return true;
                }
                // 100.64.0.0/10 (Carrier-Grade NAT)
                if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                    return true;
                }
            }
            IpAddr::V6(_) => {
                // For now, consider all IPv6 as non-private
                // (fc00::/7 is private but less common in gateway scenarios)
                return false;
            }
        }
    }
    false
}

/// Get the default route interface
fn get_default_route_interface() -> Option<String> {
    // Try to parse /proc/net/route
    if let Ok(content) = fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                // Destination 00000000 = default route
                if fields[1] == "00000000" {
                    return Some(fields[0].to_string());
                }
            }
        }
    }

    // Fallback: use `ip route` command
    if let Ok(output) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "default via X.X.X.X dev <interface>"
        for word in stdout.split_whitespace() {
            if word.starts_with("dev") {
                continue;
            }
            // The word after "dev" is the interface name
            let parts: Vec<&str> = stdout.split("dev ").collect();
            if parts.len() >= 2 {
                if let Some(iface) = parts[1].split_whitespace().next() {
                    return Some(iface.to_string());
                }
            }
        }
    }

    None
}

/// Get IPv4 addresses for all interfaces
fn get_interface_addresses() -> Result<HashMap<String, Vec<String>>> {
    let mut addresses: HashMap<String, Vec<String>> = HashMap::new();

    // Try parsing /proc/net/fib_trie or use ip command
    if let Ok(output) = Command::new("ip").args(["-4", "addr", "show"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_iface: Option<String> = None;

        for line in stdout.lines() {
            // New interface line: "2: eth0: <BROADCAST..."
            if !line.starts_with(' ') && line.contains(':') {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    current_iface = Some(parts[1].trim().to_string());
                }
            }
            // Address line: "    inet 192.168.1.1/24..."
            else if line.trim().starts_with("inet ") {
                if let Some(ref iface) = current_iface {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        addresses
                            .entry(iface.clone())
                            .or_default()
                            .push(parts[1].to_string());
                    }
                }
            }
        }
    }

    Ok(addresses)
}

/// Format detection report for display
pub fn format_detection_report(interfaces: &[DetectedInterface], lang: &str) -> String {
    let mut output = String::new();

    let title = match lang {
        "fr" => "Rapport de détection des interfaces",
        _ => "Interface Detection Report",
    };

    let header_iface = match lang {
        "fr" => "Interface",
        _ => "Interface",
    };
    let header_type = match lang {
        "fr" => "Type",
        _ => "Type",
    };
    let header_mode = match lang {
        "fr" => "Mode suggéré",
        _ => "Suggested Mode",
    };
    let header_reason = match lang {
        "fr" => "Raison",
        _ => "Reason",
    };

    output.push_str(&format!("{}\n", title));
    output.push_str(&"=".repeat(title.len()));
    output.push_str("\n\n");

    // Loopback note
    let lo_note = match lang {
        "fr" => "Note: lo (loopback) est toujours trusted (codé en dur)\n\n",
        _ => "Note: lo (loopback) is always trusted (hardcoded)\n\n",
    };
    output.push_str(lo_note);

    // Table header
    output.push_str(&format!(
        "{:<15} {:<12} {:<10} {}\n",
        header_iface, header_type, header_mode, header_reason
    ));
    output.push_str(&format!(
        "{:<15} {:<12} {:<10} {}\n",
        "-".repeat(15),
        "-".repeat(12),
        "-".repeat(10),
        "-".repeat(40)
    ));

    for iface in interfaces {
        output.push_str(&format!(
            "{:<15} {:<12} {:<10} {}\n",
            iface.name,
            iface.interface_type.as_str(),
            iface.suggested_mode.as_str(),
            iface.reason
        ));
    }

    output
}

/// Generate suggested config snippet for detected interfaces
pub fn generate_config_snippet(interfaces: &[DetectedInterface]) -> String {
    let mut output = String::new();

    output.push_str("interfaces:\n");

    for iface in interfaces {
        output.push_str("  # [AUTO-DETECTED]\n");
        output.push_str(&format!("  # {}\n", iface.reason));
        output.push_str(&format!("  {}:\n", iface.name));
        output.push_str(&format!("    mode: {}\n", iface.suggested_mode.as_str()));

        match iface.suggested_mode {
            InterfaceMode::Wan => {
                output.push_str("    blocklist_preset: paranoid\n");
                output.push_str("    allowlist_preset: cdn_common\n");
            }
            InterfaceMode::Lan => {
                output.push_str("    allowlist_preset: rfc1918\n");
                output.push_str("    outbound_monitor:\n");
                output.push_str("      blocklist_preset: recommended\n");
                output.push_str("      action: alert\n");
            }
            InterfaceMode::Trusted => {
                // No additional config for trusted interfaces
            }
        }

        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_mode_parsing() {
        assert_eq!("wan".parse::<InterfaceMode>().unwrap(), InterfaceMode::Wan);
        assert_eq!("LAN".parse::<InterfaceMode>().unwrap(), InterfaceMode::Lan);
        assert_eq!(
            "Trusted".parse::<InterfaceMode>().unwrap(),
            InterfaceMode::Trusted
        );
        assert!("invalid".parse::<InterfaceMode>().is_err());
    }

    #[test]
    fn test_detect_interface_type() {
        assert_eq!(detect_interface_type("lo"), InterfaceType::Loopback);
        assert_eq!(detect_interface_type("docker0"), InterfaceType::Docker);
        assert_eq!(detect_interface_type("br-abc123"), InterfaceType::Docker);
        assert_eq!(detect_interface_type("incusbr0"), InterfaceType::Incus);
        assert_eq!(detect_interface_type("lxdbr0"), InterfaceType::Incus);
        assert_eq!(detect_interface_type("virbr0"), InterfaceType::Libvirt);
        assert_eq!(detect_interface_type("wg0"), InterfaceType::WireGuard);
        assert_eq!(detect_interface_type("tun0"), InterfaceType::TunTap);
        assert_eq!(detect_interface_type("tap0"), InterfaceType::TunTap);
        assert_eq!(detect_interface_type("veth123abc"), InterfaceType::Veth);
        assert_eq!(detect_interface_type("eth0"), InterfaceType::Ethernet);
        assert_eq!(detect_interface_type("enp0s3"), InterfaceType::Ethernet);
        assert_eq!(detect_interface_type("wlan0"), InterfaceType::Wireless);
    }

    #[test]
    fn test_is_private_ip() {
        // RFC1918
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("10.255.255.255"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("192.168.255.255"));

        // With CIDR
        assert!(is_private_ip("192.168.1.0/24"));

        // Not private
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("172.32.0.1")); // Just outside 172.16-31

        // CGN
        assert!(is_private_ip("100.64.0.1"));
        assert!(is_private_ip("100.127.255.255"));
        assert!(!is_private_ip("100.128.0.1")); // Just outside CGN
    }

    #[test]
    fn test_suggest_mode_docker() {
        let (mode, _) = suggest_mode("docker0", InterfaceType::Docker, &[], false);
        assert_eq!(mode, InterfaceMode::Trusted);
    }

    #[test]
    fn test_suggest_mode_default_route() {
        let (mode, _) = suggest_mode(
            "eth0",
            InterfaceType::Ethernet,
            &["192.168.1.1/24".to_string()],
            true,
        );
        assert_eq!(mode, InterfaceMode::Wan);
    }

    #[test]
    fn test_suggest_mode_private_ip() {
        let (mode, _) = suggest_mode(
            "eth1",
            InterfaceType::Ethernet,
            &["10.0.0.1/24".to_string()],
            false,
        );
        assert_eq!(mode, InterfaceMode::Lan);
    }
}
