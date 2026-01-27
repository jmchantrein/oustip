# OustIP

**IP Blocklist Manager for Linux Gateways**

OustIP is a high-performance tool for blocking malicious IPs on Linux gateways and routers. Written in Rust for memory safety, zero garbage collection pauses, and minimal attack surface.

## Features

- **High Performance** - Process millions of IPs with minimal latency
- **Memory Safe** - Written in Rust with compile-time guarantees
- **Simple** - Installation and configuration in 5 minutes
- **Non-Intrusive** - Never modifies existing firewall rules
- **Flexible** - Supports both iptables and nftables backends
- **Smart Aggregation** - CIDR optimization reduces rule count
- **Auto-Allowlist** - Automatically whitelist CDN providers (Cloudflare, GitHub, etc.)
- **Alerting** - Gotify, email, and webhook notifications
- **Bilingual** - English and French interface

## Quick Start

### Installation

```bash
# Download binary
curl -sSL https://github.com/jmchantrein/oustip/releases/latest/download/oustip-linux-amd64 \
    -o /usr/local/bin/oustip
chmod +x /usr/local/bin/oustip

# Install (creates config, systemd service, timer)
sudo oustip install

# Edit configuration (optional)
sudo vim /etc/oustip/config.yaml

# Apply rules
sudo oustip update

# Check status
oustip status
```

### Docker

```bash
docker pull ghcr.io/jmchantrein/oustip:latest
docker run --rm --cap-add NET_ADMIN --network host oustip update
```

## Usage

```bash
# Core commands
oustip install                   # Install OustIP
oustip install --preset paranoid # Install with specific preset
oustip update                    # Update blocklists and apply rules
oustip update --preset minimal   # Use specific preset for this run
oustip stats                     # Show blocking statistics
oustip status                    # Show current status

# Enable/disable
oustip enable                    # Enable blocking
oustip disable                   # Disable blocking (keep config)

# IP checking
oustip check 1.2.3.4            # Check if IP is blocked

# Allowlist management
oustip allowlist add 1.2.3.4    # Add IP to allowlist
oustip allowlist del 1.2.3.4    # Remove IP from allowlist
oustip allowlist list           # List allowlisted IPs
oustip allowlist reload         # Reload from config

# IPv6 management
oustip ipv6 status              # Show IPv6 status
oustip ipv6 disable             # Disable IPv6 via sysctl
oustip ipv6 enable              # Enable IPv6

# Cleanup
oustip uninstall                # Remove everything

# Global options
--config <path>                 # Custom config path
--quiet                         # Quiet mode (for cron)
--verbose                       # Verbose mode
--lang <en|fr>                  # Force language
```

## Configuration

Configuration file: `/etc/oustip/config.yaml`

```yaml
# Language (en, fr)
language: en

# Firewall backend (auto, iptables, nftables)
backend: auto

# Filtering mode
# - raw: before conntrack (more performant)
# - conntrack: after conntrack (allows responses to outbound connections)
mode: conntrack

# Preset (minimal, recommended, full, paranoid)
preset: recommended

# Blocklist sources
blocklists:
  - name: firehol_level1
    url: https://iplists.firehol.org/files/firehol_level1.netset
    enabled: true
  # ... more lists

# Auto-allowlist CDN providers
auto_allowlist:
  cloudflare: true
  github: true
  google_cloud: false
  aws: false
  fastly: false

# Manual allowlist
allowlist:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "172.16.0.0/12"

# Alert destinations
alerts:
  gotify:
    enabled: false
    url: "https://gotify.example.com"
    token: ""
  email:
    enabled: false
    # ...
  webhook:
    enabled: false
    url: ""
```

## Presets

| Preset | Lists | False Positives |
|--------|-------|-----------------|
| `minimal` | spamhaus_drop, spamhaus_edrop, dshield | Almost none |
| `recommended` | minimal + firehol_level1, firehol_level2 | Very rare |
| `full` | recommended + firehol_level3 | Possible |
| `paranoid` | full + firehol_level4 | Likely |

## Filtering Modes

### Conntrack Mode (default)

Rules are applied after connection tracking. This allows:
- Responses to outbound connections even if destination is in blocklist
- Alerting on outbound connections to blocked IPs (possible compromise indicator)

### Raw Mode

Rules are applied before connection tracking. This is:
- More performant (no conntrack overhead)
- Blocks ALL traffic to/from blocklisted IPs including responses

## Building from Source

```bash
# Requirements: Rust 1.75+
cargo build --release

# Cross-compile for musl (static binary)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Strip binary
strip target/x86_64-unknown-linux-musl/release/oustip
```

## How It Works

1. **Fetch** - Downloads blocklists from configured sources
2. **Aggregate** - Merges overlapping CIDRs for efficiency
3. **Filter** - Removes allowlisted IPs (manual + CDN providers)
4. **Apply** - Injects rules into dedicated firewall chains

OustIP creates isolated chains (`OUSTIP-INPUT`, `OUSTIP-FORWARD` for iptables or `table ip oustip` for nftables) and never touches existing rules.

## CrowdSec Integration

OustIP is complementary to CrowdSec. While OustIP blocks known bad IPs from public blocklists, CrowdSec provides behavior-based detection.

To use both:

1. Install CrowdSec separately (see [CrowdSec documentation](https://docs.crowdsec.net/))
2. OustIP and CrowdSec use separate firewall chains and don't interfere

## Troubleshooting

### No rules applied

```bash
# Check if OustIP is active
oustip status

# Check firewall rules
sudo nft list table ip oustip  # nftables
sudo iptables -L OUSTIP-INPUT  # iptables
```

### Permission denied

OustIP requires root privileges for firewall manipulation:

```bash
sudo oustip update
```

### Blocklist fetch fails

Check network connectivity and retry:

```bash
oustip update --verbose
```

## License

MIT License - see [LICENSE](../LICENSE)

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

Code style: `cargo fmt` and `cargo clippy`
