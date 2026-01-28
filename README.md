# OustIP

[![CI](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml/badge.svg)](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**IP Blocklist Manager for Linux Gateways**

> *"Oust!"* — French interjection meaning "Get out!", "Scram!"

OustIP is a high-performance tool for blocking malicious IPs on Linux gateways and routers. Written in Rust for memory safety, zero garbage collection pauses, and minimal attack surface.

[Documentation Francaise / French Documentation](README_FR.md)

## Features

- **High Performance** - Process millions of IPs with minimal latency (nftables default)
- **Memory Safe** - Written in Rust with compile-time guarantees
- **Simple** - Installation and configuration in 5 minutes
- **Non-Intrusive** - Never modifies existing firewall rules
- **Flexible** - Supports both nftables (default) and iptables backends
- **Smart Aggregation** - CIDR optimization reduces rule count
- **Overlap Detection** - Automatic detection of allow+block overlaps with DNS resolution
- **Auto-Allowlist** - Automatically whitelist CDN providers (Cloudflare, GitHub, AWS, GCP, Fastly)
- **Alerting** - Gotify, email, and webhook notifications
- **Bilingual** - English and French interface
- **Secure** - Environment variable support for credentials, input validation, atomic file operations

## Quick Start

### Installation

```bash
# Download binary
curl -sSL https://github.com/jmchantrein/oustip/releases/latest/download/oustip-linux-amd64 \
    -o /usr/local/sbin/oustip
chmod +x /usr/local/sbin/oustip

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
docker pull jmchantrein/oustip:latest
docker run --rm --cap-add NET_ADMIN --network host jmchantrein/oustip update
```

Or with docker-compose:

```yaml
version: '3.8'
services:
  oustip:
    image: jmchantrein/oustip:latest
    cap_add:
      - NET_ADMIN
    network_mode: host
    volumes:
      - ./config.yaml:/etc/oustip/config.yaml:ro
    command: ["update"]
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

# IP checking and searching
oustip check 1.2.3.4            # Check if IP is blocked in firewall
oustip search 1.2.3.4           # Search IP in allow/blocklists
oustip search 1.2.3.4 --dns     # Search with DNS resolution

# Allowlist management
oustip allowlist add 1.2.3.4    # Add IP to allowlist
oustip allowlist del 1.2.3.4    # Remove IP from allowlist
oustip allowlist list           # List allowlisted IPs
oustip allowlist reload         # Reload from config

# Blocklist management
oustip blocklist list           # List all blocklist sources
oustip blocklist enable <name>  # Enable a blocklist source
oustip blocklist disable <name> # Disable a blocklist source
oustip blocklist show <name>    # Show IPs from a source
oustip blocklist show <name> --dns  # Show with DNS resolution

# Assume management (acknowledged allow+block overlaps)
oustip assume list              # List assumed IPs
oustip assume add 1.2.3.4       # Acknowledge overlap (no more notifications)
oustip assume del 1.2.3.4       # Remove from assumed list

# IPv6 management
oustip ipv6 status              # Show IPv6 status
oustip ipv6 disable             # Disable IPv6 via sysctl
oustip ipv6 enable              # Enable IPv6

# Reports
oustip report                   # Generate text report
oustip report --format json     # Generate JSON report
oustip report --format markdown # Generate Markdown report
oustip report --send            # Send report via email/gotify/webhook
oustip report --top 20          # Show top 20 blocked IPs

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

# Firewall backend (nftables, iptables, auto)
# nftables is default and recommended for performance
backend: nftables

# Filtering mode
# - raw: before conntrack (more performant)
# - conntrack: after conntrack (allows responses to outbound connections)
mode: conntrack

# Update interval for systemd timer (e.g., 6h, 12h, 1d)
update_interval: "6h"

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
    token: ""                    # Can be set directly here
    token_env: "MY_GOTIFY_TOKEN" # Or via environment variable
  email:
    enabled: false
    smtp_host: "smtp.example.com"
    smtp_port: 587
    smtp_user: "alerts@example.com"
    smtp_password: ""            # Can be set directly here
    smtp_password_env: "MY_SMTP_PASS" # Or via environment variable
    from: "oustip@example.com"
    to: ["admin@example.com"]
  webhook:
    enabled: false
    url: ""
    headers: {}  # Optional custom headers
```

### Environment Variables for Credentials

For enhanced security, credentials can be provided via environment variables:

| Config Field | Default Env Variable | Custom Env Variable Field |
|--------------|---------------------|---------------------------|
| `gotify.token` | `OUSTIP_GOTIFY_TOKEN` | `gotify.token_env` |
| `email.smtp_password` | `OUSTIP_SMTP_PASSWORD` | `email.smtp_password_env` |

Priority order:
1. Custom environment variable (if `token_env` or `smtp_password_env` is set)
2. Default environment variable (`OUSTIP_GOTIFY_TOKEN` or `OUSTIP_SMTP_PASSWORD`)
3. Value in config file

Example with systemd:

```bash
# /etc/systemd/system/oustip.service.d/credentials.conf
[Service]
Environment="OUSTIP_GOTIFY_TOKEN=your-secret-token"
Environment="OUSTIP_SMTP_PASSWORD=your-smtp-password"
```

## Presets

| Preset | Lists | False Positives | Use Case |
|--------|-------|-----------------|----------|
| `minimal` | spamhaus_drop, spamhaus_edrop, dshield | Almost none | Production servers |
| `recommended` | minimal + firehol_level1, firehol_level2 | Very rare | Default choice |
| `full` | recommended + firehol_level3 | Possible | High-security environments |
| `paranoid` | full + firehol_level4 | Likely | Maximum protection |

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

# Run tests
cargo test

# Cross-compile for musl (static binary)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Strip binary
strip target/x86_64-unknown-linux-musl/release/oustip
```

## How It Works

1. **Fetch** - Downloads blocklists from configured sources (with size limits: 10MB per file, 50MB total)
2. **Aggregate** - Merges overlapping CIDRs for efficiency
3. **Filter** - Removes allowlisted IPs (manual + CDN providers)
4. **Apply** - Injects rules into dedicated firewall chains

OustIP creates isolated chains (`OUSTIP-INPUT`, `OUSTIP-FORWARD` for iptables or `table ip oustip` for nftables) and never touches existing rules.

## Security

OustIP is designed with security in mind:

- **Input Validation** - All user inputs (presets, intervals, headers) are validated
- **Injection Prevention** - Systemd unit files and HTTP headers are sanitized
- **Credential Protection** - Support for environment variables instead of plaintext config
- **Atomic Operations** - State files are written atomically to prevent corruption
- **Download Limits** - Blocklist downloads are size-limited to prevent DoS
- **No Response Logging** - Error logs don't include potentially sensitive response bodies

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

### Systemd timer not running

```bash
# Check timer status
systemctl status oustip.timer

# Enable and start timer
sudo systemctl enable --now oustip.timer

# Check logs
journalctl -u oustip.service
```

## License

AGPL-3.0-or-later - see [LICENSE](LICENSE)

This means you must share source code if you:
- Distribute the software
- Provide access to it over a network (SaaS)

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

Code style: `cargo fmt` and `cargo clippy`
