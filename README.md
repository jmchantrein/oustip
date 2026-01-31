# OustIP

[![CI](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml/badge.svg)](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml)
[![Release](https://github.com/jmchantrein/oustip/actions/workflows/release.yml/badge.svg)](https://github.com/jmchantrein/oustip/actions/workflows/release.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

> [!WARNING]
> This project is currently under development. Features may change, and the software is not yet ready for production use.

**IP Blocklist Manager for Linux Gateways**

> *"Oust!"* — French interjection meaning "Get out!", "Scram!"

OustIP is a high-performance tool for blocking malicious IPs on Linux gateways and routers. Written in Rust for memory safety, zero garbage collection pauses, and minimal attack surface.

[Documentation Francaise / French Documentation](README_FR.md) | [API Documentation](https://jmchantrein.github.io/oustip/)

## Features

- **High Performance** - Process millions of IPs with minimal latency (auto-detects nftables/iptables)
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
oustip install                   # Install OustIP (interactive)
oustip install --headless        # Install with auto-detected interfaces
oustip install --preset paranoid # Install with specific preset
oustip install --config-file /path/to/config.yaml  # Install with existing config
oustip update                    # Full update: fetch lists + apply rules
oustip update presets            # Reload presets.yaml definitions
oustip update lists              # Download blocklists and allowlists
oustip update config             # Reload config.yaml and apply firewall rules
oustip update --dry-run          # Dry-run: fetch lists but don't apply rules
oustip stats                     # Show blocking statistics
oustip status                    # Show current status

# Interface detection
oustip interfaces detect         # Detect network interfaces and suggest modes

# Presets management
oustip presets list              # List all available presets
oustip presets list --blocklist  # List blocklist presets only
oustip presets list --allowlist  # List allowlist presets only
oustip presets show <name>       # Show details of a specific preset

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
oustip blocklist show <name>    # Show IPs from a source (first 20)
oustip blocklist show <name> --limit 50  # Show with custom limit
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
oustip report                   # Generate text report (top 10 blocked IPs)
oustip report --format json     # Generate JSON report
oustip report --format markdown # Generate Markdown report
oustip report --send            # Send report via email/gotify/webhook
oustip report --top 20          # Show top 20 blocked IPs (default: 10)

# Health monitoring
oustip health                   # Run health check
oustip health --json            # Output in JSON format (for monitoring)

# Version and cleanup
oustip version                  # Show version
oustip uninstall                # Remove everything

# Global options
--config <path>                 # Custom config path
--quiet                         # Quiet mode (for cron)
--verbose                       # Verbose mode
--lang <en|fr>                  # Force language
```

## Configuration

OustIP uses two configuration files:
- `/etc/oustip/config.yaml` - Main configuration (interfaces, alerts, settings)
- `/etc/oustip/presets.yaml` - Blocklist and allowlist sources and presets

After editing files, run the appropriate command:
- `oustip update config` - After editing config.yaml
- `oustip update presets && oustip update lists` - After editing presets.yaml

### Interface-Based Configuration (config.yaml)

```yaml
# Language (en, fr)
language: en

# Firewall backend (auto, iptables, nftables)
backend: auto

# Filtering mode
# - raw: before conntrack (more performant)
# - conntrack: after conntrack (allows responses to outbound connections)
mode: conntrack

# Update interval for systemd timer (e.g., 6h, 12h, 1d)
update_interval: "4h"

# Per-interface configuration
# Use 'oustip interfaces detect' to auto-detect interfaces
interfaces:
  # WAN interface - exposed to internet, full blocklist protection
  eth0:
    mode: wan
    blocklist_preset: paranoid    # Block suspicious IPs from internet
    allowlist_preset: cdn_common  # Allow CDN providers (Cloudflare, GitHub, Fastly)

  # LAN interface - internal network, monitor outbound traffic
  eth1:
    mode: lan
    allowlist_preset: rfc1918     # Allow private networks
    outbound_monitor:             # Monitor for compromise detection
      blocklist_preset: recommended
      action: alert               # alert, block, block_and_alert

  # Trusted interfaces - no filtering (containers, VPN tunnels)
  docker0:
    mode: trusted
  wg0:
    mode: trusted

# IPv6 configuration
ipv6:
  boot_state: unchanged  # disabled, enabled, unchanged

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
    smtp_password: ""            # Can be set via OUSTIP_SMTP_PASSWORD env var
    from: "oustip@example.com"
    to: "admin@example.com"
  webhook:
    enabled: false
    url: ""
    headers: {}
```

### Presets Configuration (presets.yaml)

```yaml
# Blocklist sources
blocklist_sources:
  spamhaus_drop:
    url: https://www.spamhaus.org/drop/drop.txt
    description:
      en: "Spamhaus DROP - Hijacked/leased for spam/malware"
      fr: "Spamhaus DROP - Détournées/louées pour spam/malware"
  # ... more sources

# Blocklist presets with inheritance
blocklist_presets:
  minimal:
    description:
      en: "Production servers - near-zero false positives"
    sources:
      - spamhaus_drop
      - spamhaus_edrop
      - dshield

  recommended:
    description:
      en: "Recommended default - good balance"
    extends: minimal  # Inherits all sources from minimal
    sources:
      - firehol_level1
      - firehol_level2

# Allowlist sources (static and dynamic)
allowlist_sources:
  rfc1918:
    static:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    description:
      en: "RFC1918 private networks"

  cloudflare:
    url: https://www.cloudflare.com/ips-v4
    url_v6: https://www.cloudflare.com/ips-v6
    description:
      en: "Cloudflare CDN IP ranges"

# Allowlist presets
allowlist_presets:
  cdn_common:
    sources:
      - cloudflare
      - github
      - fastly
```

### Interface Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `wan` | Full blocklist protection | Internet-facing interfaces |
| `lan` | RFC1918 auto-allowed, outbound monitoring | Internal network interfaces |
| `trusted` | No filtering | VPN tunnels, container bridges |

Note: `lo` (loopback) is always trusted and cannot be configured.

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

## Supported Environments

### Recommended For

| Environment | Notes |
|-------------|-------|
| **Linux Gateways/Routers** | Primary use case - centralized blocking |
| **VPN/Proxy Servers** | Block malicious IPs before they reach services |
| **Dedicated Servers** | With root access and nftables/iptables |
| **Docker Containers** | With `--cap-add NET_ADMIN --network host` |
| **Home Routers** | OpenWrt, custom Linux routers |

### System Requirements

- **OS**: Linux (kernel 3.13+ for nftables, 2.4+ for iptables)
- **Distributions**: Debian, Ubuntu, RHEL/CentOS, Alpine, Arch, etc.
- **Privileges**: Root or CAP_NET_ADMIN + CAP_NET_RAW capabilities
- **Firewall**: nftables (recommended) or iptables with ipset
- **Memory**: ~50 MB for 100k IPs, ~512 MB for 1M IPs
- **Disk**: ~100 MB free space recommended

### Not Recommended For

| Environment | Reason |
|-------------|--------|
| Rootless containers | Requires CAP_NET_ADMIN |
| Serverless (Lambda, etc.) | No native firewall access |
| Managed load balancers | AWS ALB, GCP LB - no iptables access |
| Windows/macOS | Linux-only (nftables/iptables) |

## Advantages & Limitations

### Advantages

- **High Performance**: Rust + nftables sets = O(1) lookup per packet
- **Memory Safe**: No buffer overflows, use-after-free, or GC pauses
- **Non-Intrusive**: Creates isolated chains, never modifies existing rules
- **Smart Aggregation**: CIDR optimization reduces rule count by up to 70%
- **Overlap Detection**: Automatic detection of allow+block conflicts with DNS resolution
- **Defense in Depth**: Input validation, HTTPS enforcement, credential zeroization
- **Production Ready**: Atomic file operations, retry logic, graceful degradation

### Limitations

| Limitation | Workaround |
|------------|------------|
| **No behavioral detection** | Use with CrowdSec for behavior-based and ML detection |
| **IPv6 aggregation limited** | Consider `oustip ipv6 disable` if not needed |
| **No automatic rollback** | Use `oustip disable` then `oustip enable` to rollback |
| **Static blocklists** | Lists updated every 6h by default (timer configurable) |

### Comparison with Alternatives

| Tool | Purpose | Use Together? |
|------|---------|---------------|
| **CrowdSec** | ML + community threat intelligence + behavior detection | Yes - OustIP for static lists, CrowdSec for dynamic |
| **firewalld** | Zone-based firewall management | Yes - OustIP adds dynamic blocklists |
| **ufw** | Simple firewall wrapper | OustIP preferred for gateways |

**Recommended Stack**: OustIP (preemptive blocking) + CrowdSec (reactive/behavioral)

## AI Architecture

OustIP uses a hybrid AI architecture for development assistance. Configuration is centralized in `.ai/` and generates platform-specific files.

### Structure

```
.ai/
├── skills/           # Agent definitions (YAML source)
├── commands/         # Quick reference
├── MEMORY.md         # Persistent context between sessions
└── generate.sh       # Multi-platform generator
```

### Supported Platforms

| Platform | Generated Files |
|----------|-----------------|
| Claude Code | `.claude/agents/*.md` |
| OpenCode | `.opencode/agent/*.md` |
| Ollama | `ollama/Modelfile.*` |
| Continue.dev | `.continuerc.json` |
| Aider | `.aider.conf.yml` |
| Cursor | `.cursorrules` |
| Codex | `.codex/agents/*.md` |

### Usage

```bash
# Regenerate all configs (if VERSION changed)
.ai/generate.sh

# Force regeneration
.ai/generate.sh --force
```

See [AGENTS.md](AGENTS.md) for development rules and [.ai/MEMORY.md](.ai/MEMORY.md) for project context.

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

Code style: `cargo fmt` and `cargo clippy`
