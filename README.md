# OustIP

[![CI](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml/badge.svg)](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**IP Blocklist Manager for Linux Gateways**

> *"Oust!"* — French interjection meaning "Get out!", "Scram!"

OustIP is a high-performance tool for blocking malicious IPs on Linux gateways and routers. Written in Rust for memory safety, zero garbage collection pauses, and minimal attack surface.

## Quick Start

```bash
# Download
curl -sSL https://github.com/jmchantrein/oustip/releases/latest/download/oustip-linux-amd64 \
    -o /usr/local/bin/oustip && chmod +x /usr/local/bin/oustip

# Install & run
sudo oustip install
sudo oustip update
oustip status
```

## Documentation

- [English Documentation](docs/README.md)
- [Documentation Française](docs/README.fr.md)

## Features

- Ultra-fast processing of millions of IPs
- Supports iptables and nftables
- CIDR aggregation for optimized rule sets
- Auto-allowlist for CDN providers (Cloudflare, GitHub, etc.)
- Alerts via Gotify, email, webhook
- Bilingual interface (EN/FR)
- Single static binary, no runtime dependencies

## License

MIT License - see [LICENSE](LICENSE)
