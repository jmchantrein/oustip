# OustIP Architecture

## Module Structure

```
src/
├── main.rs                 # Entry point, CLI dispatch
├── lib.rs                  # Library exports
├── cli.rs                  # CLI argument definitions (clap)
├── config.rs               # Configuration loading/validation
├── aggregator.rs           # CIDR aggregation and IP math
├── fetcher.rs              # HTTP client for blocklist downloads
├── alerts.rs               # Notification system (Gotify, email, webhook)
├── stats.rs                # State persistence and statistics display
├── lock.rs                 # File-based locking (concurrent execution prevention)
├── signal.rs               # Signal handling (graceful shutdown)
├── error.rs                # Error types
├── installer.rs            # Installation/uninstallation logic
├── enforcer/
│   ├── mod.rs              # Firewall backend trait and factory
│   ├── iptables.rs         # iptables backend implementation
│   └── nftables.rs         # nftables backend implementation
└── commands/
    ├── mod.rs              # Command module exports
    ├── install.rs          # oustip install
    ├── update.rs           # oustip update
    ├── stats.rs            # oustip stats
    ├── status.rs           # oustip status
    ├── check.rs            # oustip check
    ├── enable.rs           # oustip enable
    ├── disable.rs          # oustip disable
    ├── allowlist.rs        # oustip allowlist *
    ├── blocklist.rs        # oustip blocklist *
    ├── search.rs           # oustip search
    ├── assume.rs           # oustip assume *
    ├── ipv6.rs             # oustip ipv6 *
    └── uninstall.rs        # oustip uninstall
```

## Execution Flow Tree

```
main()
│
├── CLI Parsing (clap)
│   └── Cli::parse()
│
├── Logging Setup
│   └── tracing_subscriber::FmtSubscriber
│
└── Command Dispatch
    │
    ├── install
    │   ├── check_root()
    │   ├── Config::load() or default
    │   ├── create directories
    │   ├── copy config template
    │   ├── generate_service_unit()
    │   ├── generate_timer_unit()
    │   └── systemctl enable/start
    │
    ├── update [MAIN WORKFLOW]
    │   ├── check_root() [skip if --dry-run]
    │   ├── LockGuard::acquire() [prevent concurrent runs]
    │   ├── Config::load()
    │   ├── ShutdownGuard::new() [signal handling]
    │   ├── Fetcher::new()
    │   ├── create_backend() -> FirewallBackend
    │   ├── config.get_enabled_blocklists()
    │   ├── fetcher.fetch_blocklists() [concurrent HTTP]
    │   │   ├── check cumulative size limit
    │   │   ├── parse IPs/CIDRs
    │   │   └── return Vec<FetchResult>
    │   ├── [Check failure threshold (50%)]
    │   ├── fetcher.fetch_auto_allowlist()
    │   ├── subtract_allowlist()
    │   ├── aggregate() [CIDR optimization]
    │   ├── [if --dry-run: print summary, exit]
    │   ├── backend.apply_rules()
    │   │   ├── generate script/commands
    │   │   ├── validate elements (is_safe_nft_element)
    │   │   └── execute
    │   ├── state.update_sources()
    │   ├── state.save() [atomic write with backup]
    │   └── AlertManager::send() [success/error notifications]
    │
    ├── stats
    │   ├── OustipState::load()
    │   ├── create_backend()
    │   ├── backend.get_stats()
    │   └── display_stats()
    │
    ├── status
    │   ├── Config::load()
    │   ├── OustipState::load()
    │   ├── create_backend()
    │   └── backend.is_active()
    │
    ├── check <ip>
    │   ├── Config::load()
    │   ├── create_backend()
    │   └── backend.is_blocked()
    │
    ├── search <ip> [--dns]
    │   ├── parse IP
    │   ├── Config::load()
    │   ├── OustipState::load()
    │   ├── [if --dns] resolve_ip() -> DNS PTR
    │   ├── check config.allowlist
    │   ├── check state.sources[].ips
    │   └── display results + warnings
    │
    ├── enable
    │   ├── check_root()
    │   └── commands::update::run()
    │
    ├── disable
    │   ├── check_root()
    │   ├── create_backend()
    │   └── backend.remove_rules()
    │
    ├── allowlist <action>
    │   ├── add <ip>
    │   │   ├── check_root()
    │   │   ├── validate IP/CIDR
    │   │   ├── LockGuard::acquire()
    │   │   ├── Config::load()
    │   │   ├── config.allowlist.push()
    │   │   └── config.save() [atomic]
    │   ├── del <ip>
    │   │   └── [similar to add]
    │   ├── list
    │   │   └── Config::load() + display
    │   └── reload
    │       └── commands::update::run()
    │
    ├── blocklist <action>
    │   ├── enable <name>
    │   │   ├── check_root()
    │   │   ├── LockGuard::acquire()
    │   │   ├── Config::load()
    │   │   ├── find blocklist by name
    │   │   ├── set enabled = true
    │   │   └── config.save()
    │   ├── disable <name>
    │   │   └── [similar, enabled = false]
    │   ├── list
    │   │   ├── Config::load()
    │   │   ├── OustipState::load()
    │   │   └── display sources + IP counts
    │   └── show <name> [--dns] [--limit]
    │       ├── Config::load()
    │       ├── OustipState::load()
    │       ├── find source in state
    │       └── display IPs [with DNS if requested]
    │
    ├── assume <action>
    │   ├── add <ip>
    │   │   ├── check_root()
    │   │   ├── validate IP
    │   │   ├── LockGuard::acquire()
    │   │   ├── OustipState::load()
    │   │   ├── state.add_assumed_ip()
    │   │   └── state.save()
    │   ├── del <ip>
    │   │   └── [similar with remove_assumed_ip]
    │   └── list
    │       ├── OustipState::load()
    │       └── display assumed IPs + DNS
    │
    ├── ipv6 <action>
    │   ├── status -> read sysctl
    │   ├── enable -> write sysctl
    │   └── disable -> write sysctl
    │
    └── uninstall
        ├── check_root()
        ├── systemctl stop/disable
        ├── create_backend()
        ├── backend.remove_rules()
        └── remove files (except binary)
```

## Key Data Structures

### Config (config.rs)
```rust
Config {
    language: String,
    backend: Backend,           // Auto, Iptables, Nftables
    mode: FilterMode,           // Raw, Conntrack
    blocklists: Vec<BlocklistSource>,
    auto_allowlist: AutoAllowlist,
    allowlist: Vec<String>,
    alerts: AlertsConfig,
    update_interval: String,
    preset: String,
}
```

### OustipState (stats.rs)
```rust
OustipState {
    last_update: Option<DateTime<Utc>>,
    sources: Vec<SourceStats>,
    total_entries: usize,
    total_ips: u128,
    assumed_ips: Option<Vec<String>>,  // Acknowledged overlaps
}

SourceStats {
    name: String,
    raw_count: usize,
    ip_count: u128,
    ips: Vec<String>,  // Cached for display (max 1000)
}
```

### FirewallBackend Trait (enforcer/mod.rs)
```rust
#[async_trait]
trait FirewallBackend {
    async fn apply_rules(&self, ips: &[IpNet], mode: FilterMode) -> Result<()>;
    async fn remove_rules(&self) -> Result<()>;
    async fn get_stats(&self) -> Result<FirewallStats>;
    async fn is_blocked(&self, ip: &IpNet) -> Result<bool>;
    async fn is_active(&self) -> Result<bool>;
}
```

## Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Input                               │
│  (CLI args, config file, environment variables)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Validation Layer                           │
│  - IP/CIDR parsing (ipnet crate)                                │
│  - Interval format validation (ASCII-only)                       │
│  - URL scheme validation (HTTPS required)                        │
│  - Header injection prevention                                   │
│  - Preset validation                                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Processing Layer                            │
│  - CIDR aggregation                                              │
│  - Allowlist subtraction                                         │
│  - Size limit enforcement (10MB/file, 50MB total)               │
│  - Failure threshold (50% sources)                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Firewall Backend Layer                        │
│  - Element validation (is_safe_nft_element)                     │
│  - Script generation (nftables)                                  │
│  - Command execution (array-based, no shell)                     │
│  - Isolated chains (OUSTIP-* / table ip oustip)                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     System Resources                             │
│  - /var/lib/oustip/state.json (atomic writes)                   │
│  - /var/run/oustip.lock (flock)                                 │
│  - /etc/oustip/config.yaml                                       │
│  - Firewall (nft/iptables)                                       │
└─────────────────────────────────────────────────────────────────┘
```

## Dead Code Detection

To find potentially unused code:

```bash
# Find unused functions/methods
cargo +nightly udeps  # unused dependencies
cargo clippy -- -W dead_code

# Generate call graph
cargo install cargo-call-stack
cargo +nightly call-stack --bin oustip

# Module dependency graph
cargo install cargo-modules
cargo modules generate tree
cargo modules generate graph | dot -Tpng > modules.png
```

## Testing Strategy

```
Unit Tests (37 total)
├── aggregator::tests (5)
│   ├── test_aggregate_contiguous
│   ├── test_aggregate_non_contiguous
│   ├── test_count_ips
│   ├── test_deduplicate
│   └── test_subtract_allowlist
├── alerts::tests (2)
├── config::tests (14)
├── enforcer::iptables::tests (2)
├── enforcer::nftables::tests (4)
├── fetcher::tests (4)
├── installer::tests (2)
├── lock::tests (1)
├── signal::tests (2)
└── stats::tests (2)

Integration Tests (requires root)
└── cargo test --all-features -- --include-ignored
```
