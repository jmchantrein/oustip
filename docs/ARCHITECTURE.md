# OustIP Architecture

## Module Structure

```
src/
├── main.rs                 # Entry point, CLI dispatch
├── lib.rs                  # Library exports
├── cli.rs                  # CLI argument definitions (clap)
├── config.rs               # Configuration loading/validation
├── aggregator.rs           # CIDR aggregation and IP math
├── fetcher.rs              # HTTP client for blocklist downloads (6 concurrent max)
├── alerts.rs               # Notification system (Gotify, email, webhook)
├── stats.rs                # State persistence and statistics display
├── lock.rs                 # File-based locking (concurrent execution prevention)
├── signal.rs               # Signal handling (graceful shutdown)
├── installer.rs            # Installation/uninstallation logic
├── dns.rs                  # DNS resolution utilities with timeout
├── utils.rs                # Common utilities (format_bytes, truncate)
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
    ├── health.rs           # oustip health (monitoring integration)
    ├── report.rs           # oustip report (JSON/text/markdown reports)
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
    │   ├── create_backend() -> FirewallBackend (nftables default)
    │   ├── config.get_enabled_blocklists()
    │   ├── fetcher.fetch_blocklists() [6 concurrent HTTP max]
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
    │   ├── detect_overlaps() [O(1) HashSet lookup + CIDR check]
    │   │   ├── build HashMap<blocklist_ip, sources>
    │   │   ├── check allowlist against HashMap
    │   │   ├── filter out assumed IPs
    │   │   └── resolve DNS (5s timeout)
    │   ├── state.update_sources()
    │   ├── state.save() [atomic write with backup]
    │   └── AlertManager::send() [success/error/overlap notifications]
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
    ├── health [--json]
    │   ├── check_config() -> validate config file
    │   ├── check_state_file() -> freshness check
    │   ├── check_firewall_active() -> rules loaded
    │   ├── check_disk_space() -> /var/lib/oustip
    │   └── output as text or JSON (for monitoring)
    │
    ├── report [--format] [--send] [--top]
    │   ├── Config::load()
    │   ├── OustipState::load()
    │   ├── create_backend()
    │   ├── backend.get_stats()
    │   ├── format_report() -> text/json/markdown
    │   └── [if --send] AlertManager::send_report()
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

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Blocklist fetch | O(n) parallel | 6 concurrent requests max |
| CIDR aggregation | O(n log n) | ipnet crate native |
| Allowlist subtraction | O(n × m) | n=blocklist, m=allowlist |
| Overlap detection | O(n + m) | HashSet lookup + CIDR check |
| nftables apply | O(1) | Single atomic script execution |
| iptables apply | O(n) | One command per IP (slower) |

### Backend Recommendations

| Blocklist Size | Recommended Backend |
|----------------|---------------------|
| < 10,000 IPs | Either works |
| 10k - 100k IPs | nftables (default) |
| > 100,000 IPs | nftables required |

### Resource Limits

| Resource | Limit | Configurable |
|----------|-------|--------------|
| Max file size | 10 MB | No |
| Max total download | 50 MB | No |
| Concurrent HTTP requests | 6 | No |
| DNS timeout | 5 seconds | No |
| Alert timeout | 30 seconds | No |
| Overlap notifications | 50 max | No |
| Cached IPs per source | 1000 | No |

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
Unit Tests (85+ total)
├── aggregator::tests (8 unit + 8 proptest)
├── alerts::tests (2)
├── cli::tests (16)
├── commands::check::tests (7)
├── config::tests (14)
├── dns::tests (3)
├── enforcer::iptables::tests (2)
├── enforcer::nftables::tests (4)
├── fetcher::tests (10 unit + 5 proptest)
├── installer::tests (2)
├── lock::tests (1)
├── signal::tests (2)
└── utils::tests (4)

Integration Tests (tests/integration.rs)
├── test_version_command
├── test_help_command
├── test_status_command (#[ignore] - root)
├── test_update_dry_run (#[ignore] - root)
├── test_health_check (#[ignore] - root)
├── test_check_invalid_ip
├── test_search_invalid_ip
├── test_blocklist_list_without_config
└── test_concurrent_execution_lock (#[ignore] - root)

Robustness Tests (tests/robustness.rs)
├── Network timeout handling
├── Unicode/malformed input handling
├── Large input handling (100K+ IPs)
├── Concurrent operations (race conditions)
└── YAML/JSON parsing edge cases

Benchmarks (benches/aggregation.rs)
├── bench_aggregate (100-50K IPs)
├── bench_deduplicate (100-10K IPs)
└── bench_parse_blocklist (100-10K entries)

Run commands:
  cargo test                              # Unit tests
  sudo cargo test -- --ignored            # Integration tests
  cargo test --test robustness            # Robustness tests
  cargo bench                             # Benchmarks
```
