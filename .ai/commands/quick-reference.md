# Quick Reference - OustIP

## Development Commands

### Build & Test
```bash
cargo build                     # Debug build
cargo build --release           # Release build
cargo test                      # Run unit tests
cargo test --test integration   # Integration tests (some need root)
cargo test --test robustness    # Robustness tests
cargo bench                     # Run benchmarks
```

### Code Quality
```bash
cargo fmt                       # Format code
cargo fmt --check               # Check formatting (CI)
cargo clippy                    # Linting
cargo clippy -- -D warnings     # Strict linting (CI)
cargo audit                     # Security audit
cargo +nightly udeps            # Find unused dependencies
```

### Documentation
```bash
cargo doc --open                # Generate and open docs
cargo doc --no-deps             # Without dependencies
```

## OustIP Commands

### Core Operations
```bash
oustip install                  # Install (interactive)
oustip install --headless       # Install (auto-detect)
oustip update                   # Full update
oustip update --dry-run         # Dry run (no changes)
oustip status                   # Show status
oustip stats                    # Show statistics
```

### Management
```bash
oustip enable                   # Enable blocking
oustip disable                  # Disable blocking
oustip uninstall                # Remove installation
```

### IP Operations
```bash
oustip check 1.2.3.4            # Check if blocked
oustip search 1.2.3.4           # Search in lists
oustip search 1.2.3.4 --dns     # With DNS resolution
```

### List Management
```bash
oustip allowlist add 1.2.3.4    # Add to allowlist
oustip allowlist del 1.2.3.4    # Remove from allowlist
oustip allowlist list           # Show allowlist
oustip blocklist list           # Show blocklists
oustip blocklist enable <name>  # Enable a blocklist
oustip blocklist disable <name> # Disable a blocklist
```

### Monitoring
```bash
oustip health                   # Health check
oustip health --json            # JSON output
oustip report                   # Generate report
oustip report --format json     # JSON report
oustip diagnose                 # Comprehensive diagnostics
```

## Git Workflow

### Feature Development
```bash
git checkout -b feature/my-feature
# ... make changes ...
cargo fmt && cargo clippy && cargo test
git add -p                      # Stage interactively
git commit -m "feat: description"
git push -u origin feature/my-feature
```

### Commit Prefixes
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `style:` - Formatting (no code change)
- `refactor:` - Code restructuring
- `test:` - Adding tests
- `chore:` - Maintenance

## AI Architecture

### Regenerate Configs
```bash
.ai/generate.sh                 # If VERSION changed
.ai/generate.sh --force         # Force regeneration
```

### Skills Available
- `project-assistant` - Main assistant
- `rust-expert` - Rust code review
- `security-reviewer` - Security audit
- `inclusivity-reviewer` - Inclusive writing
- `translator` - EN-FR translation
- `memory-keeper` - Context management
- `workflow-orchestrator` - Task automation
