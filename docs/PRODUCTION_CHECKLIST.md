# Production Checklist - OustIP

> Checklist to verify before releasing a new version.

## Pre-Release Verification

### Code Quality

- [ ] `cargo fmt --check` passes (no formatting issues)
- [ ] `cargo clippy -- -D warnings` passes (no warnings)
- [ ] `cargo test` passes (all unit tests)
- [ ] `cargo test --test robustness` passes (robustness tests)
- [ ] `sudo cargo test -- --ignored` passes (integration tests, requires root)
- [ ] `cargo bench` shows no performance regression

### Security

- [ ] `cargo audit` shows no vulnerabilities
- [ ] No `unwrap()` without documented justification
- [ ] All user inputs are validated
- [ ] No secrets in logs or error messages
- [ ] HTTPS enforced for all external connections
- [ ] Path canonicalization for file operations
- [ ] Interface name validation (alphanumeric, max 15 chars)
- [ ] Timeout on all external operations (30s max)

### Documentation

- [ ] README.md is up to date
- [ ] README_FR.md is synchronized
- [ ] docs/ARCHITECTURE.md reflects current code
- [ ] All new commands are documented
- [ ] CHANGELOG.md is updated
- [ ] .ai/MEMORY.md is updated with session notes

### Metadata

- [ ] `Cargo.toml` version is updated
- [ ] `Cargo.toml` has complete metadata:
  - `authors`
  - `description`
  - `license`
  - `repository`
  - `keywords`
  - `categories`
  - `rust-version`

### Build

- [ ] `cargo build --release` succeeds
- [ ] Binary size is reasonable (< 10MB stripped)
- [ ] Cross-compilation works: `cargo build --release --target x86_64-unknown-linux-musl`

## Release Process

### 1. Version Bump

```bash
# Update version in Cargo.toml
# Update version in .ai/MEMORY.md
# Update CHANGELOG.md
```

### 2. Final Checks

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
cargo build --release
strip target/release/oustip
ls -lh target/release/oustip  # Check size
```

### 3. Tag and Push

```bash
git add -A
git commit -m "chore(release): X.Y.Z"
git tag -a vX.Y.Z -m "Release X.Y.Z"
git push origin main --tags
```

### 4. Post-Release

- [ ] Verify CI/CD pipeline succeeds
- [ ] Verify GitHub release is created
- [ ] Verify Docker image is published
- [ ] Update MEMORY.md with release notes

## Rollback Procedure

If issues are discovered after release:

1. **Immediate**: Disable the faulty feature via config
2. **Short-term**: Revert to previous version
3. **Long-term**: Fix and release patch version

```bash
# Rollback to previous tag
git checkout vX.Y.Z-1
cargo build --release
```

## Monitoring

After release, monitor:

- [ ] GitHub issues for bug reports
- [ ] CI/CD logs for failures
- [ ] User feedback channels

---

*Last updated: 2026-01-31*
