.PHONY: build release test clean fmt clippy docker install uninstall test-integration-docker

# Default target
all: build

# Development build
build:
	cargo build --release

# Run tests
test:
	cargo test --all-features

# Run tests including integration tests (requires root)
test-all:
	cargo test --all-features -- --include-ignored

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Run clippy
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

# Full check (format + clippy + test)
check: fmt-check clippy test

# Release build with musl (static binary)
release:
	cargo build --release --target x86_64-unknown-linux-musl
	strip target/x86_64-unknown-linux-musl/release/oustip
	@echo "Binary: target/x86_64-unknown-linux-musl/release/oustip"
	@ls -lh target/x86_64-unknown-linux-musl/release/oustip

# Release build for ARM64
release-arm64:
	cross build --release --target aarch64-unknown-linux-musl
	@echo "Binary: target/aarch64-unknown-linux-musl/release/oustip"

# Release build for ARMv7 (Raspberry Pi)
release-armv7:
	cross build --release --target armv7-unknown-linux-musleabihf
	@echo "Binary: target/armv7-unknown-linux-musleabihf/release/oustip"

# Build all release targets
release-all: release release-arm64 release-armv7

# Build Docker image
docker:
	cp target/x86_64-unknown-linux-musl/release/oustip docker/oustip-linux-amd64
	docker build -t oustip:latest -f docker/Dockerfile docker/
	rm docker/oustip-linux-amd64

# Install locally (requires root)
install: build
	sudo cp target/release/oustip /usr/local/sbin/oustip
	sudo chmod +x /usr/local/sbin/oustip
	@echo "Installed to /usr/local/sbin/oustip"
	@echo "Run 'sudo oustip install' to complete setup"

# Uninstall
uninstall:
	sudo oustip uninstall || true
	sudo rm -f /usr/local/sbin/oustip
	@echo "Uninstalled"

# Clean build artifacts
clean:
	cargo clean
	rm -f docker/oustip-linux-amd64

# Security audit
audit:
	cargo audit

# Generate documentation
doc:
	cargo doc --no-deps --open

# Watch for changes and rebuild
watch:
	cargo watch -x build

# Help
help:
	@echo "OustIP Makefile"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build        - Development build"
	@echo "  release      - Release build (x86_64-musl)"
	@echo "  release-all  - Build all release targets"
	@echo "  test         - Run tests"
	@echo "  test-all     - Run all tests including integration"
	@echo "  check        - Format + clippy + test"
	@echo "  docker       - Build Docker image"
	@echo "  install      - Install binary locally"
	@echo "  uninstall    - Uninstall"
	@echo "  clean        - Clean build artifacts"
	@echo "  audit        - Security audit"
	@echo "  doc          - Generate documentation"
	@echo "  test-integration-docker - Run integration tests in Docker"

# Integration tests in Docker (requires Docker)
test-integration-docker: release
	docker build -t oustip-integration -f tests/Dockerfile.integration .
	docker run --rm --privileged --cap-add NET_ADMIN --cap-add NET_RAW \
		-v $(PWD)/target/x86_64-unknown-linux-musl/release/oustip:/usr/local/bin/oustip:ro \
		oustip-integration /tests/run-all.sh
