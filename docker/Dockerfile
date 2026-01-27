# OustIP Docker Image
# Multi-stage build for minimal image size

FROM alpine:3.19 AS runtime

# Install runtime dependencies
RUN apk add --no-cache \
    nftables \
    iptables \
    ipset \
    ca-certificates

# Copy binary (expects it to be in the build context)
COPY oustip-linux-amd64 /usr/local/bin/oustip
RUN chmod +x /usr/local/bin/oustip

# Create directories
RUN mkdir -p /etc/oustip /var/lib/oustip /var/log

# Copy default config
COPY config.yaml /etc/oustip/config.yaml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD oustip status || exit 1

# Run as root (required for firewall manipulation)
USER root

ENTRYPOINT ["/usr/local/bin/oustip"]
CMD ["status"]
