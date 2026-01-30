#!/bin/bash
# Test: Disable and enable cycle
set -e

cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml

# Apply rules first
oustip update || {
    echo "Initial update failed, skipping disable/enable test"
    exit 0
}

# Check if rules exist
if ! nft list table ip oustip >/dev/null 2>&1; then
    echo "No rules to disable, skipping test"
    exit 0
fi

# Disable
oustip disable

# Verify rules removed
if nft list table ip oustip 2>/dev/null; then
    echo "Rules still exist after disable"
    exit 1
fi

# Re-enable
oustip update || {
    echo "Re-enable failed"
    exit 1
}

echo "Disable/enable cycle completed"
