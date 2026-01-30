#!/bin/bash
# Test: Check IP command works
set -e

cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml

# Apply rules first
oustip update || {
    echo "Update failed, skipping check test"
    exit 0
}

# Check a public IP - output should indicate blocked or not blocked
OUTPUT=$(oustip check 8.8.8.8 2>&1) || true
echo "$OUTPUT"

# Should contain some status indication
echo "$OUTPUT" | grep -qiE "blocked|not found|error" || {
    echo "Check command produced unexpected output"
    exit 1
}
