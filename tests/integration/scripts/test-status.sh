#!/bin/bash
# Test: Status command shows state
set -e

cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml

# Apply rules first
oustip update || {
    echo "Update failed, but status should still work"
}

# Status should work even without rules
OUTPUT=$(oustip status 2>&1) || true
echo "$OUTPUT"

# Should produce some output
[ -n "$OUTPUT" ] || {
    echo "Status command produced no output"
    exit 1
}
