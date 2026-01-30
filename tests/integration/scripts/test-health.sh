#!/bin/bash
# Test: Health check command
set -e

cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml

# Try to apply rules (may fail due to network)
oustip update || true

# Health check should work regardless
OUTPUT=$(oustip health 2>&1) || true
echo "$OUTPUT"

# Should contain check results
echo "$OUTPUT" | grep -qE "config|state|firewall|disk" || {
    echo "Health output missing expected checks"
    exit 1
}

# JSON output should be valid JSON
JSON_OUTPUT=$(oustip health --json 2>&1) || true
echo "$JSON_OUTPUT" | jq -e '.' >/dev/null || {
    echo "Health JSON output is invalid"
    exit 1
}

echo "Health check completed"
