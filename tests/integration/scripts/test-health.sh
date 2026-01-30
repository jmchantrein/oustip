#!/bin/bash
# Test: Health check command
cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml
oustip update

# Health check should work
oustip health

# JSON output should be valid
oustip health --json | jq -e '.checks'
