#!/bin/bash
# Test: Check IP command works
cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml
oustip update

# Check a public IP (should not be blocked with minimal config)
oustip check 8.8.8.8 | grep -qi "not blocked"
