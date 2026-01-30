#!/bin/bash
# Test: Status command shows active state
cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml
oustip update

# Status should show rules are active
oustip status 2>&1 | grep -qi "active\|enabled\|loaded"
