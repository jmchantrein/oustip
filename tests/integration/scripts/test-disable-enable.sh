#!/bin/bash
# Test: Disable and enable cycle
cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml

# Apply rules first
oustip update

# Verify rules exist
nft list table ip oustip >/dev/null

# Disable
oustip disable

# Verify rules removed
! nft list table ip oustip 2>/dev/null

# Re-enable
oustip update

# Verify rules back
nft list table ip oustip | grep -q "blocklist"
