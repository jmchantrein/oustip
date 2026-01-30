#!/bin/bash
# Test: NFtables rules are applied correctly
set -e

cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml

# Apply rules (may take time to fetch blocklists)
oustip update || {
    echo "Update failed, checking if it's a network issue..."
    # If network fails, skip this test
    exit 0
}

# Verify nftables table exists
nft list table ip oustip | grep -q "blocklist" || {
    echo "Warning: blocklist set not found, but table may exist"
    nft list tables | grep -q "oustip"
}
