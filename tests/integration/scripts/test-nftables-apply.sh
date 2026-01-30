#!/bin/bash
# Test: NFtables rules are applied correctly
cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml

# Apply rules
oustip update

# Verify nftables table exists
nft list table ip oustip | grep -q "blocklist"

# Verify chains exist
nft list chain ip oustip input | grep -q "drop"
