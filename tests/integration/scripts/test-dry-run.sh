#!/bin/bash
# Test: Dry-run mode doesn't apply rules
cp /fixtures/minimal-config.yaml /etc/oustip/config.yaml
oustip update --dry-run 2>&1 | grep -qi "dry"

# Verify no nftables table was created
! nft list table ip oustip 2>/dev/null
