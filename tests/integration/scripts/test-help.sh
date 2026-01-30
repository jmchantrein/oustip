#!/bin/bash
# Test: Help command shows all subcommands
OUTPUT=$(oustip --help)
echo "$OUTPUT" | grep -q "update"
echo "$OUTPUT" | grep -q "status"
echo "$OUTPUT" | grep -q "check"
echo "$OUTPUT" | grep -q "disable"
