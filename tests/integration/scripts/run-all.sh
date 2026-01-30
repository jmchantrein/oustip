#!/bin/bash
set -e

echo "=========================================="
echo "OustIP Integration Tests"
echo "=========================================="

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name=$1
    local script=$2
    echo ""
    echo "--- Test: $name ---"
    if bash -e "$script"; then
        echo "✓ PASSED: $name"
        ((TESTS_PASSED++)) || true
    else
        echo "✗ FAILED: $name"
        ((TESTS_FAILED++)) || true
    fi
}

# Run individual tests
run_test "Version command" /tests/test-version.sh
run_test "Help command" /tests/test-help.sh
run_test "Dry-run update" /tests/test-dry-run.sh
run_test "NFtables apply rules" /tests/test-nftables-apply.sh
run_test "Check IP command" /tests/test-check-ip.sh
run_test "Status command" /tests/test-status.sh
run_test "Disable/Enable cycle" /tests/test-disable-enable.sh
run_test "Health check" /tests/test-health.sh

echo ""
echo "=========================================="
echo "Results: $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "=========================================="

[ $TESTS_FAILED -eq 0 ]
