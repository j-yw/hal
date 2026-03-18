#!/bin/bash
set -euo pipefail

# Pre-check: syntax errors
if ! go build ./... 2>/dev/null; then
  echo "METRIC test_failures=999"
  echo "METRIC total_tests=0"
  echo "METRIC vet_clean=0"
  exit 1
fi

# Run tests with no cache, verbose for individual test results
TEST_OUTPUT=$(go test -count=1 -v ./... 2>&1) || true

# Count individual test results
TEST_FAILS=$(echo "$TEST_OUTPUT" | grep -c "^--- FAIL:" || true)
TEST_PASSES=$(echo "$TEST_OUTPUT" | grep -c "^--- PASS:" || true)

# Run vet
VET_CLEAN=1
if ! go vet ./... 2>/dev/null; then
  VET_CLEAN=0
fi

echo "METRIC test_failures=$TEST_FAILS"
echo "METRIC total_tests=$TEST_PASSES"
echo "METRIC vet_clean=$VET_CLEAN"
