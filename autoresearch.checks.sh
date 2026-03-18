#!/bin/bash
set -euo pipefail

# Verify no test failures (use -count=1 to bypass cache)
TEST_OUTPUT=$(go test -count=1 ./... 2>&1) || true
FAILURES=$(echo "$TEST_OUTPUT" | grep -c "^--- FAIL:" || true)
if [ "$FAILURES" -gt 0 ]; then
  echo "FAIL: $FAILURES test(s) failed"
  echo "$TEST_OUTPUT" | grep -E "^(FAIL|--- FAIL)" | tail -20
  exit 1
fi

# Verify vet is clean
go vet ./... 2>&1 | tail -10
