#!/bin/bash
set -euo pipefail

# Verify no test failures
FAILURES=$(go test ./... 2>&1 | grep -c "^FAIL" || true)
if [ "$FAILURES" -gt 0 ]; then
  echo "FAIL: $FAILURES test package(s) failed"
  go test ./... 2>&1 | grep -E "^(FAIL|--- FAIL)" | tail -20
  exit 1
fi

# Verify vet is clean
go vet ./... 2>&1 | tail -10
