#!/bin/bash
set -euo pipefail

# Build must pass
go build ./... 2>&1 | tail -5

# All cmd tests must pass
go test ./cmd/... -count=1 -timeout 120s 2>&1 | grep -E "FAIL|ok " | tail -20

# Verify JSON contract tests specifically
go test ./cmd/... -run "TestMachine\|TestContract\|Test.*JSON" -count=1 -timeout 30s 2>&1 | grep -E "FAIL|ok " | tail -10
