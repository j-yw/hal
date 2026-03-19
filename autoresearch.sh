#!/bin/bash
set -euo pipefail

# Pre-check: syntax errors
if ! go build ./... 2>/dev/null; then
  echo "METRIC tool_refs=999"
  echo "METRIC test_failures=999"
  echo "METRIC total_tests=0"
  echo "METRIC vet_clean=0"
  echo "METRIC migration_lines=0"
  exit 1
fi

# Count hardcoded tool references in source code (excluding .hal/, agent-os/, autoresearch files)
# Search .go files and embedded .md files (internal/skills/**, internal/template/**)
TOOL_REFS=$(grep -rc "pinchtab\|agent.browser\|dev.browser\|agentbrowser\|devborder\|dev_border" \
  --include="*.go" --include="*.md" \
  cmd/ internal/ \
  2>/dev/null | grep -v ":0$" | grep -v "autoresearch" | cut -d: -f2 | paste -sd+ - | bc 2>/dev/null || echo 0)

# Count migration lines in cmd/init.go (the string replacement chains)
MIGRATION_LINES=$(sed -n '/migrateTemplates/,/^}/p' cmd/init.go 2>/dev/null | wc -l | tr -d ' ')

# Run tests
TEST_OUTPUT=$(go test -count=1 -v ./... 2>&1) || true
TEST_FAILS=$(echo "$TEST_OUTPUT" | grep -c "^--- FAIL:" || true)
TEST_PASSES=$(echo "$TEST_OUTPUT" | grep -c "^--- PASS:" || true)

# Run vet
VET_CLEAN=1
if ! go vet ./... 2>/dev/null; then
  VET_CLEAN=0
fi

echo "METRIC tool_refs=$TOOL_REFS"
echo "METRIC test_failures=$TEST_FAILS"
echo "METRIC total_tests=$TEST_PASSES"
echo "METRIC vet_clean=$VET_CLEAN"
echo "METRIC migration_lines=$MIGRATION_LINES"
