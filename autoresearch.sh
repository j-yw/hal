#!/bin/bash
set -euo pipefail

# Pre-check: fast compilation
echo "--- Build check ---"
go build ./... 2>&1 || { echo "METRIC output_quality_score=0"; echo "METRIC styled_command_coverage=53"; echo "METRIC test_pass=0"; exit 0; }

# Run tests for cmd package
echo "--- Test check ---"
TEST_PASS=1
go test ./cmd/... -count=1 -timeout 120s 2>&1 | tail -20 || TEST_PASS=0

SCORE=0
MAX_SCORE=8

# E1: Doctor uses lipgloss-colored severity indicators
# Must import engine package AND use style constants for icons
if grep -q '"github.com/jywlabs/hal/internal/engine"' cmd/doctor.go 2>/dev/null && \
   grep -q 'engine\.Style' cmd/doctor.go 2>/dev/null; then
    SCORE=$((SCORE + 1))
    echo "E1: PASS — doctor imports engine and uses styled rendering"
else
    echo "E1: FAIL — doctor does not use engine styles for icons"
fi

# E2: Status uses styled header/box
# Must import engine package AND use box/style helpers
if grep -q '"github.com/jywlabs/hal/internal/engine"' cmd/status.go 2>/dev/null && \
   grep -qE 'engine\.(StyleTitle|StyleBold|StyleSuccess|StyleMuted|HeaderBox|BoxStyle|StyleInfo)' cmd/status.go 2>/dev/null; then
    SCORE=$((SCORE + 1))
    echo "E2: PASS — status uses styled display elements"
else
    echo "E2: FAIL — status uses raw fmt.Fprintf"
fi

# E3: Continue separates doctor from workflow visually
# Must import engine AND use at least 2 different style types (visual separation)
if grep -q '"github.com/jywlabs/hal/internal/engine"' cmd/continue.go 2>/dev/null; then
    STYLE_COUNT=$(grep -oE 'engine\.Style[A-Za-z]+' cmd/continue.go 2>/dev/null | sort -u | wc -l)
    if [ "$STYLE_COUNT" -ge 2 ]; then
        SCORE=$((SCORE + 1))
        echo "E3: PASS — continue uses ${STYLE_COUNT} distinct style types"
    else
        echo "E3: FAIL — continue imports engine but uses <2 style types"
    fi
else
    echo "E3: FAIL — continue does not import engine styles"
fi

# E4: Analyze uses lipgloss boxes instead of ASCII ═══
if ! grep -q '═══' cmd/analyze.go 2>/dev/null; then
    if grep -q '"github.com/jywlabs/hal/internal/engine"' cmd/analyze.go 2>/dev/null && \
       grep -qE 'engine\.(BoxStyle|HeaderBox|SuccessBox|StyleTitle|StyleBold)' cmd/analyze.go 2>/dev/null; then
        SCORE=$((SCORE + 1))
        echo "E4: PASS — analyze uses lipgloss boxes"
    else
        echo "E4: FAIL — analyze removed ASCII but no lipgloss replacement"
    fi
else
    echo "E4: FAIL — analyze still uses manual ═══ ASCII borders"
fi

# E5: Status shows engine + branch in human-readable output
# The human-readable path must reference engine AND it must not be only in the JSON branch
if grep -q '"github.com/jywlabs/hal/internal/engine"' cmd/status.go 2>/dev/null || \
   grep -q 'engine\.Style' cmd/status.go 2>/dev/null; then
    # Already has engine import for styles — check if it shows engine info in text output
    if grep -q 'Engine:' cmd/status.go 2>/dev/null; then
        SCORE=$((SCORE + 1))
        echo "E5: PASS — status shows engine info in human-readable output"
    else
        echo "E5: FAIL — status has engine import but doesn't display engine info"
    fi
else
    # Check if it at least shows engine in the non-JSON path
    if grep -q 'engine' cmd/status.go 2>/dev/null && grep -q 'Engine:' cmd/status.go 2>/dev/null; then
        SCORE=$((SCORE + 1))
        echo "E5: PASS — status shows engine info"
    else
        echo "E5: FAIL — status doesn't show engine/branch in human-readable output"
    fi
fi

# E6: Cleanup shows styled summary
if grep -q '"github.com/jywlabs/hal/internal/engine"' cmd/cleanup.go 2>/dev/null && \
   grep -qE 'engine\.(Style|Box)' cmd/cleanup.go 2>/dev/null; then
    SCORE=$((SCORE + 1))
    echo "E6: PASS — cleanup uses styled summary"
else
    echo "E6: FAIL — cleanup uses plain line-by-line output"
fi

# E7: Build + tests pass
if [ "$TEST_PASS" -eq 1 ]; then
    SCORE=$((SCORE + 1))
    echo "E7: PASS — build and tests pass"
else
    echo "E7: FAIL — tests failed"
fi

# E8: JSON contracts unchanged
JSON_OK=1
for f in cmd/status.go cmd/continue.go cmd/doctor.go; do
    if [ -f "$f" ]; then
        if ! grep -q "MarshalIndent" "$f" 2>/dev/null; then
            JSON_OK=0
        fi
    fi
done
if [ "$JSON_OK" -eq 1 ]; then
    SCORE=$((SCORE + 1))
    echo "E8: PASS — JSON contracts preserved"
else
    echo "E8: FAIL — JSON output paths may have changed"
fi

# Coverage calculation
TOTAL_CMDS=13
STYLED_CMDS=7  # baseline already styled
for f in status continue doctor analyze cleanup; do
    if grep -q '"github.com/jywlabs/hal/internal/engine"' "cmd/${f}.go" 2>/dev/null && \
       grep -qE 'engine\.Style' "cmd/${f}.go" 2>/dev/null; then
        STYLED_CMDS=$((STYLED_CMDS + 1))
    fi
done
COVERAGE=$((STYLED_CMDS * 100 / TOTAL_CMDS))

echo ""
echo "=== Results ==="
echo "Score: ${SCORE}/${MAX_SCORE}"
echo "Coverage: ${COVERAGE}% (${STYLED_CMDS}/${TOTAL_CMDS} commands styled)"
echo ""
echo "METRIC output_quality_score=${SCORE}"
echo "METRIC styled_command_coverage=${COVERAGE}"
echo "METRIC test_pass=${TEST_PASS}"
