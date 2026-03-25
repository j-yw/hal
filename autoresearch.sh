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
MAX_SCORE=11

# Helper: check if a file imports internal/engine (with or without alias)
has_engine_import() {
    grep -q 'github.com/jywlabs/hal/internal/engine' "$1" 2>/dev/null
}

# Helper: check if a file uses lipgloss style constants (via engine.Style* or display.Style* or any alias)
has_style_usage() {
    grep -qE '(engine|display|ui|styles)\.(Style[A-Za-z]+|BoxStyle|HeaderBox|SuccessBox|ErrorBox|WarningBox)' "$1" 2>/dev/null
}

# Helper: count distinct style types used
count_styles() {
    grep -oE '(engine|display|ui|styles)\.(Style[A-Za-z]+|BoxStyle|HeaderBox|SuccessBox|ErrorBox|WarningBox)' "$1" 2>/dev/null | sort -u | wc -l
}

# E1: Doctor uses lipgloss-colored severity indicators
if has_engine_import cmd/doctor.go && has_style_usage cmd/doctor.go; then
    SCORE=$((SCORE + 1))
    echo "E1: PASS — doctor imports engine and uses styled rendering"
else
    echo "E1: FAIL — doctor does not use engine styles for icons"
fi

# E2: Status uses styled header/box
if has_engine_import cmd/status.go && has_style_usage cmd/status.go; then
    SCORE=$((SCORE + 1))
    echo "E2: PASS — status uses styled display elements"
else
    echo "E2: FAIL — status uses raw fmt.Fprintf"
fi

# E3: Continue separates doctor from workflow visually
if has_engine_import cmd/continue.go; then
    STYLE_COUNT=$(count_styles cmd/continue.go)
    if [ "$STYLE_COUNT" -ge 2 ]; then
        SCORE=$((SCORE + 1))
        echo "E3: PASS — continue uses ${STYLE_COUNT} distinct style types"
    else
        echo "E3: FAIL — continue imports engine but uses <2 style types"
    fi
else
    echo "E3: FAIL — continue does not import engine styles"
fi

# E4: Analyze uses lipgloss boxes instead of ASCII
if ! grep -q '═══' cmd/analyze.go 2>/dev/null; then
    if has_engine_import cmd/analyze.go && has_style_usage cmd/analyze.go; then
        SCORE=$((SCORE + 1))
        echo "E4: PASS — analyze uses lipgloss boxes"
    else
        echo "E4: FAIL — analyze removed ASCII but no lipgloss replacement"
    fi
else
    echo "E4: FAIL — analyze still uses manual ASCII borders"
fi

# E5: Status shows engine + branch in human-readable output
if grep -q 'Engine:' cmd/status.go 2>/dev/null; then
    SCORE=$((SCORE + 1))
    echo "E5: PASS — status shows engine info in human-readable output"
else
    echo "E5: FAIL — status doesn't show engine info in human-readable output"
fi

# E6: Cleanup shows styled summary
if has_engine_import cmd/cleanup.go && has_style_usage cmd/cleanup.go; then
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

# E9: Repair uses styled output
if has_engine_import cmd/repair.go && has_style_usage cmd/repair.go; then
    SCORE=$((SCORE + 1))
    echo "E9: PASS — repair uses styled rendering"
else
    echo "E9: FAIL — repair uses plain fmt.Fprintf"
fi

# E10: Init uses styled output for success/next steps
if has_engine_import cmd/init.go && has_style_usage cmd/init.go; then
    SCORE=$((SCORE + 1))
    echo "E10: PASS — init uses styled rendering"
else
    echo "E10: FAIL — init uses plain fmt.Fprintf"
fi

# E11: Archive list uses styled output
if has_engine_import cmd/archive.go && has_style_usage cmd/archive.go; then
    SCORE=$((SCORE + 1))
    echo "E11: PASS — archive uses styled rendering"
else
    echo "E11: FAIL — archive uses plain fmt.Fprintf"
fi

# Coverage calculation
TOTAL_CMDS=13
STYLED_CMDS=7
for f in status continue doctor analyze cleanup repair init archive; do
    if has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go"; then
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
