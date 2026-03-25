#!/bin/bash
set -euo pipefail

# Hal CLI output quality benchmark
# Scores source code for lipgloss styling adoption across all commands

echo "--- Build check ---"
go build ./... 2>&1 || { echo "METRIC output_quality_score=0"; echo "METRIC styled_command_coverage=53"; echo "METRIC test_pass=0"; exit 0; }

echo "--- Test check ---"
TEST_PASS=1
go test ./cmd/... -count=1 -timeout 120s 2>&1 | tail -20 || TEST_PASS=0

SCORE=0
MAX_SCORE=14

has_engine_import() {
    grep -q 'github.com/jywlabs/hal/internal/engine' "$1" 2>/dev/null
}
has_style_usage() {
    grep -qE '(engine|display|ui|styles)\.(Style[A-Za-z]+|BoxStyle|HeaderBox|SuccessBox|ErrorBox|WarningBox)' "$1" 2>/dev/null
}
count_styles() {
    grep -oE '(engine|display|ui|styles)\.(Style[A-Za-z]+|BoxStyle|HeaderBox|SuccessBox|ErrorBox|WarningBox)' "$1" 2>/dev/null | sort -u | wc -l
}

# E1: Doctor uses lipgloss-colored severity indicators
if has_engine_import cmd/doctor.go && has_style_usage cmd/doctor.go; then
    SCORE=$((SCORE + 1)); echo "E1: PASS — doctor uses styled rendering"
else
    echo "E1: FAIL — doctor does not use engine styles"
fi

# E2: Status uses styled header/box
if has_engine_import cmd/status.go && has_style_usage cmd/status.go; then
    SCORE=$((SCORE + 1)); echo "E2: PASS — status uses styled display"
else
    echo "E2: FAIL — status uses raw fmt.Fprintf"
fi

# E3: Continue separates doctor from workflow visually
if has_engine_import cmd/continue.go; then
    SC=$(count_styles cmd/continue.go)
    if [ "$SC" -ge 2 ]; then
        SCORE=$((SCORE + 1)); echo "E3: PASS — continue uses ${SC} distinct styles"
    else
        echo "E3: FAIL — continue uses <2 style types"
    fi
else
    echo "E3: FAIL — continue does not import engine"
fi

# E4: Analyze uses lipgloss instead of ASCII
if ! grep -q '═══' cmd/analyze.go 2>/dev/null; then
    if has_engine_import cmd/analyze.go && has_style_usage cmd/analyze.go; then
        SCORE=$((SCORE + 1)); echo "E4: PASS — analyze uses lipgloss"
    else
        echo "E4: FAIL — analyze removed ASCII but no lipgloss"
    fi
else
    echo "E4: FAIL — analyze still uses ASCII borders"
fi

# E5: Status shows engine info
if grep -q 'Engine:' cmd/status.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E5: PASS — status shows engine info"
else
    echo "E5: FAIL — no engine info in status"
fi

# E6: Cleanup styled summary
if has_engine_import cmd/cleanup.go && has_style_usage cmd/cleanup.go; then
    SCORE=$((SCORE + 1)); echo "E6: PASS — cleanup styled"
else
    echo "E6: FAIL — cleanup plain"
fi

# E7: Build + tests pass
if [ "$TEST_PASS" -eq 1 ]; then
    SCORE=$((SCORE + 1)); echo "E7: PASS — tests pass"
else
    echo "E7: FAIL — tests failed"
fi

# E8: JSON contracts unchanged
JSON_OK=1
for f in cmd/status.go cmd/continue.go cmd/doctor.go; do
    [ -f "$f" ] && ! grep -q "MarshalIndent" "$f" 2>/dev/null && JSON_OK=0
done
if [ "$JSON_OK" -eq 1 ]; then
    SCORE=$((SCORE + 1)); echo "E8: PASS — JSON preserved"
else
    echo "E8: FAIL — JSON may have changed"
fi

# E9: Repair styled
if has_engine_import cmd/repair.go && has_style_usage cmd/repair.go; then
    SCORE=$((SCORE + 1)); echo "E9: PASS — repair styled"
else
    echo "E9: FAIL — repair plain"
fi

# E10: Init styled
if has_engine_import cmd/init.go && has_style_usage cmd/init.go; then
    SCORE=$((SCORE + 1)); echo "E10: PASS — init styled"
else
    echo "E10: FAIL — init plain"
fi

# E11: Archive styled
if has_engine_import cmd/archive.go && has_style_usage cmd/archive.go; then
    SCORE=$((SCORE + 1)); echo "E11: PASS — archive styled"
else
    echo "E11: FAIL — archive plain"
fi

# E12: Doctor wraps output in a styled title (like ShowCommandHeader does)
if grep -qE '(engine|display|ui)\.(StyleTitle|StyleBold)\.Render.*Doctor\|Health\|Checks' cmd/doctor.go 2>/dev/null || \
   grep -qE '(engine|display|ui)\.StyleTitle' cmd/doctor.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E12: PASS — doctor has styled title"
else
    echo "E12: FAIL — doctor lacks styled title/header"
fi

# E13: Status has styled title
if grep -qE '(engine|display|ui)\.StyleTitle' cmd/status.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E13: PASS — status has styled title"
else
    echo "E13: FAIL — status lacks styled title"
fi

# E14: Continue has styled title
if grep -qE '(engine|display|ui)\.StyleTitle' cmd/continue.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E14: PASS — continue has styled title"
else
    echo "E14: FAIL — continue lacks styled title"
fi

# Coverage
TOTAL=13; STYLED=7
for f in status continue doctor analyze cleanup repair init archive; do
    has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && STYLED=$((STYLED + 1))
done
COV=$((STYLED * 100 / TOTAL))

echo ""
echo "=== Score: ${SCORE}/${MAX_SCORE} | Coverage: ${COV}% ==="
echo "METRIC output_quality_score=${SCORE}"
echo "METRIC styled_command_coverage=${COV}"
echo "METRIC test_pass=${TEST_PASS}"
