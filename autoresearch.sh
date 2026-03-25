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
MAX_SCORE=26

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

# E12: Doctor has styled title
if grep -qE '(engine|display|ui)\.StyleTitle' cmd/doctor.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E12: PASS — doctor has styled title"
else
    echo "E12: FAIL — doctor lacks styled title"
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

# E15: Init has deep style integration (≥8 usages)
INIT_STYLES=$(grep -cE '(engine|display|ui)\.Style' cmd/init.go 2>/dev/null || echo 0)
if [ "$INIT_STYLES" -ge 8 ]; then
    SCORE=$((SCORE + 1)); echo "E15: PASS — init has ${INIT_STYLES} style usages"
else
    echo "E15: FAIL — init has only ${INIT_STYLES} style usages (need ≥8)"
fi

# E16: Doctor has title + check count
if grep -q 'StyleTitle' cmd/doctor.go 2>/dev/null && grep -q 'TotalChecks' cmd/doctor.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E16: PASS — doctor title + check count"
else
    echo "E16: FAIL — doctor missing title or check count"
fi

# E17: Sandbox status styled
if has_engine_import cmd/sandbox_status.go && has_style_usage cmd/sandbox_status.go; then
    SCORE=$((SCORE + 1)); echo "E17: PASS — sandbox status styled"
else
    echo "E17: FAIL — sandbox status plain"
fi

# E18: Sandbox list styled
if has_engine_import cmd/sandbox_list.go && has_style_usage cmd/sandbox_list.go; then
    SCORE=$((SCORE + 1)); echo "E18: PASS — sandbox list styled"
else
    echo "E18: FAIL — sandbox list plain"
fi

# E19: Sandbox start/stop/delete styled (≥2 of 3)
SBX_STYLED=0
for f in sandbox_start sandbox_stop sandbox_delete; do
    has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && SBX_STYLED=$((SBX_STYLED + 1))
done
if [ "$SBX_STYLED" -ge 2 ]; then
    SCORE=$((SCORE + 1)); echo "E19: PASS — ${SBX_STYLED}/3 sandbox commands styled"
else
    echo "E19: FAIL — only ${SBX_STYLED}/3 sandbox commands styled"
fi

# E20: Sandbox list deep integration (≥4 style usages)
LIST_STYLES=$(grep -cE '(engine|display|ui)\.Style' cmd/sandbox_list.go 2>/dev/null || echo 0)
if [ "$LIST_STYLES" -ge 4 ]; then
    SCORE=$((SCORE + 1)); echo "E20: PASS — sandbox list has ${LIST_STYLES} style usages"
else
    echo "E20: FAIL — sandbox list has only ${LIST_STYLES} style usages (need ≥4)"
fi

# E21: Sandbox start deep integration (≥4 style usages)
START_STYLES=$(grep -cE '(engine|display|ui)\.Style' cmd/sandbox_start.go 2>/dev/null || echo 0)
if [ "$START_STYLES" -ge 4 ]; then
    SCORE=$((SCORE + 1)); echo "E21: PASS — sandbox start has ${START_STYLES} style usages"
else
    echo "E21: FAIL — sandbox start has only ${START_STYLES} style usages (need ≥4)"
fi

# E22: Sandbox failure messages styled (≥2 of 3 commands)
SBX_FAIL=0
for f in sandbox_start sandbox_stop sandbox_delete; do
    grep -qE '(engine|display|ui)\.Style.*(Failed|failed|error|Error|\[!!\])' "cmd/${f}.go" 2>/dev/null && SBX_FAIL=$((SBX_FAIL + 1))
done
if [ "$SBX_FAIL" -ge 2 ]; then
    SCORE=$((SCORE + 1)); echo "E22: PASS — ${SBX_FAIL}/3 sandbox commands have styled failures"
else
    echo "E22: FAIL — only ${SBX_FAIL}/3 sandbox commands have styled failures"
fi

# E23: Version command styled
if has_engine_import cmd/version.go && has_style_usage cmd/version.go; then
    SCORE=$((SCORE + 1)); echo "E23: PASS — version styled"
else
    echo "E23: FAIL — version plain"
fi

# E24: Links command styled (status/clean/refresh)
if has_engine_import cmd/links.go && has_style_usage cmd/links.go; then
    SCORE=$((SCORE + 1)); echo "E24: PASS — links styled"
else
    echo "E24: FAIL — links plain"
fi

# E25: Standards command styled
if has_engine_import cmd/standards.go && has_style_usage cmd/standards.go; then
    SCORE=$((SCORE + 1)); echo "E25: PASS — standards styled"
else
    echo "E25: FAIL — standards plain"
fi

# E26: Report/auto commands styled (prd.go or report.go or auto.go)
MISC_STYLED=0
for f in prd report auto; do
    has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && MISC_STYLED=$((MISC_STYLED + 1))
done
if [ "$MISC_STYLED" -ge 1 ]; then
    SCORE=$((SCORE + 1)); echo "E26: PASS — ${MISC_STYLED}/3 additional commands styled"
else
    echo "E26: FAIL — prd/report/auto all unstyled"
fi

# Coverage
TOTAL=13; STYLED=7
for f in status continue doctor analyze cleanup repair init archive sandbox_status sandbox_list sandbox_start sandbox_stop sandbox_delete; do
    has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && STYLED=$((STYLED + 1))
done
COV=$((STYLED * 100 / TOTAL))

echo ""
echo "=== Score: ${SCORE}/${MAX_SCORE} | Coverage: ${COV}% ==="
echo "METRIC output_quality_score=${SCORE}"
echo "METRIC styled_command_coverage=${COV}"
echo "METRIC test_pass=${TEST_PASS}"
