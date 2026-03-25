#!/bin/bash
set -euo pipefail

# Hal CLI output quality benchmark — Wave 8
echo "--- Build check ---"
go build ./... 2>&1 || { echo "METRIC output_quality_score=0"; echo "METRIC test_pass=0"; exit 0; }

echo "--- Test check ---"
TEST_PASS=1
go test ./cmd/... -count=1 -timeout 120s 2>&1 | tail -20 || TEST_PASS=0

SCORE=0
MAX_SCORE=43

has_engine_import() { grep -q 'github.com/jywlabs/hal/internal/engine' "$1" 2>/dev/null; }
has_style_usage() { grep -qE '(engine|display|ui|styles)\.(Style[A-Za-z]+|BoxStyle|HeaderBox|SuccessBox|ErrorBox|WarningBox)' "$1" 2>/dev/null; }
count_styles() { grep -oE '(engine|display|ui|styles)\.(Style[A-Za-z]+|BoxStyle|HeaderBox|SuccessBox|ErrorBox|WarningBox)' "$1" 2>/dev/null | sort -u | wc -l; }

# === E1-E29: Style adoption (compact) ===
has_engine_import cmd/doctor.go && has_style_usage cmd/doctor.go && { SCORE=$((SCORE+1)); echo "E1: PASS"; } || echo "E1: FAIL"
has_engine_import cmd/status.go && has_style_usage cmd/status.go && { SCORE=$((SCORE+1)); echo "E2: PASS"; } || echo "E2: FAIL"
has_engine_import cmd/continue.go && { SC=$(count_styles cmd/continue.go); [ "$SC" -ge 2 ] && { SCORE=$((SCORE+1)); echo "E3: PASS"; } || echo "E3: FAIL"; } || echo "E3: FAIL"
! grep -q '═══' cmd/analyze.go 2>/dev/null && has_engine_import cmd/analyze.go && has_style_usage cmd/analyze.go && { SCORE=$((SCORE+1)); echo "E4: PASS"; } || echo "E4: FAIL"
grep -q 'Engine:' cmd/status.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E5: PASS"; } || echo "E5: FAIL"
has_engine_import cmd/cleanup.go && has_style_usage cmd/cleanup.go && { SCORE=$((SCORE+1)); echo "E6: PASS"; } || echo "E6: FAIL"
[ "$TEST_PASS" -eq 1 ] && { SCORE=$((SCORE+1)); echo "E7: PASS"; } || echo "E7: FAIL"
JSON_OK=1; for f in cmd/status.go cmd/continue.go cmd/doctor.go; do [ -f "$f" ] && ! grep -q "MarshalIndent" "$f" 2>/dev/null && JSON_OK=0; done
[ "$JSON_OK" -eq 1 ] && { SCORE=$((SCORE+1)); echo "E8: PASS"; } || echo "E8: FAIL"
has_engine_import cmd/repair.go && has_style_usage cmd/repair.go && { SCORE=$((SCORE+1)); echo "E9: PASS"; } || echo "E9: FAIL"
has_engine_import cmd/init.go && has_style_usage cmd/init.go && { SCORE=$((SCORE+1)); echo "E10: PASS"; } || echo "E10: FAIL"
has_engine_import cmd/archive.go && has_style_usage cmd/archive.go && { SCORE=$((SCORE+1)); echo "E11: PASS"; } || echo "E11: FAIL"
grep -qE '(engine|display|ui)\.StyleTitle' cmd/doctor.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E12: PASS"; } || echo "E12: FAIL"
grep -qE '(engine|display|ui)\.StyleTitle' cmd/status.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E13: PASS"; } || echo "E13: FAIL"
grep -qE '(engine|display|ui)\.StyleTitle' cmd/continue.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E14: PASS"; } || echo "E14: FAIL"
IS=$(grep -cE '(engine|display|ui)\.Style' cmd/init.go 2>/dev/null || echo 0); [ "$IS" -ge 8 ] && { SCORE=$((SCORE+1)); echo "E15: PASS"; } || echo "E15: FAIL"
grep -q 'StyleTitle' cmd/doctor.go 2>/dev/null && grep -q 'TotalChecks' cmd/doctor.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E16: PASS"; } || echo "E16: FAIL"
has_engine_import cmd/sandbox_status.go && has_style_usage cmd/sandbox_status.go && { SCORE=$((SCORE+1)); echo "E17: PASS"; } || echo "E17: FAIL"
has_engine_import cmd/sandbox_list.go && has_style_usage cmd/sandbox_list.go && { SCORE=$((SCORE+1)); echo "E18: PASS"; } || echo "E18: FAIL"
SBX=0; for f in sandbox_start sandbox_stop sandbox_delete; do has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && SBX=$((SBX+1)); done
[ "$SBX" -ge 2 ] && { SCORE=$((SCORE+1)); echo "E19: PASS"; } || echo "E19: FAIL"
LS=$(grep -cE '(engine|display|ui)\.Style' cmd/sandbox_list.go 2>/dev/null || echo 0); [ "$LS" -ge 4 ] && { SCORE=$((SCORE+1)); echo "E20: PASS"; } || echo "E20: FAIL"
SS=$(grep -cE '(engine|display|ui)\.Style' cmd/sandbox_start.go 2>/dev/null || echo 0); [ "$SS" -ge 4 ] && { SCORE=$((SCORE+1)); echo "E21: PASS"; } || echo "E21: FAIL"
SF=0; for f in sandbox_start sandbox_stop sandbox_delete; do grep -qE '(engine|display|ui)\.Style.*(Failed|failed|error|Error|\[!!\])' "cmd/${f}.go" 2>/dev/null && SF=$((SF+1)); done
[ "$SF" -ge 2 ] && { SCORE=$((SCORE+1)); echo "E22: PASS"; } || echo "E22: FAIL"
has_engine_import cmd/version.go && has_style_usage cmd/version.go && { SCORE=$((SCORE+1)); echo "E23: PASS"; } || echo "E23: FAIL"
has_engine_import cmd/links.go && has_style_usage cmd/links.go && { SCORE=$((SCORE+1)); echo "E24: PASS"; } || echo "E24: FAIL"
has_engine_import cmd/standards.go && has_style_usage cmd/standards.go && { SCORE=$((SCORE+1)); echo "E25: PASS"; } || echo "E25: FAIL"
MC=0; for f in prd report auto; do has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && MC=$((MC+1)); done
[ "$MC" -ge 1 ] && { SCORE=$((SCORE+1)); echo "E26: PASS"; } || echo "E26: FAIL"
has_engine_import cmd/sandbox.go && has_style_usage cmd/sandbox.go && { SP=$(grep -cE '(engine|display|ui)\.Style' cmd/sandbox.go 2>/dev/null || echo 0); [ "$SP" -ge 3 ] && { SCORE=$((SCORE+1)); echo "E27: PASS"; } || echo "E27: FAIL"; } || echo "E27: FAIL"
AC=0; for f in auto run prd; do has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && AC=$((AC+1)); done
[ "$AC" -ge 1 ] && { SCORE=$((SCORE+1)); echo "E28: PASS"; } || echo "E28: FAIL"
has_engine_import cmd/prd.go && has_style_usage cmd/prd.go && { SCORE=$((SCORE+1)); echo "E29: PASS"; } || echo "E29: FAIL"

# === E30-E38: Information density ===
grep -A1 'result\.Summary' cmd/status.go 2>/dev/null | grep -q 'Fprintf\|Fprintln\|Render' && { SCORE=$((SCORE+1)); echo "E30: PASS"; } || echo "E30: FAIL"
grep -qE 'engine.*Engine:|Engine:.*engine' cmd/continue.go 2>/dev/null && grep -q 'LoadDefaultEngine' cmd/continue.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E31: PASS"; } || echo "E31: FAIL"
sed -n '/Human-readable/,/return nil/p' cmd/doctor.go 2>/dev/null | grep -qE 'c\.Scope|c\.Severity' && { SCORE=$((SCORE+1)); echo "E32: PASS"; } || echo "E32: FAIL"
grep -qE 'CurrentBranch|gitBranch' cmd/status.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E33: PASS"; } || echo "E33: FAIL"
sed -n '/} else {/,/return nil/p' cmd/continue.go 2>/dev/null | grep -qE 'engine|Engine:' && { SCORE=$((SCORE+1)); echo "E34: PASS"; } || echo "E34: FAIL"
sed -n '/Human-readable/,/return nil/p' cmd/doctor.go 2>/dev/null | grep -qE 'c\.Remediation|Remediation\.Command' && { SCORE=$((SCORE+1)); echo "E35: PASS"; } || echo "E35: FAIL"
sed -n '/Human-readable/,/return nil/p' cmd/continue.go 2>/dev/null | grep -qE 'summary|Summary' && { SCORE=$((SCORE+1)); echo "E36: PASS"; } || echo "E36: FAIL"
sed -n '/Human-readable/,/return nil/p' cmd/continue.go 2>/dev/null | grep -qE 'NextStory' && { SCORE=$((SCORE+1)); echo "E37: PASS"; } || echo "E37: FAIL"
sed -n '/Human-readable/,/return nil/p' cmd/continue.go 2>/dev/null | grep -qE 'BranchName|Branch' && { SCORE=$((SCORE+1)); echo "E38: PASS"; } || echo "E38: FAIL"

# === E39-E41: Structural ===
grep -q 'formatArchiveListStyled' cmd/archive.go 2>/dev/null && ! grep -q 'archive\.FormatList' cmd/archive.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E39: PASS"; } || echo "E39: FAIL"
PFS=$(sed -n '/func promptField/,/^}/p' cmd/sandbox.go 2>/dev/null | grep -cE '(engine|display|ui)\.Style' || echo 0)
[ "${PFS:-0}" -ge 2 ] && { SCORE=$((SCORE+1)); echo "E40: PASS"; } || echo "E40: FAIL"
grep -qE '(engine|display|ui)\.Style.*(Saved|saved|OK)' cmd/sandbox.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E41: PASS"; } || echo "E41: FAIL"

# === E42-E43: Wave 8 — Richer content rendering ===

# E42: Analyze uses glamour for description/rationale rendering
if grep -q 'glamour\|renderMarkdown' cmd/analyze.go 2>/dev/null; then
    SCORE=$((SCORE+1)); echo "E42: PASS — analyze uses glamour/markdown rendering"
else
    echo "E42: FAIL — analyze uses plain text for description"
fi

# E43: Links status shows link count per engine
if sed -n '/Human-readable/,/return nil/p' cmd/links.go 2>/dev/null | grep -qE 'len(.*Links)|LinkCount|link.*count|links:.*%d'; then
    SCORE=$((SCORE+1)); echo "E43: PASS — links status shows per-engine link count"
else
    echo "E43: FAIL — links status doesn't show link count"
fi

echo ""
echo "=== Score: ${SCORE}/${MAX_SCORE} ==="
echo "METRIC output_quality_score=${SCORE}"
echo "METRIC test_pass=${TEST_PASS}"
