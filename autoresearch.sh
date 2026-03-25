#!/bin/bash
set -euo pipefail

# Hal CLI output quality benchmark — Wave 6: information density
echo "--- Build check ---"
go build ./... 2>&1 || { echo "METRIC output_quality_score=0"; echo "METRIC test_pass=0"; exit 0; }

echo "--- Test check ---"
TEST_PASS=1
go test ./cmd/... -count=1 -timeout 120s 2>&1 | tail -20 || TEST_PASS=0

SCORE=0
MAX_SCORE=36

has_engine_import() { grep -q 'github.com/jywlabs/hal/internal/engine' "$1" 2>/dev/null; }
has_style_usage() { grep -qE '(engine|display|ui|styles)\.(Style[A-Za-z]+|BoxStyle|HeaderBox|SuccessBox|ErrorBox|WarningBox)' "$1" 2>/dev/null; }
count_styles() { grep -oE '(engine|display|ui|styles)\.(Style[A-Za-z]+|BoxStyle|HeaderBox|SuccessBox|ErrorBox|WarningBox)' "$1" 2>/dev/null | sort -u | wc -l; }

# === WAVE 1-5: Style adoption (29 evals) ===
# E1-E6: Core commands
has_engine_import cmd/doctor.go && has_style_usage cmd/doctor.go && { SCORE=$((SCORE+1)); echo "E1: PASS"; } || echo "E1: FAIL"
has_engine_import cmd/status.go && has_style_usage cmd/status.go && { SCORE=$((SCORE+1)); echo "E2: PASS"; } || echo "E2: FAIL"
has_engine_import cmd/continue.go && { SC=$(count_styles cmd/continue.go); [ "$SC" -ge 2 ] && { SCORE=$((SCORE+1)); echo "E3: PASS"; } || echo "E3: FAIL"; } || echo "E3: FAIL"
! grep -q '═══' cmd/analyze.go 2>/dev/null && has_engine_import cmd/analyze.go && has_style_usage cmd/analyze.go && { SCORE=$((SCORE+1)); echo "E4: PASS"; } || echo "E4: FAIL"
grep -q 'Engine:' cmd/status.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E5: PASS"; } || echo "E5: FAIL"
has_engine_import cmd/cleanup.go && has_style_usage cmd/cleanup.go && { SCORE=$((SCORE+1)); echo "E6: PASS"; } || echo "E6: FAIL"

# E7-E8: Guards
[ "$TEST_PASS" -eq 1 ] && { SCORE=$((SCORE+1)); echo "E7: PASS"; } || echo "E7: FAIL"
JSON_OK=1; for f in cmd/status.go cmd/continue.go cmd/doctor.go; do [ -f "$f" ] && ! grep -q "MarshalIndent" "$f" 2>/dev/null && JSON_OK=0; done
[ "$JSON_OK" -eq 1 ] && { SCORE=$((SCORE+1)); echo "E8: PASS"; } || echo "E8: FAIL"

# E9-E11: Extended
has_engine_import cmd/repair.go && has_style_usage cmd/repair.go && { SCORE=$((SCORE+1)); echo "E9: PASS"; } || echo "E9: FAIL"
has_engine_import cmd/init.go && has_style_usage cmd/init.go && { SCORE=$((SCORE+1)); echo "E10: PASS"; } || echo "E10: FAIL"
has_engine_import cmd/archive.go && has_style_usage cmd/archive.go && { SCORE=$((SCORE+1)); echo "E11: PASS"; } || echo "E11: FAIL"

# E12-E14: Titles
grep -qE '(engine|display|ui)\.StyleTitle' cmd/doctor.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E12: PASS"; } || echo "E12: FAIL"
grep -qE '(engine|display|ui)\.StyleTitle' cmd/status.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E13: PASS"; } || echo "E13: FAIL"
grep -qE '(engine|display|ui)\.StyleTitle' cmd/continue.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E14: PASS"; } || echo "E14: FAIL"

# E15-E16: Depth
INIT_S=$(grep -cE '(engine|display|ui)\.Style' cmd/init.go 2>/dev/null || echo 0)
[ "$INIT_S" -ge 8 ] && { SCORE=$((SCORE+1)); echo "E15: PASS ($INIT_S)"; } || echo "E15: FAIL ($INIT_S)"
grep -q 'StyleTitle' cmd/doctor.go 2>/dev/null && grep -q 'TotalChecks' cmd/doctor.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E16: PASS"; } || echo "E16: FAIL"

# E17-E22: Sandbox
has_engine_import cmd/sandbox_status.go && has_style_usage cmd/sandbox_status.go && { SCORE=$((SCORE+1)); echo "E17: PASS"; } || echo "E17: FAIL"
has_engine_import cmd/sandbox_list.go && has_style_usage cmd/sandbox_list.go && { SCORE=$((SCORE+1)); echo "E18: PASS"; } || echo "E18: FAIL"
SBX=0; for f in sandbox_start sandbox_stop sandbox_delete; do has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && SBX=$((SBX+1)); done
[ "$SBX" -ge 2 ] && { SCORE=$((SCORE+1)); echo "E19: PASS ($SBX/3)"; } || echo "E19: FAIL ($SBX/3)"
LS=$(grep -cE '(engine|display|ui)\.Style' cmd/sandbox_list.go 2>/dev/null || echo 0)
[ "$LS" -ge 4 ] && { SCORE=$((SCORE+1)); echo "E20: PASS ($LS)"; } || echo "E20: FAIL ($LS)"
SS=$(grep -cE '(engine|display|ui)\.Style' cmd/sandbox_start.go 2>/dev/null || echo 0)
[ "$SS" -ge 4 ] && { SCORE=$((SCORE+1)); echo "E21: PASS ($SS)"; } || echo "E21: FAIL ($SS)"
SF=0; for f in sandbox_start sandbox_stop sandbox_delete; do grep -qE '(engine|display|ui)\.Style.*(Failed|failed|error|Error|\[!!\])' "cmd/${f}.go" 2>/dev/null && SF=$((SF+1)); done
[ "$SF" -ge 2 ] && { SCORE=$((SCORE+1)); echo "E22: PASS ($SF/3)"; } || echo "E22: FAIL ($SF/3)"

# E23-E29: Full coverage
has_engine_import cmd/version.go && has_style_usage cmd/version.go && { SCORE=$((SCORE+1)); echo "E23: PASS"; } || echo "E23: FAIL"
has_engine_import cmd/links.go && has_style_usage cmd/links.go && { SCORE=$((SCORE+1)); echo "E24: PASS"; } || echo "E24: FAIL"
has_engine_import cmd/standards.go && has_style_usage cmd/standards.go && { SCORE=$((SCORE+1)); echo "E25: PASS"; } || echo "E25: FAIL"
MC=0; for f in prd report auto; do has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && MC=$((MC+1)); done
[ "$MC" -ge 1 ] && { SCORE=$((SCORE+1)); echo "E26: PASS ($MC/3)"; } || echo "E26: FAIL"
has_engine_import cmd/sandbox.go && has_style_usage cmd/sandbox.go && { SP=$(grep -cE '(engine|display|ui)\.Style' cmd/sandbox.go 2>/dev/null || echo 0); [ "$SP" -ge 3 ] && { SCORE=$((SCORE+1)); echo "E27: PASS ($SP)"; } || echo "E27: FAIL ($SP)"; } || echo "E27: FAIL"
AC=0; for f in auto run prd; do has_engine_import "cmd/${f}.go" && has_style_usage "cmd/${f}.go" && AC=$((AC+1)); done
[ "$AC" -ge 1 ] && { SCORE=$((SCORE+1)); echo "E28: PASS ($AC/3)"; } || echo "E28: FAIL"
has_engine_import cmd/prd.go && has_style_usage cmd/prd.go && { SCORE=$((SCORE+1)); echo "E29: PASS"; } || echo "E29: FAIL"

# === WAVE 6: Information density (4 new evals) ===

# E30: Status shows Summary field in human output
# The StatusResult has a Summary field — it should be displayed
if grep -qE 'result\.Summary|Summary:' cmd/status.go 2>/dev/null && \
   ! grep -B2 'result\.Summary' cmd/status.go 2>/dev/null | grep -q 'jsonMode\|json\.'; then
    # Check it's used outside JSON block
    if grep -A1 'result\.Summary' cmd/status.go 2>/dev/null | grep -q 'Fprintf\|Fprintln\|Render'; then
        SCORE=$((SCORE+1)); echo "E30: PASS — status displays Summary"
    else
        echo "E30: FAIL — status has Summary ref but doesn't render it"
    fi
else
    echo "E30: FAIL — status doesn't show Summary in human output"
fi

# E31: Continue shows engine name in healthy output
if grep -qE 'engine.*Engine:|Engine:.*engine' cmd/continue.go 2>/dev/null && \
   grep -q 'LoadDefaultEngine' cmd/continue.go 2>/dev/null; then
    SCORE=$((SCORE+1)); echo "E31: PASS — continue shows engine"
else
    echo "E31: FAIL — continue doesn't show engine name"
fi

# E32: Doctor shows check scope or severity in human output block
if sed -n '/Human-readable/,/return nil/p' cmd/doctor.go 2>/dev/null | grep -qE 'c\.Scope|c\.Severity'; then
    SCORE=$((SCORE+1)); echo "E32: PASS — doctor renders check metadata"
else
    echo "E32: FAIL — doctor doesn't show check scope/severity"
fi

# E33: Status shows git branch from environment (not just PRD branch)
if grep -qE 'CurrentBranch|gitBranch' cmd/status.go 2>/dev/null; then
    SCORE=$((SCORE+1)); echo "E33: PASS — status shows git branch"
else
    echo "E33: FAIL — status doesn't show current git branch"
fi

# E34: Continue shows engine name in healthy path
if sed -n '/} else {/,/return nil/p' cmd/continue.go 2>/dev/null | grep -qE 'engine|Engine:'; then
    SCORE=$((SCORE+1)); echo "E34: PASS — continue shows engine in healthy output"
else
    echo "E34: FAIL — continue healthy path missing engine"
fi

# E35: Doctor shows per-check remediation hint (not just primary)
if sed -n '/Human-readable/,/return nil/p' cmd/doctor.go 2>/dev/null | grep -qE 'c\.Remediation|Remediation\.Command'; then
    SCORE=$((SCORE+1)); echo "E35: PASS — doctor shows per-check remediation"
else
    echo "E35: FAIL — doctor only shows primary remediation"
fi

# E36: Continue shows summary text
if grep -qE 'summary|Summary' cmd/continue.go 2>/dev/null && \
   sed -n '/Human-readable/,/return nil/p' cmd/continue.go 2>/dev/null | grep -qE 'summary|Summary'; then
    SCORE=$((SCORE+1)); echo "E36: PASS — continue shows summary"
else
    echo "E36: FAIL — continue doesn't show summary text"
fi

echo ""
echo "=== Score: ${SCORE}/${MAX_SCORE} ==="
echo "METRIC output_quality_score=${SCORE}"
echo "METRIC test_pass=${TEST_PASS}"
