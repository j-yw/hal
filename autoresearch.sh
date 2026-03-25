#!/bin/bash
set -euo pipefail

# Hal CLI content quality benchmark
echo "--- Build check ---"
go build ./... 2>&1 || { echo "METRIC content_quality_score=0"; echo "METRIC test_pass=0"; exit 0; }

echo "--- Test check ---"
TEST_PASS=1
go test ./cmd/... ./internal/compound/... ./internal/loop/... -count=1 -timeout 120s 2>&1 | tail -20 || TEST_PASS=0

SCORE=0

# === E1-E4: Issue detail propagation ===
sed -n '/type ReviewLoopIteration/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qE '\[\].*Review.*Issue' && { SCORE=$((SCORE+1)); echo "E1: PASS"; } || echo "E1: FAIL"
grep -qE 'iteration\.\w*(Issues|Details)\s*=\s*(append\(|make\(|\[\]|build)' internal/compound/review_loop.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E2: PASS"; } || echo "E2: FAIL"
ITER_BLOCK=$(sed -n '/for.*iteration/,/^[[:space:]]*}/p' internal/compound/review_loop_report.go 2>/dev/null)
echo "$ITER_BLOCK" | grep -qE '\.(Title|File|Severity)\b' && { SCORE=$((SCORE+1)); echo "E3: PASS"; } || echo "E3: FAIL"
DETAIL_TYPE=$(sed -n '/type Review.*Issue.*Detail/,/^}/p' internal/compound/types.go 2>/dev/null)
echo "$DETAIL_TYPE" | grep -qE '(Valid|Fixed)' && echo "$DETAIL_TYPE" | grep -qE '(Severity|Title)' && { SCORE=$((SCORE+1)); echo "E4: PASS"; } || echo "E4: FAIL"

# === E5-E7: Review output enrichment ===
echo "$ITER_BLOCK" | grep -qE '\.File' && echo "$ITER_BLOCK" | grep -qE 'range.*\.(Issues|Details)' && { SCORE=$((SCORE+1)); echo "E5: PASS"; } || echo "E5: FAIL"
grep -qE 'humanizeStop|formatStop' internal/compound/review_loop_report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E6: PASS"; } || echo "E6: FAIL"
sed -n '/type ReviewLoop\(Result\|Iteration\)/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qiE 'duration|elapsed' && { SCORE=$((SCORE+1)); echo "E7: PASS"; } || echo "E7: FAIL"

# === E8-E10: Report command enrichment ===
sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | grep -qE 'Pattern' && { SCORE=$((SCORE+1)); echo "E8: PASS"; } || echo "E8: FAIL"
sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | grep -qiE 'TechDebt|tech.debt' && { SCORE=$((SCORE+1)); echo "E9: PASS"; } || echo "E9: FAIL"
sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | grep -qiE 'issue|Issue' && { SCORE=$((SCORE+1)); echo "E10: PASS"; } || echo "E10: FAIL"

# === E11-E14 ===
grep -qE 'ShowIterationHeader.*story' internal/loop/loop.go 2>/dev/null && grep -qE 'StoryInfo' internal/loop/loop.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E11: PASS"; } || echo "E11: FAIL"
RUN_HUMAN=$(sed -n '/result := runner.Run/,/return nil/p' cmd/run.go 2>/dev/null | grep -v 'jsonMode\|outputRunJSON')
echo "$RUN_HUMAN" | grep -qiE 'progress|stories|complete|prd|Display|Show' && { SCORE=$((SCORE+1)); echo "E12: PASS"; } || echo "E12: FAIL"
grep -qE 'StoryID.*json.*storyId' cmd/run.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E13: PASS"; } || echo "E13: FAIL"
[ "$TEST_PASS" -eq 1 ] && { SCORE=$((SCORE+1)); echo "E14: PASS"; } || echo "E14: FAIL"

# === E15-E20 ===
sed -n '/func.*runAnalyzeStep/,/^func /p' internal/compound/pipeline.go 2>/dev/null | grep -qE 'ShowInfo|display' && { SCORE=$((SCORE+1)); echo "E15: PASS"; } || echo "E15: FAIL"
grep -qE 'Files\s*(Affected|Changed|Modified)' internal/compound/review_loop_report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E16: PASS"; } || echo "E16: FAIL"
sed -n '/type ReviewLoopIteration/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qiE 'duration|elapsed' && { SCORE=$((SCORE+1)); echo "E17: PASS"; } || echo "E17: FAIL"
grep -qE 'Issues.*json.*issues' cmd/report.go 2>/dev/null && grep -qE 'TechDebt.*json.*techDebt' cmd/report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E18: PASS"; } || echo "E18: FAIL"
sed -n '/Totals/,/Stop Reason/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qiE 'severity|Severity' && { SCORE=$((SCORE+1)); echo "E19: PASS"; } || echo "E19: FAIL"
sed -n '/type ReviewLoop\(Result\|Totals\)/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qiE 'files|affected' && { SCORE=$((SCORE+1)); echo "E20: PASS"; } || echo "E20: FAIL"

# === E21-E28 ===
echo "$DETAIL_TYPE" | grep -qiE 'rationale|reason' && { SCORE=$((SCORE+1)); echo "E21: PASS"; } || echo "E21: FAIL"
sed -n '/func showRunSummary/,/^}/p' cmd/run.go 2>/dev/null | grep -qiE 'time|duration|elapsed|took' && { SCORE=$((SCORE+1)); echo "E22: PASS"; } || echo "E22: FAIL"
sed -n '/type Result struct/,/^}/p' internal/loop/loop.go 2>/dev/null | grep -qiE 'duration|elapsed' && { SCORE=$((SCORE+1)); echo "E23: PASS"; } || echo "E23: FAIL"
grep -qE 'Duration|duration|time\.Since' cmd/auto.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E24: PASS"; } || echo "E24: FAIL"
echo "$ITER_BLOCK" | grep -qE '\.Rationale\b' && { SCORE=$((SCORE+1)); echo "E25: PASS"; } || echo "E25: FAIL"
sed -n '/type RunResult/,/^}/p' cmd/run.go 2>/dev/null | grep -qiE 'duration' && { SCORE=$((SCORE+1)); echo "E26: PASS"; } || echo "E26: FAIL"
sed -n '/type AutoResult/,/^}/p' cmd/auto.go 2>/dev/null | grep -qiE 'duration|elapsed' && { SCORE=$((SCORE+1)); echo "E27: PASS"; } || echo "E27: FAIL"
echo "$ITER_BLOCK" | grep -qiE 'duration|Duration' && { SCORE=$((SCORE+1)); echo "E28: PASS"; } || echo "E28: FAIL"

# === E29-E36 ===
echo "$DETAIL_TYPE" | grep -qiE 'suggestedFix|suggested.fix' && { SCORE=$((SCORE+1)); echo "E29: PASS"; } || echo "E29: FAIL"
sed -n '/Totals/,/Stop Reason/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qiE 'duration|Duration' && { SCORE=$((SCORE+1)); echo "E30: PASS"; } || echo "E30: FAIL"
sed -n '/type RunPRDInfo/,/^}/p' cmd/run.go 2>/dev/null | grep -qE 'Completed|Total' && { SCORE=$((SCORE+1)); echo "E31: PASS"; } || echo "E31: FAIL"
grep -qE 'BaseBranch|CurrentBranch|base.*branch|current.*branch' internal/compound/review_loop_report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E32: PASS"; } || echo "E32: FAIL"
echo "$ITER_BLOCK" | grep -qiE 'suggestedFix|SuggestedFix' && { SCORE=$((SCORE+1)); echo "E33: PASS"; } || echo "E33: FAIL"
sed -n '/func.*runBranchStep/,/^func /p' internal/compound/pipeline.go 2>/dev/null | grep -qiE 'ShowInfo.*branch' && { SCORE=$((SCORE+1)); echo "E34: PASS"; } || echo "E34: FAIL"
sed -n '/Totals/,/Stop Reason/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qiE 'files|Files' && { SCORE=$((SCORE+1)); echo "E35: PASS"; } || echo "E35: FAIL"
sed -n '/func outputAutoJSON/,/^}/p' cmd/auto.go 2>/dev/null | grep -qiE 'failure|kind|category' && { SCORE=$((SCORE+1)); echo "E36: PASS"; } || echo "E36: FAIL"

# === E37-E40: Wave 7 — Actionable completion context ===

# E37: loop.Result tracks completed stories (list or count beyond just Complete bool)
sed -n '/type Result struct/,/^}/p' internal/loop/loop.go 2>/dev/null | grep -qiE 'stories|completed.*stor|story' && { SCORE=$((SCORE+1)); echo "E37: PASS"; } || echo "E37: FAIL"

# E38: showRunSummary lists completed story IDs or shows next pending story
sed -n '/func showRunSummary/,/^func /p' cmd/run.go 2>/dev/null | grep -qiE 'story|stories|Story|CurrentStory|CompletedStories' && { SCORE=$((SCORE+1)); echo "E38: PASS"; } || echo "E38: FAIL"

# E39: Auto terminal completion shows pipeline summary (branch or analysis or steps)
sed -n '/pipeline.Run/,/ShowCommandSuccess/p' cmd/auto.go 2>/dev/null | grep -qiE 'branch|analysis|iteration|step|stories' && { SCORE=$((SCORE+1)); echo "E39: PASS"; } || echo "E39: FAIL"

# E40: Run JSON includes completed/total stories directly (not just inside nested PRD)
sed -n '/func outputRunJSON/,/^}/p' cmd/run.go 2>/dev/null | grep -qiE 'CompletedStories|TotalStories|stories' && { SCORE=$((SCORE+1)); echo "E40: PASS"; } || echo "E40: FAIL"

# === E41-E44: Wave 8 — Structural quality ===

# E41: showRunSummary uses loop.Result story counts (not re-reading PRD from disk)
sed -n '/func showRunSummary/,/^func /p' cmd/run.go 2>/dev/null | grep -qE 'result\.(CompletedStories|TotalStories)' && { SCORE=$((SCORE+1)); echo "E41: PASS"; } || echo "E41: FAIL"

# E42: Run JSON uses loop.Result story counts (not re-reading PRD from disk)
sed -n '/func outputRunJSON/,/^}/p' cmd/run.go 2>/dev/null | grep -qE 'result\.(CompletedStories|TotalStories)' && { SCORE=$((SCORE+1)); echo "E42: PASS"; } || echo "E42: FAIL"

# E43: Review loop single-iteration path also populates Issues
grep -qE 'collectFilesAffected' internal/compound/review_loop.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E43: PASS"; } || echo "E43: FAIL"

# E44: Auto completion summary includes branch info
sed -n '/pipeline.Run/,/ShowCommandSuccess/p' cmd/auto.go 2>/dev/null | grep -qiE 'branch' && { SCORE=$((SCORE+1)); echo "E44: PASS"; } || echo "E44: FAIL"

MAX_SCORE=44

echo ""
echo "=== Score: ${SCORE}/${MAX_SCORE} ==="
echo "METRIC content_quality_score=${SCORE}"
echo "METRIC test_pass=${TEST_PASS}"
