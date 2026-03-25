#!/bin/bash
set -euo pipefail

# Hal CLI content quality benchmark
echo "--- Build check ---"
go build ./... 2>&1 || { echo "METRIC content_quality_score=0"; echo "METRIC test_pass=0"; exit 0; }

echo "--- Test check ---"
TEST_PASS=1
go test ./cmd/... ./internal/compound/... ./internal/loop/... -count=1 -timeout 120s 2>&1 | tail -20 || TEST_PASS=0

SCORE=0

# Precompute text blocks
ITER_BLOCK=$(sed -n '/for.*iteration/,/^[[:space:]]*}/p' internal/compound/review_loop_report.go 2>/dev/null)
DETAIL_TYPE=$(sed -n '/type Review.*Issue.*Detail/,/^}/p' internal/compound/types.go 2>/dev/null)

# E1-E4: Issue detail propagation
sed -n '/type ReviewLoopIteration/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qE '\[\].*Review.*Issue' && { SCORE=$((SCORE+1)); echo "E1: PASS"; } || echo "E1: FAIL"
grep -qE 'iteration\.\w*(Issues|Details)\s*=\s*(append\(|make\(|\[\]|build)' internal/compound/review_loop.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E2: PASS"; } || echo "E2: FAIL"
echo "$ITER_BLOCK" | grep -qE '\.(Title|File|Severity)\b' && { SCORE=$((SCORE+1)); echo "E3: PASS"; } || echo "E3: FAIL"
echo "$DETAIL_TYPE" | grep -qE '(Valid|Fixed)' && echo "$DETAIL_TYPE" | grep -qE '(Severity|Title)' && { SCORE=$((SCORE+1)); echo "E4: PASS"; } || echo "E4: FAIL"

# E5-E7: Review enrichment
echo "$ITER_BLOCK" | grep -qE '\.File' && echo "$ITER_BLOCK" | grep -qE 'range.*\.(Issues|Details)' && { SCORE=$((SCORE+1)); echo "E5: PASS"; } || echo "E5: FAIL"
grep -qE 'humanizeStop|formatStop' internal/compound/review_loop_report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E6: PASS"; } || echo "E6: FAIL"
sed -n '/type ReviewLoop\(Result\|Iteration\)/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qiE 'duration|elapsed' && { SCORE=$((SCORE+1)); echo "E7: PASS"; } || echo "E7: FAIL"

# E8-E10: Report enrichment
sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | grep -qE 'Pattern' && { SCORE=$((SCORE+1)); echo "E8: PASS"; } || echo "E8: FAIL"
sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | grep -qiE 'TechDebt|tech.debt' && { SCORE=$((SCORE+1)); echo "E9: PASS"; } || echo "E9: FAIL"
sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | grep -qiE 'issue|Issue' && { SCORE=$((SCORE+1)); echo "E10: PASS"; } || echo "E10: FAIL"

# E11-E14
grep -qE 'ShowIterationHeader.*story' internal/loop/loop.go 2>/dev/null && grep -qE 'StoryInfo' internal/loop/loop.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E11: PASS"; } || echo "E11: FAIL"
RUN_HUMAN=$(sed -n '/result := runner.Run/,/return nil/p' cmd/run.go 2>/dev/null | grep -v 'jsonMode\|outputRunJSON')
echo "$RUN_HUMAN" | grep -qiE 'progress|stories|complete|prd|Display|Show' && { SCORE=$((SCORE+1)); echo "E12: PASS"; } || echo "E12: FAIL"
grep -qE 'StoryID.*json.*storyId' cmd/run.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E13: PASS"; } || echo "E13: FAIL"
[ "$TEST_PASS" -eq 1 ] && { SCORE=$((SCORE+1)); echo "E14: PASS"; } || echo "E14: FAIL"

# E15-E20
sed -n '/func.*runAnalyzeStep/,/^func /p' internal/compound/pipeline.go 2>/dev/null | grep -qE 'ShowInfo|display' && { SCORE=$((SCORE+1)); echo "E15: PASS"; } || echo "E15: FAIL"
grep -qE 'Files\s*(Affected|Changed|Modified)' internal/compound/review_loop_report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E16: PASS"; } || echo "E16: FAIL"
sed -n '/type ReviewLoopIteration/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qiE 'duration|elapsed' && { SCORE=$((SCORE+1)); echo "E17: PASS"; } || echo "E17: FAIL"
grep -qE 'Issues.*json.*issues' cmd/report.go 2>/dev/null && grep -qE 'TechDebt.*json.*techDebt' cmd/report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E18: PASS"; } || echo "E18: FAIL"
sed -n '/Totals/,/Stop Reason/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qiE 'severity|Severity' && { SCORE=$((SCORE+1)); echo "E19: PASS"; } || echo "E19: FAIL"
sed -n '/type ReviewLoop\(Result\|Totals\)/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qiE 'files|affected' && { SCORE=$((SCORE+1)); echo "E20: PASS"; } || echo "E20: FAIL"

# E21-E28
echo "$DETAIL_TYPE" | grep -qiE 'rationale|reason' && { SCORE=$((SCORE+1)); echo "E21: PASS"; } || echo "E21: FAIL"
sed -n '/func showRunSummary/,/^func /p' cmd/run.go 2>/dev/null | grep -qiE 'time|duration|elapsed|took' && { SCORE=$((SCORE+1)); echo "E22: PASS"; } || echo "E22: FAIL"
sed -n '/type Result struct/,/^}/p' internal/loop/loop.go 2>/dev/null | grep -qiE 'duration|elapsed' && { SCORE=$((SCORE+1)); echo "E23: PASS"; } || echo "E23: FAIL"
grep -qE 'Duration|duration|time\.Since' cmd/auto.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E24: PASS"; } || echo "E24: FAIL"
echo "$ITER_BLOCK" | grep -qE '\.Rationale\b' && { SCORE=$((SCORE+1)); echo "E25: PASS"; } || echo "E25: FAIL"
sed -n '/type RunResult/,/^}/p' cmd/run.go 2>/dev/null | grep -qiE 'duration' && { SCORE=$((SCORE+1)); echo "E26: PASS"; } || echo "E26: FAIL"
sed -n '/type AutoResult/,/^}/p' cmd/auto.go 2>/dev/null | grep -qiE 'duration|elapsed' && { SCORE=$((SCORE+1)); echo "E27: PASS"; } || echo "E27: FAIL"
echo "$ITER_BLOCK" | grep -qiE 'duration|Duration' && { SCORE=$((SCORE+1)); echo "E28: PASS"; } || echo "E28: FAIL"

# E29-E36
echo "$DETAIL_TYPE" | grep -qiE 'suggestedFix|suggested.fix' && { SCORE=$((SCORE+1)); echo "E29: PASS"; } || echo "E29: FAIL"
sed -n '/Totals/,/Stop Reason/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qiE 'duration|Duration' && { SCORE=$((SCORE+1)); echo "E30: PASS"; } || echo "E30: FAIL"
sed -n '/type RunPRDInfo/,/^}/p' cmd/run.go 2>/dev/null | grep -qE 'Completed|Total' && { SCORE=$((SCORE+1)); echo "E31: PASS"; } || echo "E31: FAIL"
grep -qE 'BaseBranch|CurrentBranch' internal/compound/review_loop_report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E32: PASS"; } || echo "E32: FAIL"
echo "$ITER_BLOCK" | grep -qiE 'suggestedFix|SuggestedFix' && { SCORE=$((SCORE+1)); echo "E33: PASS"; } || echo "E33: FAIL"
sed -n '/func.*runBranchStep/,/^func /p' internal/compound/pipeline.go 2>/dev/null | grep -qiE 'ShowInfo.*branch' && { SCORE=$((SCORE+1)); echo "E34: PASS"; } || echo "E34: FAIL"
sed -n '/Totals/,/Stop Reason/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qiE 'files|Files' && { SCORE=$((SCORE+1)); echo "E35: PASS"; } || echo "E35: FAIL"
sed -n '/func outputAutoJSON/,/^}/p' cmd/auto.go 2>/dev/null | grep -qiE 'failure|kind|category' && { SCORE=$((SCORE+1)); echo "E36: PASS"; } || echo "E36: FAIL"

# E37-E44
sed -n '/type Result struct/,/^}/p' internal/loop/loop.go 2>/dev/null | grep -qiE 'stories|completed.*stor|story' && { SCORE=$((SCORE+1)); echo "E37: PASS"; } || echo "E37: FAIL"
sed -n '/func showRunSummary/,/^func /p' cmd/run.go 2>/dev/null | grep -qiE 'story|stories|Story|CurrentStory|CompletedStories' && { SCORE=$((SCORE+1)); echo "E38: PASS"; } || echo "E38: FAIL"
sed -n '/pipeline.Run/,/ShowCommandSuccess/p' cmd/auto.go 2>/dev/null | grep -qiE 'branch|analysis|iteration|step|stories' && { SCORE=$((SCORE+1)); echo "E39: PASS"; } || echo "E39: FAIL"
sed -n '/func outputRunJSON/,/^}/p' cmd/run.go 2>/dev/null | grep -qiE 'CompletedStories|TotalStories|stories' && { SCORE=$((SCORE+1)); echo "E40: PASS"; } || echo "E40: FAIL"
sed -n '/func showRunSummary/,/^func /p' cmd/run.go 2>/dev/null | grep -qE 'result\.(CompletedStories|TotalStories)' && { SCORE=$((SCORE+1)); echo "E41: PASS"; } || echo "E41: FAIL"
sed -n '/func outputRunJSON/,/^}/p' cmd/run.go 2>/dev/null | grep -qE 'result\.(CompletedStories|TotalStories)' && { SCORE=$((SCORE+1)); echo "E42: PASS"; } || echo "E42: FAIL"
grep -qE 'collectFilesAffected' internal/compound/review_loop.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E43: PASS"; } || echo "E43: FAIL"
sed -n '/pipeline.Run/,/ShowCommandSuccess/p' cmd/auto.go 2>/dev/null | grep -qiE 'branch' && { SCORE=$((SCORE+1)); echo "E44: PASS"; } || echo "E44: FAIL"

# E45-E52
grep -qE 'synthesizeOutcome|Outcome:' internal/compound/review_loop_report.go 2>/dev/null && grep -qE 'func synthesizeOutcome' internal/compound/review_loop_report.go 2>/dev/null && { SCORE=$((SCORE+1)); echo "E45: PASS"; } || echo "E45: FAIL"
sed -n '/func showRunSummary/,/^func /p' cmd/run.go 2>/dev/null | grep -qiE 'story.*ID|story.*title|NextStory|CurrentStory|FindStory' && { SCORE=$((SCORE+1)); echo "E46: PASS"; } || echo "E46: FAIL"
sed -n '/type Result struct/,/^}/p' internal/loop/loop.go 2>/dev/null | grep -qiE 'lastStory|nextStory|storyID|currentStory' && { SCORE=$((SCORE+1)); echo "E47: PASS"; } || echo "E47: FAIL"
sed -n '/Totals/,/Stop Reason/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qE 'rate|%%|percent|fix.*ratio' && { SCORE=$((SCORE+1)); echo "E48: PASS"; } || echo "E48: FAIL"
sed -n '/pipeline.Run/,/fmt.Fprintln.*data/p' cmd/auto.go 2>/dev/null | grep -qiE 'branch' && { SCORE=$((SCORE+1)); echo "E49: PASS"; } || echo "E49: FAIL"
sed -n '/pipeline.Run/,/ShowCommandSuccess/p' cmd/auto.go 2>/dev/null | grep -qiE 'prd|progress|stories|tasks' && { SCORE=$((SCORE+1)); echo "E50: PASS"; } || echo "E50: FAIL"
sed -n '/type RunResult/,/^}/p' cmd/run.go 2>/dev/null | grep -qiE 'lastStory|last.*story' && { SCORE=$((SCORE+1)); echo "E51: PASS"; } || echo "E51: FAIL"
sed -n '/type AutoResult/,/^}/p' cmd/auto.go 2>/dev/null | grep -qiE 'tasks|stories|progress' && { SCORE=$((SCORE+1)); echo "E52: PASS"; } || echo "E52: FAIL"

# === E53-E56: Wave 12 — Fix-phase context + failure paths ===

# E53: ReviewIssueDetail carries fix reason (why valid/invalid)
echo "$DETAIL_TYPE" | grep -qiE 'reason|fixReason|validationReason' && { SCORE=$((SCORE+1)); echo "E53: PASS"; } || echo "E53: FAIL"

# E54: buildIssueDetails populates reason from fix results
sed -n '/func buildIssueDetails/,/^}/p' internal/compound/review_loop.go 2>/dev/null | grep -qiE 'reason|Reason' && { SCORE=$((SCORE+1)); echo "E54: PASS"; } || echo "E54: FAIL"

# E55: Review markdown details section shows fix reason for invalid issues
echo "$ITER_BLOCK" | grep -qiE 'reason|Reason|invalid.*:' && { SCORE=$((SCORE+1)); echo "E55: PASS"; } || echo "E55: FAIL"

# E56: Auto JSON failure path includes duration
sed -n '/func outputAutoJSON/,/^}/p' cmd/auto.go 2>/dev/null | grep -qiE 'duration|elapsed|Duration' && { SCORE=$((SCORE+1)); echo "E56: PASS"; } || echo "E56: FAIL"

# === E57-E60: Wave 13 — Error paths + engine tracking ===

# E57: showRunSummary handles error case (not just success/complete)
sed -n '/func showRunSummary/,/^func /p' cmd/run.go 2>/dev/null | grep -qiE 'Error|error|failed|Failed' && { SCORE=$((SCORE+1)); echo "E57: PASS"; } || echo "E57: FAIL"

# E58: ReviewLoopResult includes engine name
sed -n '/type ReviewLoopResult/,/^}/p' internal/compound/types.go 2>/dev/null | grep -qiE 'engine' && { SCORE=$((SCORE+1)); echo "E58: PASS"; } || echo "E58: FAIL"

# E59: Review markdown metadata shows engine used
sed -n '/Run Metadata/,/## Iterations/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qiE 'engine|Engine' && { SCORE=$((SCORE+1)); echo "E59: PASS"; } || echo "E59: FAIL"

# E60: RunResult JSON includes engine name
sed -n '/type RunResult/,/^}/p' cmd/run.go 2>/dev/null | grep -qiE 'engine' && { SCORE=$((SCORE+1)); echo "E60: PASS"; } || echo "E60: FAIL"

MAX_SCORE=60

echo ""
echo "=== Score: ${SCORE}/${MAX_SCORE} ==="
echo "METRIC content_quality_score=${SCORE}"
echo "METRIC test_pass=${TEST_PASS}"
