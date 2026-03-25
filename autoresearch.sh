#!/bin/bash
set -euo pipefail

# Hal CLI content quality benchmark
echo "--- Build check ---"
go build ./... 2>&1 || { echo "METRIC content_quality_score=0"; echo "METRIC test_pass=0"; exit 0; }

echo "--- Test check ---"
TEST_PASS=1
go test ./cmd/... ./internal/compound/... -count=1 -timeout 120s 2>&1 | tail -20 || TEST_PASS=0

SCORE=0

# === E1-E4: Issue detail propagation ===

# E1: ReviewLoopIteration has a field for per-issue details (a slice type, not just int counts)
if sed -n '/type ReviewLoopIteration/,/^}/p' internal/compound/types.go 2>/dev/null | \
   grep -qE '\[\].*Review.*Issue'; then
    SCORE=$((SCORE + 1)); echo "E1: PASS — iteration struct has issue detail slice"
else
    echo "E1: FAIL — ReviewLoopIteration lacks per-issue detail slice"
fi

# E2: runReviewIteration populates issue details (assigns to a slice, not just int counts)
if grep -qE 'iteration\.\w*(Issues|Details)\s*=\s*(append\(|make\(|\[\]|build)' internal/compound/review_loop.go 2>/dev/null || \
   grep -qE 'append\(iteration\.\w*(Issues|Details)' internal/compound/review_loop.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E2: PASS — runReviewIteration populates issue detail slice"
else
    echo "E2: FAIL — runReviewIteration only stores counts, discards issue data"
fi

# E3: ReviewLoopMarkdown renders per-issue detail (title or file) inside the iteration loop
ITER_BLOCK=$(sed -n '/for.*iteration/,/^[[:space:]]*}/p' internal/compound/review_loop_report.go 2>/dev/null)
if echo "$ITER_BLOCK" | grep -qE '\.(Title|File|Severity)\b' 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E3: PASS — markdown renders issue details per iteration"
else
    echo "E3: FAIL — markdown only renders counts, no per-issue detail"
fi

# E4: Issue detail type has both review fields (Severity/Title) AND fix fields (Valid/Fixed)
if sed -n '/type Review.*Issue.*Detail/,/^}/p' internal/compound/types.go 2>/dev/null | \
   grep -qE '(Valid|Fixed)' 2>/dev/null && \
   sed -n '/type Review.*Issue.*Detail/,/^}/p' internal/compound/types.go 2>/dev/null | \
   grep -qE '(Severity|Title)' 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E4: PASS — issue details include both review and fix fields"
else
    echo "E4: FAIL — no issue detail type with both review and fix outcome fields"
fi

# === E5-E7: Review output enrichment ===

# E5: Markdown renders severity or file:line per issue inside iteration blocks
if echo "$ITER_BLOCK" | grep -qE '(severity|Severity|file.*line|File.*Line|\.File)' 2>/dev/null && \
   echo "$ITER_BLOCK" | grep -qE 'range.*\.(Issues|Details)' 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E5: PASS — markdown includes severity/file info per issue"
else
    echo "E5: FAIL — markdown lacks per-issue severity or file breakdown"
fi

# E6: Stop reason rendered as human-friendly text (mapped from code to sentence)
if grep -qE 'no.valid.issues.*:=|no_valid_issues.*"[A-Z]|stopReason.*switch|humanizeStop|formatStop|friendlyStop' internal/compound/review_loop_report.go 2>/dev/null || \
   sed -n '/Stop Reason/,/WriteString/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qE 'switch|map|case|"no'; then
    SCORE=$((SCORE + 1)); echo "E6: PASS — stop reason has human-friendly rendering"
else
    echo "E6: FAIL — stop reason is raw code like 'no_valid_issues'"
fi

# E7: Duration/timing tracked in types or report
if sed -n '/type ReviewLoop\(Result\|Iteration\)/,/^}/p' internal/compound/types.go 2>/dev/null | \
   grep -qiE 'duration|elapsed'; then
    SCORE=$((SCORE + 1)); echo "E7: PASS — duration tracked in review types"
else
    echo "E7: FAIL — no duration/timing in review types"
fi

# === E8-E10: Report command enrichment ===

# E8: showReviewResult actually renders patterns to terminal (not just has field in struct)
if sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | \
   grep -qE 'Pattern'; then
    SCORE=$((SCORE + 1)); echo "E8: PASS — report renders patterns to terminal"
else
    echo "E8: FAIL — report doesn't render patterns (only summary + recommendations)"
fi

# E9: Report terminal output shows tech debt info
if sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | \
   grep -qiE 'techDebt|tech.debt|issue' || \
   grep -qE 'TechDebt' cmd/report.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E9: PASS — report surfaces tech debt or issues"
else
    echo "E9: FAIL — report doesn't surface tech debt"
fi

# E10: Report terminal output shows issue count or summary stats
if sed -n '/func showReviewResult/,/^}/p' cmd/report.go 2>/dev/null | \
   grep -qiE 'issue|Issue|found|problem'; then
    SCORE=$((SCORE + 1)); echo "E10: PASS — report shows issue info"
else
    echo "E10: FAIL — report terminal output lacks issue information"
fi

# === E11-E13: Run command enrichment ===

# E11: Run shows story ID per iteration (ShowIterationHeader takes StoryInfo)
if grep -qE 'ShowIterationHeader.*story' internal/loop/loop.go 2>/dev/null && \
   grep -qE 'StoryInfo' internal/loop/loop.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E11: PASS — run shows story info per iteration"
else
    echo "E11: FAIL — run doesn't show story info per iteration"
fi

# E12: Run human-readable (non-JSON) output shows PRD progress or completion stats
RUN_HUMAN_PATH=$(sed -n '/result := runner.Run/,/return nil/p' cmd/run.go 2>/dev/null | grep -v 'jsonMode\|outputRunJSON')
if echo "$RUN_HUMAN_PATH" | grep -qiE 'progress|stories|complete|prd|Display|Show'; then
    SCORE=$((SCORE + 1)); echo "E12: PASS — run terminal shows progress/completion info"
else
    echo "E12: FAIL — run terminal path returns bare error or nil, no progress summary"
fi

# E13: Run JSON includes story ID
if grep -qE 'StoryID.*json.*storyId' cmd/run.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E13: PASS — run JSON has story ID"
else
    echo "E13: FAIL — run JSON lacks story ID"
fi

# === E14: Tests pass ===
if [ "$TEST_PASS" -eq 1 ]; then
    SCORE=$((SCORE + 1)); echo "E14: PASS — all tests pass"
else
    echo "E14: FAIL — tests failed"
fi

# === E15-E20: Wave 2 — Deeper enrichment ===

# E15: Auto pipeline surfaces analysis result during execution
if grep -qE 'PriorityItem|priorityItem|Analysis.*display|display.*Analysis|ShowInfo.*analys|ShowInfo.*priority|ShowInfo.*branch' internal/compound/pipeline.go 2>/dev/null || \
   sed -n '/runAnalyzeStep/,/^}/p' internal/compound/pipeline.go 2>/dev/null | grep -qE 'ShowInfo|display'; then
    SCORE=$((SCORE + 1)); echo "E15: PASS — auto pipeline shows analysis details"
else
    echo "E15: FAIL — auto pipeline doesn't surface analysis results"
fi

# E16: Review markdown shows files affected across all iterations
if grep -qE 'Files\s*(Affected|Changed|Modified)|files.*changed|Affected.*Files' internal/compound/review_loop_report.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E16: PASS — review shows files affected"
else
    echo "E16: FAIL — review doesn't show files affected summary"
fi

# E17: ReviewLoopIteration tracks per-iteration duration
if sed -n '/type ReviewLoopIteration/,/^}/p' internal/compound/types.go 2>/dev/null | \
   grep -qiE 'duration|elapsed|startedAt|endedAt'; then
    SCORE=$((SCORE + 1)); echo "E17: PASS — per-iteration timing tracked"
else
    echo "E17: FAIL — no per-iteration timing in ReviewLoopIteration"
fi

# E18: Report JSON includes issues and tech debt (additive to existing contract)
if grep -qE 'Issues.*json.*issues' cmd/report.go 2>/dev/null && \
   grep -qE 'TechDebt.*json.*techDebt' cmd/report.go 2>/dev/null; then
    SCORE=$((SCORE + 1)); echo "E18: PASS — report JSON contract includes issues and tech debt"
else
    echo "E18: FAIL — report JSON lacks issues/tech debt fields"
fi

# E19: Review totals show severity distribution
if grep -qE 'severity|Severity|High|Critical|high.*:.*[0-9]|critical.*:.*[0-9]' internal/compound/review_loop_report.go 2>/dev/null && \
   sed -n '/Totals/,/Stop Reason/p' internal/compound/review_loop_report.go 2>/dev/null | grep -qiE 'severity|high|critical'; then
    SCORE=$((SCORE + 1)); echo "E19: PASS — review totals include severity distribution"
else
    echo "E19: FAIL — review totals lack severity distribution"
fi

# E20: ReviewLoopResult has FilesAffected or similar summary field
if sed -n '/type ReviewLoop\(Result\|Totals\)/,/^}/p' internal/compound/types.go 2>/dev/null | \
   grep -qiE 'files|affected|changed'; then
    SCORE=$((SCORE + 1)); echo "E20: PASS — ReviewLoopResult tracks files affected"
else
    echo "E20: FAIL — ReviewLoopResult lacks files tracking"
fi

MAX_SCORE=20

echo ""
echo "=== Results ==="
echo "Score: ${SCORE}/${MAX_SCORE}"
echo ""
echo "METRIC content_quality_score=${SCORE}"
echo "METRIC test_pass=${TEST_PASS}"
