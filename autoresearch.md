# Autoresearch: Hal CLI Content Quality

## Objective

Improve the **content richness** of `hal review`, `hal report`, `hal run`, and `hal auto` command output. Currently these commands output structural metadata (counts, timestamps, branch names) but omit the substance — what issues were found, what files were affected, what the reviewer's approach was, what stories completed. The goal is to surface actionable detail so a human or machine reading the output can understand **what happened** without opening report files.

## Primary focus: `hal review` output enrichment

The review loop is the highest-value target because it has rich internal data (`reviewLoopIssue` with id/title/severity/file/line/rationale/suggestedFix, `reviewLoopFixIssue` with valid/reason/fixed) that is parsed and counted but **discarded** before reaching `ReviewLoopIteration`. The markdown output only shows bare numbers.

### Current output (poor):
```
### Iteration 1
- Issues Found: 3
- Valid Issues: 3  
- Fixes Applied: 3
- Summary: Validated all three reported issues...
- Status: fixed
```

### Target output (rich):
```
### Iteration 1
- Issues Found: 3 (3 valid, 0 invalid)
- Fixes Applied: 3/3

| # | Severity | File | Issue | Fixed |
|---|----------|------|-------|-------|
| 1 | high | cmd/review.go:42 | Missing nil check on engine result | ✓ |
| 2 | medium | internal/compound/pipeline.go:88 | Unchecked error from saveState | ✓ |
| 3 | low | cmd/auto.go:15 | Unused import after refactor | ✓ |

Summary: Validated all three reported issues...
```

## Metrics
- **Primary**: `content_quality_score` (unitless, higher is better) — sum of binary eval passes across content richness criteria
- **Secondary**: `test_pass` — `go test ./cmd/... ./internal/compound/...` exit code (1=pass, 0=fail)

## How to Run
`./autoresearch.sh` — builds hal, runs tests, scores source for content quality, outputs `METRIC` lines.

## Files in Scope

### Data structures (enrich these first)
- `internal/compound/types.go` — `ReviewLoopIteration` needs issue detail fields. Add `Issues []ReviewIssueDetail` or similar.
- `internal/compound/review_loop.go` — `runReviewIteration()` parses issues but only stores counts. Preserve issue details in the returned iteration.

### Report generation (render the enriched data)
- `internal/compound/review_loop_report.go` — `ReviewLoopMarkdown()` renders the markdown summary. Add issue tables, file lists, severity breakdown.

### Command output (surface enriched data in terminal)
- `cmd/review.go` — Human-readable terminal output via glamour-rendered markdown.
- `cmd/report.go` — `showReviewResult()` shows summary + recommendations. Surface patterns and tech debt.
- `cmd/run.go` — `outputRunJSON()` + terminal output. Surface story completion details.
- `cmd/auto.go` — Surface pipeline step details (analysis result, branch name, task count).

### Test files (MUST update alongside changes)
- `internal/compound/review_loop_test.go` — Review loop tests
- `internal/compound/review_loop_report_test.go` — Report generation tests  
- `internal/compound/review_loop_result_test.go` — Result struct contract tests
- `cmd/review_test.go`, `cmd/report_test.go`, `cmd/run_test.go`, `cmd/auto_test.go`

## Off Limits
- `--json` output contracts — existing JSON field names/types must NOT change (can ADD new fields)
- `internal/status/`, `internal/doctor/` — pure data packages
- `docs/contracts/` — contract documentation
- Cobra command metadata (Use, Short, Long, Example)
- Engine internals (`internal/engine/*.go` except display.go for new helpers)
- Review loop prompts — do NOT change what the AI model is asked to produce

## Constraints
- `go build ./...` must pass
- `go test ./cmd/... ./internal/compound/...` must pass
- All existing `--json` contracts must remain backward compatible (additive only)
- New fields on `ReviewLoopIteration` must have `json:"..."` tags with `omitempty` to preserve backward compat
- Keep non-TTY output clean — tables should degrade gracefully when piped
- Do NOT change the review loop prompts or AI interaction logic
- Do NOT change how `parseReviewLoopResponse` / `parseReviewLoopFixResponse` work internally

## Eval Criteria (what the benchmark scores)

### E1-E4: Issue detail propagation (review loop)
- E1: `ReviewLoopIteration` has a field that can hold per-issue details (title, file, severity)
- E2: `runReviewIteration` populates issue details in the returned iteration (not just counts)
- E3: `ReviewLoopMarkdown` renders issue details (title+file or table) per iteration
- E4: Issue details include fix outcome (valid/fixed status per issue)

### E5-E7: Review output enrichment
- E5: Markdown output includes a per-iteration file list or severity breakdown
- E6: Stop reason rendered as human-friendly sentence (not raw code like "no_valid_issues")
- E7: Review duration shown (total elapsed, or per-iteration timing)

### E8-E10: Report command enrichment
- E8: `showReviewResult` renders patterns discovered (not just recommendations)  
- E9: Report markdown includes tech debt section when present
- E10: Report terminal output shows count of issues found

### E11-E13: Run command enrichment
- E11: Run terminal output shows story ID being worked on (per-iteration)
- E12: Run terminal output shows PRD progress (N/M stories) at end
- E13: Run JSON output includes per-iteration story info

### E14: Tests pass
- E14: `go test ./cmd/... ./internal/compound/...` passes

## What's Been Tried
(New session — nothing tried yet)
