# Autoresearch Ideas — Hal CLI Content Quality

## Completed (10 waves, 3→50, 17 experiments, 0 test failures)

### Review loop enrichment
- ✅ ReviewIssueDetail type with id/title/severity/file/line/rationale/suggestedFix/valid/fixed
- ✅ Per-issue table in ReviewLoopMarkdown (severity | file:line | title | fixed)
- ✅ Details section with rationale + italic suggestedFix per issue
- ✅ humanizeStopReason maps codes to sentences ("Clean review pass — no issues found in iteration 2.")
- ✅ synthesizeOutcome in metadata ("All 3 valid issue(s) fixed.")
- ✅ Duration on ReviewLoopResult and per-iteration
- ✅ FilesAffected on ReviewLoopTotals (both multi + single iteration paths)
- ✅ Severity distribution in totals
- ✅ Fix rate percentage in totals

### Report enrichment
- ✅ showReviewResult renders patterns, issues, tech debt
- ✅ Issues/TechDebt on ReviewResult type and report JSON contract

### Run enrichment
- ✅ loop.Result: Duration (named return + defer), CompletedStories/TotalStories, LastStoryID/Title
- ✅ showRunSummary: completion status, duration, last story, PRD progress (from Result, not disk)
- ✅ RunResult JSON: Duration field, story counts from Result

### Auto enrichment
- ✅ AutoResult JSON: Duration, Branch fields
- ✅ Terminal completion: Duration + Branch + PRD Tasks
- ✅ Pipeline already shows analysis priority/branch/tasks during execution

## Remaining ideas (genuinely diminishing returns)
- Auto pipeline per-step timing — requires pipeline refactor
- Review diff statistics (lines changed) — requires git stat integration
- Status command: last review/run timestamp — requires report scanning
- Non-TTY output verification — testing infrastructure change
- Collapse issue details when >10 per iteration — UX polish
