# Autoresearch Ideas — Hal CLI Content Quality

## Completed (8 waves, 3→44, 15 experiments)

### Wave 1: Issue detail propagation (E1-E4)
- ✅ ReviewIssueDetail type with title/severity/file/line/rationale/suggestedFix/valid/fixed
- ✅ Issues []ReviewIssueDetail slice on ReviewLoopIteration  
- ✅ buildIssueDetails merges review findings with fix outcomes

### Wave 2: Review output enrichment (E3-E7)
- ✅ Per-issue table in ReviewLoopMarkdown (severity|file:line|title|fixed)
- ✅ humanizeStopReason maps codes to sentences
- ✅ Duration on ReviewLoopResult and ReviewLoopIteration

### Wave 3: Report/Run enrichment (E8-E14)
- ✅ showReviewResult renders patterns, issues, tech debt
- ✅ Issues/TechDebt on ReviewResult and report JSON
- ✅ showRunSummary with PRD progress from loop.Result

### Wave 4: Timing + depth (E15-E24)
- ✅ Per-iteration timing
- ✅ FilesAffected on ReviewLoopTotals (both multi + single iteration paths)
- ✅ Severity distribution in totals
- ✅ loop.Result.Duration via named return + defer
- ✅ Run/Auto elapsed time in terminal and JSON

### Wave 5-6: Completeness + Polish (E25-E36)
- ✅ Rationale + SuggestedFix details section in review markdown
- ✅ Duration in run/auto JSON contracts (RunResult, AutoResult)
- ✅ Total duration in review totals section

### Wave 7-8: Actionable context + Structural (E37-E44)
- ✅ loop.Result tracks CompletedStories/TotalStories via defer
- ✅ showRunSummary and outputRunJSON use result counts (no redundant PRD reads)
- ✅ Auto completion shows branch name alongside duration

## Remaining ideas (genuinely diminishing returns)
- Auto pipeline: per-step timing (analyze: Xs, branch: Xs, etc.) — requires pipeline refactor
- Review: diff statistics summary (lines changed, files in diff) — requires git stat integration
- Status command: show last review/run timestamp from .hal/reports — requires report scanning
- Non-TTY testing: verify no ANSI escapes in piped output — testing infrastructure change
- Review: collapse issue details when >10 issues per iteration — UX polish
