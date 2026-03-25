# Autoresearch Ideas — Hal CLI Content Quality

## Completed (5 waves, 3→32, 10 experiments)

### Wave 1: Issue detail propagation (E1-E4)
- ✅ ReviewIssueDetail type with title/severity/file/line/valid/fixed
- ✅ Issues []ReviewIssueDetail slice on ReviewLoopIteration
- ✅ buildIssueDetails merges review findings with fix outcomes

### Wave 2: Review output enrichment (E3-E7)
- ✅ Per-issue table in ReviewLoopMarkdown (severity|file:line|title|fixed)
- ✅ humanizeStopReason maps codes to sentences
- ✅ Duration on ReviewLoopResult and rendered in metadata

### Wave 3: Report/Run enrichment (E8-E14)
- ✅ showReviewResult renders patterns, issues, tech debt
- ✅ Issues/TechDebt on ReviewResult and report JSON
- ✅ showRunSummary with PRD progress

### Wave 4: Timing + depth (E15-E24)
- ✅ Per-iteration timing (Duration on ReviewLoopIteration)
- ✅ FilesAffected on ReviewLoopTotals
- ✅ Severity distribution in totals
- ✅ Rationale on ReviewIssueDetail
- ✅ loop.Result.Duration via named return + defer
- ✅ Run/Auto elapsed time in terminal and JSON

### Wave 5: Completeness (E25-E32)
- ✅ Rationale details section in review markdown
- ✅ Duration in run/auto JSON contracts
- ✅ SuggestedFix on ReviewIssueDetail
- ✅ Total duration in review totals section

## Remaining ideas (diminishing returns)
- Review markdown: render suggestedFix alongside rationale in details section
- Auto pipeline: per-step timing (analyze, branch, prd, explode, loop, pr)
- Review: diff statistics summary (lines changed, files in diff) 
- Status command: show recent review/run activity from .hal/reports
- Non-TTY testing: verify no ANSI escapes in piped output
