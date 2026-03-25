# Autoresearch Ideas — Hal CLI Content Quality

## Priority targets (review loop enrichment)
- Store `reviewLoopIssue` details (title/file/severity) in `ReviewLoopIteration.Issues` field
- Store fix outcomes (valid/reason/fixed) alongside each issue detail
- Render issue table in `ReviewLoopMarkdown()` — severity | file:line | title | fixed
- Human-friendly stop reason mapping: `no_valid_issues` → "Stopped: clean review pass (no issues found)"
- Track per-iteration duration in types.go (StartedAt/EndedAt or Duration field)
- Show total elapsed time and average iteration time in review summary

## Secondary targets (report/run/auto enrichment)
- `showReviewResult` in report.go: render patterns list alongside recommendations  
- Report terminal: show issue count and tech debt summary
- Run terminal: show PRD progress bar at completion (N/M stories, percentage)
- Run JSON: add `storiesCompleted` and `storiesRemaining` to per-iteration data
- Auto: show analysis result summary (priority item, branch name) after analyze step

## Structural improvements
- Add `ReviewIssueDetail` type to types.go with both review-phase and fix-phase fields
- Consider `omitempty` on new JSON fields to avoid breaking existing consumers
- Markdown table rendering should gracefully handle long titles (truncate to ~50 chars)
- Non-TTY markdown should still be readable — use simple table format, not lipgloss

## Future (different optimization targets)
- Interactive review: show issues in real-time as iterations complete (streaming)
- Review diff viewer: show code context around each issue inline
- Cross-review trending: track issue patterns across multiple review runs
