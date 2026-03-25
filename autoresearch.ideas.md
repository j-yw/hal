# Autoresearch Deferred Ideas — Hal CLI Output Quality

## Session complete — 29/29 evals, score 3→29 (+867%)

All user-facing commands now use lipgloss styling. Remaining work is structural.

## Structural improvements (future sessions)
- **Archive FormatList styling** — list rendering is in `internal/archive/archive.go`, not cmd layer. Would need style injection or move rendering to cmd layer.
- **Glamour for analyze description** — render analysis rationale/description as markdown through glamour for richer output.
- **Non-TTY graceful degradation testing** — verify all styled output degrades cleanly when piped (lipgloss should handle this but untested).
- **Color theme awareness** — detect light/dark terminal via `lipgloss.HasDarkBackground()` and adjust the color palette.
- **Sandbox setup wizard interactive refinement** — the prompts could use lipgloss input styling (highlight defaults, color prompt labels).
