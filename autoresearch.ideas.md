# Autoresearch Deferred Ideas — Hal CLI Output Quality

## Completed ✓
- ~~Doctor colored severity indicators~~ (E1)
- ~~Analyze lipgloss boxes~~ (E4)
- ~~Cleanup styled summary~~ (E6)
- ~~Status styled with visual hierarchy~~ (E2)
- ~~Continue visual separation~~ (E3)
- ~~Repair styled~~ (E9)
- ~~Init styled~~ (E10)
- ~~Archive styled prompt~~ (E11)
- ~~Doctor/Status/Continue titled headers~~ (E12-E14)
- ~~Init gitignore styled~~ (E15)
- ~~Sandbox status/list/start/stop/delete fully styled~~ (E17-E20)

## Future improvements (not in current eval scope)
- **Glamour for analyze description** — The rationale/description fields from analysis could be markdown. Render through glamour like review does for richer output.
- **Boxed layouts for doctor/status/continue** — Wrap entire output in lipgloss HeaderBox/InfoBox for visual consistency with plan/review/validate.
- **Archive FormatList styling** — The list formatting is in `internal/archive/archive.go` FormatList function. Would need to either pass style helpers or move rendering to cmd layer.
- **Progress bar for sandbox batch operations** — sandbox start --count and sandbox stop --all could show a progress bar using the Display system.
- **Color theme awareness** — Detect light/dark terminal and adjust colors. Currently uses hardcoded dark-theme colors.
- **Non-TTY graceful degradation** — Verify all new styled output degrades cleanly when piped (lipgloss should handle this, but untested).
