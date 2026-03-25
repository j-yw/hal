# Autoresearch Deferred Ideas — Hal CLI Output Quality

## Next wave (beyond 8/8 baseline)
- **Archive list styled output** — `cmd/archive.go` `runArchiveListFn()` human-readable branch uses raw fmt.Fprintf. Add lipgloss table headers and styled dates/names.
- **Sandbox list styled headers** — `cmd/sandbox_list.go` uses tabwriter but no lipgloss. Style column headers and status indicators (running=green, stopped=yellow).
- **Doctor boxed output** — Wrap entire doctor output in a HeaderBox or custom InfoBox for visual consistency with plan/review.
- **Status boxed output** — Wrap status in a styled box to match ShowCommandHeader pattern.
- **Continue boxed output** — Use WarningBox for unhealthy state, SuccessBox for healthy.
- **Glamour for analyze description** — The rationale/description fields could be markdown. Render them through glamour like review does.
- **Repair command styling** — `cmd/repair.go` probably uses raw fmt.Fprintf too.
- **Init command success styling** — `cmd/init.go` completion message could use ShowCommandSuccess.
