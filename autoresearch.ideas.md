# Autoresearch Ideas — Hal CLI Output Quality

## Session summary: 3 → 41 (+1267%), 26 experiments, 24 files modified

### What was done (7 waves)
1. **Style adoption** — All commands now import and use lipgloss styles from `internal/engine/`
2. **Titles** — doctor, status, continue have StyleTitle headers
3. **Information density** — status shows git branch + Summary, doctor shows scope + per-check remediation, continue shows engine + next story + branch + summary
4. **Structural** — archive list moved from internal FormatList to cmd-layer styled renderer, sandbox setup wizard prompts styled with bold labels + muted defaults

### Remaining (diminishing returns)
- `run.go`, `validate.go`, `review.go` — only JSON output lines, no user-facing text to style
- `sandbox_ssh.go` — single hint line
- `ux.go` — deprecation warning (used by many commands)

### Future directions (beyond this session's scope)
- **Glamour for analyze description** — render analysis fields as markdown for richer formatting
- **Color theme awareness** — `lipgloss.HasDarkBackground()` adaptive palette
- **Non-TTY testing** — automated tests that verify piped output is clean
- **Progress bars** — sandbox batch start/stop could use Display system progress bars
