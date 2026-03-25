# Autoresearch Ideas — Hal CLI Output Quality

## Final: 3 → 43 (+1333%), 28 experiments, 21 files modified

### Completed (8 waves)
1. Style adoption — all commands use lipgloss
2. Titles — doctor/status/continue have StyleTitle headers
3. Deep integration — sandbox, init gitignore, doctor check count
4. Sandbox lifecycle — start/stop/delete/list styled
5. Full coverage — version/links/standards/report/auto/prd/sandbox setup
6. Information density — git branch, Summary, scope, remediation hints, next story
7. Structural — archive list cmd-layer renderer, sandbox prompt styling
8. Rich content — glamour markdown for analyze description/rationale, link count per engine

### Ceiling reached — remaining work is orthogonal
- `run.go`, `validate.go`, `review.go` — only JSON output lines
- `sandbox_ssh.go` — single hint line
- `ux.go` — deprecation warning utility

### Future sessions (different optimization targets)
- **Color theme awareness** — `lipgloss.HasDarkBackground()` adaptive palette (affects styles.go)
- **Non-TTY testing** — automated tests that pipe output and verify no ANSI leaks
- **Progress bars** — sandbox batch ops could use Display system progress (affects display.go)
