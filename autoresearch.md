# Autoresearch: Hal CLI Output Quality

## Objective

Improve the usefulness, information density, and visual consistency of all `hal` CLI command output. Currently, 7 commands use the lipgloss-based `Display` system with styled boxes and colors, while 6+ commands use raw `fmt.Fprintf` with no styling. Only `review` renders rich markdown via glamour. The goal is to bring ALL commands up to the same quality bar while increasing the actionable information each command provides.

## Metrics
- **Primary**: `output_quality_score` (unitless, higher is better) — sum of binary eval passes across all target commands (max 8)
- **Secondary**: `styled_command_coverage` — % of commands using the Display system, `test_pass` — go test exit code (1=pass, 0=fail)

## How to Run
`./autoresearch.sh` — builds hal, runs tests, scores source for rendering quality, outputs `METRIC` lines.

## Files in Scope

### Rendering infrastructure
- `internal/engine/display.go` — Display struct with ShowCommandHeader, ShowSuccess, ShowError, ShowInfo, etc. Add new helpers here.
- `internal/engine/styles.go` — Color palette, box styles, text styles. Extend for new patterns (e.g. InfoBox, StatusBox).

### Commands to improve (PRIORITY — these use raw fmt.Fprintf today)
- `cmd/doctor.go` — `runDoctorFn()` human-readable branch: unicode icons (✓✗⚠−) but NO color, no box. Needs lipgloss-colored icons.
- `cmd/status.go` — `runStatusFn()` human-readable branch: plain "Workflow:", "Branch:", "Stories:", artifact ✓/✗ list. Needs styled header/sections.
- `cmd/continue.go` — `runContinueFn()` human-readable branch: plain "Workflow:", "Health:", "Next:" labels. Needs visual separation of doctor vs workflow.
- `cmd/analyze.go` — `outputAnalysisText()` uses manual `═══` ASCII art borders. Replace with lipgloss boxes.
- `cmd/cleanup.go` — `runCleanupFn()` plain "Would remove:" / "Removed:" lines. Needs styled summary.

### Commands already styled (REFERENCE — match these patterns)
- `cmd/plan.go` — Uses ShowCommandHeader, ShowCommandSuccess, ShowNextSteps
- `cmd/convert.go` — Uses ShowCommandHeader, ShowCommandSuccess, ShowPhase, ShowCommandError
- `cmd/review.go` — Uses ShowCommandHeader + glamour for markdown result rendering

### Test files (MUST update alongside command changes)
- `cmd/status_test.go` (5 tests), `cmd/continue_test.go` (8 tests), `cmd/doctor_test.go` (7 tests)
- `cmd/analyze_test.go` (6 tests), `cmd/cleanup_test.go` (6 tests)

## Off Limits
- `--json` output paths — machine-readable contracts must NOT change
- `internal/status/`, `internal/doctor/` — pure data packages, no rendering
- `docs/contracts/` — contract documentation
- Cobra command metadata (Use, Short, Long, Example)
- JSON contract test assertions

## Constraints
- `go build ./...` must pass
- `go test ./cmd/...` must pass (update test assertions for new styled output)
- All existing `--json` contracts must remain byte-identical
- Use the existing Display system and lipgloss styles from `internal/engine/` — do NOT add new rendering dependencies
- Keep non-TTY output clean — styled output should degrade gracefully when piped
- Import `engine` styles directly in cmd files (e.g., `engine.StyleSuccess.Render("✓")`)

## What's Been Tried
(Update this section as experiments run)

- Nothing yet — this is a fresh autoresearch session.
