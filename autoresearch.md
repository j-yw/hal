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

### Wave 1: Basic lipgloss adoption (3→8/8)
- **E1 doctor**: Aliased import as `display` to avoid shadowing local `engine` var. Colored ✓✗⚠− icons + styled summary.
- **E4 analyze**: Replaced `═══` ASCII art with `StyleTitle`/`StyleBold`/`StyleInfo`. No test changes needed.
- **E6 cleanup**: Styled icons per item (✓/○), [OK]/[!] summary badges.
- **E2 status**: Bold labels, colored branch/story/artifact indicators.
- **E3 continue**: 6 distinct styles — visual separation of doctor issues from workflow.

### Wave 2: Extended coverage (8→11/11)
- **E9 repair**: Colored ✓/✗/○ per step, [OK]/[!] summaries.
- **E10 init**: [OK] badge, bold headers, colored file indicators, info-styled commands.
- **E11 archive**: Styled prompt name with bold/muted.

### Wave 3: Extended coverage + deeper integration (11→18/18)
- **E9 repair**: Colored ✓/✗/○ per step, [OK]/[!] summaries.
- **E10 init**: [OK] badge, bold headers, colored file indicators, info-styled commands, styled gitignore messages.
- **E11 archive**: Styled prompt name with bold/muted.
- **E12-E14**: Added styled titles (StyleTitle) to doctor, status, continue for visual consistency.
- **E15**: Init gitignore messages styled with ✓ icons + muted parenthetical (13 total style usages).
- **E16**: Doctor has title + check count integration.
- **E17**: Sandbox status fully styled — colored status/IPs/cost/lifecycle, bold section headers.
- **E18**: Sandbox list table headers bold, status column color-coded.

### Wave 4: Sandbox commands (18→20/20)
- **E19**: Sandbox start/stop/delete styled with [OK] success badges.
- **E20**: Sandbox list summary with colored running/stopped counts, bold total, muted cost.

### Wave 5: Full coverage (22→29/29)
- **E23 version**: StyleTitle for "hal", StyleAccent for HAL quote, muted build info.
- **E24 links**: Colored ✓✗⚠ icons, bold engine names, [OK] refresh/clean badges.
- **E25 standards**: Styled titles, warnings, info-styled commands, muted hints.
- **E26 report**: Bold summary label, info-styled numbered recommendations.
- **E27 sandbox setup**: 8 section headers replaced from `── X ──` ASCII to lipgloss Bold/Title.
- **E28 auto**: Styled no-reports warning with [!] badge and info-styled path.
- **E29 prd**: Colored ✓/✗ for file presence, info-styled branch, success-styled counts, [OK] badge.

### Wave 6: Information density (29→38)
- **E30**: Status now displays the `Summary` field from StatusResult.
- **E31**: Continue already showed engine (passed at baseline).
- **E32**: Doctor shows `[scope]` suffix (repo/engine_local/etc.) on failed/warned checks.
- **E33**: Status shows current git branch via `compound.CurrentBranchOptional()`.
- **E34**: Continue shows engine name in the healthy workflow path.
- **E35**: Doctor shows per-check remediation hints (`fix: hal init`) under failed checks.
- **E36**: Continue shows summary text at the bottom.
- **E37**: Continue shows next story ID + title in manual workflow path.
- **E38**: Continue shows branch name in manual workflow, colored story completion.

### Wave 7: Structural improvements (38→41)
- **E39**: Archive list moved from `internal/archive.FormatList` to cmd-layer `formatArchiveListStyled` with bold headers, info-styled names, muted dates/paths, and archive count footer.
- **E40**: Sandbox `promptField` function styled with bold labels and muted default hints.
- **E41**: Sandbox setup saved confirmation uses `[OK]` badge with muted config path.

### Wave 8: Richer content rendering (41→43)
- **E42**: Analyze renders `Description` and `Rationale` through glamour markdown renderer (same as review uses). Falls back to plain text on error.
- **E43**: Links status shows per-engine link count (`· N links`) alongside the engine name.

### Key patterns discovered
- Use aliased import (`display`, `ui`) when local `engine` variable exists
- `archive.go` can use `engine.Style*` directly since only `engine.PRD` conflicts
- `strings.Contains` tests survive lipgloss wrapping — ANSI escapes don't break substring matching
- Always check test assertions before changing field label text — tests check exact substrings like "Name:       my-sandbox"
- Keep field labels intact, only style the values
- `autoresearch.sh` gets overwritten by revert cycles from prior sessions — must rewrite after each keep
