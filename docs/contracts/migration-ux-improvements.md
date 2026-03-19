# Migration: UX & Machine Readability Improvements

## Summary

This release adds operational coherence to Hal through new commands and machine-readable output across the entire CLI.

## New Commands

### `hal status [--json]`
Shows workflow state. Replaces guessing by inspecting `.hal/` artifacts.

```bash
hal status         # Human-readable
hal status --json  # Machine-readable (see docs/contracts/status-v1.md)
```

### `hal doctor [--json]`
Checks environment health. Engine-aware — skips Codex checks for Pi/Claude.

```bash
hal doctor         # Human-readable with check marks
hal doctor --json  # Machine-readable (see docs/contracts/doctor-v1.md)
```

### `hal continue [--json]`
One-command answer to "what should I do now?" Combines status + doctor.

```bash
hal continue       # Shows next action (or blocker if unhealthy)
hal continue --json
```

### `hal repair [--dry-run] [--json]`
Auto-fixes safe issues detected by doctor.

```bash
hal repair --dry-run  # Preview
hal repair            # Apply fixes
```

### `hal links status [--json]` / `hal links refresh [engine]` / `hal links clean`
Manage engine skill links separately from init.

```bash
hal links status          # Inspect link health
hal links refresh codex   # Refresh only Codex links
hal links clean           # Remove deprecated/broken links
```

## `--json` Flag on All Commands

Every core command now supports `--json` for machine-readable output:

| Command | JSON Result Type |
|---------|-----------------|
| `hal init --json` | `{ok, created, skipped, summary}` |
| `hal run --json` | `{ok, iterations, complete, prd, nextAction, summary}` |
| `hal report --json` | `{ok, reportPath, patternsAdded, recommendations, nextAction}` |
| `hal auto --json` | `{ok, resumed, nextAction, error, summary}` |
| `hal validate --json` | `{valid, errors, warnings}` |
| `hal convert --json` | `{ok, outputPath, valid, summary}` |
| `hal cleanup --json` | `{ok, removed, dryRun, summary}` |
| `hal analyze --json` | Analysis result (shorthand for `--format json`) |
| `hal review --json` | `ReviewLoopResult` directly |
| `hal archive list --json` | `{contractVersion, ok, archives, error, summary}` |
| `hal version --json` | `{version, commit, buildDate, go, os, arch}` |

## UX Changes

- **`hal report`**: No longer labeled "legacy" — now "Generate summary report"
- **`hal init`**: Help text explicitly separates repo-local, engine-local, and global side effects
- **`hal init` next steps**: Now includes `hal doctor` as first recommended step
- **`hal cleanup`**: Expanded to remove deprecated engine links (`.claude/skills/ralph`, `.pi/skills/ralph`)

## Test Isolation

The Codex linker now respects `$HOME` environment variable. Tests that call `hal init` use `t.Setenv("HOME", tmpDir)` to prevent test pollution of real `~/.codex/` directory.

## Breaking Changes

None. All additions are backward-compatible:
- New commands don't affect existing workflows
- `--json` flags are opt-in
- Status/doctor fields use `omitempty` for optional detail
