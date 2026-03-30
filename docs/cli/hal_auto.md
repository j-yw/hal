## hal auto

Run the single deterministic auto pipeline

### Synopsis

Execute the single deterministic auto pipeline.

Canonical runtime PRD:
- convert writes .hal/prd.json
- validate, run, review, report, ci, and archive consume that runtime state

Pipeline order:
  analyze -> spec -> branch -> convert -> validate -> run -> review -> report -> ci -> archive

Entry behavior:
- hal auto <prd-path>: skips analyze/spec and starts at branch
- --resume ignores positional prd-path and --report

Source selection order (when not resuming):
  1. positional markdown path (hal auto <prd-path>)
  2. explicit report path (hal auto --report <path>)
  3. newest .hal/prd-*.md (auto-discovered)
  4. latest report in auto.reportsDir

Report preflight checks run only when auto does not have a markdown source.

Examples:
  hal auto                           # Prefer newest .hal/prd-*.md, else latest report
  hal auto .hal/prd-feature.md       # Start from a specific markdown PRD
  hal auto --report report.md        # Force report-driven flow (skip markdown auto-discovery)
  hal auto --dry-run                 # Show what would happen without executing
  hal auto --resume                  # Continue from last saved state
  hal auto --skip-ci                 # Skip CI step at end
  hal auto --base develop            # Use develop as the base branch
  hal auto --json                    # Machine-readable result output

```
hal auto [prd-path] [flags]
```

### Examples

```
  hal auto
  hal auto .hal/prd-feature.md --dry-run
  hal auto --json
  hal auto --report .hal/reports/report.md
  hal auto --resume
  hal auto --skip-ci
  hal auto --engine codex --base develop
```

### Options

```
  -b, --base string     Base branch for new work branch and PR target (default: current branch, or HEAD when detached)
      --dry-run         Show steps without executing
  -e, --engine string   Engine to use (claude, codex, pi) (default "codex")
  -h, --help            help for auto
      --json            Output machine-readable JSON result
      --report string   Specific report file (overrides markdown auto-discovery, skips find latest)
      --resume          Continue from last saved state
      --skip-ci         Skip CI step at end
      --skip-pr         [deprecated] Alias for --skip-ci
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

