## hal auto

Run the single deterministic auto pipeline

### Synopsis

Execute the single deterministic auto pipeline.

Canonical runtime PRD:
- convert writes .hal/prd.json
- validate, run, review, ci, report, and archive consume that runtime state

Pipeline order:
  analyze -> spec -> branch -> convert -> validate -> run -> review -> ci -> report -> archive

Side effects:
- May create or switch git branches, write .hal/prd.json and .hal/auto-state.json,
  migrate progress state, invoke AI engines, commit changes through run/review,
  generate reports, push/create pull requests during CI, and archive completed state.
- Use --dry-run to preview pipeline steps without executing them.
- Use --no-review or --no-ci to disable the review or CI gates for one run.

Entry behavior:
- hal auto <prd-path>: skips analyze/spec and starts at branch
- --resume ignores positional prd-path and --report

Source selection (when not resuming):
  1. positional markdown path (hal auto <prd-path>)
  2. explicit report path (hal auto --report <path>)
  3. discovery order uses auto.sourcePriority
     - report_first (default): latest report in auto.reportsDir -> newest .hal/prd-*.md
     - markdown_first: newest .hal/prd-*.md -> latest report in auto.reportsDir

Convert mode policy:
  - auto.convertMode=auto (default): markdown entry -> standard, report entry -> granular
  - auto.convertMode=standard|granular overrides entry defaults for new runs
  - --resume always uses saved state convert mode

Agent-safe usage:
- Pass a positional PRD path or --report <path> to avoid source discovery ambiguity.
- Use --resume only when continuing saved state.
- --sandbox currently rejects --resume until sandbox resume state rewriting is implemented.
- Use --json for the auto-v2 machine-readable contract.

Exit status with --json:
- 0 when ok=true
- 2 when validation or preflight fails after emitting ok=false JSON
- 4 when pipeline execution finishes with ok=false
- Sandbox execution preserves the inner hal command's nonzero status

Examples:
  hal auto                           # Uses auto.sourcePriority discovery + auto.convertMode policy
  hal auto .hal/prd-feature.md       # Start from a specific markdown PRD
  hal auto --report report.md        # Force report-driven flow (skip markdown auto-discovery)
  hal auto --mode strict             # Strict gate policy (review+ci, 3 clean review cycles)
  hal auto --mode fast               # Fast policy (skip review and ci)
  hal auto --no-review               # Disable review gate for this run
  hal auto --no-ci                   # Disable CI gate for this run
  hal auto --review-streak 3         # Require 3 consecutive clean review cycles
  hal auto --review-max 15           # Cap review cycles for this run
  hal auto --dry-run                 # Show what would happen without executing
  hal auto --resume                  # Continue from last saved state
  hal auto --json                    # Machine-readable result output
  hal auto --sandbox                 # Run inside a sandbox
  hal auto --sandbox --sandbox-name worker-1 # Run inside a named sandbox
  hal auto --sandbox --sandbox-sync-out # Collect sync-out handoff metadata without host apply
  hal auto --sandbox --sandbox-apply    # Run a new execution, then apply its eligible artifacts
  hal auto --sandbox --sandbox-host worker-1 --sandbox-runtime rootless_podman # Explicit worker/rootless target selection

```
hal auto [prd-path] [flags]
```

### Examples

```
  hal auto
  hal auto .hal/prd-feature.md --dry-run
  hal auto --json
  hal auto --report .hal/reports/report.md
  hal auto --mode strict
  hal auto --no-ci
  hal auto --review-streak 3 --review-max 15
  hal auto --sandbox
  hal auto --sandbox --sandbox-name worker-1
  hal auto --sandbox --sandbox-sync-out
  hal auto --sandbox --sandbox-apply
  hal auto --sandbox --sandbox-host worker-1 --sandbox-runtime rootless_podman
  hal auto --engine codex --base develop
```

### Options

```
  -b, --base string              Base branch for new work branch and PR target (default: current branch, or HEAD when detached)
      --dry-run                  Show steps without executing
  -e, --engine string            Engine to use (claude, codex, pi) (default "codex")
  -h, --help                     help for auto
      --json                     Output machine-readable JSON result
  -m, --mode string              Policy preset: fast, balanced, strict (default from config)
      --no-ci                    Disable CI gate for this run
      --no-review                Disable review gate for this run
      --report string            Specific report file (overrides markdown auto-discovery, skips find latest)
      --resume                   Continue from last saved state
      --review-max int           Maximum review cycles before failing (default from mode/config)
      --review-streak int        Consecutive clean review cycles required (default from mode/config)
      --sandbox                  Run inside a sandbox
      --sandbox-apply            explicit opt-in: run a new sandbox execution, then dry-run and apply its eligible artifacts to the host worktree
      --sandbox-host string      Cached sandbox host ID for target selection
      --sandbox-name string      Sandbox name for --sandbox execution
      --sandbox-runtime string   Cached runtime constraint for target selection (ssh_machine, rootless_podman, microvm)
      --sandbox-sync-out         Collect sandbox sync-out metadata without applying to the host worktree
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
