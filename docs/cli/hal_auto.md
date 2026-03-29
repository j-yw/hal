## hal auto

Run the single deterministic auto pipeline

### Synopsis

Execute the single deterministic auto pipeline.

Runtime PRD source:
- convert writes canonical .hal/prd.json.
- validate, run, review, report, and ci/archive gates consume that runtime PRD/state.

The pipeline steps are:
  1. analyze  - Find and analyze the latest report to identify priority item
  2. spec     - Generate a markdown PRD using the autospec skill
  3. branch   - Create or checkout the target branch
  4. convert  - Convert markdown PRD to canonical .hal/prd.json (granular tasks)
  5. validate - Validate .hal/prd.json with bounded repair attempts
  6. run      - Execute the Hal task loop until all tasks pass
  7. review   - Run iterative review/fix verification
  8. report   - Generate and persist a report artifact
  9. ci       - Push branch and create a draft pull request (unless --skip-ci)
 10. archive  - Archive feature state while preserving the latest report

If a positional markdown path is provided, auto skips analyze/spec,
uses that file as sourceMarkdown, and starts from the branch step.

The pipeline saves state after each step, allowing you to resume
from interruptions using the --resume flag.
When --resume is set, positional prd-path and --report are ignored.

Examples:
  hal auto                           # Run full pipeline with latest report
  hal auto .hal/prd-feature.md       # Start from a specific markdown PRD
  hal auto --report report.md        # Use specific report file
  hal auto --dry-run                 # Show what would happen without executing
  hal auto --resume                  # Continue from last saved state
  hal auto --skip-ci                 # Skip CI + archive steps
  hal auto --skip-pr                 # Deprecated alias for --skip-ci
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
      --report string   Specific report file (skips find latest)
      --resume          Continue from last saved state
      --skip-ci         Skip CI step at end
      --skip-pr         [deprecated] Alias for --skip-ci
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

