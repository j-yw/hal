## hal auto

Run the full compound engineering pipeline

### Synopsis

Execute the complete compound engineering automation pipeline.

The pipeline steps are:
  1. analyze  - Find and analyze the latest report to identify priority item
  2. branch   - Create and checkout a new branch for the work
  3. prd      - Generate a PRD using the autospec skill
  4. explode  - Break down the PRD into 8-15 granular tasks
  5. loop     - Execute the Hal task loop until all tasks pass
  6. pr       - Push the branch and create a draft pull request

The pipeline saves state after each step, allowing you to resume
from interruptions using the --resume flag.

Examples:
  hal auto                     # Run full pipeline with latest report
  hal auto --report report.md  # Use specific report file
  hal auto --dry-run           # Show what would happen without executing
  hal auto --resume            # Continue from last saved state
  hal auto --skip-pr           # Skip PR creation at the end
  hal auto --base develop      # Use develop as the base branch
  hal auto --json              # Machine-readable result output

```
hal auto [flags]
```

### Examples

```
  hal auto
  hal auto --json
  hal auto --report .hal/reports/report.md
  hal auto --resume
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
      --skip-pr         Skip PR creation at end
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

