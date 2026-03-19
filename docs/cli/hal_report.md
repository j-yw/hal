## hal report

Generate a summary report for completed work

### Synopsis

Generate a summary report for the completed work session.

The report process:
  1. Gathers context (progress log, git diff, commits, PRD)
  2. Analyzes what was built and how
  3. Identifies patterns worth documenting
  4. Updates AGENTS.md with discovered patterns
  5. Generates a report with recommendations

The generated report can be used by 'hal auto' to identify
the next priority item to work on.

Examples:
  hal report                  # Generate report with codex engine (default)
  hal report --engine claude  # Use Claude instead
  hal report --json           # Machine-readable JSON output
  hal report --dry-run        # Preview what would be reported
  hal report --skip-agents    # Skip AGENTS.md update

```
hal report [flags]
```

### Examples

```
  hal report
  hal report --json
  hal report --engine claude
  hal report --dry-run
  hal report --skip-agents
```

### Options

```
      --dry-run         Preview without executing
  -e, --engine string   Engine to use (codex, claude, pi) (default "codex")
  -h, --help            help for report
      --json            Output machine-readable JSON result
      --skip-agents     Skip AGENTS.md update
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

