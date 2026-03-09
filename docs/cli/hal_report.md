## hal report

Run legacy session reporting for completed work

### Synopsis

Run legacy session reporting for the completed work session and generate a summary report.

This command preserves the workflow that previously lived under 'hal review'.

The review process:
  1. Gathers context (progress log, git diff, commits, PRD)
  2. Analyzes what was built and how
  3. Identifies patterns worth documenting
  4. Updates AGENTS.md with discovered patterns
  5. Generates a report with recommendations

The generated report can be used by 'hal auto' to identify
the next priority item to work on.

Examples:
  hal report                  # Review with codex engine (default)
  hal report --engine claude  # Use Claude instead
  hal report --dry-run        # Preview what would be reviewed
  hal report --skip-agents    # Skip AGENTS.md update

```
hal report [flags]
```

### Examples

```
  hal report
  hal report --engine claude
  hal report --dry-run
  hal report --skip-agents
```

### Options

```
      --dry-run         Preview without executing
  -e, --engine string   Engine to use (codex, claude, pi) (default "codex")
  -h, --help            help for report
      --skip-agents     Skip AGENTS.md update
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

