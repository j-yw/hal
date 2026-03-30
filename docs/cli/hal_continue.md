## hal continue

Show what to do next

### Synopsis

Show the next recommended action by combining workflow state and health checks.

This command inspects both the workflow state (hal status) and environment
health (hal doctor) to determine the safest next step.

If the environment needs repair, the repair step is shown first.
Otherwise, the workflow-appropriate next action is shown.

When the suggested next command is hal auto, source selection is:
  1. explicit markdown path (when provided to hal auto)
  2. newest .hal/prd-*.md
  3. latest report

With --json, outputs combined status and doctor results.

Examples:
  hal continue          # Human-readable next step
  hal continue --json   # Machine-readable combined status + doctor

```
hal continue [flags]
```

### Examples

```
  hal continue
  hal continue --json
  hal auto              # prefers newest .hal/prd-*.md, then latest report
```

### Options

```
  -h, --help   help for continue
      --json   Output machine-readable JSON
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

