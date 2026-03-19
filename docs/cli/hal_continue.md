## hal continue

Show what to do next

### Synopsis

Show the next recommended action by combining workflow state and health checks.

This command inspects both the workflow state (hal status) and environment
health (hal doctor) to determine the safest next step.

If the environment needs repair, the repair step is shown first.
Otherwise, the workflow-appropriate next action is shown.

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
```

### Options

```
  -h, --help   help for continue
      --json   Output machine-readable JSON
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

