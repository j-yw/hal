## hal review

Run an iterative review loop against a base branch

### Synopsis

Run an iterative review-and-fix loop against a base branch.

This command powers branch-vs-branch review loops.
Use 'hal report' for legacy session reporting.

```
hal review --base <base-branch> [iterations] [flags]
```

### Examples

```
  hal review --base develop
  hal review --base develop --json
  hal review --base origin/main 5
  hal review --base develop --iterations 3 -e codex
  hal review against develop 3   # Deprecated alias
```

### Options

```
      --base string      Base branch to review against
  -e, --engine string    Engine to use (claude, codex, pi) (default "codex")
  -h, --help             help for review
  -i, --iterations int   Maximum review iterations (default 10)
      --json             Output machine-readable JSON result (skip terminal rendering)
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

