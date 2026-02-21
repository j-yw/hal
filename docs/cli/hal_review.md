## hal review

Run an iterative review loop against a base branch

### Synopsis

Run an iterative review-and-fix loop against a base branch.

This command powers branch-vs-branch review loops.
Use 'hal report' for legacy session reporting.

```
hal review against <base-branch> [iterations] [flags]
```

### Examples

```
  hal review against develop
  hal review against origin/main 5
  hal review against develop 3 -e codex
  hal review -e pi against develop 3
  hal review -e claude against develop 3
```

### Options

```
  -e, --engine string   Engine to use (claude, codex, pi) (default "codex")
  -h, --help            help for review
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

