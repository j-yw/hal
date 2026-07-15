## hal sandbox apply

Apply a completed sandbox execution to the current worktree

### Synopsis

Apply durable sync-out artifacts from one completed sandbox execution to
the current host worktree.

This is an apply-only path. It does not resolve, provision, start, materialize,
or execute a sandbox. The execution must have succeeded, its collected
.hal/prd.json must show every story complete, and it must contain an eligible
committed patch or bundle. Its stored host project and workspace branch must
match the current worktree; a commit-valued sync ref must also match host HEAD.
Host mutation still uses the standard clean-worktree, workspace-lock, and Git
dry-run safety checks.

Use the sandboxExecutionId emitted by a prior sandbox run with --json and
--sandbox-sync-out. An execution that already records a successful apply is
rejected to prevent accidental double application. Tracked uncommitted output,
including PRD completion metadata, remains a separate manual-review handoff.

```
hal sandbox apply EXECUTION_ID [flags]
```

### Examples

```
  hal run --sandbox --sandbox-sync-out --json
  hal sandbox apply run-1784128525446734264
```

### Options

```
  -h, --help   help for apply
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
