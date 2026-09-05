## hal sandbox sync-out

Recover sandbox outputs without applying them

### Synopsis

Observe one durable daemon-owned sandbox execution and retry its
requested sync-out finalization.

This command never applies outputs to the host worktree, starts an agent,
cancels a job, or creates a replacement sandbox.

```
hal sandbox sync-out NAME [flags]
```

### Examples

```
  hal sandbox sync-out NAME
  hal sandbox sync-out NAME --run RUN_ID
```

### Options

```
  -h, --help         help for sync-out
      --run string   Select a durable execution by run ID
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
