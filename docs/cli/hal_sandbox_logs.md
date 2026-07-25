## hal sandbox logs

Read durable sandbox execution logs

### Synopsis

Read redacted logs for one durable daemon-owned sandbox execution.

The command is observation-only. It never starts, cancels, retries, recovers, or
finalizes a job. When more than one recoverable execution exists, select one
explicitly with --run.

```
hal sandbox logs NAME [flags]
```

### Examples

```
  hal sandbox logs NAME
  hal sandbox logs NAME --run RUN_ID
  hal sandbox logs NAME --follow
```

### Options

```
      --follow       Follow logs until the durable job becomes terminal
  -h, --help         help for logs
      --run string   Select a durable execution by run ID
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
