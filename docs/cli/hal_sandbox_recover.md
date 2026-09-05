## hal sandbox recover

Recover a durable sandbox execution

### Synopsis

Observe and retry finalization for one daemon-owned sandbox execution.

Recovery adopts only the durable job already linked to the selected execution.
It never relaunches the agent command and never cancels the worker job.

```
hal sandbox recover NAME [flags]
```

### Examples

```
  hal sandbox recover NAME
  hal sandbox recover NAME --run RUN_ID
```

### Options

```
  -h, --help         help for recover
      --run string   Select a durable execution by run ID
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
