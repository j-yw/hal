## hal sandbox stop

Stop a running sandbox

### Synopsis

Stop a running Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
The sandbox state file is updated to reflect the stopped status.

```
hal sandbox stop [flags]
```

### Examples

```
  hal sandbox stop
  hal sandbox stop --name hal-dev
```

### Options

```
  -h, --help          help for stop
  -n, --name string   sandbox name (defaults to active sandbox from sandbox.json)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage Daytona sandboxes

