## hal sandbox status

Show sandbox status

### Synopsis

Show the current status of a Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
Fetches live status from the Daytona API and displays Name and Status.
When local sandbox state is used, also displays SnapshotID and CreatedAt.

```
hal sandbox status [flags]
```

### Examples

```
  hal sandbox status
  hal sandbox status --name hal-dev
```

### Options

```
  -h, --help          help for status
  -n, --name string   sandbox name (defaults to active sandbox from sandbox.json)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage Daytona sandboxes

