## hal sandbox delete

Delete a sandbox permanently

### Synopsis

Permanently delete a Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
After successful deletion, sandbox.json is removed if it matches the deleted sandbox.

```
hal sandbox delete [flags]
```

### Examples

```
  hal sandbox delete
  hal sandbox delete --name hal-dev
```

### Options

```
  -h, --help          help for delete
  -n, --name string   sandbox name (defaults to active sandbox from sandbox.json)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage Daytona sandboxes

