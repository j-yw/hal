## hal sandbox shell

Open an interactive shell in a sandbox

### Synopsis

Open an interactive shell session in a running Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
The sandbox must be in the running (started) state.

```
hal sandbox shell [flags]
```

### Examples

```
  hal sandbox shell
  hal sandbox shell --name hal-dev
```

### Options

```
  -h, --help          help for shell
  -n, --name string   sandbox name (defaults to active sandbox from sandbox.json)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage Daytona sandboxes

