## hal sandbox exec

Execute a command in a sandbox

### Synopsis

Execute a non-interactive command in a running Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name/-n is specified.
The sandbox must be in the running (started) state.

Use '--' when the remote command starts with flags, for example:
  hal sandbox exec -- -n foo

stdout and stderr from the remote command are streamed to the local terminal.
The exit code from the remote command is propagated as the local exit code.

```
hal sandbox exec [-n NAME] [--] <command...> [flags]
```

### Examples

```
  hal sandbox exec -- pwd
  hal sandbox exec --name hal-dev -- go test ./...
```

### Options

```
  -h, --help          help for exec
  -n, --name string   sandbox name (defaults to active sandbox from sandbox.json)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage Daytona sandboxes

