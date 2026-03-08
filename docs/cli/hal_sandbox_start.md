## hal sandbox start

Create and start a sandbox

### Synopsis

Create and start a Daytona sandbox.

The sandbox name defaults to the current git branch (with slashes replaced by hyphens).
Use --name to override the default name.

hal always starts from the template snapshot "hal".
If "hal" does not exist, it is created from sandbox/Dockerfile with context ".".

```
hal sandbox start [flags]
```

### Examples

```
  hal sandbox start
  hal sandbox start --name hal-dev
```

### Options

```
  -h, --help          help for start
  -n, --name string   sandbox name (defaults to current git branch)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage Daytona sandboxes

