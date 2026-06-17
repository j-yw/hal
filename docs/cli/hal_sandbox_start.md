## hal sandbox start

Start stopped sandboxes

### Synopsis

Start one or more stopped sandboxes.

Targets can be specified as positional arguments, with --all for every stopped
sandbox, or with --pattern to match a glob pattern.

When no arguments or flags are provided, the command auto-resolves:
  - If exactly one sandbox is stopped, it is selected automatically.
  - If zero stopped sandboxes exist, an error tells you to create one.
  - If multiple are stopped, an error lists the available choices.

Explicit names are loaded from the registry regardless of cached lifecycle
status, so stale registry state can be corrected by the provider's idempotent
start operation. Resolved targets are de-duplicated and sorted by name before
execution.

```
hal sandbox start [NAME ...] [flags]
```

### Examples

```
  hal sandbox start my-sandbox
  hal sandbox start api-backend frontend
  hal sandbox start --all
  hal sandbox start --pattern "worker-*"
```

### Options

```
      --all              Start all stopped sandboxes
  -h, --help             help for start
      --pattern string   Start sandboxes matching a glob pattern
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

