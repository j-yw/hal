## hal sandbox stop

Power off / shut down one or more running sandboxes

### Synopsis

Power off / shut down one or more running sandboxes.

Targets can be specified as positional arguments, with --all for every running
sandbox, or with --pattern to match a glob pattern.

When no arguments or flags are provided, the command auto-resolves:
  - If exactly one sandbox is running, it is selected automatically.
  - If zero running sandboxes exist, an error is returned.
  - If multiple are running, an error lists the available choices.

Resolved targets are de-duplicated and sorted by name before execution.

Provider billing note: DigitalOcean and Hetzner continue billing while powered off.
Use 'hal sandbox delete' to permanently remove a sandbox and end provider charges.

```
hal sandbox stop [NAME ...] [flags]
```

### Examples

```
  hal sandbox stop my-sandbox
  hal sandbox stop api-backend frontend
  hal sandbox stop --all
  hal sandbox stop --pattern "worker-*"
```

### Options

```
      --all              Power off / shut down all running sandboxes
  -h, --help             help for stop
      --pattern string   Power off / shut down sandboxes matching a glob pattern
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

