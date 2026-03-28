## hal sandbox delete

Delete one or more sandboxes permanently

### Synopsis

Permanently delete one or more sandboxes.

Targets can be specified as positional arguments, with --all for every sandbox,
or with --pattern to match a glob pattern.

When no arguments or flags are provided, the command auto-resolves:
  - If exactly one sandbox exists, it is selected automatically.
  - If zero sandboxes exist, an error is returned.
  - If multiple exist, an error lists the available choices.

When --all is used without --yes, a confirmation prompt is shown.

Resolved targets are de-duplicated and sorted by name before execution.

```
hal sandbox delete [NAME ...] [flags]
```

### Examples

```
  hal sandbox delete my-sandbox
  hal sandbox delete api-backend frontend
  hal sandbox delete --all --yes
  hal sandbox delete --pattern "worker-*"
```

### Options

```
      --all              Delete all sandboxes
  -h, --help             help for delete
      --pattern string   Delete sandboxes matching a glob pattern
  -y, --yes              Skip confirmation prompt for --all
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

