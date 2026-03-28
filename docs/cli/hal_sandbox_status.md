## hal sandbox status

Show sandbox status

### Synopsis

Show detailed status of a named sandbox, or list all sandboxes.

When a NAME is provided, queries the provider for live status and displays
all fields: identity, networking, lifecycle, config, and labels.

When no NAME is provided, delegates to 'hal sandbox list' to show all
sandboxes in the global registry.

```
hal sandbox status [NAME] [flags]
```

### Examples

```
  hal sandbox status my-sandbox
  hal sandbox status
```

### Options

```
  -h, --help   help for status
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

