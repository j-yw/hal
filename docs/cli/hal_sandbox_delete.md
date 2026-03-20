## hal sandbox delete

Delete a sandbox permanently

### Synopsis

Permanently delete a sandbox.

By default, reads the sandbox name and provider from .hal/sandbox.json.
Use --name to delete by explicit sandbox name when local state is missing.
After successful deletion, sandbox.json is removed only when it matches the deleted sandbox.

```
hal sandbox delete [flags]
```

### Examples

```
  hal sandbox delete
  hal sandbox delete --name hal-feature-auth
```

### Options

```
  -h, --help          help for delete
  -n, --name string   Delete sandbox by explicit name (without reading .hal/sandbox.json)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

