## hal archive restore

Restore an archived feature

### Synopsis

Restore files from an archive directory back into .hal/.

If there is current feature state, it will be auto-archived first.

The name argument is the archive directory name (e.g., 2026-01-15-my-feature).
Use 'hal archive list' to see available archives.

```
hal archive restore <name> [flags]
```

### Examples

```
  hal archive restore 2026-01-15-checkout-flow
```

### Options

```
  -h, --help   help for restore
```

### Options inherited from parent commands

```
  -n, --name string   Archive name (default: derived from branch name)
```

### SEE ALSO

* [hal archive](hal_archive.md)	 - Archive current feature state

