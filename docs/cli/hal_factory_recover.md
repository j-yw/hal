## hal factory recover

Apply a stored sandbox recovery bundle locally

### Synopsis

Apply the recovery bundle collected from a stored sandbox factory run
to the current local repository. This command does not push a branch or create
a pull request.

```
hal factory recover <run-id> [flags]
```

### Examples

```
  hal factory recover run-20260620-001
  hal factory recover run-20260620-001 --json
```

### Options

```
  -h, --help   help for recover
      --json   Output machine-readable JSON (factory-recover-v1 contract)
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
