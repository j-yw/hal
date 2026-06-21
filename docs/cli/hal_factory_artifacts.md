## hal factory artifacts

List artifacts for a stored factory run

### Synopsis

List collected artifacts for one stored factory run from the global factory store.

The output includes each artifact's display path, store-backed path when
available, type, warning state, and summary metadata. Use --json for
machine-readable output following the factory-artifacts-v1 contract. JSON
output omits raw source paths and remote URLs from artifact records.

```
hal factory artifacts <run-id> [flags]
```

### Examples

```
  hal factory artifacts run-20260620-001
  hal factory artifacts run-20260620-001 --json
```

### Options

```
  -h, --help   help for artifacts
      --json   Output machine-readable JSON (factory-artifacts-v1 contract)
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
