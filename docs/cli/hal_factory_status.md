## hal factory status

Inspect a stored factory run

### Synopsis

Inspect one stored factory run from the global factory store.

The default output is a compact table with run metadata and timeline entries.
Use --json for machine-readable output following the factory-status-v1 contract.
JSON output includes the full run record and timeline events in append order.

```
hal factory status <run-id> [flags]
```

### Examples

```
  hal factory status run-20260620-001
  hal factory status run-20260620-001 --json
```

### Options

```
  -h, --help   help for status
      --json   Output machine-readable JSON (factory-status-v1 contract)
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Inspect factory run history

