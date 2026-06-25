## hal factory logs

Inspect stored factory run logs

### Synopsis

Inspect stored stdout, stderr, or summarized output chunks for one
factory run from the global factory store.

The default output is ordered human-readable log text with stream and source
metadata. Use --json for machine-readable output following the factory-logs-v1
contract. Log text is sanitized before display.

```
hal factory logs <run-id> [flags]
```

### Examples

```
  hal factory logs run-20260620-001
  hal factory logs run-20260620-001 --json
```

### Options

```
  -h, --help   help for logs
      --json   Output machine-readable JSON (factory-logs-v1 contract)
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
