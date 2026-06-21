## hal factory list

List stored factory runs

### Synopsis

List stored factory runs from the global factory store.

The default output is a compact table of run IDs, statuses, branches, steps,
and update timestamps. Use --json for machine-readable output following the
factory-list-v1 contract. JSON output includes run summaries only; event
timelines are intentionally omitted from the list surface.

```
hal factory list [flags]
```

### Examples

```
  hal factory list
  hal factory list --json
```

### Options

```
  -h, --help   help for list
      --json   Output machine-readable JSON (factory-list-v1 contract)
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
