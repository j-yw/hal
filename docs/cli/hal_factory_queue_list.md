## hal factory queue list

List factory queue entries

### Synopsis

List durable factory queue entries from the global factory store.

Use --json for machine-readable output following the factory-queue-list-v1
contract. JSON output is intended for automation that needs deterministic queue
ordering and inspectable queued, claimed, and failed entries.

```
hal factory queue list [flags]
```

### Examples

```
  hal factory queue list
  hal factory queue list --json
```

### Options

```
  -h, --help   help for list
      --json   Output machine-readable JSON (factory-queue-list-v1 contract)
```

### SEE ALSO

* [hal factory queue](hal_factory_queue.md)	 - Manage queued factory work

