## hal factory queue work

Claim and process one queued factory run

### Synopsis

Claim and process at most one queued factory run.

Queue work uses the durable factory queue to atomically claim a pending entry
before running it through the local factory executor. Use --json for
machine-readable output following the factory-queue-work-v1 contract, including
the no-work response when no queued entries are available.

```
hal factory queue work [flags]
```

### Examples

```
  hal factory queue work
  hal factory queue work --json
```

### Options

```
  -h, --help   help for work
      --json   Output machine-readable JSON (factory-queue-work-v1 contract)
```

### SEE ALSO

* [hal factory queue](hal_factory_queue.md)	 - Manage queued factory work
