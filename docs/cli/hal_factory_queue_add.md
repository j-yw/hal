## hal factory queue add

Add a factory run to the queue

### Synopsis

Add an existing factory run to the durable factory queue.

Provide the run ID to enqueue and the executor mode that the worker should use
when processing it. Use --json for machine-readable output following the
factory-queue-add-v1 contract. Sandbox executor mode requires the run record to
include a base branch.

```
hal factory queue add <run-id> <executor-mode> [flags]
```

### Examples

```
  hal factory queue add run-20260620-001 local
  hal factory queue add run-20260620-001 local --json
  hal factory queue add run-20260620-001 sandbox
```

### Options

```
  -h, --help   help for add
      --json   Output machine-readable JSON (factory-queue-add-v1 contract)
```

### SEE ALSO

* [hal factory queue](hal_factory_queue.md)	 - Manage queued factory work
