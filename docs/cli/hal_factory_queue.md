## hal factory queue

Manage queued factory work

### Synopsis

Manage queued factory work stored in the global factory queue.

Queue commands enqueue existing factory runs, list durable queue entries, and
claim one queued run for bounded local worker processing. Queue state is stored
in the global factory store so pending work survives CLI exits and restarts.

### Examples

```
  hal factory queue add run-20260620-001 local
  hal factory queue list --json
  hal factory queue work --json
```

### Options

```
  -h, --help   help for queue
```

### SEE ALSO

* [hal factory](hal_factory.md)	 - Run and inspect factory workflows
* [hal factory queue add](hal_factory_queue_add.md)	 - Add a factory run to the queue
* [hal factory queue list](hal_factory_queue_list.md)	 - List factory queue entries
* [hal factory queue work](hal_factory_queue_work.md)	 - Claim and process one queued factory run

