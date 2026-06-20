## hal factory

Inspect factory run history

### Synopsis

Inspect durable factory run history stored under Hal's global config directory.

Factory commands read the global factory store, which is separate from per-project
.hal runtime state. Use the list command to inspect stored run summaries.

### Examples

```
  hal factory list
  hal factory list --json
```

### Options

```
  -h, --help   help for factory
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
* [hal factory list](hal_factory_list.md)	 - List stored factory runs

