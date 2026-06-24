## hal factory

Run and inspect factory workflows

### Synopsis

Run local factory workflows and inspect durable factory run history stored
under Hal's global config directory.

Factory run wraps the local auto pipeline while list and status read the global factory store,
which is separate from per-project .hal runtime state.

### Examples

```
  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md --json
  hal factory list
  hal factory list --json
  hal factory status <run-id> --json
```

### Options

```
  -h, --help   help for factory
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
* [hal factory list](hal_factory_list.md)	 - List stored factory runs
* [hal factory run](hal_factory_run.md)	 - Run a factory executor
* [hal factory status](hal_factory_status.md)	 - Inspect a stored factory run

