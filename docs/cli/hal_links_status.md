## hal links status

Show link status for all engines

### Synopsis

Show the status of skill links for all registered engines.

Checks that symlinks in engine directories point to the correct .hal/skills/ targets.
Use --engine to filter to a specific engine.

```
hal links status [flags]
```

### Examples

```
  hal links status
  hal links status --json
  hal links status --engine codex
```

### Options

```
  -e, --engine string   Filter to specific engine (claude, pi, codex)
  -h, --help            help for status
      --json            Output machine-readable JSON
```

### SEE ALSO

* [hal links](hal_links.md)	 - Manage engine skill links

