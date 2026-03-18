## hal links refresh

Refresh skill links for engines

### Synopsis

Recreate skill links for all engines, or a specific engine.

This is equivalent to the linking step of 'hal init', but without
touching any other .hal/ files.

Examples:
  hal links refresh          # Refresh all engines
  hal links refresh claude   # Refresh only Claude links
  hal links refresh codex    # Refresh only Codex links

```
hal links refresh [engine] [flags]
```

### Examples

```
  hal links refresh
  hal links refresh claude
  hal links refresh codex
```

### Options

```
  -h, --help   help for refresh
```

### SEE ALSO

* [hal links](hal_links.md)	 - Manage engine skill links

