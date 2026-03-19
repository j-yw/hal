## hal repair

Auto-fix environment issues detected by doctor

### Synopsis

Automatically fix environment issues detected by hal doctor.

Only applies safe remediations:
  - hal init (for missing .hal/ files, skills, commands)
  - hal cleanup (for legacy debris)
  - hal links refresh (for stale engine links)

Use --dry-run to preview what would be fixed.
Use --json for machine-readable output.

Examples:
  hal repair            # Fix all safe issues
  hal repair --dry-run  # Preview fixes
  hal repair --json     # Machine-readable result

```
hal repair [flags]
```

### Examples

```
  hal repair
  hal repair --dry-run
  hal repair --json
```

### Options

```
      --dry-run   Preview repairs without applying
  -h, --help      help for repair
      --json      Output machine-readable JSON result
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

