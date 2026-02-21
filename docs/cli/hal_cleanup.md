## hal cleanup

Remove orphaned files from .hal/

### Synopsis

Remove orphaned files from .hal/ that are no longer used.

This command removes:
  - auto-progress.txt (replaced by unified progress.txt)

Use --dry-run to preview what would be removed without making changes.

This command is idempotent and safe to run multiple times.

```
hal cleanup [flags]
```

### Examples

```
  hal cleanup --dry-run
  hal cleanup
```

### Options

```
      --dry-run   Preview changes without removing files
  -h, --help      help for cleanup
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

