## hal cleanup

Remove orphaned and deprecated files

### Synopsis

Remove orphaned and deprecated files from .hal/ and engine link directories.

This command removes:
  - .hal/auto-progress.txt (replaced by unified progress.txt)
  - .hal/rules/ directory (replaced by standards/)
  - .claude/skills/ralph (deprecated alias)
  - .pi/skills/ralph (deprecated alias)

Use --dry-run to preview what would be removed without making changes.

This command is idempotent and safe to run multiple times.

```
hal cleanup [flags]
```

### Examples

```
  hal cleanup --dry-run
  hal cleanup
  hal cleanup --json
```

### Options

```
      --dry-run   Preview changes without removing files
  -h, --help      help for cleanup
      --json      Output machine-readable JSON result
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

