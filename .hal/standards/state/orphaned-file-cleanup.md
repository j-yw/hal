# Orphaned File Cleanup

When deprecating state files, migrate content first, then register for cleanup.

## Deprecation Workflow

1. **Write migration logic** — Merge content into the replacement file (see `MigrateAutoProgress()` pattern)
2. **Add to `orphanedFiles`** in `cmd/cleanup.go` — Cleanup only handles final deletion
3. **`hal cleanup`** removes the orphaned files; `--dry-run` previews without deleting

## Current Orphaned Files

```go
var orphanedFiles = []string{
    "auto-progress.txt",  // Replaced by unified progress.txt
}
```

## Rules

- Cleanup is idempotent — safe to run multiple times
- Skips directories (only removes files)
- Skips non-existent files silently
- Always provide `--dry-run` for safe preview
- Never add a file to `orphanedFiles` without first migrating its content elsewhere
