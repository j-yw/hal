# Migration Pattern

Two kinds of migrations exist: structural (directory renames) and template (content fixes).

## Structural Migrations

For directory or file renames (e.g., `.goralph` → `.hal`):

```go
type migrateResult int
const (
    migrateNone    migrateResult = iota  // no migration needed
    migrateDone                           // migration completed
    migrateWarning                        // ambiguous state (both exist)
)

func migrateConfigDir(oldDir, newDir string, w io.Writer) (migrateResult, error)
```

Rules:
- Extract into a **testable function** that accepts `io.Writer` for output capture
- Use the `migrateResult` enum to signal the outcome
- Check existence of both old and new before acting
- If both exist, warn and continue with the new — never delete automatically

## Template Migrations

For idempotent content fixes in existing files (e.g., renaming a skill reference):

```go
replaceFileContent(path, func(content string) string {
    return strings.ReplaceAll(content, "old-value", "new-value")
})
```

- Run on every `hal init` — must be idempotent
- Use `replaceFileContent` helper: reads, transforms, writes only if changed
- No enum needed — these are fire-and-forget fixes
- Best-effort per file (errors logged, not fatal)

## Legacy File Merging

When consolidating legacy files (e.g., `auto-progress.txt` → `progress.txt`):
- If destination has content, append with `---` separator
- If destination is empty/default, replace entirely
- Delete legacy file after successful merge
