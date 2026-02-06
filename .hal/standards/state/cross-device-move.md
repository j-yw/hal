# Cross-Device Move Fallback

Use `moveFile` and `moveDir` from `internal/archive/move.go` instead of raw `os.Rename` for any file/directory moves.

## Why

`os.Rename` fails with `EXDEV` when source and destination are on different filesystems. This happens in Docker volumes, tmpfs, CI environments, and unusual disk layouts. Without the fallback, the tool breaks silently.

## Pattern

```go
// moveFile: rename → copy+remove fallback
err := os.Rename(src, dst)
if isEXDEV(err) {
    // copy file contents, preserve permissions, remove source
}

// moveDir: rename → walk+copy+remove fallback
err := os.Rename(src, dst)
if isEXDEV(err) {
    // walk tree, copy each file, preserve dir permissions, remove source tree
}
```

## Rules

- Only falls back on `syscall.EXDEV` — other errors propagate immediately
- Cleans up partial copies on failure
- Preserves file permissions during copy
- Use these helpers for all archive and state file moves
