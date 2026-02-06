# Test Helpers & Isolation

## Filesystem Isolation

Every test that touches the filesystem uses `t.TempDir()`:

```go
func TestFoo(t *testing.T) {
    dir := t.TempDir()  // auto-cleaned up
    // ... test using dir ...
}
```

For CLI tests that use relative paths (e.g., `runInit` uses `.hal`), save and restore the working directory:

```go
origDir, _ := os.Getwd()
t.Cleanup(func() { os.Chdir(origDir) })
os.Chdir(t.TempDir())
```

## Standard Helpers

Each test package defines its own helpers (intentionally duplicated to keep packages independent):

```go
func writePRD(t *testing.T, dir, branchName string) {
    t.Helper()
    // marshal and write prd.json
}

func writeFile(t *testing.T, dir, name, content string) {
    t.Helper()
    // write file with content
}
```

Always call `t.Helper()` so test failures report the caller's line number.

## Permission Testing

To test `os.Rename` failure:

```go
os.Chmod(dir, 0555)  // deny writes
t.Cleanup(func() { os.Chmod(dir, 0755) })  // restore for TempDir cleanup
```

Always probe whether chmod actually prevents writes (some filesystems/users ignore it):

```go
if err := os.WriteFile(probe, data, 0644); err == nil {
    t.Skip("chmod did not prevent writes")
}
```

## Output Capture

- **stdout**: `var buf bytes.Buffer` passed as `io.Writer`
- **stdin**: `strings.NewReader("input\n")` passed as `io.Reader`
- **assertions**: `strings.Contains(buf.String(), "expected")`
