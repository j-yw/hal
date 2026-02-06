# Testable Function Extraction

Extract testable logic out of Cobra `RunE` handlers into standalone functions.

## Pattern

```go
// Cobra handler — thin wrapper
var archiveCmd = &cobra.Command{
    RunE: func(cmd *cobra.Command, args []string) error {
        return runArchiveCreate(halDir, nameFlag, os.Stdin, os.Stdout)
    },
}

// Testable function — accepts io.Reader/io.Writer
func runArchiveCreate(halDir, name string, in io.Reader, out io.Writer) error {
    // all logic here
}
```

## Naming

Use `run<Command>` (e.g., `runInit`, `runArchiveCreate`, `runArchiveListFn`). Prefer `run<Command>` without the `Fn` suffix.

## What to Accept

| Parameter | Why |
|---|---|
| `io.Writer` (out) | Capture output in `bytes.Buffer` instead of os.Stdout |
| `io.Reader` (in) | Simulate stdin with `strings.NewReader` |
| `halDir string` | Pass temp directory instead of real `.hal/` |

## Testing the Extracted Function

```go
func TestRunArchiveCreate(t *testing.T) {
    tmpDir := t.TempDir()
    halDir := filepath.Join(tmpDir, ".hal")
    os.MkdirAll(halDir, 0755)

    in := strings.NewReader("\n")  // simulate Enter key
    var out bytes.Buffer

    err := runArchiveCreate(halDir, "my-feature", in, &out)
    // assert on err, out.String(), filesystem state
}
```

## When to Extract

Extract when the Cobra handler does more than wire flags to a library call. If the handler just calls a package function, no extraction needed.
