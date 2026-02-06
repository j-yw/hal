# Table-Driven Test Structure

Use table-driven tests for any function with 3+ meaningful test cases.

## Standard Structure

```go
func TestFoo(t *testing.T) {
    tests := []struct {
        name      string
        setup     func(t *testing.T, dir string)
        wantErr   string   // substring match; empty means no error expected
        wantOutput string  // substring match on output
        check     func(t *testing.T, dir string)  // post-execution assertions
    }{
        {
            name: "descriptive case name",
            setup: func(t *testing.T, dir string) { /* create state */ },
            check: func(t *testing.T, dir string) { /* verify result */ },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            dir := t.TempDir()
            if tt.setup != nil { tt.setup(t, dir) }
            // ... call function under test ...
            if tt.check != nil { tt.check(t, dir) }
        })
    }
}
```

## Common Fields

| Field | Purpose |
|---|---|
| `name` | Descriptive subtest name |
| `setup` | Creates test preconditions (files, dirs) |
| `wantErr` / `errSubstr` | Expected error substring (empty = no error) |
| `wantOutput` | Expected output substring |
| `check` | Post-execution assertions on filesystem/state |

Field naming is flexible (e.g., `setupFn` vs `setup`) — just be consistent within a file.

## Error Checking Pattern

```go
if tt.wantErr != "" {
    if err == nil {
        t.Fatalf("expected error containing %q, got nil", tt.wantErr)
    }
    if !strings.Contains(err.Error(), tt.wantErr) {
        t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
    }
    return
}
if err != nil {
    t.Fatalf("unexpected error: %v", err)
}
```
