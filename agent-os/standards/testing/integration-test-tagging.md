# Integration Test Tagging

Integration tests require external CLIs (codex, pi) and are excluded from normal `go test`.

## Build Tag

```go
//go:build integration

package codex
```

Run with: `go test -tags=integration ./internal/engine/codex/...`

## Skip Guard

Every integration test must check for the CLI first:

```go
func TestCodexCLIAvailable(t *testing.T) {
    if _, err := exec.LookPath("codex"); err != nil {
        t.Skip("codex CLI not found, skipping integration tests")
    }
}
```

Repeat the `LookPath` check in each test function (not just the first) so tests can run independently.

## Document CLI Quirks

Integration test files are the right place to document CLI-specific quirks. Use a block comment at the top:

```go
// Codex CLI Integration Notes
//
// 1. JSONL Event Format:
//    - Events are: thread.started, item.started, item.completed, turn.completed
//    - No explicit success/failure in turn.completed
//
// 2. Command Wrapping:
//    - All bash commands are wrapped: /usr/bin/bash -lc 'actual command'
```

These notes are discovered during testing and kept alongside the tests that exercise them.

## Live vs Integration Tests

- `integration_test.go` — Tagged, requires CLI, tests actual execution
- `live_test.go` — Also tagged, for exploratory/manual verification (may not be deterministic)
