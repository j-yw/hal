# Sandbox Runtime v2 Phase 10 Verification

Phase 10 covers git-bundle workspace materialization for sandbox execution.
Final acceptance requires these commands, without running `hal run`:

```sh
go test -timeout=180s ./internal/sandboxworkspace ./internal/sandboxexec ./cmd ./internal/sandboxexecution ./internal/sandbox ./internal/factory
git diff --check
go test -timeout=300s ./...
```

These checks cover the workspace sync primitives, shared sandbox executor
adapter, run/auto command contracts, sandbox execution manifests, sandbox state,
factory compatibility, whitespace safety, and the full Go package graph.
