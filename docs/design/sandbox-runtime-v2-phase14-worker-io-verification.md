# Sandbox Runtime v2 Phase 14 Worker I/O Verification

Phase 14 covers the worker I/O foundation for bounded `exec`, `copy_in`, and
`copy_out` protocol, service, client, adapter, capability, safety, and default
runtime-selection behavior.

Hal story verification uses focused checks:

```sh
go test -timeout=180s ./internal/sandboxworker
go test -timeout=180s ./internal/sandboxworker/...
go test -timeout=180s ./cmd -run 'TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn|TestClientDriverSelectedOnlyWhenExplicitlyConstructed|TestRunSandboxDefaultRuntimeDriverResolver|TestAutoSandboxDefaultRuntimeDriverResolver|TestFactorySandboxDefaultRuntimeDriverResolver'
make build
make vet
```

The full-suite `go test ./...` command is intentionally skipped by the Phase 14 Hal story verification.
Phase 14 story verification is restricted to focused worker I/O tests and must not exercise unrelated runtime providers or command workflows.
Supervisors may run broader pre-merge verification separately.

Verification must not run `hal run`, `hal auto`, factory execution, real runtime adapters, Podman, Docker, KVM, cloud resources, network proxy, credential proxy, templates, or kits.
