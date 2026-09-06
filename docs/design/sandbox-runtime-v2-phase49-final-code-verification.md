# Sandbox Runtime v2 Phase 49 Final Code Verification

Phase 49 final code verification barrier checks implemented code, tests, and
runtime behavior only. It closes the diagnostics and E2E hardening phase with a
fake-only default matrix over secure-default diagnostics, runtime status,
workflow status, run/auto/factory propagation, redaction evidence, live-provider
gate guards, touched package suites, repository-wide tests, typecheck, vet, and
conditional lint.

This barrier verifies behavior from US-001 through US-009 after fan-in. It does
not require validating, auditing, regenerating, or reconverting the PRD after
implementation, and it does not change canonical Hal PRD or progress state.

## Focused Checks

Run the focused secure-default diagnostic summary checks:

```bash
go test -count=1 ./internal/sandbox -run 'TestUS001SecureDefaultDiagnosticSummariesExposeSafeReadinessDecisions'
```

Run the focused Phase 49 command-surface checks for runtime status, workflow
status, run/auto propagation, factory propagation, fake-only E2E, redaction
evidence, live-provider gates, and this final barrier:

```bash
go test -count=1 ./cmd -run 'Test(US00[2-9]|RunStatusFn_(JSONDecodesWorkflowStates|DoesNotExposeSandboxSecretsOrProviderConfig)|Phase49)'
```

## Touched Package Suites

Run the relevant package test suites for packages touched by Phase 49:

```bash
go test -count=1 ./cmd ./internal/compound ./internal/factory ./internal/sandbox ./internal/status
```

## Repository Checks

Run the default repository test suite:

```bash
go test ./...
```

Run repository typecheck by compiling tests without running test bodies:

```bash
go test -count=1 -run '^$' ./...
```

`go test -count=1 -run '^$' ./...` is the typecheck-only pass.

Run vet:

```bash
go vet ./...
```

Run lint only when `golangci-lint` is installed:

```bash
golangci-lint run ./...
```

`golangci-lint run ./...` is conditional. If `golangci-lint` is unavailable,
report `golangci-lint unavailable` in the verification evidence instead of
claiming lint success.

## Non-Goals

The final Phase 49 barrier does not run PRD validation, PRD audit, PRD
conversion, PRD regeneration, report ingestion, or Hal workflow commands. Do
not add `hal validate`, `hal convert`, `hal plan`, `hal auto`, `hal run`,
`hal report`, live-provider build tags, integration build tags, worker daemon setup,
provider API calls, network access, Docker, Podman, Firecracker, KVM, or live
credential prerequisites to the default final code verification matrix.
