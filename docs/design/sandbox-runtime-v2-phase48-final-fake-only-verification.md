# Sandbox Runtime v2 Phase 48 Final Fake-Only Verification

Phase 48 final verification barrier is fake-only. It validates secure-default
readiness, proof projection, target selection, command propagation, runtime
status, contracts, docs, and import boundaries without introducing live
subsystem requirements.

This barrier verifies behavior from US-001 through US-010 after fan-in. It does
not change canonical Hal PRD/progress state and does not require live sandbox
execution.

## Focused Checks

Run the focused fake-only secure-default readiness, proof projection, and pure
readiness import-boundary checks:

```bash
go test -count=1 ./internal/sandbox -run 'Test(SecureDefaultReadiness|ProjectSecureDefaultReadinessInput|SecurityCapability.*(Import|Source))'
```

Run the focused fake-only target-selection and target import-boundary checks:

```bash
go test -count=1 ./internal/sandboxtarget -run 'Test(SelectStrictSecureDefault|SelectCompatibilitySecureDefault|Sandboxtarget.*Import|SchedulerImportBoundary)'
```

Run the focused fake-only factory/run/auto secure-default propagation checks:

```bash
go test -count=1 ./cmd -run 'TestUS007'
```

Run the focused fake-only runtime status, contract, docs, and final barrier
checks:

```bash
go test -count=1 ./cmd -run 'Test(US009SandboxRuntime|US009RuntimeDocs|Phase48Final)'
```

## Broad Checks

```bash
go test ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`go test -count=1 -run '^$' ./...` is the typecheck-only pass. `make
docs-check` is the generated CLI documentation drift check. No intentional
Phase 48 contract drift is expected; if drift is intentional in a later change,
document it in the PR summary.

## Import Boundary

Pure secure-default readiness decisions stay in `internal/sandbox` metadata
logic. The import-boundary tests prove these files do not import concrete
microVM or Firecracker packages, live network/proxy/firewall implementation
packages, credential activation implementation packages, template acquisition
implementation packages, Docker or Podman clients, cloud SDKs, network
packages, `os/exec`, command/factory/worker orchestration packages, or provider
packages.

The source guards also reject live behavior markers such as process execution,
proxy startup, firewall mutation, credential activation or injection, template
acquisition, provider construction, and worker-client construction while
allowing safe enum labels and documentation comments.

## Non-Goals

Verification remains fake-only. It does not require KVM, Firecracker live boot,
real firewall, real proxy, real secret broker, Docker/Podman, cloud, network, or
live E2E setup.

Do not add live Firecracker boot checks, KVM prerequisites, firewall or proxy
mutation, credential broker sessions, credential injection, template pulls,
Docker or Podman workflows, cloud API calls, external network calls, `hal
sandboxd` daemon requirements, live worker daemon requirements, or optional live
build tags to the default Phase 48 barrier.
