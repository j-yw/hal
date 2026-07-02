# Sandbox Runtime v2 Phase 32 Firecracker Backend Foundation Verification

Phase 32 adds a fake-only Firecracker backend foundation for the existing
microVM runtime. The implementation creates a backend-specific package boundary
without making Firecracker part of default command, scheduler, factory, or
sandboxd behavior.

## Implemented Scope

The Firecracker foundation lives in
`internal/sandboxruntime/microvm/firecracker`.

The Firecracker package maps `microvm.Config` into backend-specific config,
plans deterministic target paths, renders Firecracker machine, boot source, and
root drive payloads, and builds sanitized start, stop, inspect, and delete
operation plans.

Configuration, path planning, payload rendering, operation plans, process
descriptors, target metadata, and public errors are redaction-safe. Public JSON
and error strings must omit raw host paths, socket paths, kernel or rootfs
paths, tokens, credentials, raw provider details, and raw backend errors.

The process adapter boundary prepares descriptors through injected fakes by
default; default verification does not start a Firecracker process. Start
planning records process descriptor metadata and payload roles only. Stop,
inspect, and delete planning records safe lifecycle summaries. Exec, copy-in,
and copy-out return sanitized unsupported-operation errors because guest agent
or vsock transport is not implemented in this phase.

`microvm.Driver` can use an injected Firecracker backend, but default production
microVM construction remains backend-neutral and unavailable until an explicit
backend factory is supplied.

## Command Defaults

Command defaults remain explicit-only: run, auto, factory, scheduler, and
sandboxd defaults do not import, construct, register, or launch Firecracker.

Default target resolution must continue to preserve legacy SSH-machine
compatibility when no explicit sandbox runtime or host is selected, even when a
cached worker host advertises microVM capability. Explicit Firecracker backend
construction remains behind injected test or future-phase dependencies.

## Focused Verification Commands

Run backend-neutral microVM contract and guard coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm
```

Run Firecracker backend foundation coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm/firecracker
```

Run command-level microVM, Firecracker, and Phase 32 regression coverage:

```sh
go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase32'
```

These focused commands are fake-only. They cover backend package exports,
backend-neutral microVM import boundaries, Firecracker import boundaries,
config mapping, deterministic path planning, exact payload rendering,
operation-plan summaries, injected process adapter behavior, metadata-only
backend target creation, sanitized lifecycle planning, unsupported exec/copy
operations, default resolver preservation, sandboxd explicit-only behavior,
and documentation guard coverage.

## Broad Verification Commands

Run the full PRD verification stack before integrating Phase 32:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` should run only when `golangci-lint` is installed. If the linter is
unavailable, report it as unavailable instead of treating lint as a required
passing check.

## Fake-Only Scope

Default Phase 32 verification is fake-only and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, or provider/runtime
integration.

Default Phase 32 tests must use pure contracts, deterministic path and payload
rendering, injected fake process adapters, fake command dependencies, parsed
imports, AST source guards, JSON redaction assertions, and temporary stores
only.

Default Phase 32 verification must not use integration build tags, require live
environment variables, start Firecracker, access KVM, require root, bind network
sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman,
contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or
runtime adapters.

## Non-Goals

No live Firecracker VM launch is included in Phase 32.
No Firecracker SDK integration is included in Phase 32.
No KVM access, root requirement, jailer execution, or privileged host setup is
included in Phase 32.
No live API socket listener, guest networking, vsock transport, guest agent,
exec transport, copy transport, or SSH access is included in Phase 32.
No default command, scheduler, factory, or sandboxd path imports, constructs,
registers, or launches Firecracker.
No Docker, Podman, cloud provider, worker daemon, or provider/runtime
integration dependency is introduced by Phase 32 verification.

Future phases are responsible for real Firecracker backend construction,
Firecracker SDK or API-socket integration, VM process launch, KVM or jailer
setup, guest networking, guest agent or vsock transport, file transfer,
interactive exec, root-sensitive host setup, and explicit production command
wiring.

## Review Notes

Keep Firecracker code isolated under
`internal/sandboxruntime/microvm/firecracker`. Backend-neutral microVM code must
not import the Firecracker backend directly, and command defaults must not gain
implicit Firecracker construction.

When Phase 32 test names or focused selectors change, update this document and
`cmd/phase32_firecracker_docs_test.go` together so the documented verification
commands remain executable and fake-only by default.
