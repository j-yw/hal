# Sandbox Runtime v2 Phase 33 Firecracker Process Launch Adapter Verification

Phase 33 implements an explicit opt-in Firecracker process launch adapter for
the existing fake-only Firecracker backend foundation. The implementation adds
the testable process boundary needed to start a Firecracker binary only when a
caller explicitly enables live start through injected dependencies.

## Implemented Scope

The Phase 33 launch boundary lives in
`internal/sandboxruntime/microvm/firecracker`.

The adapter converts rendered start-operation descriptors into injected
process-runner requests, passes cancellation through the provided context,
omits host environment delivery, and stores only sanitized process handle
metadata. Process handle IDs and sources are treated as safe labels only after
sanitization.

The default Firecracker backend remains planning-only unless
`BackendOptions.LiveStart` is set with an injected `ProcessAdapter` or
`ProcessLaunchAdapter`. Planning-only start behavior continues to render the
start operation plan and process descriptor without calling the process starter.

Explicit live start attempts may record safe attempted or accepted launch
metadata, but they do not claim guest boot readiness, VM health, networking,
exec/copy availability, credential delivery, or sandbox security enforcement.
Runner failures are wrapped with sanitized errors that omit raw executable
paths, socket paths, config paths, argv fragments, credentials, tokens,
endpoints, stderr, stdout, and process IDs.

## Command Defaults

No default command, scheduler, factory, or sandboxd path launches Firecracker.

Default run, auto, factory, scheduler, sandboxd, and backend construction paths
must remain planning-only or backend-neutral unless a future phase adds an
explicit production registration path. Phase 33 guard tests keep default Hal
paths from importing the Firecracker adapter package, constructing Firecracker
backends, setting `LiveStart: true`, constructing process launch adapters, or
starting a Firecracker process.

## Focused Verification Commands

Run backend-neutral microVM contract and guard coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm
```

Run Firecracker launch metadata, process adapter, backend live-start, redaction,
and package-boundary coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm/firecracker
```

Run command-level microVM, Firecracker, and Phase 33 default-path guard
coverage:

```sh
go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase33'
```

These focused commands are fake-only. They cover backend-neutral microVM import
boundaries, live-operation omission in microVM defaults, process launch metadata
states, sanitized process handle projection, descriptor-to-runner request
construction, cancellation handling, environment rejection, default
planning-only backend starts, explicit live-start adapter calls, sanitized
runner-failure errors, live process code containment inside the explicit
adapter/backend boundary, default command non-wiring, sandboxd non-registration,
and documentation guard coverage.

## Broad Verification Commands

Run the full PRD verification stack before integrating Phase 33:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` should run only when `golangci-lint` is installed. If
`golangci-lint` is unavailable, report lint unavailable instead of reporting
lint as passed.

## Fake-Only Scope

Default Phase 33 verification is fake-only and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, provider/runtime
integration, or a live guest.

Default Phase 33 tests must use pure contracts, deterministic plans, injected
fake process adapters and starters, fake command dependencies, parsed imports,
AST source guards, JSON redaction assertions, and temporary stores only.

Default Phase 33 verification must not use integration build tags, require live
environment variables, start Firecracker by default, access KVM, require root,
bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or
Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live
providers or runtime adapters.

## Non-Goals

Phase 33 does not implement Firecracker SDK integration, API socket machine
configuration calls, boot readiness checks, guest networking, guest agent or
vsock transport, exec/copy support, Docker/Podman inside the guest, credential
delivery, network proxy/firewall enforcement, jailer/root setup, cgroups,
default registration, or default live E2E tests.

No default command, scheduler, factory, or sandboxd path imports, constructs,
registers, or launches Firecracker.

No default backend path starts Firecracker. Live process launch is available
only through explicit backend options and injected fake-safe process adapter
dependencies.

Future phases are responsible for any production Firecracker SDK or API-socket
integration, VM machine configuration, boot readiness checks, guest networking,
guest agent or vsock transport, exec/copy support, guest container engine
support, credential delivery, network proxy/firewall enforcement, jailer/root
setup, cgroup setup, default registration, and live E2E coverage.

## Review Notes

Keep live process launch code isolated under the explicit Firecracker
adapter/backend boundary in
`internal/sandboxruntime/microvm/firecracker`. Backend-neutral microVM code,
command defaults, scheduler paths, factory paths, and sandboxd defaults must
not gain implicit Firecracker process construction or launch behavior.

When Phase 33 test names or focused selectors change, update this document and
`cmd/phase33_firecracker_docs_test.go` together so the documented verification
commands remain executable and fake-only by default.
