# Sandbox Runtime v2 Phase 38 Firecracker Guest Transport Verification

Phase 38 adds the explicit Firecracker guest transport delegation boundary.
It lets the Firecracker backend delegate `Exec`, `CopyIn`, and `CopyOut` only
through an injected `GuestTransport` and only after guest readiness metadata is
`ready`.

## Implemented Scope

`internal/sandboxruntime/microvm/firecracker` owns the guest transport
interface and request shapes. `GuestExecRequest` and `GuestCopyRequest` carry
raw command, environment, stream, target, and path data only across the
injected transport boundary, and every field is tagged `json:"-"`.

The Firecracker controller keeps default behavior inert:

- `firecracker.NewBackend(BackendOptions{})` returns unsupported capability
  errors for `Exec`, `CopyIn`, and `CopyOut`.
- `BackendOptions.LiveStart` must be true.
- `BackendOptions.GuestTransport` must be configured.
- target metadata must include guest readiness with state `ready`.

If any of those conditions is missing, the guest transport is not called. When
delegation is allowed, `Exec`, `CopyIn`, and `CopyOut` forward their respective
streaming and path fields to the injected transport. Transport failures return
redaction-safe operation errors while preserving `errors.Is` matching against
the original cause.

`internal/sandboxruntime/microvm/firecrackerhost.NewLiveDriver` exposes
optional guest transport wiring through `LiveDriverOptions.GuestTransport`, but
no default command path constructs or supplies it.

## Non-Goals

Phase 38 does not implement a concrete vsock transport, concrete SSH transport,
guest agent protocol, Firecracker API machine configuration, image/rootfs/kernel
provisioning, Docker or Podman inside the guest, network proxy enforcement,
credential broker/proxy delivery, sandbox templates/kits, production secure
default policy, or default Firecracker runtime selection.

## Verification Commands

Run focused runtime and host transport coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run command-level Firecracker default guard coverage:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Phase3[45678].*Firecracker|MicroVM|GuestReadiness|GuestTransport|LiveDriver'
```

Compile or run optional live-tagged Firecracker coverage:

```sh
go test -tags firecracker_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run the host adapter race check:

```sh
go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/firecrackerhost
```

Run the full repository verification stack:

```sh
go test -count=1 -timeout=420s ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Fake-Safe Default Scope

Default Phase 38 verification is fake-safe and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, provider/runtime
integration, host-specific kernel or rootfs images, a live guest, a guest
agent, vsock, or SSH.

The focused tests use fake guest transports, fake guest readiness metadata,
backend/controller fakes, JSON redaction assertions, import-boundary tests, and
AST default-path guards.
