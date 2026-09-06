# Sandbox Runtime v2 Phase 36 Firecracker Explicit Live Driver Verification

Phase 36 exposes the live Firecracker driver only as an explicit construction
API for future worker or runtime configuration. It does not enable live
Firecracker by default.

## Implemented Scope

The Phase 36 construction API lives in
`internal/sandboxruntime/microvm/firecrackerhost`.

`firecrackerhost.LiveDriverOptions`, `firecrackerhost.NewLiveDriver`, and
`firecrackerhost.NewLiveBackendOptions` are the only Phase 36 live-driver entry
points. They validate the existing microVM config, validate a caller-provided
base state directory, require an explicit boot acceptance poller, and compose a
Firecracker backend with `BackendOptions.LiveStart: true`,
`firecracker.ProcessLaunchAdapter{Starter: adapter}`, a boot acceptance waiter,
and a live process manager.

This API is for future worker or runtime configuration that explicitly chooses
Firecracker live start. It is not a registration hook, command default, worker
routing default, scheduler default, or sandbox daemon default. If a caller does
not call `NewLiveDriver` or `NewLiveBackendOptions`, Phase 36 does not construct
the host adapter or host process runner.

The explicit constructor may create `firecrackerhost.NewOSExecProcessRunner`
inside the `firecrackerhost` package when the caller does not inject a fake or
custom host process runner. That remains inside the explicit API boundary.
Default command, factory, sandboxexec, worker, scheduler, sandboxd, and
backend-neutral microVM paths must not import `firecrackerhost`, construct
`LiveDriverOptions`, call `NewLiveDriver`, call `NewLiveBackendOptions`, or
select the explicit live driver by literal.

Successful fake-backed starts record only host-side process-launch metadata
after the injected boot acceptance poller reports host process acceptance and
API socket availability. This is a host API socket acceptance signal only. It
is not a guest readiness, guest health, networking, exec/copy, credential, or
security-enforcement claim.

## Default Command Wiring

Default `hal run`, `hal auto`, `hal factory run`, `sandboxexec`, worker
routing, scheduler selection, and `hal sandboxd` do not enable live
Firecracker.

Default microVM and Firecracker backend construction remains planning-only
unless a future caller explicitly injects the Phase 36 construction API.
Default `firecracker.NewBackend(BackendOptions{})`, backends without
`LiveStart: true`, and backends with injected adapters but without
`LiveStart: true` must continue to render plans without launching a Firecracker
process.

Phase 36 guard tests keep default CLI, factory, sandboxexec, worker, scheduler,
and sandboxd paths from importing the explicit live-driver package or
constructing `LiveDriverOptions`, `NewLiveDriver`, or `NewLiveBackendOptions`.

## Default Verification Commands

Run backend-neutral microVM, Firecracker backend, and explicit host live-driver
package coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run command-level Phase 34, Phase 35, Phase 36, and microVM documentation and
default-path guard coverage:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Phase3[456].*Firecracker|MicroVM'
```

Run the full repository verification stack before integrating Phase 36:

```sh
go test -count=1 -timeout=420s ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` should run only when `golangci-lint` is installed. If
`golangci-lint` is unavailable, report lint unavailable instead of reporting
lint as passed.

These default commands cover default constructor non-selection, planning-only
Firecracker backend behavior, explicit backend-option composition, fake host
runner starts, host API socket acceptance polling, boot-acceptance failure
cleanup, honest runtime metadata, live-started stop/delete delegation through
the injected process manager, default command non-wiring, documentation guard
coverage, and fake-safe package boundaries.

## Fake-Safe Default Scope

Default Phase 36 verification is fake-safe and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, provider/runtime
integration, host-specific kernel or rootfs images, or a live guest.

Default Phase 36 tests use pure contracts, injected fake host process runners,
injected fake boot acceptance pollers, injected fake cleanup filesystems, fake
command dependencies, parsed imports, AST source guards, JSON redaction
assertions, temporary stores, and temporary state directories only.

Default Phase 36 verification must not use integration build tags, the
`firecracker_live` build tag, require live environment variables, start a real
Firecracker process, access KVM, require root, bind network sockets, start
worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs,
invoke Firecracker SDKs, or depend on live providers or runtime adapters.

## Optional Live Tests

Phase 36 keeps optional live integration coverage behind the
`firecracker_live` build tag. It is not part of default verification. The
tagged command compiles optional live tests and should skip with redacted
messages when required live prerequisites are absent, so the tests compile or
skip under `firecracker_live` without requiring live Firecracker execution.

Run the optional live command only on a prepared Linux host:

```sh
go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Shared live-test prerequisites:

- Linux host with `/dev/kvm` present and read/write accessible to the test
  process for backend live boot coverage.
- `HAL_FIRECRACKER_LIVE_FIRECRACKER`: executable regular file for the
  Firecracker binary.

Backend live boot prerequisites:

- `HAL_FIRECRACKER_LIVE_KERNEL`: readable regular file for the kernel image.
- `HAL_FIRECRACKER_LIVE_ROOTFS`: read/write regular file for the rootfs image.
- `HAL_FIRECRACKER_LIVE_INITRD`: optional readable regular file for an initrd
  image.
- `HAL_FIRECRACKER_LIVE_TIMEOUT`: optional positive Go duration for host-side
  API socket acceptance, defaulting to `10s`.
- `HAL_FIRECRACKER_LIVE_CPU_COUNT`: optional integer greater than or equal to
  `1`, defaulting to `1`.
- `HAL_FIRECRACKER_LIVE_MEMORY_MIB`: optional integer greater than or equal to
  `1`, defaulting to `256`.

Host runner live-test prerequisites:

- `HAL_FIRECRACKER_LIVE=1`: explicit opt-in for the host adapter live-runner
  test.

The optional live command starts real Firecracker processes only inside tagged
tests when every prerequisite is present. It does not wire the explicit live
driver into default `hal run`, `hal auto`, `hal factory run`, `sandboxexec`,
worker routing, scheduler selection, or `hal sandboxd` paths.

## Non-Goals

Guest exec, guest copy in or out, guest readiness beyond host API socket
acceptance, Firecracker SDK dependency, machine configuration API calls,
image/rootfs/kernel provisioning, network proxy, credential broker,
templates/kits, Docker/Podman guest engines, deny-by-default networking, and
brokered secrets are non-goals.

Phase 36 does not implement guest exec, guest copy in, guest copy out, guest
readiness beyond host API socket acceptance, guest health checks, Firecracker
SDK dependency, machine configuration API calls, image provisioning, rootfs
provisioning, kernel provisioning, network proxy integration, credential
broker integration, templates or kits, Docker/Podman guest engines,
deny-by-default networking, brokered secrets, default command enablement,
default worker routing, default scheduler selection, default sandboxd
enablement, or default live E2E verification.

Future phases are responsible for any production registration path, worker or
runtime configuration that selects this explicit API, Firecracker SDK or
API-socket integration, VM machine configuration through a control API,
guest readiness checks, guest networking, guest agent or vsock transport,
exec/copy support, guest container engine support, image/rootfs/kernel
provisioning, credential broker integration, brokered secrets, template/kit
support, network proxy/firewall enforcement, deny-by-default networking,
jailer/root setup, cgroup setup, and live E2E coverage.

## Review Notes

Keep Phase 36 live-driver behavior isolated to explicit construction in
`internal/sandboxruntime/microvm/firecrackerhost`, with the backend live-start
contract remaining in `internal/sandboxruntime/microvm/firecracker`.
Backend-neutral microVM code, command defaults, factory paths, sandboxexec
paths, worker routing, scheduler selection, and sandboxd defaults must not gain
implicit Firecracker live-driver behavior.

When Phase 36 test names, focused selectors, optional live-test prerequisites,
or non-goals change, update this document and
`cmd/phase36_firecracker_live_driver_docs_test.go` together so documented
verification commands remain executable, fake-safe by default, explicit about
optional live tests, and clear that the live driver is an explicit API rather
than default command enablement.
