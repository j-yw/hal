# Sandbox Runtime v2 Phase 37 Firecracker Guest Readiness Verification

Phase 37 adds an explicit, redaction-safe guest readiness boundary for
live-started Firecracker microVMs. It keeps host process acceptance, guest
readiness, default runtime selection, and unsupported guest capabilities as
separate contracts.

## Implemented Scope

`internal/sandboxruntime` owns the additive guest readiness runtime metadata
contract. The metadata can represent not configured, waiting, and ready states,
with only safe transport and label values.

`internal/sandboxruntime/microvm/firecracker` owns the optional backend
`GuestReadinessWaiter` contract, request/result sanitization, and live-start
sequencing. Guest readiness requests carry only sanitized process-handle and
runtime identity metadata. Guest readiness results carry only state, safe
transport labels, and safe readiness labels.

`internal/sandboxruntime/microvm/firecrackerhost` owns host-side polling through
an injected `GuestReadinessProbe`. The adapter polls with deterministic timeout
and interval dependencies, sanitizes requests before probing, sanitizes results
before returning them, and redacts public error text.

Live Firecracker start waits for host process and API socket acceptance before
invoking guest readiness. When no guest readiness waiter is configured, live
start must skip guest readiness and leave runtime guest readiness metadata
absent. When guest readiness succeeds, runtime metadata records only `ready`, a
sanitized transport label such as `vsock`, and safe labels such as `ready` and
`probe_ok`. When guest readiness fails or returns a non-ready result, live
start cleans up the accepted host process and returns a redaction-safe operation
error.

Guest readiness metadata is not an exec, copy, guest health, network, credential
delivery, or security enforcement claim.

## Default Command Wiring

Default command, factory, sandboxexec, worker, scheduler, and sandboxd paths
must not import Firecracker backend or host readiness packages, configure
`GuestReadinessWaiter`, configure `GuestReadinessProbe`, call readiness
wait/probe methods, or construct guest readiness metadata.

Default `hal run --sandbox`, `hal auto --sandbox`, and
`hal factory run --sandbox` must not select Firecracker or microVM guest
readiness unless explicit runtime metadata selects that path. Default
`firecracker.NewBackend(BackendOptions{})`, backends without
`BackendOptions.LiveStart: true`, and backends with injected guest readiness
waiters but without `LiveStart: true` remain planning-only.

## Verification Commands

Run the focused runtime and host guest readiness coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run command-level Phase 34, Phase 35, Phase 36, Phase 37, microVM, guest
readiness, and live-driver documentation and default-path guard coverage:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Phase3[4567].*Firecracker|MicroVM|GuestReadiness|LiveDriver'
```

Compile or run optional live-tagged Firecracker coverage. Cases lacking live
prerequisites should skip rather than fail:

```sh
go test -tags firecracker_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run the race check over the host adapter package, including deterministic guest
readiness polling:

```sh
go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/firecrackerhost
```

Run the full repository verification stack before integrating Phase 37:

```sh
go test -count=1 -timeout=420s ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint run ./...` should run only when `golangci-lint` is installed.
If `golangci-lint` is unavailable, report lint unavailable instead of reporting
lint as passed.

Passing this matrix satisfies the Phase 37 tests and typecheck gates.

## Fake-Safe Default Scope

Default Phase 37 verification is fake-safe and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, provider/runtime
integration, host-specific kernel or rootfs images, a live guest, or a guest
readiness agent.

Default Phase 37 tests use pure runtime metadata contracts, backend fake
process adapters, fake boot acceptance waiters, fake guest readiness waiters,
injected fake host probes, fake clocks and sleepers, fake command dependencies,
parsed imports, AST source guards, JSON redaction assertions, temporary stores,
and temporary state directories only.

Default Phase 37 verification must not use integration build tags, the
`firecracker_live` build tag, require live environment variables, start a real
Firecracker process, access KVM, require root, bind network sockets, start
worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs,
invoke Firecracker SDKs, or depend on live providers or runtime adapters.

The focused commands cover runtime metadata shape and redaction, inert microVM
defaults, optional backend guest readiness contracts, planning-only Firecracker
defaults, live-start guest readiness sequencing, host adapter polling, live
driver composition, cleanup on readiness failure, non-ready rejection, default
path non-wiring, and documentation guard coverage.

## Optional Live Tests

Phase 37 keeps optional live integration coverage behind the `firecracker_live`
build tag. It is not part of default verification. The tagged command compiles
optional live Firecracker host-process coverage and should pass or skip only
live-gated cases when prerequisites are absent.

Guest readiness itself remains tested through injected fake waiters and probes
in default Phase 37 tests; the tagged command does not require a real guest
readiness agent.

Use the live-tagged command from the verification matrix above only on a
prepared Linux host.

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
tests when every prerequisite is present. It does not wire guest readiness into
default `hal run`, `hal auto`, `hal factory run`, `sandboxexec`, worker
routing, scheduler selection, or `hal sandboxd` paths.

## Non-Goals

Guest exec, guest copy in or out, real guest agent implementation, concrete
vsock protocol implementation, Firecracker SDK dependency, machine
configuration API calls, image/rootfs/kernel provisioning, network proxy,
credential broker, default command enablement, default worker routing, default
scheduler selection, default sandboxd enablement, and default live E2E
guest-readiness verification are non-goals.

Phase 37 does not implement guest exec, guest copy in, guest copy out, a real
guest agent, a concrete vsock readiness protocol, Firecracker SDK dependency,
machine configuration API calls, image provisioning, rootfs provisioning,
kernel provisioning, network proxy integration, credential broker integration,
default command enablement, default worker routing, default scheduler
selection, default sandboxd enablement, or default live E2E guest-readiness
verification.

Future phases are responsible for any production registration path, worker or
runtime configuration that selects live Firecracker guest readiness, real guest
agent or vsock readiness protocols, Firecracker SDK or API-socket integration,
VM machine configuration through a control API, exec/copy support, guest
container engine support, image/rootfs/kernel provisioning, credential broker
integration, network proxy/firewall enforcement, deny-by-default networking,
jailer/root setup, cgroup setup, and live E2E guest-readiness coverage.

## Review Notes

Keep Phase 37 guest readiness isolated to explicit live-start backend options
and host adapter injection. Backend-neutral microVM code, command defaults,
factory paths, sandboxexec paths, worker routing, scheduler selection, and
sandboxd defaults must not gain implicit Firecracker guest readiness behavior.

When Phase 37 test names, focused selectors, optional live-test prerequisites,
or non-goals change, update this document and
`cmd/phase37_firecracker_guest_readiness_docs_test.go` together so documented
verification commands remain executable, fake-safe by default, explicit about
optional live tests, and clear that guest readiness is an explicit boundary
rather than default command enablement.
