# Sandbox Runtime v2 Phase 34 Firecracker Boot Vertical Slice Verification

Phase 34 adds an explicitly opt-in Firecracker live boot vertical slice on top
of the existing fake-only Firecracker backend foundation and Phase 33 process
launch adapter boundary. The implementation renders host-side boot files into
Firecracker state directories, launches only through injected process runner
dependencies, waits for a host-side API socket acceptance signal, records only
sanitized metadata, and cleans up live-started process state through injected
manager hooks.

## Implemented Scope

The Phase 34 boot slice lives in
`internal/sandboxruntime/microvm/firecracker`.

Default `firecracker.NewBackend(BackendOptions{})` and backends without
`LiveStart: true` remain planning-only. Live boot requires explicit
`BackendOptions.LiveStart`, an injected `ProcessAdapter` or
`ProcessLaunchAdapter`, an injected boot acceptance waiter, and an injected
live process manager. Missing or incomplete live options must not start
Firecracker and must return planning-only metadata or sanitized configuration
errors.

Before an injected process starter is called, Phase 34 renders the Firecracker
machine configuration, boot source, root drive payload, log path, metrics path,
and API socket path into the planned state directory. Render failures prevent
launch and surface only sanitized errors.

Successful fake-backed live boot records accepted host-side process metadata
only after the injected boot acceptance waiter reports host process acceptance
and API socket availability. This is a host-side acceptance signal only; it is
not a guest readiness or guest health claim.

Stop, delete, and failed-acceptance cleanup use injected live process manager
hooks only for targets that were live-started. Cleanup requests are scoped to
the Firecracker-owned state directory and must not delete caller-owned paths.

Public metadata, public JSON errors, skip messages, and operation errors must
omit raw state directories, API socket paths, config paths, log paths, metrics
paths, kernel paths, rootfs paths, initrd paths, argv fragments, endpoints,
process IDs, environment values, tokens, and secrets.

## Command Defaults

No default command, scheduler, factory, sandboxexec, sandboxd, or worker path
starts Firecracker or wires Phase 34 live boot options.

Default run, auto, factory, scheduler, sandboxexec, sandboxd, worker, and
backend construction paths must remain planning-only or backend-neutral unless
a future phase adds an explicit production registration path. Phase 34 guard
tests keep those default paths from importing Firecracker live adapter types,
constructing `BackendOptions` live boot fields, constructing process launch
adapters, waiting for boot acceptance, managing live processes, or launching a
literal Firecracker process.

## Focused Verification Commands

Run backend-neutral microVM contracts and import-boundary coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm
```

Run Firecracker boot rendering, injected launch, host-side acceptance,
cleanup, redaction, default-off, import-boundary, and live-test opt-in guard
coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm/firecracker
```

Run command-level microVM, Firecracker, and Phase 34 default-path and
documentation guard coverage:

```sh
go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase34'
```

These focused commands are fake-only. They cover default planning-only backend
behavior, complete live-option gating, boot-file rendering before injected
launch, render-failure launch prevention, host-side acceptance ordering,
acceptance-failure cleanup, stop/delete cleanup for live-started targets,
cleanup path scoping, seeded redaction of sensitive values, production import
boundaries, direct `os/exec` avoidance in production Firecracker code,
Docker/Podman guest-engine exclusion, default command non-wiring, optional
`firecracker_live` test exclusion from default coverage, and documentation
guard coverage.

## Broad Verification Commands

Run the full PRD verification stack before integrating Phase 34:

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

## Fake-Only Default Scope

Default Phase 34 verification is fake-only and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, provider/runtime
integration, host-specific kernel or rootfs images, or a live guest.

Default Phase 34 tests must use pure contracts, deterministic path and payload
rendering, injected fake process starters and adapters, injected fake boot
acceptance waiters, injected fake live process managers, fake command
dependencies, parsed imports, AST source guards, JSON redaction assertions,
temporary stores, and temporary state directories only.

Default Phase 34 verification must not use integration build tags, the
`firecracker_live` build tag, require live environment variables, start a real
Firecracker process, access KVM, require root, bind network sockets, start
worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs,
invoke Firecracker SDKs, or depend on live providers or runtime adapters.

## Optional Live Test

Phase 34 includes an optional live integration test behind the
`firecracker_live` build tag. It is not part of default verification.

Run it only on a prepared Linux host:

```sh
go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker -run 'TestFirecrackerLiveBootWithRealProcess|TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted'
```

Required live-test prerequisites:

- `HAL_FIRECRACKER_LIVE_FIRECRACKER`: executable regular file for the
  Firecracker binary.
- `HAL_FIRECRACKER_LIVE_KERNEL`: readable regular file for the kernel image.
- `HAL_FIRECRACKER_LIVE_ROOTFS`: read/write regular file for the rootfs image.
- Linux host with `/dev/kvm` present and read/write accessible to the test
  process.

Optional live-test settings:

- `HAL_FIRECRACKER_LIVE_INITRD`: readable regular file for an initrd image.
- `HAL_FIRECRACKER_LIVE_TIMEOUT`: positive Go duration for host-side API
  socket acceptance, defaulting to `10s`.
- `HAL_FIRECRACKER_LIVE_CPU_COUNT`: integer greater than or equal to `1`,
  defaulting to `1`.
- `HAL_FIRECRACKER_LIVE_MEMORY_MIB`: integer greater than or equal to `1`,
  defaulting to `256`.

The optional live command starts a real Firecracker process through the same
injected `ProcessRunnerStartRequest` boundary used by fake tests. The harness
passes an empty environment to the process, waits only for host-side API socket
availability, stops or kills remaining process state during cleanup, and
removes only the Firecracker-owned state directory.

## Non-Goals

Guest exec, copy, Docker/Podman, guest readiness, networking enforcement,
credential delivery, workspace sync, and default production enablement remain
unsupported.

Phase 34 does not implement guest exec, guest copy, Docker/Podman guest
engines, guest readiness checks, guest health checks, guest agent or vsock
transport, SSH access, workspace synchronization, credential delivery, network
proxy/firewall enforcement, Firecracker SDK integration, API socket machine
configuration calls, jailer/root setup, cgroups, default registration, or
default live E2E tests.

No default command, scheduler, factory, sandboxexec, sandboxd, worker, or
backend path imports, constructs, registers, or launches Firecracker live boot.

The optional live test proves only host-side Firecracker process launch,
rendered boot files, host-side API socket acceptance, sanitized metadata, and
cleanup through injected dependencies. It does not prove guest workload
execution, guest health/readiness, network policy enforcement, credential
delivery, workspace synchronization, command/factory/sandboxd enablement, or a
production Firecracker control plane.

Future phases are responsible for any production registration path, Firecracker
SDK or API-socket integration, VM machine configuration through a control API,
guest readiness checks, guest networking, guest agent or vsock transport,
exec/copy support, guest container engine support, credential delivery,
workspace sync, network proxy/firewall enforcement, jailer/root setup, cgroup
setup, and live E2E coverage.

## Review Notes

Keep Phase 34 live boot behavior isolated to explicit backend options and
injected Firecracker package boundaries. Backend-neutral microVM code, command
defaults, scheduler paths, factory paths, sandboxexec paths, sandboxd defaults,
and worker paths must not gain implicit Firecracker live boot behavior.

When Phase 34 test names, live-test prerequisites, focused selectors, or
non-goals change, update this document and
`cmd/phase34_firecracker_docs_test.go` together so documented verification
commands remain executable, fake-only by default, and explicit about the
optional live-test contract.
