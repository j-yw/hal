# Sandbox Runtime v2 Phase 35 Firecracker Host Adapter Verification

Phase 35 adds an injection-ready Firecracker host adapter package for the
Phase 34 live boot boundaries. It does not enable Firecracker by default.

## Implemented Scope

The Phase 35 host adapter lives in
`internal/sandboxruntime/microvm/firecrackerhost`.

The package is intentionally separate from
`internal/sandboxruntime/microvm/firecracker`. Phase 34 owns the backend live
boot contract and keeps live boot behind explicit `BackendOptions.LiveStart`
plus injected `ProcessAdapter`, `BootAcceptanceWaiter`, and
`LiveProcessManager` dependencies. Phase 35 provides host-side implementations
that can satisfy those injected interfaces, but it does not register, select,
or pass them to backend options from default Hal execution paths.

`firecrackerhost.NewAdapter` builds an inert adapter unless dependencies are
explicitly provided with options such as `WithProcessRunner`,
`WithBootAcceptancePoller`, and `WithLiveProcessCleanup`. Calling live methods
without those dependencies returns a configured sentinel error instead of
starting or accepting a process.

`firecrackerhost.NewProcessLifecycleManager` owns fake-safe host process handle
lifecycle and state cleanup through injected boundaries. It stores only opaque
handle metadata publicly, keeps raw process state in memory, treats unknown
handles as idempotent cleanup no-ops, validates Firecracker-owned state
directories before deletion, and sanitizes lifecycle and filesystem errors.

`firecrackerhost.NewOSExecProcessRunner` is the only production `os/exec`
boundary for starting a Firecracker host process. It is still explicit
injection plumbing: default paths do not construct it, and it rejects host
environment delivery before launch.

## Default Command Wiring

The adapter is not wired into default `hal run`, `hal auto`, `hal factory run`,
`sandboxexec`, or worker execution paths.

Default CLI, factory, sandboxexec, worker, scheduler, sandboxd, and backend
construction paths must remain planning-only or backend-neutral unless a future
phase adds an explicit production registration path. Phase 35 guard tests keep
those default paths from importing `firecrackerhost`, constructing
`NewAdapter`, constructing `NewProcessLifecycleManager`, constructing
`NewOSExecProcessRunner`, selecting `firecrackerhost` by literal, or injecting
host adapter dependencies into Phase 34 backend live boot options.

## Focused Verification Commands

Run Firecracker host adapter contract, polling, lifecycle, cleanup, real-runner
boundary, opt-in live-test, and package-boundary coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm/firecrackerhost
```

Run the Phase 34 backend live boot boundary coverage that the host adapter
satisfies only through explicit injection:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm/firecracker
```

Run command-level Phase 34 and Phase 35 default-path and documentation guard
coverage:

```sh
go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase34|TestPhase35'
```

These focused commands are fake-safe by default. They cover inert zero-option
adapter behavior, explicit dependency option wiring, injected process start
delegation, deterministic boot acceptance polling, sanitized polling errors,
opaque lifecycle handles, idempotent stop/delete/cleanup, cleanup path
validation, sanitized lifecycle and filesystem failures, confinement of
`os/exec` to the host adapter package, default command non-wiring, optional
`firecracker_live` exclusion from default coverage, and documentation guard
coverage.

## Broad Verification Commands

Run the full PRD verification stack before integrating Phase 35:

```sh
go test ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` should run only when `golangci-lint` is installed. If
`golangci-lint` is unavailable, report lint unavailable instead of reporting
lint as passed.

## Fake-Safe Default Scope

Default Phase 35 verification is fake-safe and does not require KVM, a
Firecracker binary, root privileges, live network sockets, Firecracker SDKs,
cloud credentials, Docker, Podman, worker daemons, provider/runtime
integration, host-specific kernel or rootfs images, or a live guest.

Default Phase 35 tests must use pure contracts, injected fake process runners,
injected fake boot acceptance pollers, injected fake live process cleanup,
fake filesystems, fake command dependencies, parsed imports, AST source guards,
JSON redaction assertions, temporary stores, and temporary state directories
only.

Default Phase 35 verification must not use integration build tags, the
`firecracker_live` build tag, require live environment variables, start a real
Firecracker process, access KVM, require root, bind network sockets, start
worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs,
invoke Firecracker SDKs, or depend on live providers or runtime adapters.

## Optional Live Tests

Phase 35 includes optional live integration coverage behind the
`firecracker_live` build tag. It is not part of default verification. When live
prerequisites are unavailable, these tagged tests should skip with redacted
messages instead of failing default verification.

Run the optional live command only on a prepared Linux host:

```sh
go test -tags firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Shared live-test prerequisites:

- Linux host with `/dev/kvm` present and read/write accessible to the test
  process for backend live boot coverage.
- `HAL_FIRECRACKER_LIVE_FIRECRACKER`: executable regular file for the
  Firecracker binary.

Phase 34 backend live boot prerequisites:

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

Phase 35 host adapter live-runner prerequisites:

- `HAL_FIRECRACKER_LIVE=1`: explicit opt-in for the host adapter live-runner
  test.
- `HAL_FIRECRACKER_LIVE_FIRECRACKER`: executable regular file for the
  Firecracker binary.

The optional live command starts real Firecracker processes only inside tagged
tests. It does not wire the host adapter into default `hal run`, `hal auto`,
`hal factory run`, `sandboxexec`, worker, scheduler, or sandboxd paths.

## Non-Goals

Phase 35 does not implement default Firecracker registration, default host
adapter selection, default backend option injection, guest exec, guest copy,
Docker/Podman guest engines, guest readiness checks, guest health checks,
guest agent or vsock transport, SSH access, workspace synchronization,
credential delivery, network proxy/firewall enforcement, Firecracker SDK
integration, API socket machine configuration calls, jailer/root setup,
cgroups, default live E2E tests, or command/factory/sandboxd enablement.

No default `hal run`, `hal auto`, `hal factory run`, sandboxexec, worker,
scheduler, sandboxd, or backend path imports, constructs, selects, injects, or
launches the Firecracker host adapter.

Future phases are responsible for any production registration path, default
runtime selection, Firecracker SDK or API-socket integration, VM machine
configuration through a control API, guest readiness checks, guest networking,
guest agent or vsock transport, exec/copy support, guest container engine
support, credential delivery, workspace sync, network proxy/firewall
enforcement, jailer/root setup, cgroup setup, and live E2E coverage.

## Review Notes

Keep Phase 35 host adapter behavior isolated to
`internal/sandboxruntime/microvm/firecrackerhost` and explicit Phase 34 backend
injection. Backend-neutral microVM code, command defaults, scheduler paths,
factory paths, sandboxexec paths, sandboxd defaults, and worker paths must not
gain implicit Firecracker host adapter behavior.

When Phase 35 test names, live-test prerequisites, focused selectors, or
non-goals change, update this document and
`cmd/phase35_firecracker_host_adapter_docs_test.go` together so documented
verification commands remain executable, fake-safe by default, explicit about
the optional live-test contract, and consistent with repository
`golangci-lint` availability guidance.
