# Sandbox Runtime v2 Phase 31 MicroVM Runtime Foundation Verification

Phase 31 adds a concrete fakeable microVM sandbox runtime foundation. The
foundation covers sanitized configuration and operation-error contracts,
fakeable host capability detection, config validation, a `microvm.Driver`
runtime boundary, backend/controller lifecycle delegation, command resolver
integration, metadata-driven worker behavior, sandboxd registration boundaries,
and import/fake-only dependency guards.

## Runtime Foundation

The microVM foundation lives in `internal/sandboxruntime/microvm`.
`Config` and `Options` describe kernel image, rootfs, optional initrd,
optional jailer or hypervisor executable, CPU count, memory size, disk size,
guest workdir, network mode, image metadata, and template metadata. The default
network mode is `no_live_networking`.

Stable operation error codes cover unavailable capability, invalid config,
backend not configured, backend operation failure, target required, and target
name required. Public error strings and JSON output are sanitized so unsafe host
paths, endpoint details, tokens, credentials, provider internals, and raw
backend messages are not persisted or printed.

`HostCapabilityDetector` is injectable and fakeable. macOS and other non-Linux
hosts report unavailable without live KVM access. Linux KVM and configured
hypervisor checks are represented as safe capability metadata and can be faked
in unit tests.

`microvm.Driver` satisfies `sandboxruntime.Driver`, returns
`sandboxruntime.DriverMicroVM`, reports VM isolation metadata, states that no
host Docker socket is used, and reflects sanitized capability state. Lifecycle,
exec, copy-in, and copy-out operations delegate through injected
backend/controller boundaries. Default production construction starts
unavailable until a later phase provides a real backend.

## Resolver And Worker Boundaries

Explicit microVM runtime metadata resolves to the microVM driver and does not
fall back to SSH-machine or rootless Podman behavior. Existing default
SSH-machine behavior remains unchanged when no explicit microVM runtime is
selected, and existing rootless Podman behavior remains unchanged for explicit
rootless runtime metadata.

Worker microVM metadata remains metadata-driven. Without an explicit injected
worker runtime hook, worker-backed microVM selection reports an unsupported
runtime classification instead of constructing a live worker client, starting a
microVM, or falling back to a local driver. With an injected hook, the command
boundary can route a fake worker microVM driver for tests.

`hal sandboxd` rejects the microVM driver unless a microVM driver factory is
injected. The default sandboxd path does not start KVM, Firecracker, Cloud
Hypervisor, Docker, Podman, or any live microVM backend.

## Focused Verification Commands

Run the PRD-required Phase 31 microVM foundation package coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime/microvm
```

Run the PRD-required command-level microVM, default resolver, and runtime
resolver selector:

```sh
go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*DefaultRuntimeDriverResolver|Test.*RuntimeResolver'
```

Run explicit runtime-compatibility default preservation coverage:

```sh
go test -timeout=120s ./cmd -run 'TestSandboxRuntimeCompatDefaultsToSSHMachineUnlessExplicitRuntimeSelected'
```

Run the PRD-required base runtime and worker metadata coverage:

```sh
go test -timeout=120s ./internal/sandboxruntime ./internal/sandboxworker
```

Run target-selection microVM fallback protection:

```sh
go test -timeout=120s ./internal/sandboxtarget -run 'TestSelectRequestedMicroVMRuntimeDoesNotUseWeakerRuntimeFallback'
```

Run the Phase 31 documentation guard coverage:

```sh
go test -timeout=120s ./cmd -run 'TestPhase31MicroVMRuntimeFoundation(VerificationDocs|FakeOnlyVerification)'
```

These focused commands are fake-only. They cover microVM contracts,
capability detection, validation, driver metadata, lifecycle delegation,
resolver integration, worker metadata preservation, sandboxd registration
boundaries, target-selection no-fallback behavior, import-boundary guards,
default-test fake-only guards, and documentation guard coverage.

## Broad Verification Commands

Run the full PRD verification stack before integrating Phase 31:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` is optional for Phase 31 and should be reported only if
`golangci-lint` is installed. If the linter is unavailable, record it as
unavailable rather than as a required failed check.

## Fake-Only Scope

Default verification is fake-only and does not require KVM, Firecracker, Cloud
Hypervisor, Docker, Podman, network sockets, root privileges, or cloud
credentials.

Phase 31 tests should use data contracts, JSON marshaling, reflection over
struct tags, fake capability probes, fake backend/controller implementations,
fake command dependencies, temporary stores, parsed imports, AST checks,
explicit build-tag checks, and seeded unsafe strings.

Default Phase 31 verification must not use integration build tags, require live
environment variables, contact cloud APIs, start providers, start Docker or
Podman workflows, start Firecracker or Cloud Hypervisor, access live KVM,
bind network sockets, start worker daemons, run `hal sandboxd`, require root,
or create live microVM backends.

## Non-Goals

No live Firecracker backend is included in Phase 31.
No live Cloud Hypervisor backend is included in Phase 31.
No KVM-backed microVM launch is included in Phase 31.
No root-privileged runtime behavior is included in Phase 31.
No live network sockets are included in Phase 31 default verification.
No Docker or Podman dependency is introduced for the microVM foundation.
No cloud provider SDK or cloud credential behavior is introduced.
No worker protocol expansion is included for microVM execution.
No default sandboxd live microVM registration is included.

Future phases are responsible for real Firecracker or Cloud Hypervisor backend
construction, live VM launch, guest networking, root or jailer integration,
worker protocol expansion, and operational microVM lifecycle support.

## Review Notes

Keep `internal/sandboxruntime/microvm` command-agnostic and independent from
factory orchestration, worker-server implementation packages, concrete
provider adapters, sibling runtime adapters, network clients, Docker/Podman
clients, Firecracker or Cloud Hypervisor SDKs, KVM helper packages, cloud SDKs,
Cobra, and command packages.

When Phase 31 test names change, update this document and
`cmd/phase31_microvm_docs_test.go` together so the focused fake-only commands
keep matching the actual coverage.
