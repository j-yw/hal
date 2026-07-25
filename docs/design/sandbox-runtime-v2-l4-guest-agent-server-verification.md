# Sandbox Runtime v2 L4 Guest-Agent Server Verification

This document is the red-first verification boundary for issue #49 phase L4.
The locked issue comments, the Linux completion architecture, and
`sandbox-runtime-v2-l4-guest-agent-server-architecture.md` remain authoritative.

## Scope and claim boundary

L4 implements the production guest-agent protocol server and Linux operation
backend behind an injected in-memory transport. It proves versioned readiness,
strict dispatch, exec, copy, limits, containment, cancellation, cleanup,
redaction, concurrency, and shutdown independently of Firecracker.

L4 does not add a listener, vsock, a guest image, Firecracker machine
configuration, network enforcement, credential delivery, OCI acquisition, or
a strict-security claim. An endpoint, process handle, API socket, or configured
transport is not readiness proof. MicroVM worker capabilities remain
lifecycle-only throughout L4.

## Red-first default matrix

The protocol and client package locks the additive error contract and strict
host response decoder:

- `TestL4ProtocolAdditiveErrorCodes`;
- `TestL4ErrorResponseExactJSONShape`;
- `TestL4ClientStrictlyRejectsMalformedResponseObjects`.

The injected server tests lock:

- `TestL4ServerDispatchesAllV1OperationsFromWireBytes`;
- `TestL4ServerStrictRequestFailuresNeverReachBackend`;
- `TestL4ServerCanonicalReadinessByStateAndBackend`;
- `TestL4ServerTransportFailureDrainsThenFailsAndClosesOnce`.

The explicitly tagged prepared-Linux acceptance test
`TestL4PreparedLinuxLocalServerE2E` owns the real local server/backend
end-to-end contract.

The command capability tests prove that a configured guest-agent endpoint does
not advertise `exec`, `copy_in`, or `copy_out`. Default and configured-endpoint
microVM descriptors remain lifecycle-only until L5 correlates an exact v1
readiness handshake with a live guest/runtime.

Malformed, unknown, duplicate, trailing, oversized, canceled, busy, not-ready,
and unsupported-version requests make zero backend calls. Exec coverage
includes binary stdin/output, non-zero exit, independent stdout/stderr
truncation, fail-closed environment resolution, timeout, cancellation,
shutdown, process-group termination, reap, work-directory descriptor pinning,
and descriptor non-inheritance.

Readiness, exec, copy-in, and copy-out deadlines remain authoritative when an
injected backend returns success only after its operation context expires.

Copy coverage includes byte-for-byte round trip, exact lowercase SHA-256,
oversize rejection, atomic replacement, `0600` mode, existing-target
preservation, temporary-file cleanup, mutation detection, traversal and prefix
confusion, symlink and coordinated parent swap, mount and magic-link rejection,
and directory, multiply-linked file, FIFO, socket, and device rejection.

Public error and JSON assertions seed path, endpoint, executable, argument,
environment, token, header, payload, socket, and raw syscall canaries. Only
stable code, operation, field, and fixed summary metadata may cross the public
boundary.

## Import, source, and fake-only guards

The root `internal/sandboxruntime/microvm/guestagent` package remains data-only.
The server package may import the parent protocol package, required
standard-library OS/process packages, and `golang.org/x/sys/unix`.

`internal/sandboxruntime/microvm/guestagent/server/import_boundary_test.go`
parses production imports and source. It rejects command, factory, worker,
execution, workspace, Firecracker/host, provider/runtime adapter, Podman,
Docker, cloud, Cobra, HTTP/RPC, network listener/dialer, ambient environment,
implicit shell, Docker socket, and raw public-error forwarding dependencies.

Default L4 tests are untagged and deterministic. They do not bind listeners,
start daemons or Firecracker, access KVM, use vsock, pull images, use
Docker/Podman, contact providers, require credentials, or make network calls.
Default and tagged L4 tests must not call `t.Skip` or `t.Skipf`.

## Prepared-Linux acceptance

The prepared test is
`TestL4PreparedLinuxLocalServerE2E` in
`internal/sandboxruntime/microvm/guestagent/server/l4_linux_backend_integration_test.go`.
Its only build tag is `l4_guest_agent_server_integration`, so selecting the tag
on a non-Linux host runs the test and fails rather than silently matching no
tests. The test itself requires Linux and treats missing `openat2`, user/mount
namespace capability, or required process/filesystem behavior as a failure,
never a skip.

It runs the production server and Linux backend through the injected in-memory
transport and proves real readiness, exec, copy, timeout/cancel, containment,
descriptor isolation, shutdown, and cleanup. It creates no cloud, container,
Firecracker, KVM, network, listener, socket, or billed resource.
The test re-executes itself through the local `unshare` utility in a rootless
user and mount namespace, makes mount propagation private, and creates a
disposable tmpfs workspace mount. Missing rootless user/mount namespace,
`unshare`, or tmpfs-mount capability is a failure, never a skip.

Before running it, prove both the host and exact test match:

```sh
test "$(go env GOOS)" = linux
go test -list '^TestL4PreparedLinuxLocalServerE2E$' -tags=l4_guest_agent_server_integration ./internal/sandboxruntime/microvm/guestagent/server | grep -qx 'TestL4PreparedLinuxLocalServerE2E'
go test -race -count=1 -timeout=180s -tags=l4_guest_agent_server_integration ./internal/sandboxruntime/microvm/guestagent/server -run '^TestL4PreparedLinuxLocalServerE2E$'
```

## Focused verification

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/guestagent ./internal/sandboxruntime/microvm/guestagent/server
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(GuestAgent|L4)'
go test -count=1 -timeout=180s ./cmd -run '^Test(L4GuestAgent|Phase40MicroVM|Sandboxd.*GuestAgent)'
go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/guestagent ./internal/sandboxruntime/microvm/guestagent/server ./internal/sandboxruntime/microvm/firecrackerhost
```

Cross-platform compilation verifies that non-Linux construction fails closed
without turning compilation into a Windows or macOS runtime claim:

```sh
GOOS=darwin GOARCH=amd64 go test -exec=true -count=1 -run '^$' ./internal/sandboxruntime/microvm/guestagent ./internal/sandboxruntime/microvm/guestagent/server ./internal/sandboxruntime/microvm/firecrackerhost
GOOS=windows GOARCH=amd64 go test -exec=true -count=1 -run '^$' ./internal/sandboxruntime/microvm/guestagent ./internal/sandboxruntime/microvm/guestagent/server ./internal/sandboxruntime/microvm/firecrackerhost
```

Run the broad repository gates:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
test -z "$(gofmt -l cmd internal)"
git diff --check
```

Run `golangci-lint run ./...` only when `command -v golangci-lint` succeeds.
If it is unavailable, report lint unavailable instead of reporting lint as
passed. A skipped or zero-match prepared test is a blocker, never a pass.

## L5 handoff

L5 owns the guest image, guest AF_VSOCK transport, host-side bridge/framing,
Firecracker machine wiring, readiness evidence bound to the live runtime,
capability activation after the exact v1 handshake, and real in-guest
end-to-end proof. No L4 result is Firecracker, image, vsock, microVM-isolation,
network-enforcement, credential, OCI, or strict-default evidence.
