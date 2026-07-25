# Sandbox Runtime v2 L4 Guest-Agent Server Architecture

## Authority and phase boundary

This note refines issue #49 phase L4 under the locked Linux-first technical
specification and implementation plan. The checked-in Linux completion
architecture remains the cross-phase authority.

L4 implements the production guest-side protocol server and Linux operation
backend behind an injected transport. It proves protocol handling, process
execution, file copy, bounds, containment, cancellation, cleanup, and
redaction on the prepared Linux machine.

L4 does not add a listener, virtio-vsock, a Firecracker machine configuration,
a kernel or root filesystem build, a guest image, networking, credentials,
OCI acquisition, or a strict security claim. L5 owns those integrations and
the real Firecracker guest end-to-end proof.

## Package ownership

The existing
`internal/sandboxruntime/microvm/guestagent`
package remains the standard-library-only wire-contract and client package.
It owns:

- `guest-agent-v1` request and response DTOs;
- stable operations and error codes;
- validation and redaction-safe protocol errors;
- strict host-side response decoding; and
- the existing injected client `Transport`.

Production server and operating-system behavior live in:

```text
internal/sandboxruntime/microvm/guestagent/server
```

The server package may import the parent protocol package, operating-system
and process packages, and `golang.org/x/sys/unix`. It must not import command,
factory, worker, execution, workspace, provider, rootless Podman, Firecracker,
Firecracker-host, cloud, Cobra, HTTP/RPC, or network-listener packages.

No command, manifest, factory, worker, runtime-status, or other durable schema
changes are part of L4.

## Public server boundary

The server is a protocol handler whose byte transport is injected:

```go
type Limits struct {
    MaxRequestBytes  int64
    MaxResponseBytes int64
}

type Transport interface {
    Serve(context.Context, Limits, Handler) error
}

type Request struct {
    Encoded []byte
}

type Response struct {
    Encoded []byte
}

type Handler interface {
    Handle(context.Context, Request) Response
}

type Options struct {
    Transport           Transport
    Backend             Backend
    EnvironmentResolver EnvironmentResolver
    MaxRequestBytes     int64
    MaxResponseBytes    int64
    MaxConcurrent       int
    MaxOperationTime    time.Duration
    MaxShutdownTime     time.Duration
}

func New(Options) (*Server, error)
func (*Server) Serve(context.Context) error
func (*Server) Handle(context.Context, Request) Response
func (*Server) Shutdown(context.Context) error
func (*Server) State() State
```

`Request` and `Response` contain wire bytes only. Version and operation are
derived exclusively from encoded JSON. The server does not consume the
host-client-only `guestagent.TransportRequest` sideband.

`Transport` owns acceptance and framing. It must enforce the supplied request
limit before allocating or reading a complete frame, enforce the response
limit before writing a frame, stop accepting when its context is canceled,
allow no handler call after `Serve` returns, and return promptly after
cancellation. A transport whose return is caused only by cancellation must
return nil, a single wrapped error chain ending in the supplied context error,
or a joined error whose every non-nil leaf has that same cancellation cause.
A joined error containing any other leaf is an independent transport failure,
including when it races with `Shutdown`. `Server` repeats the encoded bounds
defensively and owns strict decoding, dispatch, operation timing, response
encoding, concurrency, and shutdown. L4 tests use an in-memory transport. L5
supplies the concrete guest vsock transport and its framing proof.

The server state machine is:

```text
new ---------> serving -> draining -> stopped
 \                            \----> failed
  \-> draining -> stopped
```

The exact states are `new`, `serving`, `draining`, `stopped`, and `failed`.
`Serve` may run once. `Shutdown` before `Serve` transitions
`new -> draining -> stopped`, closes the backend exactly once, and makes a
later `Serve` fail without invoking the transport.

A transport failure atomically moves `serving -> draining` before it cancels
in-flight handlers, so readiness and direct handler admission fail closed
during cleanup. It runs the same exactly-once backend cleanup as shutdown and
moves `draining -> failed` only after cleanup completes. If cleanup itself
fails or exceeds `MaxShutdownTime`, the terminal state is also `failed`.

Cancellation or `Shutdown` moves it to `draining`, rejects new work, cancels
in-flight work, waits for transport return and backend cleanup, and ends in
`stopped`. `Shutdown` is idempotent and bounded by its caller context. If that
context expires, it returns the matching context error while cleanup continues
under the server's bounded `MaxShutdownTime`; the state remains `draining`
until cleanup reaches `stopped` or `failed`. A terminal cleanup failure is
retained and returned by every later `Shutdown` call without rerunning cleanup;
repeated shutdown can never convert failed cleanup into apparent success.

Readiness is canonical:

- only `serving` plus successful `Backend.Ready` returns
  `ready=true,status=ready`;
- every other state or backend-not-ready result returns
  `ready=false,status=not_ready`; and
- contradictory boolean/status pairs are invalid on both server and client
  validation boundaries.

## Backend boundary

Decoded requests cross into a fakeable backend as private live plans:

```go
type Backend interface {
    Ready(context.Context) error
    Exec(context.Context, ExecPlan) (ExecResult, error)
    CopyIn(context.Context, CopyInPlan) (CopyResult, error)
    CopyOut(context.Context, CopyOutPlan) (CopyResult, error)
    Close(context.Context) error
}

type EnvironmentResolver interface {
    Resolve(context.Context, guestagent.EnvironmentEntry) (string, error)
}

type ExecPlan struct {
    Args           []string
    Environment    []string
    WorkDir        string
    Stdin          []byte
    StdoutMaxBytes int64
    StderrMaxBytes int64
}

type ExecResult struct {
    ExitCode        int
    Stdout          []byte
    Stderr          []byte
    StdoutTruncated bool
    StderrTruncated bool
}

type CopyInPlan struct {
    DestinationPath string
    Data            []byte
    MaxBytes        int64
    Digest          string
}

type CopyOutPlan struct {
    SourcePath string
    MaxBytes   int64
}

type CopyResult struct {
    Data      []byte
    SizeBytes int64
    Digest    string
}
```

Plans carry decoded bytes and, for exec, resolved in-memory environment
assignments. They are not JSON or durable types. Results carry bounded bytes,
exit/truncation metadata, size, and digest only.

The production constructor is Linux-only:

```go
type LinuxBackendOptions struct {
    WorkspaceRoot   string
    GuestRoot       string
    BaseEnvironment []string
    ExecutablePaths []string
    TermGrace       time.Duration
}

func NewLinuxBackend(LinuxBackendOptions) (Backend, error)
```

`WorkspaceRoot` is the private local path of the mounted guest workspace. It
must be the root of a distinct filesystem with no second mount of that
filesystem visible in the agent's mount namespace. Construction verifies the
pinned root and parent devices plus a bounded parse of
`/proc/self/mountinfo`, and fails closed when the boundary is absent or
aliased. This immutable cross-device boundary prevents an opened descendant
from later being renamed onto the surrounding filesystem through either the
workspace mount or another mount alias. `GuestRoot` is its protocol-visible
absolute prefix, normally `/workspace`. Neither value is serialized or
included in public errors. Non-Linux builds provide the same constructor and
fail closed with `unsupported_platform`.

Backend construction opens and pins the workspace root, verifies Linux
`openat2` support plus the private `/proc/self/fd` descriptor bridge used for
safe reopen/chdir, and fails closed if the required containment primitives are
unavailable. It never falls back to string-only checks, `os.Root`, or an
unchecked host path.

Each configured executable root is opened and pinned in one `openat2` call
with `O_PATH|O_DIRECTORY|O_CLOEXEC` and `RESOLVE_NO_MAGICLINKS`. Ordinary
image-owned symlinks such as `/bin` remain supported, but procfs-style magic
links are rejected. Root selection never resolves a pathname and reopens the
result in a second syscall, so a rename between validation and acquisition
cannot substitute the descriptor.

Every root, directory, temporary-write, copy-in, copy-out, and observation
descriptor is created atomically with `O_CLOEXEC`. No unrelated server-owned
descriptor is inheritable by concurrently launched commands. The specific
pinned work-directory descriptor is deliberately supplied through that
command's `ExtraFiles`. When the pinned executable is an interpreter script,
its read-only `O_PATH` descriptor is also deliberately remapped into that
child so the kernel-selected interpreter reopens the pinned inode rather than
a mutable pathname; native binaries do not inherit it. The child receives no
other server descriptor. A `MaxConcurrent > 1` regression inspects a launched
child while copy operations are active and proves descriptor non-inheritance.

Backend errors may return a `guestagent.ProtocolError` with an allowed stable
L4 code. Context cancellation and deadline errors preserve `errors.Is`
semantics. Any other backend or resolver error is mapped to a fixed
`internal_failure`, `execution_failed`, `copy_failed`, or
`environment_unavailable` envelope without raw error detail.

## Defaults and hard limits

The public constants and constructor validation are locked by tests:

```text
DefaultMaxRequestBytes       = 1 MiB
DefaultMaxResponseBytes      = 1 MiB
MinimumMaxResponseBytes      = 512 bytes
MaximumEncodedMessageBytes   = 8 MiB
DefaultMaxConcurrent         = 1
MaximumMaxConcurrent         = 64
DefaultMaxOperationTime      = 24 hours
MaximumMaxOperationTime      = 24 hours
DefaultMaxShutdownTime       = 30 seconds
MaximumMaxShutdownTime       = 2 minutes
MaximumJSONNestingDepth      = 32
DefaultExecStdinBytes        = 512 KiB
DefaultExecStdoutBytes       = 256 KiB
DefaultExecStderrBytes       = 256 KiB
DefaultCopyBytes             = 512 KiB
```

Zero values select defaults. Negative values and values above a maximum are
constructor errors. A positive response limit below
`MinimumMaxResponseBytes` is rejected, so a fixed error envelope always fits.
Request metadata may select a smaller effective operation limit but may never
raise these server-side limits.

## Strict protocol handling

`Handle` accepts one bounded JSON object. Before a backend call it:

1. rejects an encoded request larger than the configured server limit;
2. rejects empty, null, array, invalid UTF-8, excessive nesting, duplicate
   keys at any depth, unknown fields, and trailing documents;
3. extracts but does not trust the header;
4. requires exact `guest-agent-v1` and one of `readiness`, `exec`, `copy_in`,
   or `copy_out`;
5. strictly decodes the selected DTO and runs its validator; and
6. derives an operation context from the shortest of caller cancellation,
   request timeout/deadline, and `MaxOperationTime`.

Unsupported versions do not downgrade. Responses always use the server's v1
envelope and the selected safe operation when one was validly identified.
Malformed input never reaches the backend.

The root protocol package adds the generic error envelope used when no typed
operation response can be selected:

```go
type ErrorResponse struct {
    ProtocolVersion ProtocolVersion `json:"protocolVersion"`
    Operation       Operation       `json:"operation,omitempty"`
    Error           *ProtocolError  `json:"error"`
}
```

The envelope always reports `guest-agent-v1`. `operation` is present only when
the body contained one exact supported operation; malformed or unknown
operations omit it. Known-operation errors may use the same generic envelope
because the existing client checks the shared header and `error` before
validating operation-specific result fields.

Responses are encoded within the configured response limit. If a successful
response would exceed that bound, the server discards it and emits a fixed
bounded `oversized_response` error envelope. Constructor validation guarantees
the fixed envelope fits. The server never emits a partial JSON document.

The parent client receives the matching strictness change: response JSON with
duplicates, unknown fields, non-object roots, or trailing documents is
`malformed_response`.

## Stable failure codes and redaction

L4 adds these protocol codes:

```text
malformed_request
server_not_ready
server_busy
environment_unavailable
execution_failed
copy_failed
digest_mismatch
resource_changed
durability_uncertain
backend_unavailable
unsupported_platform
internal_failure
```

Existing version, operation, field, malformed-path, invalid metadata,
oversized, cancellation, timeout, response, and transport codes remain in use.

Public error messages are fixed summaries selected by code. They never embed
raw backend or syscall text. Paths, executable and argument values,
environment names or values, payload content, hostnames, endpoints, IP
addresses, ports, sockets, URLs, headers, tokens, or credentials do not cross
the protocol error boundary. Internal errors remain unwrap-compatible where
needed for cleanup and tests but are omitted from JSON.

## Environment semantics

The v1 wire intentionally carries environment name and source only. It cannot
faithfully carry caller values. The server therefore never reads `os.Environ`,
looks up an ambient variable by request name, infers a literal value, or
silently substitutes an empty value.

Each requested entry must be resolved by an injected
`EnvironmentResolver`. The default resolver rejects every requested entry with
`environment_unavailable`. Secret-source entries fail closed in L4; L8 owns
their live activation and are rejected before the resolver is called.
A typed-nil resolver is treated as absent and selects the same rejecting
default; it must never reach a method call or panic.

The Linux backend always passes a non-nil environment containing only its
validated fixed base environment plus explicit resolver results. Duplicate
names, NUL bytes, malformed assignments, and invalid resolver output are
rejected. Empty `BaseEnvironment` selects the fixed image-owned
`PATH=/usr/local/bin:/usr/bin:/bin`, `LANG=C`, and `LC_ALL=C`; it never selects
the server's ambient environment. Values exist only in the live exec plan and
are never logged or persisted.

## Linux execution semantics

Exec is direct argv execution with no implicit shell. The executable is either
an absolute path contained by one configured `ExecutablePaths` root or is
resolved by basename through those roots; ambient `PATH` is not consulted.
Empty `ExecutablePaths` defaults to `/usr/local/bin`, `/usr/bin`, and `/bin`
inside the guest. Paths and files are validated at construction/launch without
entering public errors. The prepared-host test uses an explicit test-only
executable-root list.

The backend identifies an interpreter script only by reading the first two
bytes through the already-pinned executable descriptor. For that case,
`exec.Cmd.Path` references a child-only inherited descriptor; this preserves
the same executable inode across `execve` and the interpreter reopen. The
script must itself have passed the configured executable-root containment and
regular executable-file checks. The descriptor is never persisted, exposed in
protocol metadata, or shared with another command.

The requested work directory must be beneath `GuestRoot`. It is opened from
the pinned workspace root with:

```text
RESOLVE_BENEATH
RESOLVE_NO_MAGICLINKS
RESOLVE_NO_XDEV
RESOLVE_NO_SYMLINKS
```

and verified as a directory. The opened descriptor is registered in
`exec.Cmd.ExtraFiles`, and `Cmd.Dir` is the server-constructed
`/proc/self/fd/<source-fd>` path. On the supported Go/Linux launch path, chdir
resolves that already-open descriptor before inherited descriptors are
remapped. No request path is reopened. A subprocess regression test coordinates
replacement of the original path between open and start and proves the child
remains in the pinned directory.

Stdin is decoded and bounded before launch. Stdout and stderr use independent
bounded writers that retain the permitted prefix, continue draining discarded
bytes, and set `truncated=true`. Returned binary bytes are base64 encoded.
Non-zero exit is a normal `ExecResponse`.

Every process starts in a new process group. Linux `waitid` with `WNOWAIT`
observes leader exit without reaping it, so the leader continues to anchor its
PGID while cleanup signals are sent. Cancellation, timeout, shutdown, and
transport loss cancel the live operation context. After all descriptor,
environment, and command preparation, the backend checks that context again
immediately before process start; an already-canceled operation returns
without launching the executable. After launch, cancellation, timeout,
shutdown, output-pipe failure, or observed leader exit sends `SIGTERM` to the
group,
waits a bounded grace period, sends `SIGKILL` if necessary, and only then calls
`Wait` once to reap the leader. The same termination grace configures
`exec.Cmd.WaitDelay`, bounding pipe-copy cleanup when an escaped descendant
retains stdout or stderr after the leader exits; forced pipe closure returns a
fixed `execution_failed` response. Request cancellation and deadlines remain
authoritative throughout process and output cleanup, including after leader
exit; cleanup observes them, closes retained output pipes, and returns the
matching fixed request error instead of a late success. No group signal is sent
after reap, avoiding PGID-reuse races. A signaled exit is reported
deterministically as `128+signal`. Start failures use `execution_failed`
without executable, path, argument, or OS-error detail.

The L4 process-group proof covers the launched command and descendants that
remain in its group. A deliberately escaping `setsid`/`setpgid` descendant is
outside the standalone L4 server kill guarantee, but cannot keep the parent
exec operation blocked through inherited output pipes. L5 must run the server
as a dedicated unprivileged guest identity within the guest PID/cgroup/mount
topology and prove whole-guest teardown, which contains such an escape. L4 does
not present process groups alone as an adversarial guest-isolation claim.

The backend's fixed effective defaults are 512 KiB stdin and 256 KiB for each
output stream. Smaller request limits win. The existing protocol maxima are
ceilings, not promised effective capacities.

## Linux copy and containment semantics

Protocol paths must be normalized absolute paths beneath `GuestRoot`.
Contained resolution is descriptor-relative through the pinned root and
`openat2`; lexical validation is necessary but not sufficient.

Copy-in:

- accepts one regular-file payload;
- requires exact lowercase `sha256:<64 hex>` and verifies it before mutation;
- requires an existing contained parent directory;
- creates a random same-directory file with
  `O_CREAT|O_EXCL|O_NOFOLLOW` and mode `0600`;
- writes bounded bytes, applies mode `0600`, fsyncs, closes, and atomically
  renames it over the destination;
- fsyncs the parent after publication; and
- removes its temporary file on every pre-publication failure.

The atomic rename is the publication commit point. Cancellation, digest
mismatch, oversize input, and write/fsync/close failures before that point
preserve an existing destination. Cancellation is masked from rename through
the parent fsync attempt. If parent fsync fails after publication, the server
returns `durability_uncertain`: the new destination is visible but crash
durability is not proven. The response on success always acknowledges exact
size and digest.

Copy-out:

- first opens an `O_PATH|O_NOFOLLOW` descriptor through contained resolution;
- verifies that pinned descriptor is a regular file with link count exactly
  one, rejecting symlinks, directories, multiply linked files, devices, FIFOs,
  and sockets before any readable open;
- reopens only that server-owned descriptor through
  `/proc/self/fd/<source-fd>` as `O_RDONLY|O_NONBLOCK`, then verifies
  matching device/inode/type before reading;
- reads at most the effective limit plus one byte;
- compares pre/post inode, size, ctime, and mtime and fails
  `resource_changed` on mutation;
- returns base64 bytes, exact size, and SHA-256; and
- never follows mount crossings or magic links.

L4 does not copy directories, preserve ownership or arbitrary modes, or
support sparse/chunked/resumable transfer. L5 additionally proves the
dedicated guest UID and mount topology; L4 nevertheless rejects multiply
linked copy-out files rather than deferring hard-link containment.

## Concurrency and cleanup

The default state-changing concurrency is one. A positive `MaxConcurrent`
creates that many slots. Readiness bypasses the state-changing semaphore.
Admission is nonblocking: saturation returns `server_busy` immediately and no
request queue is created. A context already canceled before admission returns
the matching canceled/timeout code.

Backend `Close` is called once with the internal shutdown context after
in-flight operations end. Shutdown removes only temporary files and
non-escaped process-group members owned by this server instance. It does not
delete workspace files, runtime state, endpoints, sockets, mounts, Firecracker
resources, or any resource it did not create. A transport or backend that
violates its bounded cancellation/close contract moves the server to `failed`;
it is never reported stopped or ready.

## Capability honesty

An endpoint, process handle, API socket, or configured transport is not proof
that the guest server is ready. L4 removes the current endpoint-only
microVM exec/copy capability advertisement from `sandboxd`.

L4 leaves microVM worker capabilities lifecycle-only. L5 may advertise exec,
copy-in, and copy-out only after an exact v1 readiness handshake succeeds for
the corresponding live guest/runtime. Malformed, unsupported, failed,
not-ready, stale, or mismatched readiness evidence remains lifecycle-only.

The L4 implementation updates the historical Phase 40 document and guards to
say that its endpoint adapter does not itself authorize capability
advertisement.

## Red-first acceptance

The red commit precedes implementation and covers:

- exact additive error-code/envelope JSON;
- strict request and response JSON, including duplicate nested keys;
- version, operation, and canonical readiness behavior in every server state;
- zero backend calls for malformed, unknown, oversized, canceled, or busy
  requests;
- exec stdin, binary output, non-zero exit, independent truncation,
  environment fail-closed behavior, timeout, cancellation, shutdown, process
  group termination, and reap;
- copy round trip, exact digest, oversize, atomic replacement, existing-target
  preservation, mode, temporary-file cleanup, mutation detection, traversal,
  prefix confusion, symlink/swap, mount/magic-link, directory, FIFO, socket,
  and device rejection;
- fixed public error redaction against path, endpoint, argument, environment,
  token, header, and payload canaries;
- concurrency, idempotent shutdown, file-descriptor/goroutine/process cleanup,
  and race behavior;
- server import/source boundaries and fake-only default scope;
- endpoint-only capability removal; and
- client rejection of unknown or duplicate response fields.

The capability red tests flip the endpoint-only expectations in
`cmd/phase40_microvm_guest_agent_transport_guard_test.go`,
`cmd/sandboxd_test.go`, and the Phase 40 docs guard. The server package adds
parsed import and source guards that preserve the root protocol package's
existing data-only guard while rejecting network listeners/dialers, HTTP/RPC,
ambient `os.Environ`, implicit shell execution, raw public error forwarding,
Docker sockets/APIs, command/factory/worker/execution/workspace imports,
Firecracker/host imports, provider/runtime adapters, Podman, and cloud SDKs.

Default tests use injected transports/backends and temporary directories. They
do not bind listeners, start daemons or Firecracker, access KVM, use vsock,
pull images, use Docker/Podman, contact a provider, require credentials, or
make network calls.

The prepared-Linux test is explicitly tagged
`l4_guest_agent_server_integration`, runs the production server and Linux
backend through an in-memory transport, and proves real exec/copy,
timeout/cancel, containment, and cleanup. It uses a disposable unprivileged
user/mount namespace for mount-crossing and magic-link negatives and removes
all mounts and processes it creates. Once selected by its build tag it must not
skip; non-Linux execution, missing `openat2`, unavailable prepared user/mount
namespace capability, or missing required Linux process/filesystem behavior is
a blocking failure.

## Verification commands

```sh
go test -count=1 -timeout=180s \
  ./internal/sandboxruntime/microvm/guestagent \
  ./internal/sandboxruntime/microvm/guestagent/server

go test -count=1 -timeout=180s \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  -run '^Test(GuestAgent|L4)'

go test -count=1 -timeout=180s ./cmd \
  -run '^Test(L4GuestAgent|Phase40MicroVM|Sandboxd.*GuestAgent)'

go test -race -count=1 -timeout=240s \
  ./internal/sandboxruntime/microvm/guestagent \
  ./internal/sandboxruntime/microvm/guestagent/server \
  ./internal/sandboxruntime/microvm/firecrackerhost

test "$(go env GOOS)" = linux
go test -list '^TestL4PreparedLinuxLocalServerE2E$' \
  -tags=l4_guest_agent_server_integration \
  ./internal/sandboxruntime/microvm/guestagent/server |
  grep -qx 'TestL4PreparedLinuxLocalServerE2E'

go test -race -count=1 -timeout=180s \
  -tags=l4_guest_agent_server_integration \
  ./internal/sandboxruntime/microvm/guestagent/server \
  -run '^TestL4PreparedLinuxLocalServerE2E$'

GOOS=darwin GOARCH=amd64 go test -exec=true -count=1 -run '^$' \
  ./internal/sandboxruntime/microvm/guestagent \
  ./internal/sandboxruntime/microvm/guestagent/server \
  ./internal/sandboxruntime/microvm/firecrackerhost

GOOS=windows GOARCH=amd64 go test -exec=true -count=1 -run '^$' \
  ./internal/sandboxruntime/microvm/guestagent \
  ./internal/sandboxruntime/microvm/guestagent/server \
  ./internal/sandboxruntime/microvm/firecrackerhost

go test -count=1 -timeout=420s ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run gofmt verification on all changed Go files. Run
`golangci-lint run ./...` only when `command -v golangci-lint` succeeds.

## L5 handoff

L5 builds reproducible guest kernel/rootfs assets containing this server,
adds guest AF_VSOCK and the host-side bridge/framing lifecycle, configures the
Firecracker machine, binds readiness evidence to the live runtime, activates
capabilities only after the exact v1 handshake, and proves real guest
readiness/exec/copy/timeout/cancel plus teardown. No L4 result is a
Firecracker, image, vsock, microVM-isolation, network-enforcement, credential,
OCI, or strict-default proof.
