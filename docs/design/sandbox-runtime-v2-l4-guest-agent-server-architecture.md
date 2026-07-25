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
type Transport interface {
    Serve(context.Context, Handler) error
}

type Handler interface {
    Handle(context.Context, guestagent.TransportRequest) guestagent.TransportResponse
}

type Options struct {
    Transport           Transport
    Backend             Backend
    EnvironmentResolver EnvironmentResolver
    MaxRequestBytes     int64
    MaxResponseBytes    int64
    MaxConcurrent       int
    MaxOperationTime    time.Duration
    Now                 func() time.Time
}

func New(Options) (*Server, error)
func (*Server) Serve(context.Context) error
func (*Server) Handle(context.Context, guestagent.TransportRequest) guestagent.TransportResponse
func (*Server) Shutdown(context.Context) error
func (*Server) State() State
```

`Transport` owns only acceptance and framing. `Server` owns bounded decoding,
dispatch, operation timing, response encoding, concurrency, and shutdown.
L4 tests use an in-memory transport. L5 supplies the concrete guest vsock
transport.

The server state machine is:

```text
new -> serving -> draining -> stopped
                 \----------> failed
```

`Serve` may run once. A transport failure moves the server to `failed`.
Cancellation or `Shutdown` moves it to `draining`, rejects new state-changing
work, cancels in-flight work, waits for cleanup, and ends in `stopped`.
`Shutdown` is idempotent and bounded by its caller context.

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
    Close() error
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

`WorkspaceRoot` is the private local path of the mounted guest workspace.
`GuestRoot` is its protocol-visible absolute prefix, normally `/workspace`.
Neither value is serialized or included in public errors. Non-Linux builds
provide the same constructor and fail closed with `unsupported_platform`.

Backend construction opens and pins the workspace root, verifies Linux
`openat2` support, and fails closed if the required containment primitives are
unavailable. It never falls back to string-only checks, `os.Root`, or an
unchecked host path.

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

Responses are encoded into the lower of the configured response limit and
`TransportRequest.MaxResponseBytes`. If a successful response would exceed
that bound, the server discards it and emits a bounded
`oversized_response` error envelope. It never emits a partial JSON document.

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
their live activation.

The Linux backend always passes a non-nil environment containing only its
validated fixed base environment plus explicit resolver results. Duplicate
names are rejected. Values exist only in the live exec plan and are never
logged or persisted.

## Linux execution semantics

Exec is direct argv execution with no implicit shell. The executable is either
an absolute image path or is resolved through the backend's fixed
`ExecutablePaths`; ambient `PATH` is not consulted.

The requested work directory must be beneath `GuestRoot`. It is opened from
the pinned workspace root with:

```text
RESOLVE_BENEATH
RESOLVE_NO_MAGICLINKS
RESOLVE_NO_XDEV
RESOLVE_NO_SYMLINKS
```

and verified as a directory. The child changes directory through that pinned
descriptor during launch; it does not reopen the request path.

Stdin is decoded and bounded before launch. Stdout and stderr use independent
bounded writers that retain the permitted prefix, continue draining discarded
bytes, and set `truncated=true`. Returned binary bytes are base64 encoded.
Non-zero exit is a normal `ExecResponse`.

Every process starts in a new process group. Cancellation, timeout, shutdown,
or output-pipe failure sends `SIGTERM` to the group, waits a bounded grace
period, sends `SIGKILL` if necessary, reaps the leader exactly once, and makes
a final best-effort group kill. A signaled exit is reported deterministically
as `128+signal`. Start failures use `execution_failed` without executable,
path, argument, or OS-error detail.

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

Cancellation, digest mismatch, oversize input, or a write failure preserves an
existing destination. The response always acknowledges exact size and digest.

Copy-out:

- opens with `O_RDONLY|O_NONBLOCK|O_NOFOLLOW` through contained resolution;
- accepts regular files only and rejects symlinks, directories, devices,
  FIFOs, and sockets;
- reads at most the effective limit plus one byte;
- compares pre/post inode, size, ctime, and mtime and fails
  `resource_changed` on mutation;
- returns base64 bytes, exact size, and SHA-256; and
- never follows mount crossings or magic links.

L4 does not copy directories, preserve ownership or arbitrary modes, support
sparse/chunked/resumable transfer, or claim that hard links are safe without
the dedicated guest UID and mount topology proved in L5.

## Concurrency and cleanup

The default state-changing concurrency is one. A positive `MaxConcurrent`
creates that many slots. Readiness bypasses the state-changing semaphore.
Saturation returns `server_busy`; queued work is not allowed to grow without
bound. Caller cancellation while acquiring a slot returns the matching
canceled/timeout code.

Backend `Close` is called once after in-flight operations end. Shutdown removes
only temporary files and processes owned by this server instance. It does not
delete workspace files, runtime state, endpoints, sockets, mounts, Firecracker
resources, or any resource it did not create.

## Capability honesty

An endpoint, process handle, API socket, or configured transport is not proof
that the guest server is ready. L4 removes the current endpoint-only
microVM exec/copy capability advertisement from `sandboxd`.

L4 leaves microVM worker capabilities lifecycle-only. L5 may advertise exec,
copy-in, and copy-out only after an exact v1 readiness handshake succeeds for
the corresponding live guest/runtime. Malformed, unsupported, failed,
not-ready, stale, or mismatched readiness evidence remains lifecycle-only.

The historical Phase 40 document is updated to say that its endpoint adapter
does not itself authorize capability advertisement.

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

Default tests use injected transports/backends and temporary directories. They
do not bind listeners, start daemons or Firecracker, access KVM, use vsock,
pull images, use Docker/Podman, contact a provider, require credentials, or
make network calls.

The prepared-Linux test is explicitly tagged
`l4_guest_agent_server_integration`, runs the production server and Linux
backend through an in-memory transport, and proves real exec/copy,
timeout/cancel, containment, and cleanup. Once selected by its build tag it
must not skip; missing `openat2` or required Linux process/filesystem behavior
is a blocking failure.

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
