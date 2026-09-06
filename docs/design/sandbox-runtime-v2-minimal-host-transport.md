# Minimal host transport availability

## Scope and authority

Base: `0a41be54479fe0baf86b45154b650966fe0d96f4`. This is transport availability
for the [selected minimal control design](sandbox-runtime-v2-minimal-authenticated-control-design.md),
not authenticated readiness, strict launch acceptance or credential delivery.
The Linux completion architecture and L8 reset remain authoritative. One fresh
VM belongs to one job; the hostile guest cannot supply terminal absence proof.

The existing `productionL8V2ControlConnector.OpenL8V2Control` first requires
`ProductionVsockBridge.sessionForTarget` and `SessionActive`. That session and
its generation are published only after v1 readiness. A minimal-only guest
cannot satisfy this prerequisite without an unwanted v1 path. Preserve those
legacy contracts; do not insert a fake bridge session, readiness response or
generation to reach port 1025.

## Small private API and retained authority

Implementation ownership is new `minimal_control_transport*.go` and
tests in `internal/sandboxruntime/microvm/firecrackerhost`, plus this note.
No shared extraction is currently necessary: reuse the existing private socket
observation/peer/ACK helpers directly. Do not edit the lifecycle, coordinator,
cgroup, identity, recovery or owner files assigned to the J worker.

`newMinimalControlTransport` receives only the actual retained
`*ProcessLifecycleManager`, exact `firecracker.ProcessHandleMetadata` and
canonical runtime ID. A one-shot `Open(ctx)` returns an opaque stream supporting
`Read`, `Write`, `SetDeadline`, idempotent `Close` and `Done`, with read-only safe
process/transport correlation through `Correlation()`. That method returns a
copy of the exact manager-issued handle and a nonzero process-local counter;
closed or stale streams return a zero handle/counter. No caller PID, UID, socket
path, readiness flag, serialized target, credential seed or generation override
is accepted. Private
per-instance test dependencies may inject existing socket/peer observations,
a context-aware dial, and shorter time limits; they cannot enlarge the fixed
time bounds. The production constructor always uses actual Linux observations
and `net.Dialer.DialContext`. These private test dependencies are trusted bounded
operations, not an arbitrary blocking extension API. The polling interval does
not promise interruption of arbitrary blocking filesystem/injected observations.

Resolve through `manager.resolveLiveProcessIdentity(handle)` and require an
exact handle/source, positive tracked PID, non-nil live process channel, paths
belonging to the exact runtime, and a **non-nil active strict** `vsockProcessOwner`.
`owner.active()` alone is insufficient because nil deliberately means legacy
compatibility in the shared helper. Owner UID must be nonzero, with retained
parent identity and matching strict record. No daemon reconstruction is allowed.
This record is necessary transport authority, not proof of a dedicated UID,
cgroup enforcement, namespace separation or complete strict launch acceptance.

The connector freezes the resolved identity and private socket observation.
Before dial, after dial, after ACK, before/after each application read/write,
and while I/O is pending, require the same manager handle/PID/process channel,
runtime paths, strict owner UID and retained parent device/inode. Reuse
`statVsockSocketForOwner`: exact ordinary socket0600, parent directory0700,
matching owner UID and device/inode. Reuse `verifyVsockPeerForOwner`: actual
Linux peer PID and UID must match the retained process. Replacement, missing
state, changed record, failed observation or process/owner loss closes the
stream; no replacement connection is silently adopted.

## Admission and lifetime

Open one ordinary Unix connection to the tracked Firecracker UDS, then write
only `CONNECT 1025\n`. Reuse the existing bounded 64-byte canonical ACK parser:
one `OK <canonical positive uint32 host-port>\n`, excluding the reserved maximum;
no CR, leading zero, partial/duplicate/trailing buffered content. This ACK is
only transport availability. It does not authenticate the guest or invoke v1,
minimal readiness, execution, helpers, network proof or credential operations.

The complete dial/CONNECT/ACK attempt shares one deadline, no later than the
caller deadline or the existing five-second handshake bound. Pending dial and
read/write must observe cancellation and owner/process loss. Keep the watcher
for the full returned-stream lifetime, not only until ACK. The captured owner
channel currently equals process Done; manager record revocation has no separate
event. Therefore a joined bounded-interval currentness watcher (at most 25ms
between checks, excluding bounded local observation work) also re-resolves the
record/socket and closes on loss. No lifecycle/store framework is added.

Caller cancellation remains authoritative after Open returns. The transport
has the existing 35-minute session hard lifetime as an upper bound; application
deadlines can shorten it but cannot extend it. Closing interrupts blocked I/O,
joins owned watchers, and retires the connection exactly once. `Done` means
only that this stream is closed, not that the process or any host resource is
absent. Watchdog cleanup is not counted as product behavior. Close never signals
the VM, unlinks a socket, releases a UID/cgroup, or advances terminal state.

Allocate fresh process-local transport correlation only after successful ACK
and all final currentness/cancellation checks, against the retained stream.
An overflow-checked process-local monotonic generation is sufficient for this
opaque owner; it is not persistent authority or a substitute for the separately
pinned boot/runtime/job tuple. The process correlation comes from the actual
manager-issued handle, not a guessed prelaunch generation. Failed Open returns
no stream or usable correlation; the connector is consumed even on failure.
No legacy bridge session is published, and no reconnect/fallback is automatic.

Errors are fixed sanitized transport errors; do not print observation causes,
paths, PIDs, UIDs, raw protocol bytes or caller context causes. Safe error identity
may preserve cancellation/deadline classification without raw error disclosure.

## Behavioral RED and implemented verification

At frozen RED `45ea39e6`, `minimal_control_transport_red_test.go` deliberately
adapted the actual legacy connector, without calling `ActivateSession`. Its
ordinary private Unix fixture uses the existing manager/process fixture and
explicitly injected strict-UID
observations; it is not a real Jailer, alternate UID, AF_VSOCK or privileged test.
Every new post-open loss/cancellation case first requires actual CONNECT1025,
ACK and an unchanged byte roundtrip. At RED the old connector returns unavailable
before opening: that is protocol-gap evidence, **not** evidence that its future
post-open negative assertions ran. GREEN replaces only the explicit opener
adapter with the new private constructor; all eight actual CONNECT/ACK/byte
transcripts and pending-I/O/termination assertions are unchanged.

Passing controls retain the legacy no-readiness rejection and existing
`TestJailerVsockOwnerControlReconnect` behavior after real fixture v1 readiness.
`minimal_control_transport_test.go` adds before/during/after admission negatives
for nil or legacy owner, wrong runtime/handle/source, socket/parent type/mode/UID/inode,
peer PID/UID, record loss, malformed/oversized/partial/trailing ACK, pending dial,
ACK timeout, cancellation, one-shot concurrent admission and generation retirement.
Delayed real dial and silent ACK share the same deadline; caller and hard expiry
survive admission and attempted deadline extension. Rejected partial/non-Unix
dial results are closed. Closure leaves the tracked process and socket untouched.
Every rejection must assert no usable stream, no generation, no legacy session,
bounded termination and joined handlers. Default fixtures may use ordinary Unix
sockets as the existing firecrackerhost tests do; no guest/image execution occurs.

Focused implementation and compatibility commands (ordinary Unix fixtures only):

```sh
go test -p 2 -race ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalHostTransport' -count=3
go test -p 2 -race ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(MinimalHostTransportLegacy|JailerVsockOwnerControlReconnect|L8D6V2ControlFoundation)' -count=1
go test -p 2 -race ./internal/sandboxruntime/microvm/firecrackerhost -count=3
go vet -p 2 ./internal/sandboxruntime/microvm/firecrackerhost
```

## Subsequent supervisor consumer (not wired here)

The surviving strict supervisor must pass its actual retained
`strictJailerLifecycle.manager` and the exact `strictJailerLifecycleProcess`
held by the session's coordinator generation, through the J owner's reviewed
private access after gate release. Those references remain in the same
supervisor; the daemon must never reconstruct them from stored PID/UID/path
values. The owner must close this transport before its existing terminal
teardown sequence.

The later controller combines actual process/transport correlation with exact
prelaunch boot/image/job/L7 pins, renders the separately reviewed provisional
late public prelude, and performs the unchanged session handshake/Finished and
minimal authenticated readiness. No signing key, session secret or credential
bytes enter argv/environment/durable metadata. Guest bootstrap, host public boot
producer, actual handshake consumer, L7 NIC correlation, credential activation,
supervisor wiring and rebuilt-image/no-skip live acceptance remain separate
dependencies. Nothing here unlocks current selected live dependency stubs.
