# Minimal supervisor composition

## Joint fixture private-directory prerequisite

The combined work receiver exposed another below-root fixture prerequisite:
the inherited testing record directory was mode 0755, whereas the unchanged
concrete constructor requires 0700. This early directory rejection is not a
functional publication/work RED. The new joint fixture now makes its same owned
directory private before bootstrap, checks device/inode/UID continuity and
actual mode, and confirms no tracked launch has run. No directory, original
FSM, lifecycle, manager or process is replaced. The original-manager fixture,
149-line joint RED and all production directory checks remain unchanged.
The separate directory control checks the same private FD after bootstrap;
its explicit test rescue still is not selected cleanup-barrier evidence.

Design checkpoint from `0b18f8f2235428311d6eaf3ddea37dca7743a492`.
This refines the [host controller design](sandbox-runtime-v2-minimal-host-controller.md)
under the [Linux completion architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md).
It does not select the executable, attest readiness, or complete a runtime lane.

## Exact missing edges

The selected executable still passes `unavailableMinimalControlSupervisor` to
the eight-role admission callback. `newMinimalControlLinuxRuntime` constructs
retained resources only; `serveMinimalControlPreparation` performs the original
bootstrap and sends revision 2 but does not start a guest controller.
`minimalControlReadinessEventV1` is a codec, not a publisher or receiver.
`handleControllerWithCleanup` has no production serving caller.

The preparation observer currently waits for `preparationCtx.Done()` and always
revokes the owner. Calling `stopPreparation()` after successful readiness would
therefore kill that successful owner. Passing `preparationCtx` to the guest
controller would also cap its whole lifetime at P. Neither is a valid transition
from admission to work. Existing component tests do not prove that transition.

The accepted workload transport also remains process-local. Its actual
`minimalControlReadiness` cannot cross the supervisor's exec boundary. A worker
receiving the public HLMINRD1 event cannot reconstruct that pointer, signing key,
session, or process-manager authority. The old design permits no further parent
messages on that channel. The work bridge below preserves that rule; credentials
remain a separate required bridge, not an event-only implementation claim.

## Supervisor-owned controller

Keep the eight-role admission scope open for the entire selected supervisor.
Use the actual root-gated constructor and existing supervisor options; do not
copy a test owner or substitute a process observation to pass its root gate.
Preserve the six/seven-role routes, packet validators and serving behavior.

After `serveMinimalControlPreparation` successfully sends the immediate
BootstrapPublished reply, capture one selected control owner from that exact
runtime. Capture under selected/coordinator bookkeeping locks, then release
them before any manager/filesystem observation, I/O or join. Require the same
preparation, store, config correlation, lifecycle, coordinator/session, active
generation and retained `strictJailerLifecycleProcess`. Require completed gate
release, not just an admitted send. Resolve that original process in its original
manager; no handle decoded from the record or event is a constructor input.

Read the historical gate window without modifying it. Controller D is its exact
`min(P,R+15s)`; reject a missing, expired or mismatched window. Use `prep.ctx` for
the continuing controller lifetime, not `prep.preparationCtx` or a new background
owner. Construct exactly one `newMinimalControlTransport` and invoke the existing
controller scope. Its connector exclusively owns pre-ACK retry; do not add a
supervisor retry loop. Retain the original owner context and hard expiry H.

Use `withMinimalWorkloadController` and pair it with the work bridge below.
Do not first implement an HLMINRD1 publisher which the provider cannot use.
Selecting that controller alone is not a worker-facing execution implementation.

Start the owned controller/publisher task only after bootstrap has returned,
then enter the existing cleanup accept loop concurrently. A blocked guest
handshake must not block cleanup authentication. The controller scope and its
borrowed key cannot outlive admission; all task completion paths join before the
admission callback returns, and key clearing remains owned by existing scopes.

## One publication and admission-timer transition

Only the original current readiness from that controller may feed the publisher.
Recheck the retained selected generation/process/manager, original-channel owner,
controller currentness, and half-open A/D/P bounds immediately before publication.
Build work-ready HLMINRD2 from the full config digest, supervisor generation,
actual process handle, transport generation, session ID and the shared binding's
session-bound digest. No caller-created event grants authority.

Writing uses an identity-matched owned duplicate of the same original socket,
with one registered operation, bounded remaining A and exactly one ancillary
descriptor: the producer endpoint of a new anonymous work socketpair.
It owns its cancellation shutdown and joins its watcher before closing the
duplicate. The preparation mutex does not cover send, controller observations
or task joins. Failed, late or ambiguous sends retire readiness and shut down
the original socket; a packet possibly reaching the parent does not imply a
successful publication. Do not resend the event or replace its endpoint. A peer
can receive the descriptor before sendmsg returns; the work server must not
dispatch its first request until successful send completion and the post-send
A/D/P publication decision. Failure shuts down original and work I/O, making any
transferred copy unusable without claiming to close another process's FD.

The observer needs an explicit successful-publication stop signal distinct from
context cancellation. Publication and deadline cancellation must serialize at
one retained lifetime boundary, with current absolute time checked there. An
expired P cannot be rescued because its timer callback has not yet run. A
successful stop ends and joins only the admission observer; it does not clear
an existing cancellation, detach `prep.ctx`, or mint another owner. Preserve the
monotonic release/cancel latch and original release timestamp.

Keep prelaunch `prep.current()` and all release guards preparation-bounded.
Post-publication owner checks must use the continuing owner loss latch plus the
original controller/transport H, not repurpose `prep.current()` into a weaker
launch predicate. Close must still stop/join the admission observer whether it
ended by expiry, explicit cancellation, or successful publication. Original
channel EOF/error/unsolicited input continues revoking after P has elapsed.

## Cleanup dispatch and task ownership

The selected actual `serveController` path must call the existing
`handleControllerWithCleanup` with this exact owner's concrete shutdown barrier.
Do not create a second packet/session/sequence classifier. Nil stays the legacy
handler. Authentication, Inspect and invalid/stale cleanup requests must retain
their existing semantics; only admitted cleanup intent triggers the barrier.

The barrier first cancels the continuing context and shuts down original and
guest I/O, then joins publisher/controller/monitor and transport tasks outside
FSM, selected, coordinator and session locks. Only then may the existing FSM
enter its containment callback. Controller or original-channel reader reports
loss; neither calls a close routine that joins itself.

Separate the I/O shutdown barrier from the lifecycle task that may itself enter
containment. A cleanup caller must not join a task waiting for the same FSM
operation. Loss and explicit cleanup converge on the existing selected
coordinator, never a parallel process cleanup authority. Keep reconnect service
and ownership records on uncertainty. Jailer cleanup alone cannot prove L7,
credential, worker-receipt or whole-job terminal cleanup.

## Reachable tests before activation

Use actual sealed admission, BootstrapStart SCM, durable genesis/revisions and
the same retained coordinator/manager. A new fixture may prepare an ordinary
private socket parent before its original fake launch and use existing injected
filesystem/process boundaries. It must not replace an already-launched manager
handle with an independently constructed controller fixture. The existing
preparation fixture deliberately lacks a production vsock-parent proof: copying
its objects into another fixture is not a positive transport prerequisite.

Required behavioral REDs are immediate revision-2 reply before blocked guest
boot, cleanup serviceability during handshake, one real authenticated transcript
and one work-ready event plus adopted endpoint, cleanup joining guest I/O before
containment, and successful readiness surviving original P while continuing to
observe owner loss. Verify real packet bytes/shared binding rather than a mocked
ready flag. Ordinary fake process/cgroup fixtures still cannot prove live Jailer
child authority, namespace entry, KVM, credential use, or terminal absence.

Forward cases include original loss before/during/after publication; expired A/P
including delayed timer observation; wrong selected generation; actual socket or
manager loss; blocked event send; duplicate attempts; borrowed and successor FD
survival; cleanup racing publication; controller errors/panics; all joined tasks
and key/buffer clearing. Preserve all earlier RED files and guards. Run focused
and whole-host races, unchanged cleanup/legacy/command guards, vet and Darwin
compile, followed by integration-owned broad checks at the assembled head.

## Required producer and work bridge handoff

The producer must validate revision 2 and the single work-ready event against
its independently retained supervisor/config/25 prelaunch fields, own the sole
reader, and retire on later EOF/error/extra bytes. Obtain supervisor generation
from the exact owned record plus observed supervisor PID/start identity, not by
using the candidate event as its own expectation. Process handle and transport
generation are late facts originating inside that retained supervisor; the
producer does not independently own its process manager. Reconstruct and check
the full shared binding/session digest before adopting the endpoint. The opaque
candidate stays provider-owned; cleanup reconnect can never reissue it. Receiving
RD2 plus its endpoint does not establish the supervisor's post-send publication
commit: channel liveness cannot distinguish a delayed sender in that interval.
The first work request waits at the supervisor publication gate and fails closed
on publication loss. This slice therefore exposes a candidate work carrier, not
an independently publication-ready result, and selects no worker/runtime success
consumer. A later API promising readiness before first work must obtain an actual
post-commit observation; it cannot just rename this candidate or assume liveness
proves that commitment. No extra acknowledgment is introduced in this slice.

The concrete producer retains a private guestagent.Transport over the accepted
endpoint. Its supervisor peer calls the existing authenticated controller's
workloadTransport, not a second guest backend. Both peers belong to the original
launch owner and close/join before containment. The neutral owner currently has
no workload consumer: a subsequent explicit provider/worker composition must
use this transport through that exact retained owner, never an exported raw-FD
constructor or reconstructed readiness. The credential activation route is still
required and must not use workspace CopyIn for secrets.

## Proposed paired work wire (review before implementation)

This refinement follows independent review of design `675b8478`. It replaces
that checkpoint's optional readiness-only publisher with one combined work-ready
handoff and work bridge. It does not relax HLMINRD1, the six/seven/eight inherited
roles, legacy bootstrap/cleanup validators, or the original monitor's ban on
further parent packets. All earlier nil-rights HLMINRD1 controls remain valid.
No codec or production implementation is authorized by this document alone.

HLMINRD2 has the same bounded metadata layout as HLMINRD1, with its own eight-byte
magic and version 2 at bytes 8..9. The fixed revision fields remain 1 and 2.
It requires exactly one received AF_UNIX, connected anonymous SOCK_STREAM with
CLOEXEC and no listening/pathname identity. This is a new private discriminator,
not permissive fallback in the old decoder. The supervisor creates the pair and
retains both endpoints in its partial owner before fallible setup; successful
transfer releases its local copy of the producer endpoint only after the send
operation joins. The producer immediately owns all received rights and closes
all of them on malformed, truncated, duplicate, extra or mismatched input.
Validate socket kind/address and retain the accepted endpoint under the original
owner. Socketpair SO_PEERCRED describes creation-time credentials; it is not new
authentication of the worker after SCM transfer. Authority comes from the exact
retained original channel and independently correlated supervisor, not FD type,
public metadata, or possession of a decoded event alone.

The paired stream uses bounded length-prefix framing, not JSON/base64 wrappers
around an already encoded guest request. Each frame is a uint32 big-endian body
length followed by this 88-byte fixed header and a nonempty opaque v1 JSON payload.
The prefix is exactly 88 plus payload length (89 through 1,048,664), excluding
the prefix's own four bytes:

| Header offset | Field |
| --- | --- |
| 0..7 | `HLMINWK1` magic |
| 8 | Direction: request=1, response=2 |
| 9 | Operation: exec=1, copy_in=2, copy_out=3 |
| 10..11 | Reserved zero bytes |
| 12..19 | uint64 ordinal, starting at 1, no wrap or replay |
| 20..23 | uint32 maximum response bytes, 1 through 1,048,576 |
| 24..55 | Original 32-byte session ID |
| 56..87 | Original 32-byte session-bound binding digest |

Responses echo the exact operation, ordinal, maximum, session and binding.
Validate the fixed header and body length before allocating payloads; cap both
directions at 1,048,576 payload bytes and the producer response at its smaller
requested maximum. Do not increase existing inner guest limits or add
readiness/credential/arbitrary operations. The bridge treats v1 JSON as opaque;
the existing Client and guest Server retain semantic validation. Reuse existing
framing helpers where they preserve header-first validation; do not change the
shared guest framing protocol to fit this private envelope.

Do not serialize/rebase a Go context or invent an operation timeout on the wire.
The producer retains its original caller context and deadline locally. Admitted
cancellation shuts down its work endpoint; the supervisor's continuous reader
observes EOF/error and cancels the active RoundTrip. The supervisor enforces its
original H and closes the work endpoint on expiry; the producer's sole reader
observes that loss. The producer does not know H from this event or invent a new
one. Both recheck their retained local owner before admission. Existing guest
request timing metadata remains unchanged. The continuous-reader and
blocked-backend cancellation tests are required for this no-wire-deadline choice.

Exactly one producer call is admitted at a time. A pre-canceled or concurrent
losing call sends nothing and does not retire the active owner. Use one continuous
reader per endpoint so EOF still cancels an admitted operation while its backend
or writer blocks. The supervisor has one active operation, no unbounded queue,
and at most one bounded pending next frame while writing the prior response:
the producer may consume that response and send its next request before the
previous write returns. Do not dispatch that pending request until the previous
operation joins, and reject further/premature pipeline input. A full pending
slot must not stop EOF/loss observation. Reader state publication and write-phase
transitions need one owner; no competing probe may consume stream bytes.

Admitted cancellation retires the entire stream and original owner, with no
reconnect, resend, retry or cancellation opcode. Preserve response bytes that
the producer has already completely framed and correlated when cancellation
wins: return those bytes with nil transport error even on the retired connection,
and let the unchanged Client decide whether they establish CopyIn publication.
Bytes received only by the supervisor, partial IPC responses and guessed outcomes
do not qualify. There is no post-cancel drain or wait for a future reply. Clear
owned partial buffers and sanitize errors/panics; do not clear caller-owned input.

Original-channel loss, work stream loss, controller loss, explicit cancellation
and H expiration converge on the same retained owner. The cleanup barrier shuts
down I/O, joins both endpoint readers, active work, writers and watchers outside
locks, then lets existing containment run. Neither reader joins itself. Pair
allocation or transfer failure retains the genuine partial cleanup owner and
uncertainty; neither a closed socket nor a successful event proves VM absence.

The first joint test must use the same-manager prerequisite above, then reach
Client -> adopted IPC endpoint -> original controller -> selected guest
transport/Server with an injected backend and a counted real operation. Include
early first work before send return, ambiguous descriptor transfer, original P
survival, EOF during blocked work/write, bounded pending-next races, exact maximum
copy, pre-canceled/busy isolation, and completed CopyIn after retirement. Ordinary
Unix tests are component evidence; a real exec-boundary handoff and prepared
Linux tests remain later gates. Freeze reached RED before paired bridge and
supervisor-composition GREEN; no executable/default activation, native image,
credential delivery, live result or feature-completion claim follows here.

## Compiling joint RED checkpoint

The private `owned.serveMinimalControlSupervisor(owner, admission)` entry takes
the same original concrete FSM, not an options/controller factory or a new
runtime constructor. It validates the retained store/genesis/UID/preparation,
binds one serving object, and reuses the existing bootstrap. After actual
revision 2 it captures the same selected session, lifecycle, launched process,
manager and completed original R/D window under their bookkeeping locks, then
runs the existing workload controller outside those locks. Its internal
readiness callback reaches only the unavailable `publishWork` stub.

The main task remains the existing cleanup accept/serve loop even when that
controller task returns. Selected cleanup dispatch supplies the retained
`closeIO` stub to the existing authenticated cleanup preflight; legacy nil
serving still calls its unchanged handler. `closeIO` rejects rather than
pretending I/O has joined. No loss-containment task, successful-publication/P
transition, RD2 codec/rights carrier, work server or producer reader exists in
this checkpoint. No executable/default path calls the new entry, and the root
constructor is unchanged. Whole serving return revokes and joins the borrowed
key consumer before admission can end; it does not call `owned.close` or erase
cleanup records/listener because an I/O task ended. Unexpected listener failure
still returns an error, not terminal cleanup or a receipt.

The private producer launch object is only a retained resource holder. Its
`awaitWork` and candidate Transport fail closed; there is no raw FD/event
constructor and no issued candidate. The eventual original eight-role producer
and its single original-channel reader remain unimplemented.

The new ordinary-socket fixture extends the accepted original-manager fixture
only before bootstrap: it keeps that FSM and manager, attaches an ordinary
private cleanup listener, fills the existing concrete cleanup callbacks, and
retains the actual producer peer/directory/config and read-only parent process
observation. It does not call the root constructor or cross an exec boundary.
Its fake process/cgroup and parent/self topology are not native/root/VM proof.
The existing original-manager positive and all earlier RED tests stay intact.

The first behavioral RED reaches actual gate release, durable revision 2,
original-manager shared guest authentication, and an authenticated cleanup
Inspect from the new serving entry before failing for the missing work
candidate. The following Client-to-private-IPC-to-guest Exec assertion is
explicitly unreached, not bridge coverage. A separate passing control blocks
the real guest hello write and proves cleanup authentication/Inspect can still
run. An independent RED sends authenticated StopReap after that control and
receives rejection because the selected cleanup barrier is unavailable, before
any containment. Its later I/O-join/containment assertions are also unreached.

Every fixture task is rescued explicitly: cancel the shared guest, revoke
preparation, shutdown the still-owned listener to interrupt accept, and join the
serving/controller before closing listener FDs or returning the admission.
Borrowed-key clearing is checked after that join. This rescue is not evidence
for the missing selected cleanup barrier or loss-containment behavior. No
source guard is relaxed. Freeze this reached RED for independent reproduction
and approval before implementing the paired bridge, publication or barrier.

The first checkpoint's handoff test sampled live `stream.Correlation()` after
`readyDone`, racing the unavailable publisher's immediate return and stream
Close. Independent review and repetition exposed failures before the intended
candidate seam; those original logs/commit remain evidence, not reliable reached
RED. The test-only correction snapshots retained historical manager/process
handle under `stream.mu` and keeps the actual `authenticated` flag and shared
verifier/backend counts. It neither samples nor claims retained numeric stream
generation: `finish` explicitly resets that value. The unchanged authentication
and `admissionCurrent` paths require a genuine nonzero matched generation, and
`run` rechecks it immediately before publishing `authenticated=true`. That flag
plus original source identity therefore proves a past completed transcript, not
live/current readiness. The original-manager positive's active binding and
generation assertions stay unchanged. No production hold, history field or
observer hook is introduced by this correction.

A second independent fixture race exposed the actual socket between bind and
chmod: the new post-bootstrap controller correctly rejected its temporary 0755
mode before GuestHello while preparation remained current. The fix is confined
to the new joint fixture. An existing private starter wrapper on the same
original runner creates and fully configures the listener **after** the real
manager's stale-socket checks, but **before** delegating the original fake
starter. Binding during staging would be too early: the unchanged manager
correctly rejects a pre-existing socket without a terminal prior owner.

The wrapper retains partial listener ownership before fallible setup, observes
0600 plus the exact original parent while tracked launch calls are zero and
the original starter is not started, then returns the exact original starter's
process/result. The guest adopts that same listener. Actual cgroup launch-FD,
manager/FSM/process, release, timeouts, umask, production checks and all earlier
assertions are unchanged. Explicit rescue closes any partial listener and joins
guest/controller/serving before the original fixture directory is released.
This ordering is fixture setup, not a production readiness hold or authority.
