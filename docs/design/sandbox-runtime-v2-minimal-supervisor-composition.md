# Minimal supervisor composition

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
messages on that channel. This is a separately required work/credential bridge,
not something an event-only implementation may silently claim to provide.

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

The first composition may use the readiness-only constructor while the work
bridge below is unresolved; it must remain private/unselected and unavailable
as a usable provider. Selecting `withMinimalWorkloadController` alone is not a
worker-facing execution implementation.

Start the owned controller/publisher task only after bootstrap has returned,
then enter the existing cleanup accept loop concurrently. A blocked guest
handshake must not block cleanup authentication. The controller scope and its
borrowed key cannot outlive admission; all task completion paths join before the
admission callback returns, and key clearing remains owned by existing scopes.

## One publication and admission-timer transition

Only the original current readiness from that controller may feed the publisher.
Recheck the retained selected generation/process/manager, original-channel owner,
controller currentness, and half-open A/D/P bounds immediately before publication.
Build HLMINRD1 from the admitted full config digest, actual supervisor generation,
actual process handle, transport generation, session ID and the shared binding's
session-bound digest. No caller-created event grants authority.

Writing uses an identity-matched owned duplicate of the same original socket,
with one registered operation, bounded remaining A and no ancillary descriptors.
It owns its cancellation shutdown and joins its watcher before closing the
duplicate. The preparation mutex does not cover send, controller observations
or task joins. Failed, late or ambiguous sends retire readiness and shut down
the original socket; a packet possibly reaching the parent does not imply a
successful publication. Do not resend HLMINRD1.

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
and one original-channel event, admitted cleanup joining blocked guest I/O before
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

The producer must validate revision 2 and the single ready event against its
independently retained supervisor/process/config/25-field binding, own the sole
reader, and retire on later EOF/error/extra bytes. Its opaque current result must
remain provider-owned; cleanup reconnect can never reissue it.

Before claiming a usable runtime, resolve the actual worker-to-supervisor work
transport and credential activation route. It must call the existing authenticated
controller inside the supervisor, enforce bounded payloads and exact job/session
identity, carry cancellation without automatic retry, retain completed CopyIn
publication, and close/join before containment. A process-local Go interface or
public readiness digest does not provide that route. Any change to the old
original-channel no-further-messages rule or inherited FD schema needs an explicit
supersession design and reached cross-process tests; do not widen a validator or
add a fallback as an incidental consequence of readiness composition.

This checkpoint chooses no new IPC schema. The bridge remains an explicit
blocking dependency for provider activation, credential use and worker end-to-end
acceptance. No executable/default selection, native image, live test, source-guard
exception, public schema change or feature-completion claim belongs to this note.
