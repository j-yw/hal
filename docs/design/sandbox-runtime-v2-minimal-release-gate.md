# Selected minimal revision-1 release gate

DESIGN, first compiling RED and initial narrow GREEN, based on accepted
`f98ee83658856d16a20a4cdaa90ac4dfd437e0db`. This refines only the second
checkpoint of [preparation composition](sandbox-runtime-v2-minimal-runtime-preparation.md).
The [constructor](sandbox-runtime-v2-minimal-runtime-constructor.md),
[host handoff](sandbox-runtime-v2-minimal-host-controller.md),
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md) and
[minimal L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md)
remain binding. The original DESIGN commit changed no behavior; the initial
tests-only RED and narrow observed-loss fix are recorded below. The complete
second preparation checkpoint is not yet implemented.

## Actual seam and unchanged boundaries

`jailerRecoveryRuntime.startChildForPreparation` already passes the admitted
preparation context, capped by the unchanged 30-second stage limit, into the
existing coordinator. At DESIGN it returned `selected.starter.release` directly.
`HandleBootstrap` publishes/readbacks revision 1 and then invokes that closure.
The starter method checks only flags, gate presence and pidfd ownership;
it neither verifies the current record/resources nor observes preparation loss.
It holds `starter.mu` over an uninterruptible selected send. The same starter's
arming receive also holds that mutex and uses a fresh five-second socket timeout.

Only the eight-role closure changes. Legacy seven-role `startChild`, six-role
behavior, packet roles, gate config, FSM ABI and default-off executable remain
unchanged. Reuse the actual `startJailerRecoveryGateCommand`, retained creating
thread, private mounted executable snapshots, clone-time cgroup FD and additive
Pdeathsig. No alternate runner, launch authority, child FD role or environment.

The outer FSM still holds its existing `owner.mu` across bootstrap. This slice
does not claim otherwise or refactor it. Cancellation publication and gate I/O
interruption must not acquire that mutex or any selected/coordinator/starter
mutex. The existing shutdown hook remains outside the bootstrap operation it
joins. No controller, readiness event, cleanup preflight, quarantine transition,
missing-generation repair, producer or executable consumer is activated here.

## Revision-1 currentness from retained owners

The selected release method accepts no caller PID, revision, descriptor or
callback. It closes over the same `selected` and constructor-bound preparation.
It must do these checks before release admission:

1. Briefly capture the original selected session, concrete lifecycle, starter
   and coordinator generation. Require exact coordinator/session identity,
   active state, `hasProcess`, no unresolved staging and the same concrete
   lifecycle in coordinator dependencies. A copied record cannot mint a process.
2. Under the existing selected-store lock/flock, read the actual canonical
   retained record using `readRecord`. Require revision 1, starting/none, full
   admitted config correlation and job, exact armed PID/start, nonterminal
   checkpoint and the same reservation pointer/busy bytes as that generation.
   Match the independent eight-role record binding and FC digest. Preserve the
   selected operation's context/deadline checks after lock waits. Do not reuse
   `recoveryAuthority.current`, whose revision-0-only contract stays unchanged.
3. Reuse `identity.verify(preparationCtx)` and `staging.verifyOwnedRoot()`.
   Add only a launched-cgroup currentness predicate: exact runtime/config,
   prepared AND launched, not quiesced/released, then existing
   `verifyLimitsLocked`/filesystem ancestry and exact limit readback. Do not
   reset `launched`, call prelaunch-only `verifyForLaunch`, allocate/migrate,
   infer empty or change resource controls.
4. Resolve the exact tracked process through the original concrete lifecycle's
   `validProcess` and manager's `resolveLiveProcessIdentity`. Require the same
   canonical handle/source, host paths, intended runtime UID, PID and live Done
   channel. This is process ownership, not vsock/readiness issuance. Before
   Jailer exec, the armed process is still root; its current Linux UID must NOT
   be compared to the future runtime UID recorded by the strict manager.
5. Under `starter.mu`, validate and duplicate its retained armed pidfd with
   CLOEXEC; keep the duplicate through observation, never close a borrowed raw
   number concurrently. Use existing `l8RuntimeOwnerProcessAlive` plus
   `inspectL8RuntimeOwnerProcess` to correlate actual PID/start/parent with the
   retained armed observation and original supervisor. Close both temporary
   observations on every result. No decoded PID alone or ordinary file is a
   live process observation. The production path uses no injected observer.
6. Recheck the same selected/session/generation/process after observations and
   the exact revision-1 store state before final admission. Recheck immutable P
   synchronously after potentially waiting locks/readback, not just timer Err.

Preserve existing local lock ordering: selected runtime then coordinator when
capturing/rechecking; store then identity for busy correlation. Do not hold a
store or resource lease lock while acquiring selected/coordinator locks. Perform
manager/process observation outside these bookkeeping locks. Resource predicates
retain only their existing local locks. Release all newly acquired locks before
gate I/O or joining. Valid cleanup through the same FSM remains serialized by
the existing owner lock; runtime shutdown first cancels/joins preparation.
These currentness checks are not an atomic filesystem snapshot, outside-Hal UID
dedication proof or permission to reconstruct resources after owner loss.

## One release attempt and original R/P/D

Extend the existing private preparation cancellation latch to one atomic word
with canceled and release-admitted bits. Preserve the existing `canceled.Load()`
test observation through a narrow boolean accessor if its representation changes;
do not keep two independent cancellation authorities or weaken assertions.
`revoke` atomically sets canceled before canceling the owned context, without
waiting for another lock. No operation clears either bit.

After successful last currentness, capture one conservative R immediately before
CAS admission. Require current preparation and the half-open `R < P`, then CAS
untouched state to release-admitted. Prior cancellation or an earlier attempt
rejects. Retain exactly that R and `D = min(P, R + 15s)` as immutable selected
attempt data before send, not timestamps obtained from a later successful reply.
Recheck currentness/absolute P before entering the send. Successful send marks
released once; failure/cancellation consumes admission permanently because the
byte might have reached the gate. No retry or 'definitely unlaunched' inference.

No deadline is rebased. Arming gets `min(stage deadline, now + 5s)` using the
already-derived stage context. Release gets `min(P, now + 5s)`, never a new stage
budget. The P observer survives revision 2 and bootstrap reply as already
implemented; only the later successful HLMINRD1 publication may end it. Later
controller admission consumes this exact D; that consumer is not implemented.

## Retained gate operation lifetime

Add a selected-only gate operation beside the existing starter. Constructor
assembly binds it to the same preparation before launch; missing or foreign
binding rejects selected work. Legacy starter calls retain their old branch.
Each arming/release operation takes one CLOEXEC gate duplicate under a brief
starter lock, registers one in-flight operation, then drops the lock before I/O.
The borrowed/starter endpoint remains owned until all such operations join.

An operation-owned cancellation watcher performs shutdown on its duplicate to
interrupt both send and receive. It never closes a raw FD used by another task.
Use bounded exact seqpacket framing/role checks, close received rights, and
recheck the original context/deadline before/after I/O. Reject sub-microsecond
remaining budget instead of rounding a timeout to zero. Any retry of an
interrupted syscall must stay within the same absolute bound and must not resend
an ambiguously completed packet; no unrelated legacy transport rewrite here.

Starter close cancels active selected I/O and joins outside its mutex, then
closes its own gate/pidfd once. Operation completion joins its watcher before
closing its duplicate. No watcher calls the close operation that joins itself.
The outer preparation shutdown still interrupts the original channel and waits
for bootstrap before closing remaining handles. A failed gate operation returns
the exact created process to existing containment; partial cleanup remains owned.
No new automatic terminal or quarantine state transition is part of this slice.

## Honest compiling RED split

First add behavioral RED at actual durable revision 1, not a missing symbol.
Use the real eight-role admission, selected canonical store, actual bootstrap
SCM receipt and actual gate pair. Pause the original returned Release closure
after confirming durable revision 1. Observe original EOF or unchanged sealed P
expiry, then resume and require no ChildRelease packet, no successful reply and
no fabricated terminal claim. Existing bootstrap success/revision order and
seven-role controls run independently. Later currentness assertions must not be
credited if a fixture fails before their boundary.

There is a concrete fixture correction to agree before GREEN: the current
`withMinimalPreparationFixture` inherits a `coordinatorFakeLifecycle`, no actual
selected lifecycle manager, and a directory FD used ONLY as pidfd-close ownership.
It cannot become positive release-currentness evidence. Keep all its existing
behavior assertions; replace only selected test setup with the existing real
`strictJailerLifecycle`/manager and a test-only HostProcess/starter. The fake
starter consumes the real lease's `withLaunchFD` against its existing fake
cgroup filesystem, so launched state is reached through its real method rather
than toggled by the test. No actual process, namespace entry or cgroup is started.

For the lower process observation control, that fake HostProcess can expose the
current test process PID and its own controllable Done channel. Retain a real
read-only self pidfd/proc observation through the existing inspector. The fake
genesis/owner is explicitly correlated for this ordinary fixture; this is NOT
positive proof of an actual supervisor-created gate child. Fake Signal/Kill
only close the fake Done channel and never signal the test process. This avoids
new production observer injection. If actual fixture constraints make that
composition impossible, report the exact obstacle before adding a seam.

Then add separately reached record/busy/session/process mismatches, fake-root
replacement and fake launched-cgroup readback drift, with zero release sends.
Require the real manager handle/source/path/UID/Done checks to run. Actual
supervisor-parent/child, private mount/clone3/cgroup and live Jailer correlation
remain prepared-host acceptance, not this self-observation control.

The gate-I/O RED is a separate reachable checkpoint: ordinary seqpacket pair,
bounded filled send queue, actual blocked send/arming receive, cancellation/P/
Close and joined tasks. Queue filler is not a valid protocol message; separately
count the ChildRelease packet, preserve successor alias canaries, and fail if a
watchdog rather than cancellation makes progress. Add one-shot/concurrent
admission and exact R/D tests only after their methods compile and execute.

## Ownership, gates and next approval

Expected files: new `minimal_control_release_linux.go` and narrowly named tests;
selected-only additions in `minimal_control_preparation_linux.go`,
`jailer_recovery_runtime_linux.go`, `jailer_recovery_starter_linux.go`; a narrow
launched-only cgroup method and selected-store currentness helper alongside the
existing private owner files. No new observer interface or generic operations
framework. No public/schema/default changes. Source guards stay unchanged;
report any actual blocked operation before requesting a narrow allowance.

Freeze and independently reproduce each meaningful compiling RED before GREEN.
After approved implementation: focused preparation/release/gate and legacy
tests, full firecrackerhost race, affected owner/Phase33 guards, vet and Darwin
compile. Any tagged harmless subprocess or new process/namespace action needs
separate explicit authorization; none runs for this design. This checkpoint
does not implement later no-generation/quarantine recovery, controller/event
publication, producer/L7 cleanup, worker receipt or strict/live acceptance.

## First compiling RED: actual revision-1 loss

The new `minimal_control_release_red_linux_test.go` pauses the actual returned
Release after the unchanged FSM persists revision 1. It independently reads the
canonical selected record, checks the tracked manager handle/paths/Done and
real self pidfd, then observes either original-channel EOF or natural expiry of
the unchanged sealed P. Cancellation, the original reader, its I/O interrupter
and P observer all finish before the fixture resumes Release. Both cases still
receive an actual ChildRelease packet and observe `starter.released=true`.
The later revision-2 transition rejects the canceled context; preventing that
publication is already-green control behavior, not prevention of gate release.

Only new fixture setup is added in
`minimal_control_release_fixture_linux_test.go`; every original preparation RED
file is byte-identical. Before starting, the wrapper replaces the unused
close-only directory descriptor with an actual read-only self pidfd and uses
the real strict lifecycle/manager, pure launch planner and retained owner's
namespace duplication. A test-only starter calls real `withLaunchFD` against
the existing fake cgroup filesystem, checks CLOEXEC, returns only a fake
HostProcess, and verifies the scoped duplicate was closed. Its Signal/Kill
methods close only the fake Done channel; they never signal the observed PID.
The fake owner genesis parent is explicitly set for that self observation.

No current-process lifetime is presented as actual supervisor-child proof. The
fixture does not select the production vsock-parent option because fake staging
does not create a runtime-UID directory. Existing staged-root/identity/cgroup
operations remain fakes. No process launch, namespace entry, host UID change,
live cgroup operation, observer injection or root-constructor bypass is added.

```text
go test -race -p 2 ./internal/sandboxruntime/microvm/firecrackerhost \
  -run '^(TestMinimalReleaseRevisionOne|TestMinimalPreparationActualBootstrapOrderControl|TestJailerRecoveryActualSelectedOwnerRetainsCoordinatorAcrossReconnect)' \
  -count=3 -json
```

The actual run exits 1: six intended failing leaves across three repetitions
(nine failure events including parents), 15 passing control events, zero skips
and no race diagnostic. The independent new tracked positive control reaches
genesis, armed process, revision 1, actual gate send and revision-2 reply with
the original preparation still active. Existing eight-role bootstrap ordering
and seven-role retained-owner/reconnect controls pass independently. Every
blocked bootstrap and cancellation task joins; watchdog-assisted progress is
a fixture failure, not accepted cancellation evidence.

Remaining currentness mismatches, atomic release admission/R/D, interruptible
arming/send, Close concurrency and prepared-host parent/child observations are
not exercised or implemented by this first RED. Existing Abort may genuinely
finish the fake coordinator's cleanup after failure; the test makes no new
absence, terminal, idle or quarantine claim from that behavior.

## Initial narrow GREEN: reject already-observed loss

After RED `0a27f806`, only the selected eight-role returned Release closure checks
the same retained preparation's `current()` before calling its captured starter
release. That existing predicate checks sticky cancellation, the owned context
and synchronous absolute P. Six-/seven-role behavior retains the original
starter callback. All 264 new RED/fixture lines and previous tests are unchanged.

This fixes only loss observed before entry to the old release operation. It does
not make the check atomic with admission or send, check current resources, retain
R/D, interrupt blocked gate I/O or reject cancellation first observed while
waiting for the starter mutex. Those remain separately reproduced/approved
work; no full release-gate or runtime acceptance is claimed.

## Separate compiling RED: retained resource currentness

After narrow GREEN `2ddb13c0`, the new 87-line
`minimal_control_release_currentness_red_linux_test.go` reuses the unchanged
tracked fixture and revision-1 pause. Both cases keep original P/channel live.
One closes only the fake HostProcess Done channel and requires the real
manager's exact handle lookup to observe termination. The other changes only
the fake filesystem's `memory.max` from admitted 512 MiB to finite, page-aligned
1 GiB, requiring the existing exact limit readback to reject that difference.
Neither is a new observer, production seam or real process/cgroup mutation.

Despite those independently observed changes, the current Release still sends
the actual ChildRelease packet, marks released, advances the canonical record
to running revision 2 and reports successful bootstrap. These are new reachable
resource-currentness failures, not repeated evidence for the fixed cancellation
case. Fake cleanup remains through the same owner and all blocked tasks join.

```text
go test -race -p 2 ./internal/sandboxruntime/microvm/firecrackerhost \
  -run '^(TestMinimalRelease|TestMinimalPreparationActualBootstrapOrderControl|TestJailerRecoveryActualSelectedOwnerRetainsCoordinatorAcrossReconnect)' \
  -count=3 -json
```

Actual RED: six intended failing leaves (nine failure events including parents),
24 passing control events, zero skips and no race diagnostics. The initial
EOF/P RED now passes unchanged. No positive record/identity/staging/pidfd
revalidation, R/D admission or interruptible gate implementation is claimed;
their remaining independent boundary cases are not covered by these two leaves.
