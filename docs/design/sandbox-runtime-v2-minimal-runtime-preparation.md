# Selected minimal preparation and release composition

Status: first compiling RED only, based on `347331910718c4f967d27fa7b7624021152813e5`.
This refines section 2 of the [constructor design](sandbox-runtime-v2-minimal-runtime-constructor.md)
and the accepted [host controller design](sandbox-runtime-v2-minimal-host-controller.md).
It follows the [Linux completion architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [minimal L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md).
No executable delegate, controller task, readiness event, guest, or producer is
activated by this proposal. All six/seven-role behavior remains unchanged.

## Existing consumer and missing behavior

The accepted `newMinimalControlLinuxRuntime` revalidates actual sealed admission,
then `assembleJailerRecoveryLinuxRuntime` retains three asset duplicates, cleanup
key, reconnect listener, full eight-role store binding, namespace projection,
and the original manager/starter/coordinator. Its executable delegate remains
unavailable. That constructor is the eventual consumer of this lifetime, not a
second supervisor or another ownership store.

The gaps are concrete:

- `l8_runtime_owner_runtime_linux.go:serveBootstrap` validates the packet, peer,
  received namespace descriptors and selected projection, but calls
  `HandleBootstrap(context.Background(), ...)` and stops reading after reply.
- `jailer_recovery_runtime_linux.go:startChild` replaces caller lifetime with a
  fresh Background-based 30-second containment budget. It cannot observe
  original-channel loss during preparation.
- `l8_runtime_owner_supervisor.go:HandleBootstrap` already provides the required
  genesis → armed PID/start at revision 1 → Release → revision 2 ordering. Its
  `StartChild func()` and `Release func()` closures need no ABI/schema change.
- `jailer_recovery_starter_linux.go` holds `starter.mu` during arming receive and
  release send. The send has no selected cancellation or absolute-deadline check.
- `recoveryAuthority().current` only accepts genesis revision 0, and
  `strictJailerCgroupLease.verifyForLaunch` rejects an already-launched cgroup.
  Neither can be reused as a revision-1, post-clone release check.

The selected path will retain the existing FSM and install concrete selected
closures. It will not introduce a callback-configurable launch framework.

## One lifetime, three different deadlines

Create a private `minimalControlPreparation` after independently revalidating
sealed admission and before shared assembly allocates retained resources. Take
`P` only from that validated config's `PreparationDeadlineUnixNano`, not a mutable
callback copy or a new duration. Reject already expired `P` before allocation.
Recheck cancellation/deadline across selected assembly and before returning its
retained owner; late assembly failure closes only the locally owned resources.

The object owns a cancellation context without a deadline and a preparation
child context whose absolute deadline is `P`. It also owns one sticky atomic
state, a completion channel for preparation, and later the original-channel
monitor. Its constructor is internal to the selected runtime; zero/missing
selected lifetime fails closed. There is no generic request-supplied cancel,
clock, callback, or FD authority.

The executable supplies no existing caller context. Creating the owned root
once is legitimate; replacing it inside selected start/store work is not.
Explicit owner cancellation and original-channel loss latch cancellation before
canceling the context. The immutable-P observer remains active through stage
completion, revision 2, reply and until the future HLMINRD1 notification has
actually been published successfully. Neither stage success nor a successful
`serveBootstrap` return completes that lifetime or disposes its watcher. Only
successful publication may stop/join the admission observer without canceling
the continuing owner context; owner failure instead cancels and joins it. If
it has already run, successful work cannot erase its cancellation. The original
channel monitor continues after publication until owner shutdown.

Selected `StartChild` is a closure over this object's context. Derive its stage
context with deadline `min(P, stageStart + 30s)`, retaining the existing bound
currently expressed by `l8RuntimeOwnerContainmentBudget`. Do not reset that
deadline at each operation. Pass it through the existing coordinator, cgroup
creation, lifecycle, creating thread and armed-gate wait. Bound arming by the
smaller of remaining stage time and the existing five-second handshake cap.

The preparation context, not the narrower child-stage context, governs genesis,
revision 1, release and revision 2. Release gets no fresh stage budget. A stage
success can still fail release because `P` has elapsed.

After release admission, retain exactly one conservative timestamp `R` and
compute `D = min(P, R + 15s)` once. The later controller receives this original
`D`, never a timestamp taken after send, revision 2 or reply. Its existing
`A = min(D, prelude + 5s)` and transport-origin hard lifetime remain independent.
Completing staging or sending BootstrapPublished does not end owner lifetime.
Only later successful HLMINRD1 publication ends the admission observer, not loss
monitoring; local controller readiness alone is insufficient.

Existing cleanup contexts remain independent and bounded: canceled launch
context cannot suppress cgroup kill/empty checks, root cleanup, durable terminal
checkpoint or exact identity release. This does not make currently synchronous
filesystem calls forcibly cancelable; check their result/context before the
next irreversible phase and retain uncertainty on failure.

## Original-channel reader transfer

Use the actual socket already admitted as the first eight-role FD. Before the
consumer returns, own a CLOEXEC duplicate with an explicit joined lifetime;
never close the executable/admission callback's borrowed FD.

The existing bootstrap receive is the only reader initially. Bound it by the
smaller of remaining `P` and five seconds, with the same retained-FD cancellation
interruption discipline; cancellation does not need a second reader. After exact peer,
BootstrapStart, namespace-kind/dev/inode and selected projection checks, and
before genesis or launch, transfer its receive role to one monitor. Clear the
five-second receive timeout before starting that reader. Keep independent
bounded send handling; clearing receive timeout cannot accidentally authorize
an unbounded bootstrap-reply send.

The monitor uses the existing bounded seqpacket receiver, closes any received
SCM_RIGHTS copies, and treats EOF, receive error or ANY packet/data as loss.
There is no second valid parent-to-supervisor operation on this original
endpoint after BootstrapStart. Cleanup uses the existing reconnect endpoint.
The monitor only latches cancellation and signals loss; it never invokes
containment or an operation that joins itself. It must not wait for owner,
coordinator, selected-runtime, controller or starter locks to publish loss.

The task owning shutdown calls `shutdown(SHUT_RDWR)` on the retained endpoint
to unblock receive, joins the monitor, then closes only its duplicate. It must
not call raw Close while another goroutine might use that FD number. Parent
loss observed before release admission prevents release. Physical EOF not yet
received cannot be retrospectively ordered ahead of a successful admission.

Returning BootstrapPublished leaves this monitor alive. The future controller
and HLMINRD1 publisher share that lifetime and the original sole writer's
ordered reply/event sequence; neither is implemented in this stage. The actual
producer retains L7 Session/proxy ownership. Channel loss requests J containment;
J cleanup alone is never network cleanup proof.

## Revision-1 currentness, atomic admission and retained gate I/O

The selected closure returned as `child.Release` runs only after the FSM's
revision-1 durable readback. It performs a new narrow selected currentness
check over existing owners, not an invocation of the genesis-only callback:

1. Load the current canonical eight-role record from the same retained store.
   Require exact revision 1, starting/none state, full admitted correlation/job,
   armed PID/start observation and same nonterminal busy reservation.
2. Resolve the exact session in the original coordinator, active generation,
   retained identity, staged root, launched cgroup and original lifecycle
   process. Reject missing, stale, cleanup-pending or replaced ownership.
3. Reverify the busy identity, staged root and current limits/anchor of the
   already-launched cgroup. Do not reset `launched`, allocate a replacement,
   call `verifyForLaunch`, migrate a process, or expand its limits.
4. Correlate the retained armed observation with the original lifecycle manager
   process handle/generation/PID and still-live process. Reuse its existing
   process observations and pidfd rules; decoded PID or a boolean fake is not
   production authority. Recheck the original selected session after these
   observations, before final admission.

These checks cannot make the filesystem/process immutable. Their purpose is
last currentness of already-retained exact authority; cancellation and later
failure still contain that same generation. No new serialized authority or
second resource owner is introduced. Stage 2 RED must establish the concrete
manager/process observation seam before adding an injection for tests.

Use an atomic bit state with sticky canceled and one-shot release-admitted bits.
Cancellation sets the canceled bit without acquiring a mutex. Release checks
preparation context, takes `R` immediately before the final admission attempt,
requires the half-open bound `R < P`, then CASes untouched state to admitted.
Observed cancellation or a prior attempt makes that CAS fail. Recheck context
and time before entering send; expiration after admission remains failure, not
permission to wait beyond `P`. There is no reversible 'uncancel' transition.

After admission, bounded actual send uses only the retained gate endpoint. A
cancellation watcher interrupts its I/O with shutdown, not raw Close; timeout
is at most remaining `P` and the existing handshake cap. No latch/starter
operation mutex is held over send, receive, shutdown or joining. Gate arming
must use the same interruption discipline, including cancellation before the
watcher starts. Starter closure first cancels, then waits outside its mutex for
in-flight operations/watchers, then closes its owned gate and observation once.
An operation retains its own CLOEXEC duplicate until both its I/O and shutdown
watcher have joined; closing another alias cannot redirect it to a reused FD.
No duplicate crosses the child boundary or adds a gate FD role.
Never round a positive remaining timeout down to zero (which disables the socket
timeout). Reject insufficient remaining precision instead. The absolute-P
observer remains armed through I/O; a relative timeout is not a rebased budget.

Successful send records released once. Failed/canceled send consumes the
attempt and is uncertain execution: the byte may have reached the gate. Do not
retry or infer 'not launched' from the send error. The FSM's existing Abort
closure performs independent exact cleanup after the preparation operation has
unwound. It does not synchronously join the task currently calling Abort.

The existing owner FSM deliberately serializes bootstrap under `owner.mu`;
this proposal does not refactor that legacy serialization. Independent loss
publication and socket interruption cannot acquire it. Existing local resource
verification locks retain their established ordering; no new lock protects a
blocking socket operation. Shared pre-exec construction must continue calling
`startJailerRecoveryGateCommand` and the retained creating-thread/mount path,
with cgroup-at-clone and additive Pdeathsig unchanged. Keep legacy arming/release
behavior on its old branch; do not duplicate or replace the exec framework.

## Failure and cleanup handoff

Before genesis, failed preparation may close only known constructor-local
handles. After genesis, cancellation can reach `startWithMinimalLease` before
it allocates a generation or returns an identity. Such a record has no terminal
proof. Missing generation, missing reservation, PID zero or `attempted == false`
must not retire it, release a slot, or cause selected ownership to be discarded.
It remains quarantined, including an unauthenticatable starting record if the
existing durable shape cannot safely transition it. This stage does not invent
absence proof or automatic repair for that boundary.

Where the same retained generation exists, bootstrap failure requests existing
containment and `quarantineJailerBootstrap` with independent cleanup budget.
Only existing exact checkpoint/identity/descriptor evidence can become terminal.
Revision-2 persistence or reply-send failure also cancels and contains; neither
a release send nor a missing reply establishes successful readiness.

The future selected runtime serving loop must remain alive for cleanup if owned
resources are unresolved. Its cleanup preflight will cancel and interrupt/join
preparation and later controller work BEFORE entering `HandleController` and its
FSM mutex. The monitor only signals this outer owner; it never runs that join.
The existing callback-scoped controller key cannot outlive its joined consumer.
All-owner loss remains incomplete/quarantined; no second recovery daemon is
proposed. The no-generation record needs a separate accepted proof design if
automatic reclamation is ever required.

## Smallest compiling RED sequence

Only the first checkpoint now has compiling behavioral RED coverage. Second
and third checkpoints remain design-only; their cases are not reported passes
or current executable selectors.

**First checkpoint: context and original-reader transfer.** Add only a narrow
selected closure/serve scaffold which delegates to the current implementation
so tests compile and reach the actual defect. Build on
`jailerRecoveryRuntimeFixture`, the real eight-role admission/request fixtures,
and `withMinimalNamespaceTestBinding`: real sealed measured config/assets,
ordinary retained record directory, actual seqpacket/SCM_RIGHTS and namespace
kind checks, with explicitly fake identity/cgroup/process allocation. Do not
claim the ordinary fixture passed the root constructor or L7 authorization.

- `TestMinimalPreparationBootstrapLossCancelsStart`: actual BootstrapStart,
  pause the existing fake preparation callback, close the original peer, and
  require its received context to become canceled before releasing the fixture.
  Current Background rebasing must fail that assertion. Join on all paths.
- `TestMinimalPreparationKeepsAbsoluteAndStageDeadline`: record the context
  entering the fake allocator and assert the original absolute P/30-second
  minimum, including an expired-P/no-allocation case. Never sleep 30 seconds.
- Positive control must actually persist genesis/revisions 1 and 2 and deliver
  one release packet through the existing real starter socket. Malformed
  BootstrapStart/namespace and ordinary seven-role controls stay independent.

**Second checkpoint: currentness and release.** After the first is reachable,
add RED at durable revision 1 using the actual selected store, real gate pair
and same retained coordinator. Exercise cancellation before release, wrong
revision/busy/session/process, replaced root and stale launched-cgroup controls;
require no release packet. Process/cgroup observations remain labeled fakes
where applicable, not an ordinary file relabeled as a live pidfd. Bind real
manager/process positive coverage through its existing fake HostProcess runner;
request review before adding any otherwise missing observation seam.

Use a task-owned seqpacket pair with deliberately filled send queue to reproduce
blocked send/cancel/Close. Fixture filler is not a valid gate transcript. Count
the actual release packet separately, drain/join every peer, and test retained
duplicate identity against disposal/reuse of another alias. Add one-shot and
simultaneous-cancel tests, exact retained R/D assertions, blocked arming and
deadline-with-delayed-reply cases. A timeout of a fixture is not a product RED.

**Third checkpoint: failure matrix and future handoff.** Cover post-genesis
nil-generation quarantine, partial allocation, revision-1/2 write/readback
failure, reply failure, cancellation after admitted send, uncertain cleanup,
repeated shutdown and no self-join. Reconnect must still reach the same retained
owner. No readiness event/controller execution is credited until the later
consumer is actually wired and reviewed.

## Proposed file ownership and review boundary

New selected code/tests: `minimal_control_preparation_linux.go`,
`minimal_control_preparation_*_test.go`, and narrowly named
`jailer_recovery_preparation_linux.go`/tests if gate-operation ownership needs a
separate file. Coupled edits are limited to the accepted constructor and its
shared assembly (`minimal_control_runtime_linux.go`,
`jailer_recovery_runtime_linux.go`), selected branch in
`l8_runtime_owner_runtime_linux.go:serveBootstrap`, and
`jailer_recovery_starter_linux.go`. Narrow same-owner currentness may require
`jailer_coordinator.go` and `jailer_cgroup.go`; no new issuance or default policy.

Do not edit `HandleController`, cleanup preflight or its validation while that
work is separately owned. Agree the cancel/interrupt/join call boundary with
that owner before implementation. HLMINRD1 codec, post-reply controller consumer,
producer/L7 lifetime, executable selection, worker grant/provider, guest and
assembler remain separate dependent tasks. No guard changes are presumed.

Review each immutable compiling RED before GREEN. Run meaningful focused
selected/legacy tests and race repetitions, then the affected full package,
source guards, vet and Darwin compile. Namespace-root constructor tests retain
their explicit tag and limited scope. No real cgroup, Jailer, KVM or live
prepared-host acceptance is claimed by this design or its ordinary fixtures.

## First compiling RED evidence

`minimal_control_preparation_linux.go` contains two unselected delegates into
the existing bootstrap and startChild. It neither activates the executable nor
implements lifetime ownership. The adjacent RED uses actual eight-role byte
admission with the ordinary fixture's explicit caller-UID seed observation and
actual caller-UID socket peer; it does not bypass or exercise the root constructor.
The PID/owned descriptor in its fake starter remains explicitly a close-ownership
stand-in, not a live pidfd observation. No new process-currentness seam is added.

Run with the pinned Go toolchain and a short task-owned TMPDIR:

```sh
GOMAXPROCS=3 go test -p 2 -race ./internal/sandboxruntime/microvm/firecrackerhost -run '^(TestMinimalPreparation|TestMinimalRuntimeRequestLegacySevenWithoutNICStillValid|TestJailerRecoveryActualSelectedOwnerRetainsCoordinatorAcrossReconnect)' -count=3
```

Observed: nine intended failure events (three tests, each repeated three times),
30 passing test/subtest events, zero skips or race reports. The failures are
original-peer EOF leaving the paused allocator context uncanceled, admitted
absolute P being replaced by a later 30-second deadline, and already-expired P
still permitting one allocation and actual gate release. Every paused fixture
was released and its bootstrap goroutine joined before cleanup/admission return.
The positive actual bootstrap/order, unchanged stage cap, malformed packet and
seven-role/reconnect controls pass. Initial fixture setup failure was corrected
before this evidence; it is not counted as a product RED.

This checkpoint does not yet demonstrate monitor lifetime after the bootstrap
reply, cancellation-interruptible gate I/O, release currentness, or the later
failure/recovery matrix. Those remain explicit requirements before acceptance.

### Explicit setup correction before GREEN

The original 305-line RED assembled an ordinary fake owner before entering the
new serving method. That cannot become a production lazy-initialization path.
The compiling follow-up therefore introduces `beginMinimalControlPreparation`,
which independently revalidates admission, rejects expired P and retains one
CLOEXEC original-socket duplicate plus cancellation lifetime. It grants no
launch/root authority. The ordinary fixture invokes it BEFORE constructing its
fake owner/store/asset resources, binds exactly one matching full-correlation
object to owner and selected runtime, and calls the shared outside-lock
`shutdownMinimalControlPreparation` hook before its handle-cleanup defers.

The exact edits to the original RED are setup-only: initialization/failure
cleanup before fake assembly; explicit matching binding; shared shutdown first
in fixture cleanup; and replacing past-P setup in the expired-bootstrap leaf
with one future sealed P followed by its actual expiry after valid setup. The
three original failure assertions and positive ordering assertions are unchanged.
No P is mutated, resealed or rebased. Separate controls cover already-expired
initialization, missing owner/selected binding, and retained setup context/FD
after bootstrap return followed by explicit joined shutdown.

The setup object tracks the active bootstrap operation so shutdown interrupts
its retained socket, joins outside its mutex, and closes only its own duplicate.
It does NOT yet start the P observer or original monitor, or propagate its
context to the existing startChild. The new post-reply control proves only setup
lifetime retention, not nonexistent goroutine survival. The same focused race
command now yields nine intended failures, 45 passing test/subtest events,
zero skips/race reports, and joined fixtures.

Production constructor and close functions are unchanged; only private pointer
fields were added to their owned structs. Consequently actual root constructor
init-before-assembly ordering, mandatory selected-eight preparation versus
legacy-seven nil, constructor failure cleanup and the production close-hook
consumer remain unimplemented and unverified here. GREEN must wire that exact
placement after the real EUID gate, before shared retained allocations, with
no nil-preparation lazy fallback. Executable activation and shared cleanup-FSM
changes remain outside this checkpoint.
