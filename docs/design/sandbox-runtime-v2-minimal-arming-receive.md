# Selected arming receive lifetime

Design only, exact base `d567bec8935235c83f7879be3b26d517fd10aee6`.
This refines the remaining arming paragraph of the complete
[release-gate design](sandbox-runtime-v2-minimal-release-gate.md), under the
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md) and
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md).
The accepted [atomic release admission](sandbox-runtime-v2-minimal-release-admission.md)
and original R/P/D remain unchanged. No extraction, test or implementation is
part of this design commit. Review this exact seam before the compiling RED.

## Actual consumer and held locks

The selected callback currently follows:

```text
serveMinimalControlPreparation
  HandleBootstrap                         owner.mu
    selected.startChildForPreparation      selected.mu; ctx=min(P,entry+30s)
      coordinator.start                   coordinator.mu
        identity.withLaunch               identity.mu
          lifecycle -> manager -> runner  runner.mu
            starter.startStrictJailerNamespaceProcess   starter.mu
              existing gate command + child PID/parent inspection
              receiveL8RuntimeOwnerSeqpacket(owned gate)
```

The final receive is in `jailer_recovery_starter_linux.go`, immediately after
`startJailerRecoveryGateCommand`, actual child HostPID extraction, retained
pidfd/proc inspection and parent equality. It uses a newly installed five-second
socket timeout and keeps starter.mu locked. That is the exact operation to
extract. No new launch, namespace, identity, process-observation or runner
implementation is needed. The manager does not hold manager.mu over this start.
The clone-time cgroup callback has returned before arming receive.

Only starter.mu may be released during selected arming I/O. All outer locks
above remain unchanged. Cancellation and operation completion must acquire none
of them. A created child still returns with the start error to the original
namespace runner, whose existing terminate/reap and uncertain-process retention
remain the containment owner. No error, timeout or socket shutdown proves child
absence or authorizes direct process signals in the new helper.

## Cancellation routes, not implied Close guarantees

| Entry during blocked arming | Existing route to cancellation | Locks before publication |
| --- | --- | --- |
| Original-channel EOF/error/unsolicited packet | Sole original monitor calls prep.revoke | None |
| Original sealed P expires | Existing preparation deadline observer calls prep.revoke | None |
| Original stage context expires/cancels | The same context reaches arming; its Done directly wakes the new watcher | None |
| starter.close | closeMinimalGate calls prep.revoke before starter.mu | None |
| owned.close | Calls shutdownMinimalControlPreparation first; prep.close captures local bookkeeping, then revokes before joining bootstrap | Only brief prep.mu; no owner/selected/coordinator/identity/runner/starter lock |

`prep.revoke` publishes the same atomic canceled bit before context cancellation.
The arming watcher observes the stage context AND the retained preparation
context. It performs shutdown on its operation-owned duplicate, not on a borrowed
integer. The original-channel interrupter remains separate and unchanged.

`prep.close` waits for its bootstrap operation after revoking, but releases prep.mu
before that join. Unblocked arming lets the existing runner perform containment,
the coordinator return, and bootstrap unwind. Only then does preparation shutdown
join its monitor/observer and close its original duplicate. `owned.close` reaches
selected containment and starter cleanup only after that barrier. It is not
called from the bootstrap it joins.

This does NOT make an arbitrary call to `owner.HandleController`,
selected.contain, or runner cleanup interruptible: such paths can first wait for
the outer locks. In particular the separate cleanup-controller preflight must
first acquire owner.mu and has no selected executable serving caller yet. It is
not the cancellation trigger for this pre-revision-1 operation. The selected
executable loop remains unavailable; no live serving/daemon-close claim follows.

## Selected-only extraction and operation ownership

Proposed private method: `starter.awaitMinimalGateArmedLocked(ctx) error`.
Its sole input is the original already-derived context. The retained starter
supplies its own immutable minimalGate/preparation binding, gate and observation;
the method accepts no descriptor, process, PID, callback or observer. The caller
holds starter.mu on entry, and the method returns with that same mutex held.
The actual selected call is inserted only after the existing successful child
inspection, before the existing legacy timeout/receive statements. The nil-gate
legacy start path and its receive body remain unchanged.

First reviewed extraction keeps the old selected timeout/receive/context/role
checks and lock-held behavior inside that method. This permits a compiling
behavioral RED at the real receive algorithm without pretending an unavailable
stub or a fabricated process observation is reached arming. GREEN then changes
only that selected method and narrowly necessary retained gate bookkeeping:

1. Under the already-held starter mutex, require the exact constructor binding,
   current P/context, started/not closed/not released state, owned observation,
   and no prior arming operation or release attempt. Validate the retained socket
   and create one identity-matched CLOEXEC duplicate using the same checks as
   release. Register the operation before dropping the mutex.
2. Capture a conservative arming expiry `B=min(original stage deadline,P,now+5s)`.
   A missing stage deadline rejects this selected helper. No context, P or socket
   wait gets a replacement budget after lock waits. Check absolute B and both
   contexts before and after I/O; reject less than one microsecond remaining
   rather than installing a zero timeout. A local B-bounded child context owns
   its timer; stopping it on completion does not cancel preparation.
3. Drop starter.mu. One operation-owned watcher observes B/stage cancellation,
   preparation loss or normal operation completion. Only cancellation triggers
   `shutdown(SHUT_RDWR)` on the duplicate. Perform one shared bounded seqpacket
   receive; no retry loop or second reader. Require the unchanged exact
   ChildArmed role and zero rights; shared truncation/codec rejection remains.
   Close every returned right on all paths.
4. Stop/join the watcher before closing the operation duplicate. Then reacquire
   starter.mu, record cleanup uncertainty, recheck exact binding, operation slot,
   closed/closing state, context and absolute B/P, and complete the operation
   while returning with the caller's lock held. Completion never calls Close or
   prep.close, and does not need an outer lock. Every error remains sanitized.
5. Close retains its current revoke-first ordering and joins the registered
   operation outside starter.mu before closing its original gate/pidfd once.
   Concurrent close callers share its existing completion/error. The receive
   never joins enclosing bootstrap; preparation shutdown remains its owner.

Reuse the existing private operation slot; do not add a generic operation
framework or another cancellation/admission authority. Arming does not consume
the release `attempted` flag or alter R/D. A release may replace a completed
arming slot but never an active one. Retain the completed slot to reject repeated
arming. Existing pre-armed release fixtures remain valid without manufacturing
an additional readiness flag; only the actual successful start can supply the
real returned Release closure. Failed arming never returns that closure.

## Reachable RED and forward verification

Do not change any existing fixture or behavior assertions. In a new narrowly
named test file, wrap only the existing test fake namespace starter interface:
run its unchanged fake withLaunchFD/start setup, then invoke the extracted method
under the retained starter mutex, passing the exact context received from the
real runner. On failure return the same fake HostProcess plus error so the real
runner's existing fake Kill/Wait cleanup is exercised. There is no new production
injection. The fixture keeps its actual sealed admission, SCM receipt, canonical
store, FSM/coordinator/manager, ordinary gate pair and read-only self pidfd.

Observe that exact bootstrap task blocked in the extracted receive/Recvmsg before
triggering EOF, natural P expiry, starter.close, outside-lock preparation
shutdown, or the actual owned.close entry. The latter must demonstrate that
publication precedes its selected containment; do not substitute only a direct
revoke call for that whole-entry case. Assert the actual canceled latch/context,
no ChildRelease/revision-2 reply, and join within a bound shorter than the old
five-second timeout. Assert
the outer locks remain held while cancellation reaches the watcher; only the
starter lock becomes available. A watchdog rescue happens only after recording
failure and never counts as cancellation progress. All tasks join on failure too.

Separate controls send the real ChildArmed packet, reach the real revision-1
record/release/revision-2 reply, and preserve the legacy seven-role start control.
At arming failure the current coordinator may perform genuine fake cleanup, so
assert no released/running publication rather than inventing a permanent
revision-0/idle/quarantine state. The self pidfd is not a supervisor-created child.

Forward cases cover malformed/wrong-role/rights/truncated packets, EOF, expired
entry, exact shorter stage/P bounds, context loss after receipt, one receive under
concurrency, active arming versus release, successful arming followed by the one
original release, concurrent Close, watcher/duplicate joins, retained socket alias
identity, successor descriptor canaries and repeated cleanup. Lower helper tests
may use a real shortened derived stage context; those are not proof that the
unchanged actual 30-second stage elapsed. No production clock/observer seam.

After GREEN, run focused arming/preparation/release/gate/legacy races, full
firecrackerhost races, unchanged owner/Phase33 guards, vet and Darwin compile.
Report any actual source-guard conflict before changing a guard. No privileged
launch, signal, namespace, host cgroup, executable/default, provider, guest,
packet/schema, readiness publication or cleanup-authority change is in scope.

## Priority and approval checkpoint

Arming is the smaller actual composition prerequisite: interruption must work
before starting the future controller from the same post-release owner. Readiness
event adoption is currently only a stateless codec; its actual sole-reader,
independent tuple/binding authority, original-channel loss and publisher lifetime
remain a larger separate slice. Activating the executable would also compose
those missing owners, so it should not be used as this receive test seam.

This design requires supervisor approval before extraction/RED, then frozen RED
reproduction before GREEN. Its only verification is source/call/lock tracing and
`git diff --check`; no new behavioral or live acceptance result is claimed.
