# Selected controller cleanup preflight

Design based on `2d91b1d18671c8a2721dd01ead69f0e22c129bab`, followed by the
bounded compiling RED below. No selected serving route or shutdown behavior
is implemented.
This is the bounded dependency in section 4 of the constructor design frozen at
`0021de07` (`sandbox-runtime-v2-minimal-runtime-constructor.md`), governed by the
[controller handoff](sandbox-runtime-v2-minimal-host-controller.md),
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md) and
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md).

## Actual problem and source boundary

Paths below are under `internal/sandboxruntime/microvm/firecrackerhost/`.

- `l8_runtime_owner_supervisor.go:964`, `HandleController`, holds `owner.mu`
  across sequence/session checks, `dispatchController` and response caching.
  `dispatchController:1032` loads the current controlled record before dispatch.
- `reinspectAbsence:1160` calls `ContainChild` while that lock is held;
  `jailer_recovery_runtime_linux.go:181`, `contain`, takes `selected.mu` before
  coordinator cleanup. Neither callback may join a controller whose observation
  is waiting for these same ownership locks.
- `finalize:1218` checks the absence tuple, decodes the seed digest, validates or
  derives the exact commit intent, then performs durable transitions and namespace
  closure. Opcode, session and absence tuple alone are insufficient preflight.
- `l8_runtime_owner_runtime_linux.go:325`, `serveController`, already performs
  peer UID, packet-role/rights and actual `AdmitController` handshake checks.
  Every later packet is role-checked before `HandleController`. Keep this order.
- `HandleController` currently adopts a request's session when its local session
  is empty. Direct legacy fixtures rely on this behavior. A nonempty session
  alone therefore does not prove the selected route completed `AdmitController`.
- Exact replay precedes a store load. It returns the cached packet without a new
  transition; namespace replay alone duplicates fresh FDs. Preserve this behavior,
  including the current cached result's `Exit`/files semantics.

The selected controller and its original-channel tasks must be closed/joined
outside these locks, but a forged, stale or malformed cleanup request must never
cause that shutdown. No opcode-only close, preparatory Inspect replay, second
permissive decoder or caller-created cleanup capability solves the problem.

## Smallest proposed API and shared factoring

Keep the existing public-to-package `HandleController(ctx, received)` entry and
six/seven-role serving behavior. Add a private compound implementation:

```text
owner.handleControllerWithCleanup(ctx, received, closeSelectedControl)
    -> existing l8RuntimeOwnerControlResult, error

closeSelectedControl: private func() error, or nil for the legacy path
```

This is a control-flow barrier, not an authorization/absence predicate. The future
selected server binds it only to its same retained lifecycle's concrete shutdown
method. It is not a request field, exported constructor option, arbitrary owner
replacement or true-returning proof callback. The concrete barrier and serving
callsite remain constructor-owner work; this dependency initially tests a counted,
blocked callback against the real FSM. Legacy `HandleController` delegates with
nil, keeping its current single-lock order, observation counts and responses.

Extract, rather than duplicate:

1. The existing replay, sequence and typed-session classification into one private
   side-effect-free locked helper. Reuse existing request decoders. Return only
   local classification data, not an escaping authority token. Preserve legacy
   session adoption in the default caller; selected classification must not adopt.
2. The pre-mutation Finalize logic into a private plan calculation, and its current
   transitions/closure into plan application. The existing `finalize` entry uses
   that same plan once, with unchanged commit-ID function selection, evaluation
   order, error categories and namespace-close failure checkpoints.
3. The existing Commit state and exact whole-request comparison into a shared pure
   check. The current `RetireFinalized` call remains the only retirement effect.
4. The StopReap eligible-state/required-containment-or-reinspection check from
   `reinspectAbsence`; its existing transitions and actual observations stay there.

`owner.commitID` currently selects either `l8RuntimeOwnerCommitID` or the private
`jailerRecoveryCommitID`; both production functions are pure. Use that existing
selection, not a new HMAC/domain implementation. The Finalize plan retains the
computed intent/ack, so default dispatch does not gain duplicate callbacks or
store loads. Selected revalidation compares the complete unchanged source record
before applying that same plan; it must not recompute a plan from changed state.
Do not move the legacy absent-to-finalizing checkpoint past `CloseNamespaces`,
or turn namespace-close uncertainty into a successful cached response.

One additional private session-provenance scalar is necessary: retain the exact
session successfully established by `AdmitController`, only after its existing
transition/ack construction succeeds. Clear it on the existing successful
Close/ControllerLost session reset. The default handler never consults it and
legacy request-based session adoption never sets it. Fresh selected cleanup
requires nonempty equality between this latch and `owner.sessionGeneration`. This is not
a new handshake, credential token, durable field or independently issued proof.

## Compound algorithm

1. **Preserve packet ownership.** The actual server still validates peer/role and
   owns received FDs. The selected compound entry also calls the existing request
   role validator, including exact zero rights for cleanup, before doing any
   selected work. Bound the request to the existing 512-byte packet limit before
   copying its body. Never consume/close the request's FDs here.
2. **Classify under `owner.mu`.** Run the shared classifier. Exact cached replay
   returns through the existing cache path immediately: no barrier, record read,
   commit computation or cleanup.
   Inspect, AcquireNamespaces, Close and rejected/unsupported operations retain
   the default dispatch path; only a fresh StopReap, Finalize or Commit can select
   the barrier. Those fresh cleanup requests additionally require the exact
   admitted-session latch before any legacy session adoption. Wrong sequence,
   status, typed body or session returns unchanged sanitized failure without
   mutating the replay ledger. Cached Close remains replayable after its session
   reset: returning that old packet grants no new shutdown authority.
3. **Validate fresh cleanup.** Load the current record once through the original
   store and require controlled state. Produce the shared operation plan below.
   No Transition, containment, namespace duplication/close, retirement or response
   caching occurs. Snapshot the complete comparable record, exact owner session
   and admitted-session latch, `hasLast`, last sequence/opcode and owned copies of
   the request/cache packet bodies. Do not persist or export the snapshot.
4. **Unlock, then close/join.** Release `owner.mu` before the concrete selected
   barrier. Check the caller's current context and half-open absolute deadline
   before selected preflight and again at unlocked barrier entry; waiting for
   the mutex/store cannot admit an already-canceled or expired shutdown callback.
   No additional bookkeeping mutex surrounds the callback or its waits.
   It must close original/guest I/O before joining the selected publisher,
   original-channel monitor and controller scope. The controller already revokes
   its own session after joining its own I/O/idle-reader tasks, before its done
   signal; preserve that ownership/order. Do not add a third-party Revoke or
   require controller completion before its own deferred Revoke. All selected
   tasks must join before containment. The barrier must not call this FSM, contain
   the VM, close namespaces, retire a record or join its own caller. Those are
   later lifecycle implementation obligations, not proof supplied by this helper.
5. **Reacquire and revalidate.** A barrier failure/panic or expired/canceled caller
   returns unavailable with no dispatch or replay advancement. After successful
   join, reacquire `owner.mu`, require the exact same session/latch/sequence/cache
   snapshot, and load the same retained store again. Require full record equality,
   not revision alone. Missing/poisoned store, owner loss/reconnect, same-revision
   changed fields or another completed request rejects the old plan. After that
   second Load, recheck the caller's Err and half-open absolute deadline
   immediately before applying the plan: reacquisition/readback may outlive the
   caller even when the barrier returned in time. No automatic retry, rebase,
   new handshake or fallback to default dispatch is permitted.
6. **Apply and cache under the existing lock.** Dispatch the validated request
   using the shared plan and revalidated current record, without a third Load or
   re-running the barrier. Keep the normal containment, Finalize and Commit CAS/
   readback boundaries and unchanged successful response-cache update. An error
   keeps the existing sequence/retry semantics; it is not cached as success.

| Fresh cleanup | Required validation before shutdown |
| --- | --- |
| StopReap | Controlled record; running/stopping/uncertain with existing ContainChild, or absent with ReinspectAbsence. Other states reject. No actual absence observation before the barrier. |
| Finalize | Exact typed session, absence revision and observed-at tuple; state absent/finalizing/finalized; exactly decoded 32-byte seed digest. Absent requires the existing revision-overflow check and computed finalizing/target intent. Finalizing requires exact next target, revision bounds and constant-time expected commit match. Finalized requires the existing constant-time expected commit match and produces the same cached finalization ack. |
| Commit | Controlled finalized record and exact whole decoded request equal to current session, FinalizedCommitID and FinalizeTargetRevision. No early RetireFinalized. |

Finalize planning must follow the existing branch-specific checks exactly, not
invent stricter legacy record acceptance. Missing namespace-close capability or
an actual close failure retains its existing application-phase error/checkpoint;
it is not a request-authentication shortcut or resource-absence proof.

An operation valid at preflight can become stale while joining. Its already
admitted same-owner shutdown is irreversible; the second check prevents a stale
store transition, not retroactive cancellation of that shutdown. An in-flight
duplicate is not yet a cached replay: concurrent calls may reach the idempotent
same-owner barrier, but only one unchanged ledger/record snapshot can dispatch.
A later exact cached replay performs no new shutdown or load. No new attempt
registry, request reservation, detached watchdog or lifetime framework is needed.

## Failure ownership and compatibility

The concrete selected lifecycle retains/quarantines incomplete shutdown and all
original handles on uncertain join. The compound helper reports failure without
writing an invented uncertain/terminal record or permitting resource release.
The serving/loss owner must not respond to this error by closing that retained
graph before its existing recovery/containment obligations are satisfied. This
is an explicit integration dependency, not behavior added to legacy serving here.

Replay after Commit keeps its current cached-packet behavior and performs no
store read even if the record has already retired. Namespace replay still issues
fresh duplicated handles only on its existing path. Six/seven use nil barrier;
there are no added store observations, session requirements or cleanup hooks on
their default route. Existing role validators, decoders, record schemas, receipt
domains, credential semantics and source guards remain unchanged.

## Required RED sequence and gates

Use `newL8RuntimeOwnerSupervisor`, `l8RuntimeOwnerTestStore`, actual encoded
handshake plus `AdmitController`, and real packet codecs. No fake successful
session field assignment may establish selected admission. Synchronize test store
mutations with `owner.mu`; a paused barrier allows safe concurrent changes.

1. Meaningful compiling RED: a valid authenticated StopReap enters the real
   containment callback before a counted barrier; assert barrier completion and
   `owner.mu.TryLock` before containment. A blocked barrier must leave store,
   replay state, namespace and retirement counters unchanged while another test
   goroutine can acquire the owner lock. Existing legacy calls are controls.
2. Valid StopReap states, absent/finalizing/finalized Finalize and exact Commit
   reach one barrier and unchanged existing transitions/acks. Cached byte-exact
   replays run no barrier/Load/finalizer/retirement; namespace replay stays intact.
3. Wrong peer/handshake, unestablished session, legacy-inferred-only session,
   wrong token/sequence/status/body/rights, altered replay, forbidden state,
   stale absence tuple, bad seed digest, overflow, invalid finalizing target/HMAC
   and invalid Commit must make zero barrier/destructive calls. Assert full
   state/ledger preservation, not just a returned error.
4. During blocked join, change each session/cache/record identity component,
   perform ControllerLost/reconnect, advance the sequence, fail/poison Load or
   replace same-revision contents. After release, no stale transition or cache
   publication. Concurrent identical attempts cannot both dispatch.
5. Barrier error/panic, cancellation/deadline and incomplete join retain owner
   obligations and never mark cleanup complete. Callbacks/waits hold no new lock.
   The later concrete barrier must additionally prove blocked real application
   Write plus concurrent StopReap closes I/O and joins before containment.

Run focused default/race FSM and selected tests, existing six/seven protocol,
replay/Finalize/reconnect/store regressions, relevant unchanged source guards,
vet and Darwin compile. Freeze/review RED before GREEN. This plan enables no
selected constructor, actual controller shutdown, producer, L7/credential cleanup,
strict default or live VM acceptance.

## Initial compiling RED

The private `handleControllerWithCleanup` seam only delegates to unchanged
`HandleController` and ignores its callback. No production serving path calls
it. The 188-line `minimal_cleanup_preflight_red_test.go` uses actual encoded
packets, role validation, `AdmitController`, its decoded ack and the existing FSM
over `l8RuntimeOwnerTestStore`. It does not assign a successful session directly.
The UID/containment observations remain ordinary injected fixture facts.

`go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalCleanupPreflight'`
compiles and reproduces exactly two failing tests per repetition: authenticated
StopReap enters containment with zero shutdown callbacks, and the request returns
success/absent before entering a blocked shutdown callback. There are six failure
events, twelve passing control/parent events and no skips across three repetitions.
Legacy cleanup, wrong-session rejection and cached replay are reached controls.

The blocked callback's subsequent mutex/state assertions are not reached at RED;
they are future acceptance assertions, not evidence of a reproduced lock deadlock.
Finalize/Commit planning, admitted-only provenance, changed-store/session checks,
post-readback deadline, real I/O shutdown and complete fault coverage remain
unimplemented. No claims about those missing paths follow from this RED.

The unchanged adjacent selector
`^TestL8RuntimeOwner(Admission|Replay|Finalize|Stop|Protocol|Typed)` passes with
`-race -count=3`: 177 test/subtest events, zero failures and zero skips.
