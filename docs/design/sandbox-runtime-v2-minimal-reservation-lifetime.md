# Separate owned cancellation from preparation expiry

Implemented after DESIGN `325ed1f3` and compiling RED `180c55c6`, from
`b8b9cd2c0f0d2947947e9823c862b508d64f403f`.
The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) and
[controller handoff](sandbox-runtime-v2-minimal-host-controller.md) remain binding.
This slice authorizes no provider, readiness, terminal receipt or restart path.

## Actual gap and preserved behavior

At the RED checkpoint, `internal/sandboxruntime/minimal_launch_admission.go:Reserve`
created one context with `WithDeadline(ownerContext, P)`. `Context()`, `ArmDispatch`,
`ClaimLaunch` and provider-binding `Start` use that context; `StartMinimalJob`
receives it. The authorizer's existing `AfterFunc` and explicit `Revoke` both
cancel it. Those preparation semantics must remain unchanged.

`internal/sandboxworker/minimal_launch_dispatch.go:reserveMinimalLaunch` supplies
the manager's retained `minimalContext`, not the initiating request context,
after selection. A successful provider return retains the owner before closing
`dispatchDone`; failed/partial/error outcomes revoke. The service still returns
unavailable, not ready. Explicit cancel and shutdown call `Revoke` while holding
`manager.mu`; provider completion is joined outside that mutex.

A future partial owner needs ongoing service/authorizer/explicit cancellation
after P. The original single context cannot provide it: after its deadline fires,
its Done channel cannot signal a later cancellation. Ignoring DeadlineExceeded
or using `WithoutCancel` would lose authority loss, not extend a valid lifetime.

## Exact additive API

Add only this method to the existing original reservation:

```go
func (reservation *MinimalLaunchReservation) OwnedContext() context.Context
```

Like `Context()`, nil, zero and copied reservations return nil through the
existing `self == reservation` check. Valid originals return the same stored
context on every call, including after cancellation. The accessor neither checks
nor grants readiness, claim, resource ownership, credential authority or cleanup.
It may be observed before claim; allocation still requires `ClaimLaunch` and
the unchanged bounded provider context. No new public handle or schema is needed.

Inside Reserve, create exactly one retained cancellation parent and one bounded
preparation child, only once:

```text
actual ownerContext (including any real deadline)
  -> WithCancel: owned context, exposed by OwnedContext()
       -> WithDeadline(P): existing context, exposed by Context()/passed to Start

authorizer cancellation -> existing cancel-only AfterFunc -> owned cancel
explicit Revoke        -> owned cancel + existing preparation cancel
```

Retain the owned context/cancel in private reservation fields. Keep the current
preparation context/cancel/deadline fields and checks; retarget the existing
authorizer callback to the owned cancel. Explicit Revoke still sets the original
irreversible flag, cancels the bounded preparation context and stops that
callback; it also cancels the owned parent. Calling it repeatedly is harmless.

The owned context inherits the original owner's values and deadline. Its
Deadline is the real parent deadline, if any; preparation's effective deadline
is min(P, parent deadline). Do not replace the parent with Background, reset its
deadline at Claim/Start/return, or silently treat a shorter parent deadline as P.
Cancellation error propagation follows ordinary context semantics. If P alone
expires, only preparation ends. If the actual parent expires or is canceled,
both end. Authorizer close and explicit revoke also end both, even after P.
Consumers requiring an exact absolute deadline check must still check it at
their operation boundary; this accessor is not a timer/currentness proof.

There is no Ready, Extend, Renew, Detach or timer-reset API. A provider may retain
OwnedContext for its future owned task, but Start still receives Context and
remains obligated to return within preparation bounds; this does not preempt an
arbitrary provider that ignores cancellation. A successful fake owner before P
proves only bookkeeping; it does not authorize continued real execution. Actual later
controller/owner hard-lifetime limits remain independently enforced.

## Ownership, cancellation and joins

Reserve and Revoke stay nonjoining under their existing caller locks. Do not
add a goroutine, callback registry, join API or completion framework. The sole
existing authority AfterFunc calls only a standard context cancel function; it
owns no file, process, I/O, provider callback or resource cleanup operation.
Stopping it can race a callback already running. Preserve this inherited
asynchronous behavior: a false Stop result is not proof that the callback has
finished, and this slice does not claim synchronous callback joining.

Revoke cancels both contexts directly, so it never relies on the callback's
eventual execution to publish explicit local cancellation. Authorizer-triggered
cancellation is observed eventually through the callback, with bounded waits
in tests; no hard scheduling latency guarantee is invented. Failed issuance
still calls Revoke and stops its registration. A concurrent cancel-only callback
may finish afterward; it does not invoke provider code or own resources awaiting
cleanup. Do not put a new wait under selection/reservation/manager.mu.

The manager continues to own `minimalActive` and `dispatchDone` joins. Consumers
of OwnedContext must shut down/join their own I/O and tasks outside manager locks
before their resource lifecycle completes; observing Done is not such a join.
This slice does not call Finalize/Recover, close selections/partial owners, release
occupancy, change cleanup_pending publication, or acknowledge terminal success.
Cancel-request waiter cancellation remains separate from owned cancellation.

## Proposed compiling RED and follow-up coverage

The approved RED accessor delegates to existing Context(), exposing the actual
combined lifetime without changing it. Tests reach Reserve/Arm/Start and P
expiry before failing; their later post-P revoke assertions are not RED evidence.
Valid-start and rejection controls execute independently. All following cases
must be reachable at GREEN:

1. Actual neutral reservation: Context's original deadline and provider argument
   remain exact; P expires while the retained OwnedContext remains live. Later
   explicit Revoke, authorizer Close or real parent cancel each cancel it.
2. A real earlier parent deadline is inherited by both; later parent deadline
   survives P only on OwnedContext. Use immutable real contexts, not a mutable
   Deadline fixture. Already-canceled parents/callers still reject Reserve.
3. Nil/zero/copied accessors return nil; copied Revoke cannot cancel the original.
   Original repeated access returns the same context; concurrent revoke/access,
   authority cancellation and P expiration never revive or replace it.
4. Actual worker service: an injected provider claims and returns its exact owner
   before P, with no readiness assertion. Retain both contexts, let P expire,
   then issue authenticated OperationJobCancelV2. Require owned cancellation,
   unchanged exact cleanup_pending/CancelRequested projection and retained owner.
   Repeat for service Close and authorizer Close after P. The public result stays
   unavailable; no finished/started/exit facts may be added.
5. Wrong issuer/principal, cancel requests canceled before admission, and
   initiating-client loss do not cancel a durably accepted owned context. A
   waiter canceled after authorized revoke cannot undo that revoke or abandon
   the manager's joined handoff. Existing store-loss/poison, partial-owner and
   blocked-provider cancel/shutdown tests remain unchanged and prove both
   contexts are canceled where original revocation was required.

Use bounded event waits and join fixture tasks; watchdog assistance is failure,
not cancellation evidence. No VM, socket, real host setup or metadata readiness
shortcut is needed. Run focused neutral/worker lifetime and existing cancellation
tests under race, then adjacent package/guard/vet gates at the fixed GREEN.

Proposed production scope is only `internal/sandboxruntime/minimal_launch.go`
and `minimal_launch_admission.go`, plus narrowly named neutral and worker tests.
No worker production change or source-guard relaxation is expected. Any guard
coupling requires exact source review before a change. Existing tests are unchanged.

## Frozen RED evidence

The focused actual race run selected both new files:

```text
go test -race -p 2 ./internal/sandboxruntime ./internal/sandboxworker \
  -run '^(TestMinimalReservationOwnedContext|TestMinimalLaunchServiceOwnedContext)' \
  -count=1 -json
```

It produced seven expected leaf failures (ten failure events including parents),
14 passing test/subtest events, zero skips and no race reports. Six failures
observe original ownership canceled at P before explicit cancel/service close/
authority close/parent cancel; the seventh observes that a later real parent
deadline was replaced by P. The earlier-parent deadline, exact Start context,
nil/zero/copy, durable initiating-client separation and pending cancel-waiter
controls pass independently. No readiness or provider cleanup is exercised.
An initial new-fixture nil-timestamp dereference was corrected before this run;
that initial log is retained separately and is not final RED evidence.
The independent new controls plus unchanged neutral attempt, worker cancel,
client-disconnect and shutdown regressions pass race three times: 288 passing
test/subtest events, zero failures/skips. Vet passes for both affected packages.
These are RED checkpoint checks, not implementation or live acceptance.

## GREEN scope

The two-file neutral implementation retains WithCancel(ownerContext), derives
the unchanged preparation context with WithDeadline, and cancels both on Revoke.
The existing authority callback now cancels the retained parent. No worker
production or source-guard changes were needed. Both original RED files are
byte-for-byte unchanged and now pass all 24 test/subtest cases, reaching every
previously blocked post-P assertion and the later real parent deadline.
Separate tests cover concurrent revoke/access, a test-owned blocked cancellation
observer without joining it in Revoke, and actual-service partial/error/authority
loss retention. Focused lifetime, cancellation, shutdown, attempt and source-guard
race checks pass three times: 717 passing events, zero failures/skips. Fixed-head
adjacent package, vet and Darwin compilation results are reported in the handoff.
None of these checks selects a concrete runtime or establishes readiness/cleanup.
