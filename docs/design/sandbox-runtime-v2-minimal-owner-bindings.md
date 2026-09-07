# Selected minimal retained cleanup bindings

Status: initial neutral binding implementation after frozen RED `a48d67da`,
following approved design `0e03e48a` at base
`ea0ae1e2f2c88300701a6fc69bbf235ff22bf4e4`. The original RED passes; the additional
validation matrix below is still pending. No worker consumer, recovery activation,
or cleanup proof is included. The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md),
[selected host handoff](sandbox-runtime-v2-minimal-host-controller.md), and
[accepted cancellation coordination](sandbox-runtime-v2-minimal-worker-cancel.md)
remain authoritative. This proposal refines the next neutral binding slice only.

## Actual source boundary

All paths below are relative to the repository root.

- `internal/sandboxruntime/minimal_launch.go` declares the constructor-injected
  `MinimalJobRuntimeProvider`, cleanup-only `RecoverMinimalJob`, and exact-owner
  `MinimalJobRuntimeOwner.Finalize`. `MinimalLaunchCleanupReceipt` contains only
  identity, commit ID, and revision. Those public scalar fields are bookkeeping,
  not independently verifiable cleanup authority.
- `internal/sandboxruntime/minimal_launch_admission.go`, `Start`, retains the
  original nonnil provider owner before checking its error, identity, cancellation,
  and reservation claim. `MinimalLaunchOwnerBinding` currently has no operational
  methods, self guard, or callback serialization. Partial ownership must survive
  adding those methods; a Start error must never become permission to discard it.
- `internal/sandboxworker/minimal_launch_dispatch.go`, `finishMinimalDispatch`,
  retains that binding before closing `dispatchDone`.
  `minimal_launch_cancel.go` irreversibly revokes the original reservation and
  joins dispatch outside the manager mutex. It deliberately leaves the private
  record pending and occupancy retained; it calls neither Finalize nor Recover.
- `internal/sandboxruntime/microvm/firecrackerhost/jailer_recovery_client_linux.go`,
  `stopAndCommit`, verifies StopReap absence, sends Finalize, reads the matching
  finalized record, then sends Commit immediately. It does not expose a worker
  persistence barrier between Finalize and host-record retirement.
- `internal/sandboxworker/job_manager_v2.go`, `recoverStoredJobCredentialsV2`,
  illustrates the separate legacy order: validate absence, obtain receipt, save
  the worker receipt, Commit the host record, then save the worker terminal state.
  `replayStoredJobCredentialRuntimeRecoveryReceiptV2` resumes the saved receipt.
  The selected wrapper must not silently substitute J-only `stopAndCommit` for
  that crash-safe whole-job ordering.

## Proposed API and smallest ownership unit

Add these methods/types in the neutral `internal/sandboxruntime` package:

```go
func (owner *MinimalLaunchOwnerBinding) Finalize(ctx context.Context) (MinimalLaunchCleanupReceipt, error)
func (binding *MinimalLaunchProviderBinding) BindRecovery(identity MinimalLaunchIdentity) (*MinimalLaunchRecoveryBinding, error)
func (recovery *MinimalLaunchRecoveryBinding) Recover(ctx context.Context) (*MinimalLaunchOwnerBinding, error)
```

`BindRecovery` performs only local identity validation and retains the exact
original provider binding. It neither contacts a provider nor allocates runtime
resources. Its result is a cleanup-attempt handle, NOT an owner or proof. Require
an original self-bound provider and all selected identity fields: existing
1–64-byte ID syntax, the existing canonical request-key syntax, distinct job and
job-generation IDs, and nonzero launch-policy revision. Copy the identity exactly;
never normalize, rekey a daemon epoch, or convert launch grants into credentials.

The small recovery handle is preferable to a bare `binding.Recover(ctx, identity)`
that loses partial results between calls, or a provider-wide identity registry.
It owns one immutable provider/identity pair, one callback-attempt latch, and the
first nonnil owner result. There is no new store, global map, scheduler, or daemon.
Serialization is per original handle, not a cross-handle or cross-process lock.
The future worker must create/retain exactly one recovery handle under its
existing entry lock, after trusted stored-identity admission, and use it outside
that lock. Constructing another handle is not a safe retry or owner replacement.
That worker admission/caller is NOT implemented in this slice.

Started and recovered owner bindings get the same private self guard and attempt
state. Their original provider interface, owner interface, and expected identity
are retained once, never reassigned. Do not compare arbitrary provider interfaces
for Go comparability; use the original self-bound provider pointer and retained
interface, without caller-supplied replacements. A copied/zero/nil handle fails.
No exported constructor accepts a caller-created owner or cleanup receipt.
The existing Start identity check must record an observed mismatch/Identity panic
on its already-retained binding, without changing its owner-plus-error result;
later Finalize must not forget that quarantine when the fake owner changes back.

## Callback, cancellation, and retry semantics

One active callback per retained handle. Under its mutex, admit an attempt or
take the existing attempt's done channel; release the mutex before Identity,
Recover, Finalize, or any wait. Publish the complete result and retained partial
owner before closing that attempt's done channel. Concurrent callers join that
specific attempt, not an automatic retry loop. Independent handles/jobs do not
share a callback lock. Callbacks must not synchronously reenter their own handle.

The caller that admits an attempt executes the callback synchronously using its
cleanup context. The wrapper creates no goroutine, detached Background cleanup,
timer, or replacement deadline. A joining caller may stop waiting with its own
context; it cannot cancel the admitting caller or forget the retained operation.
Nil/typed-nil/canceled contexts are rejected before entry. Check cancellation and
any absolute context deadline again after every callback and immediately before
returning a usable result, including a cached result; delayed deadline delivery
must not bless late success. If cancellation races a completed result, observed
cancellation wins for that caller, not for an unrelated successful attempt.

An admitted caller remains joined until its provider callback actually returns.
Context checks cannot interrupt arbitrary blocking trusted code. The concrete
provider must implement bounded, context-aware, idempotent cleanup; no leaked
goroutine or test watchdog substitutes for that obligation. Use a fresh owned
cleanup context, not the already-revoked preparation reservation. Scope withdrawal,
reservation expiry, and selection closure must not forbid cleanup of a retained
owner. They never authorize a new launch through these APIs.

### Finalize

1. Require the original binding and nonnil/non-typed-nil retained owner. Inspect
   that same owner's Identity and compare every field with the immutable expected
   identity before invoking Finalize. An observed identity mismatch or Identity
   panic quarantines the binding permanently: no destructive callback or repaired
   identity/replacement owner is admitted through it.
2. Call only that owner's Finalize; never Resolve, Start, Recover, ClaimLaunch,
   selection Close, host Commit, or another owner's method as a fallback.
3. After callback return, recheck the same owner Identity, caller context/deadline,
   and receipt identity. Require nil error and nonzero finalized revision. Reuse
   the existing pure `ValidateJobCredentialRuntimeRecoveryCommitReceipt` token
   shape: canonical 43-byte raw-base64url encoding of 32 bytes. This reuses syntax
   only; it is neither HMAC validation nor legacy cleanup/credential proof.
4. On accepted return, cache an immutable receipt value for same-handle repeated
   calls without another finalization callback. Before returning cached metadata,
   revalidate the same owner's Identity and current caller/context under the same
   serialized attempt rule; identity repair cannot erase an observed quarantine.
   That value records the checked callback result, not a terminal capability.

Any error, panic, missing/invalid/partial receipt, late success, or mismatched
result returns a ZERO receipt with `ErrMinimalLaunchUnavailable`; provider errors
and panic strings never escape. Always retain the original owner. Identity
contradictions permanently quarantine as above. Other failures retain pending
ownership and permit a later explicit, serialized retry on that SAME owner with
a fresh cleanup context; there is no automatic retry or concurrent reentry.
Provider Finalize must therefore be idempotent across uncertain prior completion,
including a panic. If it cannot meet that contract, it is not an admissible
concrete provider; this wrapper cannot repair it by replacing the owner.

### Recover

Invoke only the original provider's `RecoverMinimalJob(ctx, exactIdentity)`.
Store every nonnil returned owner in a self-bound owner wrapper BEFORE inspecting
its Identity, its accompanying error, or post-callback cancellation. Return that
same owner wrapper alongside unavailable on partial/error/canceled return; never
close it, finalize it implicitly, or drop it. Wrong identity/Identity panic keeps
the quarantined wrapper but prevents its destructive Finalize callback.

Once any nonnil owner is retained, the recovery handle never calls the provider
again. Repeated/concurrent callers receive that same owner and the original
recovery outcome (subject to their own cancellation); they cannot swap in a
later owner with equal-looking IDs. Exact partial owners remain eligible for an
explicit same-owner Finalize; successful Finalize does not rewrite the earlier
recovery outcome into success. No need to call Recover again to access that owner.

Nil/typed-nil plus nil error is unavailable, never evidence of absence or
`no_dispatch`. Nil plus error or provider panic is also uncertain. Keep the
recovery handle and occupancy; after the callback has joined, an explicit retry
may call only the same provider with the same identity. A panic before the provider
returns an allocated handle cannot be recovered by Go named returns: the trusted
provider must itself retain/return partial ownership or recover it from its own
existing exact records. The neutral wrapper cannot invent that missing handle.

## Proof and durable boundaries remain closed

There is deliberately no cleanup-proof constructor, receipt decoder, terminal
predicate, public JSON field, worker state transition, automatic release, or
Commit API here. A fake provider can return syntactically valid receipt fields;
passing neutral tests proves callback correlation only, NOT resource absence.
No future terminal path may accept this metadata merely because these wrappers
returned nil error. The concrete provider must independently verify complete
correlated VM/cgroup/Jailer, controller, L7, and credential cleanup and expose a
reviewed proof-consuming terminal boundary.

Before a worker terminal consumer exists, separately split/coordinate the actual
selected host Finalize/Commit handoff: retain finalized host evidence, persist the
exact worker receipt durably, then retire host evidence and commit worker terminal
state. Failure/crash at each step keeps an exact replayable record. Missing host
records or plain receipt strings are not success. J-only cleanup does not establish
L7 or credential absence. This is an unresolved concrete-provider/durable-caller
dependency, not a request to modify those owners in this neutral slice.

Prior-epoch restart, selected nonempty-store quarantine, explicit-cancel responses,
stored schemas/CAS/locks, selection release, and occupied runtime slots stay
unchanged. Recovery identity validation supplies syntax, not trusted prior-daemon
authorization or launch permission. No default or legacy runtime route changes.

## Frozen RED and implementation verification

The frozen RED added only unavailable method scaffolds in
`internal/sandboxruntime/minimal_launch_owner.go` and behavioral tests in
`minimal_launch_owner_red_test.go` and `minimal_launch_recovery_red_test.go`.
Its fixture uses the real neutral constructor, authenticated principal, selection,
Reserve, ArmDispatch, and Start chain, following the existing attempt fixture.
It does not construct a successful owner binding by filling its private fields.
Valid/partial/wrong-identity/panicking-identity Start and foreign/copy binding
controls execute independently. Another control directly exercises the injected
provider's Recover fixture; that is NOT wrapper or prior-epoch admission proof.

- Real returned owner: Finalize reaches that exact callback after the original
  reservation is revoked, validates its exact receipt, and repeated/concurrent
  callers observe one joined successful attempt. Baseline fails at unavailable
  wrapper entry; later assertions are not claimed reached until GREEN.
- Recover: one bound identity reaches the actual injected provider; it returns a
  partial owner plus error, all waiters retain the same pointer, and later Recover
  does not invoke a second owner. Exercise that partial owner's actual Finalize.
- All identity fields independently mismatch; nil/copy/foreign handles, typed
  nils, Identity panic/change, malformed commit tokens, zero revision, partial
  receipt plus error, and receipt identity substitution return no usable receipt.
- Block callbacks with joined channels; prove no mutex-held callbacks, no overlap,
  canceled waiters leave the owner intact, pre-entry cancellation makes zero calls,
  admitted caller cancellation rejects late valid output, and later explicit
  same-owner retry cannot reenter until the first attempt has actually returned.
- Recovery nil/error/panic retries use the original provider/identity only;
  mismatched owner stays retained/quarantined; no Resolve/Start/Claim/Close/Commit
  counter changes. Sensitive error/panic canaries never reach error text.

RED reachability was deliberately narrow: Finalize positives failed unavailable
after actual Start retained the owner; invalid-result cases failed because their
Finalize callback counter was zero. Recovery cases failed at unavailable BindRecovery,
before any wrapped provider call. Cached/repair/join/retry assertions after those
first failures were unreached on RED; they execute in the initial GREEN. Watchdogs only fail tests;
fixture teardown releases its gate and joins its goroutines, never product cleanup.
The joining-waiter fixture observes its cancellation channel before cancellation
so the later GREEN test cannot pass by rejecting a caller canceled before entry.

The remaining GREEN matrix must add nil/copied handle and complete recovery-ID
admission negatives, absolute-deadline/late-observation checks, and a deterministic
probe that an old waiter receives its own failed attempt even after another retry
begins. Do not count this initial unavailable scaffolding as those checks.

Focused commands (pinned Go, task-owned home scratch/cache):

```sh
go test -p 2 -race -count=3 ./internal/sandboxruntime -run '^(TestMinimalLaunchOwner|TestMinimalLaunchRecovery)'
go test -p 2 -race -count=3 ./internal/sandboxruntime -run '^(TestMinimalLaunchOwnerBindingExistingStartControls|TestMinimalLaunchRecoveryInjectedProviderControl|TestMinimalLaunchBinding|TestMinimalLaunchAttempt)'
go test -p 2 ./internal/sandboxruntime -run '^$'
```

At frozen RED the first selector had 42 failure events (37 leaves), eight control
passes, zero skips per repetition. Initial GREEN has 156 passing events across
three repetitions, zero failures/skips/races; two formerly unreached Start
quarantine subcases now execute per repetition. The second selector independently
runs the controls plus existing attempt tests.

Implementation ownership: new `minimal_launch_owner.go` and narrowly named tests;
only the existing owner-binding declaration/initialization in
`minimal_launch_admission.go`, its retained-owner identity quarantine marking,
and interface contract comments in
`minimal_launch.go` as necessary. No worker, host/controller, generic store, guest,
provider implementation, or source-guard relaxation. Review any discovered guard
coupling explicitly instead of adding an exemption.

Run the focused neutral RED/controls, then focused race ×3, whole neutral package,
relevant existing worker selected/source guards, vet, and Darwin compilation.
Use pinned Go with task-owned home TMPDIR/GOTMPDIR/GOCACHE and low parallelism.
This revision is also checked by source inspection and `git diff --check`.
Neither neutral callback tests nor syntactically valid receipts prove a live
runtime or cleanup. Full review awaits the remaining matrix and adjacent gates.
