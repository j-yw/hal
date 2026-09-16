# Atomic selected release admission

Base `b9354f8e4601b48ac34655b59384f5115903d7e7`. This refines the
"One release attempt and original R/P/D" section of the complete minimal
release-gate design, under the Linux completion architecture and L8 reset.
Selected gate release/Close interruption is already accepted. Its `attempted`
flag remains local I/O bookkeeping, not atomic cancellation/release authority.

## Single authority and retained time

Replace the preparation's atomic.Bool cancellation latch with one private
atomic.Uint32-backed latch containing canceled and release-admitted bits. Keep
the existing `prep.canceled.Load()` observation as a narrow boolean method on
that same word. `revoke` atomically ORs canceled before canceling the original
context and never waits for preparation/starter/selected/FSM locks. No second
cancellation flag and no operation that clears either bit.

The real selected returned Release is the only admission caller. Reuse its
original captured resource snapshot and exact gate/preparation binding. After
the last actual snapshot.current succeeds, require current preparation and
capture a conservative `R = time.Now()` immediately before CAS. Require `R < P`
against the immutable sealed P; CAS only untouched state to release-admitted.
Prior observed cancellation or any earlier admission rejects permanently.

Retain the winning R and `D = min(P, R + minimalControlStartupTimeout)` in the
same exact selected gate, never from a later successful send/reply. The existing
startup timeout is fifteen seconds. Publish these fields under the starter
mutex only after winning CAS, before gate I/O can begin. Waiting for that mutex
does not change R/D. Recheck lifetime/P after the wait and before send. Loss in
that interval consumes admission but prevents I/O; it does not permit retry.
No mutex is newly held over the resource-currentness observations, and canceled
publication does not need the timestamp mutex. The original outer FSM owner
mutex remains unchanged.

The selected gate entry requires the same admitted preparation and retained
window before allocating its operation duplicate/sending. Its old local
attempted slot still rejects extra local I/O. A failed or canceled send never
clears admission/window; ambiguity cannot prove no child launch. Legacy nil-gate
six-/seven-role starter behavior remains unchanged. No packet/schema/default,
arming receive, executable/provider/controller or readiness handoff changes.

An internal `releaseWindow` getter returns a locked copy of the original R/D
after publication, even after later cancellation. It is historical attempt
metadata, not permission to send, readiness, or a fresh lifetime. The later
controller must still consume actual correlated authority; this slice does not
implement that consumer. Losing attempts cannot alter the original window.

## Compiling RED and verification

Add only a private unavailable window getter/type for compiling tests first.
Use the unchanged real eight-role/revision-1/SCM/gate fixture, whose process,
identity, staging and cgroup are explicitly fake and whose real self pidfd is
not supervisor-child proof. Successful actual release and its canonical
revision-2 reply must retain an R between pre-release and post-release clock
observations and the exact D, both for P shorter and longer than fifteen
seconds. An actual blocked send must already expose that window before
cancellation, then preserve it after failed joined cleanup. Current code sends
without retaining any such window: that is the first reached RED, not yet
atomic-CAS proof. Independent prior-cancel/no-send, one-send/retry and legacy
controls remain distinct evidence.

Freeze this RED for main reproduction/approval before implementation. Later
GREEN tests must separately reach CAS/cancel races and concurrent admission,
post-CAS lock delay/expiry, immutable publication, failed-send consumption, and
lock-free canceled publication. Do not mutate P or inject a clock/observer into
production. No new real process, signal, namespace or cgroup action.

Run focused preparation/release/gate/legacy races, full host race, unchanged
owner/Phase33 guards, vet, Darwin compile and diff/format checks. All tasks and
watchers must join; watchdog rescue cannot count as passing cancellation.

## Implemented boundary and forward evidence

The selected callback now calls `gate.admitRelease(snapshot)` before its
original captured sender. That method checks the exact original binding,
executes the unchanged actual resource-currentness algorithm, checks original
P and wins the preparation's single-word CAS before publishing its captured
R/D under `starter.mu`. The sender requires that same admission and published
window in addition to its existing local attempt/FD/operation checks. The
original release budget remains `min(P, now + 5s)`; D is retained for the later
controller consumer, not silently substituted as a new release I/O budget.
`revoke` ORs the same word before waking the original context. There is no
second cancellation authority, no reset, and no new production observer or
clock dependency. Existing mutex waits and OS syscalls are not made forcibly
interruptible by the CAS; the accepted operation watcher still owns I/O
interruption and joining.

The original 168-line compiling RED remains byte-for-byte unchanged from
`0fafe693b2dd719cb9cd344022b275b11d0f5c21`. Forward tests separately cover:

- A pure 256-iteration cancel/CAS race, supplementing the actual owner tests.
- Sixteen simultaneous actual selected callbacks, one success, one actual
  ChildRelease packet and canonical revision 2. All contenders join before
  the real FSM proceeds.
- Sixteen losing selected callbacks while the original actual bootstrap is
  blocked in sendmsg. Each contender completes all three existing identity
  read phases in the real resource-currentness algorithm, then rejects
  without resetting R/D or canceling the winner. Draining only the exact
  ordinary queue fillers lets that original send complete successfully.
- The existing fake identity filesystem's final successful verification hook
  takes `starter.mu` after actual armed-process readback. The unchanged
  currentness path then returns and the real selected CAS executes before
  timestamp publication can acquire the mutex. Real elapsed delay cannot
  rebase R/D. Cancellation and original-P expiry while blocked preserve the
  consumed window, allocate no gate operation, send nothing and cannot retry.
- Revoke completes with starter, supervisor-owner and preparation mutexes
  held. The getter after cancellation is explicitly historical metadata only.

Only the two new concurrent-callback tests bypass the older fixture's
sequential-only order-recording wrapper: they use the actual
`selected.startMinimalControlChild` constructor directly, like the existing
retained-mismatch matrix. The first draft race run exposed concurrent appends
to that test-only order slice. No original fixture, ordering assertion, RED,
resource guard, gate ownership test or legacy behavior was changed to fix it.

Two external test-only overlays independently checked those forward assertions:
replacing CAS with a resettable store fails the actual blocked-winner test on
changed R/D, and recapturing R after acquiring the starter mutex fails all three
actual post-CAS delay/cancel/P cases. Both probes compiled, reached their
intended behavior failures and joined without skips or races; neither mutated
the worktree implementation or is part of the shipping change.

Interruptible arming receive, executable/provider/controller activation,
consumption of D, live prepared-host authority and end-to-end Linux VM
acceptance remain outside this slice.

## Author verification checkpoint

Pinned Go 1.25.7, offline, GOMAXPROCS=3, private temporary directory and shared
task cache. Counts exclude package events. All test/vet/build processes joined.

- `go test -race -p 2 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalReleaseAdmission' -count=3 -json`:
  39 passes, no failures/skips/races (11.609s).
- `go test -race -p 2 ./internal/sandboxruntime/microvm/firecrackerhost -run '^(TestMinimalGateIO|TestMinimalRelease|TestMinimalPreparation|TestJailerRecoveryActualSelectedOwnerRetainsCoordinatorAcrossReconnect)' -count=3 -json`:
  402 passes, no failures/skips/races (98.394s).
- `go test -race -p 2 ./internal/sandboxruntime/microvm/firecrackerhost -count=3 -json`:
  7,776 passes, no failures/races (262.322s); 12 existing skips, three each for
  the non-Linux rejection test and three subprocess-only helper entrypoints.
- `go test -p 2 ./cmd -run '^Test(L8D6RuntimeOwner|L8D2ImageProfileMintAuthorityStaysNarrow|L8D6SSHRelayActivatorRemainsDefaultOff|Phase33Firecracker)' -count=1 -json`:
  73 passes, no failures/skips (2.964s). No guard needed modification.
- `go vet -p 2 ./internal/sandboxruntime/microvm/firecrackerhost`, Darwin/arm64
  host-package test compilation, `gofmt` and `git diff --check`: passed.
  `golangci-lint` is unavailable, so lint is not reported as passed.

This is author-side package/guard verification, not an independent review,
whole-repository result or live VM test. External checkpoint logs and the exact
frozen commit are recorded in the integration handoff.
