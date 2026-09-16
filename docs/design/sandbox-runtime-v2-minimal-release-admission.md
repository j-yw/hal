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
