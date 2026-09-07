# Selected Jailer finalization handoff

Status: DESIGN ONLY at `b8b9cd2c0f0d2947947e9823c862b508d64f403f`.
No implementation, compiling RED, provider, worker persistence, or terminal
activation is included. This refines the deferred client split in
[minimal owner bindings](sandbox-runtime-v2-minimal-owner-bindings.md), under
the [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md), and
[selected constructor](sandbox-runtime-v2-minimal-runtime-constructor.md).

## Exact gap and existing authorities

Paths in this section are relative to the repository root, at the base above.

- `internal/sandboxruntime/microvm/firecrackerhost/jailer_recovery_client_linux.go:50–123`,
  `stopAndCommit`, authenticates the retained client, checks StopReap absence,
  validates FinalizeAck against fresh finalized record bytes, then immediately
  sends Commit. There is no interval for another owner to complete cleanup or
  durably save its receipt. Its mutex covers socket I/O; `close` takes that mutex.
- `jailer_recovery_reconnect_linux.go:57–145`, `readRecord`/`authenticate`, uses
  the retained directory, canonical bounded selected record, independently
  expected six-field job tuple, boot/process observation and exact socket peer.
  It pins full config correlation and supervisor generation/PID/start time.
  These functions reacquire cleanup only, never launch or readiness authority.
- `l8_runtime_owner_supervisor.go`, `planFinalize`/`applyFinalize`, verifies the
  actual absence revision/time and private owner commit derivation, closes owned
  namespace copies, and persists finalized state. On reconnect after finalization,
  the controller revision/secret change, but finalized commit ID and target
  revision remain stable. A still-finalizing reconnect may change that target.
- The same FSM's Commit branch validates the exact session/commit/revision and
  calls `RetireFinalized` BEFORE replying. The selected store unlinks, syncs and
  checks its exact retained record. A lost reply may therefore leave no record.
  `TestJailerRecoveryMissingRecordAndLostCommitAckStayUnresolved` intentionally
  rejects both lost ACK and subsequent missing-record inference.
- `internal/sandboxruntime/minimal_launch.go` exposes owner `Finalize`, but no
  Commit method. `minimal_launch_owner.go` retains/caches its exact provider's
  checked result; `MinimalLaunchCleanupReceipt` is bookkeeping, not proof.
  `internal/sandboxworker/job_manager_v2.go:322–424` illustrates the separate
  legacy receipt-save → host Commit → worker terminal-save order. The selected
  worker does not yet have that writer/replay/commit consumer.

## Chosen private client split

Add only a selected sibling and one retained completion object in
`firecrackerhost`, with these proposed private entry points:

```go
func (client *jailerRecoveryClient) finalizeMinimalCleanup(ctx context.Context) (*minimalJailerFinalization, error)
func (completion *minimalJailerFinalization) commit(ctx context.Context) error
```

Use the existing client's close operation for explicit disposal; closing never
means Commit or successful cleanup. No persistence callback, receipt argument,
`allowCommit` boolean, generic cleanup framework or public proof constructor is
added. Future in-package provider code may copy the validated commit ID/revision
from the completion's private frozen result into bookkeeping. Such a copy does
not recreate the completion or authorize a worker terminal transition.

The completion is self-bound, belongs to one exact original client, and is
retained on that client before selected protocol work. It retains the original
job/config/supervisor identity and first validated finalized result. Zero, copied,
foreign, closed or contradicted handles cannot operate. Once claimed, a client
cannot also enter legacy `stopAndCommit`; ordinary unclaimed clients preserve
that method's existing transcript, error, retry and idempotency behavior.

Copied clients also need rejection on this new route: add a private origin
pointer initialized at the two existing actual client mint sites,
`reconnectJailerRecoverySupervisorWithOps` and
`startJailerRecoverySupervisorCommand`. The selected entry checks origin equality;
legacy behavior does not depend on this new stamp. A value-copy cannot establish
a second selected completion over shared descriptors. No global client registry
or caller-supplied origin is permitted. This narrow constructor-field coupling
must be reviewed with the future RED; it does not select eight-role execution.

Initial selected admission records one cleanup handle; concurrent callers join
that exact attempt rather than retrying under another client. Partial/error
results retain the same handle/client alongside an error. A valid finalized
result is stored only after the actual successful ACK and canonical readback.
Before that, the handle is pending, not a completion proof. Contradictory
owner/config/finalization identity is sticky quarantine, not a recoverable label.
Repeated Finalize returns that same handle only after the selected caller and
same-owner finalized-record checks below; it must not refresh a lost owner from
cached receipt fields. No returned handle asserts that a paused connection is live.

## Finalize, pause without a connection, then Commit

1. Validate selected handle/client ownership and current cleanup context. Use
   the existing authenticated client or authenticate the same retained owner.
   Reuse existing canonical packet/body validators and selected record decoder.
   Reject starting/unknown states; preserve the currently supported running,
   stopping, uncertain, absent, finalizing and finalized cleanup routes.
2. For running/stopping/uncertain, send StopReap and correlate its exact absence
   response and canonical record as today. For absent/finalizing/finalized,
   resume Finalize as today, never bootstrap or repeat a successful process stop.
   Keep direct-wait and actual owned-checkpoint requirements; no PID-zero shortcut.
3. Send Finalize. Require the exact expected opcode, sequence, status, no rights,
   canonical ACK and fresh matching finalized record. Compare the whole ACK to
   the expected struct derived from that record, not a caller commit token.
   Freeze the complete finalized in-memory record and its stable commit target.
4. End the one-use reconnect connection, clear its session, and join all selected
   local I/O/watchers BEFORE returning the handle. Keep the original directory,
   supervisor observation and immutable identity, not a socket/session or mutex
   across L7 cleanup or worker persistence. Closing the connection requests the
   existing server's unclaim; it is not proof that unclaim already completed.
   No monitor, keepalive, or background reconnect loop runs during this pause.
5. The future composition performs actual L7 and other owner cleanup, then saves
   and reads back the exact selected worker receipt. Those are separate gates
   below. Failure leaves the finalized J record and completion pending. Neither
   handle return nor ordinary receipt syntax silently advances those gates.
6. Only an explicitly admitted later `completion.commit(ctx)` reauthenticates
   through the SAME retained client/directory to the SAME supervisor. Recheck
   boot, process, peer, job, full config correlation and finalized identity.
   Reuse actual Finalize once in the new session to obtain its canonical ACK;
   require the original frozen commit ID, target and absence revision/time.
   Then send Commit at that session's next exact sequence, deriving fields only
   from the independently read record. Require the exact canonical Commit reply
   and eight-byte original target revision. Only that response records local
   acknowledged commitment; close/join the connection on every outcome.

After finalization, permit only the existing controller transition fields to
change during reconnect: `Revision`, `ControllerState`, and `ReconnectSecret`.
Check their existing schema/handshake rules, monotonic revision and exact
handshake increment separately. Compare all other record fields byte-for-byte
via immutable value copies; do not normalize IDs, replace the frozen result,
or accept changed process/absence/listener/config/commit fields. The new session
must be controlled and the record must still be finalized: finalizing is not a
permitted regression after a handle has frozen a finalized result. Reauthentication
while the prior connection is still controlled returns unavailable. An explicit
later call may retry after unclaim; do not spin or create another owner.

Once locally acknowledged, repeated Commit returns the cached outcome only on
the same noncopied, nonclosed handle with the same frozen client identity and a
current caller. It does not reread a missing record as evidence. If the caller
expires after an exact ACK was received, retain that ACK outcome internally but
return cancellation/unavailable to that caller; a later same-handle retry may
observe the retained ACK. No ACK means no cached success.

## I/O, cancellation and locks

Do not reuse `jailerRecoveryClientExchange` and call it cancellation-interruptible:
it checks context only before/after blocking calls, relying on socket timeouts.
Likewise holding `client.mu` while waiting, as legacy `stopAndCommit` does, would
prevent selected close from interrupting that wait. Keep the legacy branch's
behavior intact; the new route needs a concrete bounded selected exchange.

Use one per-client active attempt under a short bookkeeping lock. Run context
methods, authentication/inspection, socket operations and all waits outside it.
An attempt retains its exact socket (or CLOEXEC operation duplicate) through
all send/receive/shutdown work. A joined cancellation watcher shuts down that
retained endpoint; it never closes an FD number while I/O can still use it.
Use the smaller of the unchanged five-second per-exchange cap and the remaining
absolute caller deadline. Never round a positive timeout to zero. Recheck
half-open caller currentness after observations/readback and immediately before
each send or usable result publication; cancellation cannot bless late output.

Selected close first withdraws admission/cancels the active operation, shuts
down I/O outside locks, joins its operation/watcher, then closes only owned
descriptors and the process observation. It must not wait for `client.mu` while
that lock protects blocked I/O. Concurrent close callers join one exact close;
an operation never invokes a close that joins itself. Constructor/authentication
partial sockets and error paths require the same retention discipline. Any
selected extension to `authenticate`/connect must preserve the existing Linux
owner/peer validation, with no injected pass observation in production.

Concurrent Finalize/Commit calls cannot overlap exchanges or replace a pending
operation. A joining caller can cancel its own wait without canceling the admitted
caller's cleanup or starting another attempt. Actual caller cancellation ends
that one-use session; retry is explicit with a fresh cleanup context. Use no
revoked launch-reservation context for cleanup and no automatic Background task.
The gap between calls holds no worker/L7 callback and no active protocol goroutine.
Nil/typed-nil contexts and expired callers fail before protocol admission. Errors
remain static sanitized owner errors, without raw record bodies, paths, reconnect
secrets, commit material, injected errors or panic text in public output.

## Later composition and crash boundary

The eventual order is:

```text
withdraw admission + controller I/O shutdown/joins outside the cleanup FSM
  → actual J StopReap/Finalize + retained validated completion (record remains)
  → exact retained L7/remaining host credential cleanup and its real proof
  → selected worker receipt atomic save + same-root/current-entry readback
  → this completion's exact same-owner Commit ACK
  → worker terminal checkpoint, then separately authorized occupancy release
```

The new private Commit method cannot independently verify L7 or worker storage;
it is an internal protocol capability, not an external persistence gate. No
production caller may wire it until that composition has its own accepted RED.
There is deliberately no fake successful writer/proof passed to this method.
The accepted selected cleanup preflight requires controller shutdown before entering
the mutex-held containment FSM; this split must not postpone those joins until
after J Finalize or move them into this client's protocol/bookkeeping locks.

`l7network.Session.CleanupAfterVMQuiesced` requires the original full L7 identity
and a termination binding accepted by its configured verifier. The J client
does not acquire that live session or mint such a binding from FinalizeAck,
`CleanupCheckpoint`, PID fields, or the plain recovered-observation constructor.
The same surviving J owner's verified termination must be concretely correlated
to the retained/recovered L7 verifier. L7 cleanup/recovery, controller joins,
credential absence and their cross-daemon authority remain separate dependencies.

The neutral `MinimalJobRuntimeOwner.Finalize` can eventually return bookkeeping
only after those genuine cleanup steps, while its concrete provider retains this
J completion. The current neutral binding has no post-persistence Commit API.
A later narrow exact-provider/owner bridge and selected worker receipt writer
are therefore required; do not put a worker store callback in the host client,
import worker internals, reuse legacy credential receipt authority, or make
neutral Finalize secretly persist/Commit. Prior-epoch selected stores currently
quarantine; this design does not authorize their recovery admission.

| Interruption | Required retained/retry outcome |
|---|---|
| Stop/Finalize send or ACK/readback fails | Keep same client pending; close/join session. Reauthenticate current canonical state and resume only supported cleanup on explicit retry. No returned finalized result from guessed fields. |
| Finalize completed, before or during L7 cleanup | J record remains finalized. Retry exact retained owners; never discard L7 ownership or invoke pre-VM abort after launch. |
| Worker receipt save/readback fails | Send zero Commit packets. Preserve finalized J record, whole-job ownership and occupancy. |
| Daemon crashes before receipt publication | Fresh trusted recovery must reacquire same J/L7 owners and reverify actual finalization; a copied completion is unusable. No relaunch. |
| Receipt durable, before Commit | Future authorized worker replay reestablishes exact owners and compares retained finalization to the saved receipt before invoking Commit. Plain decoded receipt alone is insufficient. |
| Commit fails and exact finalized record remains | Explicit same-client retry reauthenticates, confirms the same stable finalized result, and attempts Commit under the existing FSM. |
| Commit retires record but ACK is lost | Unresolved, exactly as today. Neither missing record, EOF, receipt fields nor identical-looking successor establishes acknowledgment. Retain worker receipt/occupancy; no fabricated success. |
| ACK received but daemon crashes before terminal save | The in-memory ACK is lost. Existing J schema supplies no crash-durable ACK replay after retirement. Remain unresolved unless a separate accepted durable acknowledgement design closes this window. |

Thus this split creates the necessary pre-retirement persistence interval; it
does NOT alone provide complete crash-safe terminal convergence. Resolving the
last two rows would require separate protocol/durable-ACK work, not a relaxed
missing-record check or a new tombstone hidden inside this client slice.

## First meaningful RED and follow-up gates

After this design is approved, begin with a compiling private sibling scaffold
delegating to existing `stopAndCommit` and returning unavailable. Use the actual
`jailerRecoveryWireFixture`/canonical selected store/real seqpacket/FSM. The
intended first RED asserts that a completed Finalize leaves the exact record
finalized and records only StopReap/Finalize, with ZERO Commit packets. Baseline
instead emits Commit and retires the record: this is the reached behavior, not
an absent-symbol failure. A later opaque-handle assertion is not reached yet.
Keep an independent unchanged legacy transcript/retirement control passing.

Then freeze separate reachable tests as the selected path becomes available:

- Valid finalization → connection fully closed/unclaimed → retained result →
  independently authenticated same-owner Commit; no session or mutex across a
  blocked fixture gap. Finalize retry before/after successful ACK/readback.
- Actual store failures in finalizing/finalized transition/readback and retirement,
  dropped Finalize/Commit responses, wrong ACK opcode/sequence/body/rights,
  truncated packets, replaced record/owner/boot/process/listener/config/absence,
  stale session, wrong stable commit target, and successor preservation.
- Nil/zero/copied client or completion, foreign completion, repeated binding,
  expired/canceled caller, concurrent same-attempt waiters, and copied result
  fields cannot issue Commit. Every negative must reach its intended boundary.
- Block actual selected send/receive, cancel/close, require retained-FD shutdown
  and joins outside locks; no watchdog-assisted product success or detached
  reader. Canceled waiters do not cancel an unrelated admitted attempt.
- Drop ACK after actual retirement and reproduce unresolved missing record.
  Repeated same-handle success requires an actually retained ACK. No fake writer
  is accepted as worker receipt proof; order-marker fixtures prove ordering only.

Ordinary fixtures inject host/process/peer observations; they prove protocol,
store and handle ordering, not privileged owner or VM/L7 cleanup. Future gates
include selected and legacy reconnect/record/FSM race repetitions, neutral owner
regressions, the existing D6 receipt-access/source guards, whole affected host
package, vet and Darwin compilation. Existing canonical encoders and the whole
FinalizeAck comparison avoid introducing another receipt projection; report any
guard coupling before changing its allowlist. No tests have been added or run
as acceptance evidence by this design-only commit.

## Bounded future ownership

Proposed host implementation: new `minimal_jailer_finalization_linux.go` and
focused tests, narrow client fields/selected routing/close coupling in
`jailer_recovery_client_linux.go`, and the two client mint stamps noted above.
Any extraction of legacy operations must retain its exact transcript and error
semantics, or remain a selected sibling reusing existing codecs and validators.
No store schema, cleanup FSM, readiness receiver, original bootstrap monitor,
preparation runtime, guest, tools, command or default selector changes.

Jailer preparation files remain with that worker; neutral reservation lifetime
remains with its owner. The future neutral Commit bridge, L7 termination handoff,
worker receipt writer/replay and durable lost-ACK solution need separately
assigned designs/REDs. This document grants none of those implementations.
