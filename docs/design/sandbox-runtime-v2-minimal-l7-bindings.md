# Selected minimal L7 bindings

## Host inspection behavioral RED checkpoint

The tests-only host slice starts at accepted integration `3031e096`: the selected
guest inspection, pre-exec assembler and original supervisor/work composition are
now integrated dependencies. The historical design status below remains the
record of their status when this design was accepted, not their current status.
This checkpoint changes no production code or legacy/public Client behavior.

The existing generic `TransportRequest.ProtocolVersionV1` carrier metadata stays
unchanged. Only its private operation is `inspect_isolation`; its inner JSON must
be the exact 76-byte minimal-v1 request. The new REDs reach real opcode-4 codec
rejection and original producer request rejection after genuine guest readiness.
They also reach the incorrect forwarding of this payload under all three old
Exec/Copy opcodes, through the original producer, server and controller to the
actual encrypted guest Server. A concrete Linux no-request verifier consumes
counted fake OS/network observations: initial Ready runs once; hidden inspection
currently advances fresh inspection without backend/environment work.

Positive opcode-4 response/H/ordinal assertions are not yet reached. Invalid
opcode-4 header controls currently reject at the missing-opcode gate, so they do
not yet prove implemented inspection-specific size guards. Pre-cancel/retired
controls similarly cannot prove admitted-inspection loss handling. Later forwards
must reach the original publication gate, host-added H versus guest timing,
deadline/monotonic pinning, drift, busy/blocked inspection, delayed or completed
replies, final writer/watcher joins and loss-wins acceptance. Keep unchanged
ordinary Exec/CopyIn cancellation controls. No L7 binding or activation follows
from this RED checkpoint; independent fixed RED review precedes host GREEN.

DESIGN ONLY, from `372a279445d7c751eab1bd87d598e9948d4551e7`.
The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) govern.
The [pre-exec assembler](sandbox-runtime-v2-minimal-preexec-assembler.md) is intent,
not GREEN. Anticipated [work composition](sandbox-runtime-v2-minimal-supervisor-composition.md):
`760ab73e`, with production `87d61ad5`; its compound-close REDs still fail.
Neither dependency is accepted as completed here. No code/activation is authorized.

## Decision and exact missing edge

Keep existing L7 verifier interfaces, bindings and proof shapes. Old verifiers
in `l7_live_composition.go` require their private legacy bridge/tracker, not
selected metadata; `production_vsock_bridge.go:refreshL7Proof` makes a fresh
proof-required readiness exchange, not a cached proof lookup.

Choose `inspect_isolation`, not inner v1 readiness with request-controlled
generations, optional network proof, backend.Ready and public ready/status result.
Preserve selected rejection in `server/protocol.go`; the new operation uses the
existing no-request `WorkloadIsolationVerifier`, without backend work.
This note supersedes only the composition/workload design's exec/copy-only
allowlist for this one selected operation. Ordinary readiness rejection, legacy
Bootstrap/v1 behavior, readiness capability, credentials and defaults stay intact.

## Selected inspection wire and admission

Private work-header code **4** maps to `guestagent.Operation("inspect_isolation")`.
No public Client method/legacy expansion. Header layout, complete 27-field/session
binding, ordinal sequence and existing secure workload envelope
are unchanged. Inspection consumes the SAME sequence as Exec/Copy, never another
reader, queue, session, transport, reconnect or handshake.

Exact canonical inner request: 76 UTF-8 bytes, without LF:

```json
{"operation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1"}
```

No body, timing, generation, environment, path, command, network configuration or
proof flag is accepted. The selected codec rejects duplicate, unknown, reordered,
escaped or trailing fields/bytes. IPC requires maximum response **2048**, exact
request length and response size 1..2048, checked before IPC body allocation.
Existing encrypted-envelope and 1MiB Exec/Copy ceilings are not increased.

Guest success has exactly `operation`, `protocolVersion`, `isolationProof`, in
that order: fixed request literals and canonical `guestagent.IsolationProof`. Both
status values are `verified`; all five process booleans and all three network
booleans are true. Generation is the authenticated binding's
`topologyGenerationId`; RuntimeGeneration is its `runtimeGeneration`. The guest
transport supplies these IDs from its retained boot/session binding, NEVER the
request or verifier. No new proof shape or guest capability is introduced.

On a current-context inspection failure, the bounded response is exactly
`{"operation":"inspect_isolation","protocolVersion":"guest-agent-minimal-v1","error":"unavailable"}`;
join its attempted writer then retire the stream. On malformed input, panic,
owner loss, H expiry or cancellation, retire without requiring a reply. No raw
syscall error, status contents, routes, endpoint or diagnostic escapes. Unknown
or noncanonical success/error combinations fail closed. Clear owned buffers on
every return; never clear borrowed caller data. Failure never yields a partial
positive proof or a reusable cached-success bit.

`minimalcontrol.workloadConnection` recognizes this selected request only after
its existing secure binding/ordinal admission. It calls a narrow optional server
interface `InspectWorkloadIsolation(context.Context) (IsolationProofResult,error)`;
missing support is unavailable, not fallback to Handle/readiness. Actual Server
implements it using the SAME permit/operation tracking and fresh inspection
algorithm as `server/workload_dispatch.go`. Factor existing bookkeeping and
result return as necessary, rather than inspecting twice or creating a second
verifier. It performs no Backend.Ready/Exec/Copy, environment resolution or
workspace mutation. Preserve proof-attempt/state/context checks before AND after
the verifier, zero result on failure, and join the operation before Server.Close.
The concrete Linux verifier remains the existing status/groups/denied AF_PACKET
check followed by the boot-configured concrete network inspector/proxy check.

One call is admitted across work and inspection. Pre-canceled/busy losers send
nothing and do not poison active work; an admitted inspection loss retires the
same owner. The single continuous reader still sees EOF during inspection/write;
one bounded next frame is permitted only in the prior response-WRITING phase,
never concurrent inspection/backend work. No timeout goroutine abandons a trusted
inspector. Cancellation responsiveness remains that callback's responsibility.

## Current inspection across the supervisor/producer boundary

The original work server and controller inspection helper require code 4 plus
the exact inner request; reject this payload under codes 1..3. Call the original
workload controller transport with the same readiness, actual manager/process/
socket correlation and continuing context.
Check `minimalControlReadiness.Current()` and the retained selected generation
before and after the fresh exchange, before publishing success, and after its
owned response writer joins. Reuse actual stream correlation/manager inspection;
an event's process generation alone is not that check. Validate guest proof IDs,
all required outcomes and exact response schema before returning any proof.

RD2 carries no H; a producer cannot inspect a cross-exec readiness pointer.
Inspect-only IPC success adds `hardExpiryUnixNano`, then `remainingLifetimeNanos`
after `isolationProof`: original captured `ready.hardExpiry.UnixNano()` and
`time.Until(ready.hardExpiry)` sampled before sending that reply. Neither is
guest-supplied; guest responses containing either field reject. Retain 2048 bytes.
This private refinement adds no event, acknowledgment or persistent proof schema.

The producer admits one request context with an absolute local deadline of
`min(caller deadline if present, admission time + 5s)`, retained through response
acceptance and joins. This is an inspection operation bound, not a replacement
P/D/H or ownership context. Pin the absolute H unchanged for the exact session;
missing/expired/changed H rejects. Wall time alone is not monotonic expiry proof.
Require positive remaining <= the existing 35-minute session maximum, no overflow.
On this SAME host, compute a conservative monotonic not-after by adding remaining
to the retained REQUEST-ADMISSION timestamp, never receipt time. The supervisor
sample causally follows request admission, so this bound cannot exceed actual H.
Retain the minimum of old/new derived bounds; reject when it or the original
request deadline has passed. The real supervisor H timer and original loss/EOF
remain mandatory; no clock discontinuity or response delay can extend that bound.

Inspection MUST NOT inherit completed-CopyIn late-success semantics. Its selected
branch shares the existing exchange/reader, retaining the admitted operation
through proof decoding/final acceptance. Recheck owner, self/candidate, context,
session, both expiry guards and retired latch after the sole reader completes and
after its writer/cancellation watcher join; loss wins over a complete response.
No drain/resend rescues inspection; CopyIn behavior stays unchanged. The candidate's
first inspection waits at the actual publication gate; RD2/FD/IDs cannot pass it.

## Original producer L7 binding

The original claimed `minimalTemplateAssetOwner` attaches one private self-bound
running binding to its SAME pre-exec attempt/L7 Session and producer launch; no
raw-FD/event/label constructor exists. Retain independent Claim/request/template,
eight-config digest, L7 identity, 25 boot fields, observed original supervisor
PID/start/pidfd and record generation; cross-check late process/vsock fields and
shared 27-field/session digest. None is request-supplied authority.

Use existing `l7EnforcementCorrelation` and `l7ProofID`: readiness ID is
`l7ProofID("ready", identity, bindingDigest)` and raw ID is the corresponding
`"raw"` ID. The digest is the existing public session-bound Binding.Digest, not
a key/seed hash. IDs remain identical on every refresh; a new timestamp is issued
only after successful fresh inspection. Return the existing verified
`RunningGuestRawPacketIsolationProof`/`RawPacketIsolationProof` shape and reason.
IDs are correlation only; passing this binding to InspectAfterGuestReady is not
permission to publish a ready/active owner.

Every selected verifier invocation performs the fresh exchange and rechecks
original ownership/supervisor liveness before and after. L7 retains its actual
guest -> proxy -> TAP -> rules -> TAP -> proxy -> binding-stability inspection
sequence. No host_prepared/cached/requested-rule proof; drift uses quarantine.
Pending snapshots expose correlation only. After first success, invalidate on
retirement or either SESSION-expiry guard, including after host inspection;
the released per-request context is never the binding's continuing lifetime.

Install fixed concrete selected verifiers at per-job Coordinator construction,
replacing pre-exec's incapable placeholders only in later selected composition.
Never swap Session options. Accept only original selected private bindings.
L7 holds Session.mu through both verifier callbacks: neither callback nor any
joined task may call that Session, Quarantine, or outer Finalize synchronously.
Use only owner-local snapshots/latches with short locks; no source/attempt mutex
is held over guest I/O, callback, cancellation or joins. Session loss notification
records loss/cancels only; outer lifecycle cleanup runs outside that callback.

## Terminal binding and retry ownership

Retirement order remains: stop admission and JOIN owned work/inspection/I/O ->
original containment -> JFinalize -> same L7 quarantine/cleanup and credential
cleanup -> durable outer cleanup receipt -> Commit. Credential revocation may
start earlier; its completion is mandatory before the receipt/Commit. J-only
finalized, L7-only stopped or socket EOF is never whole-job terminal success.

Create a private selected terminal binding only from that original producer's
retained `jailerRecoveryClient` and successful self-bound
`minimalJailerFinalization`. Match original owner/attempt, directory identity,
expected job, full eight-config digest, L7 correlation, supervisor generation/
PID/start and frozen finalized record. Validate the recorded child PID/start;
if readiness existed, also match its actual process/transport association.
Failed handshake/partial start remains cleanable without invented readiness.

Require selected stop/reap AND cgroup emptiness, owned jail/cgroup release,
original UID/store idle checkpoint/lease release, `confirmTerminalCleanup`,
namespace close and durable FSM finalized readback. Manager forget is not proof.
No successor UID reopen, old bridge/tracker booleans, absent lookup or ACK alone.

Before each VMTermination result, repeat the original split JFinalize/readback
using its existing bounded/cancellable attempt and original client, with outer
bookkeeping locks released. It may idempotently repeat Finalize, never Commit,
Start, kill/reap through a new owner, or reenter L7/outer Finalize. Require joined
success, exact frozen-record comparison, no contradictory/quarantined/disposed
completion, and current caller; `state.ready` after a failed retry is insufficient.
The owning finalizer's legitimate closing state is not a foreign/disposed owner.
Use stable termination ID `l7ProofID("terminated", identity, generation)` where
generation joins config digest, supervisor generation, FinalizedCommitID and
canonical decimal FinalizeTargetRevision with NUL (not mutable reconnect revision).
Return existing VMTerminationProof with `l7ProofID("vm", identity, terminationID)`
and stopped/reaped true only after that substantive chain is verified.

Retain one owner/completion; retry the incomplete stage with existing budgets,
no detached/parallel cleanup. L7 failure retains J-finalized ownership;
receipt failure prohibits Commit. Only pre-exec rollback may use AbortBeforeVM.
Recovery uses existing authenticated inputs, not live bindings from public IDs.

## RED-first ownership and acceptance

Limit implementation to selected inspection codec/transport and Server factoring,
selected host IPC/controller inspection, and private producer L7 bindings. Keep
L7 contracts/inspection/cleanup algorithms, legacy/default classifiers and public
machine schemas unchanged. Guard conflicts/defects need review, not exemptions.
Review fixed compiling RED before GREEN; dependencies precede runtime activation.

REDs must reach actual crypto/Server/no-request verifier and original IPC/manager;
count zero backend/environment calls and fresh status/groups/raw/network checks.
Cover drift after readiness, malformed/oversized/replayed/cross-session/27-field
requests, pre-publication gating, busy/pre-cancel, H/caller loss after complete
reply, clock steps/delays/exact expiry without extending the monotonic bound,
unchanged CopyIn semantics, blocked inspector/writer EOF and all joins.
Use actual L7 Coordinator with fake-only topology/proxy/rules to prove fresh
inspection order, stable IDs, rule drift and no Session reentry deadlock.
Terminal REDs fail process wait, cgroup emptiness, jail/UID/store/namespace cleanup
and authenticated finalized readback; forbid L7/receipt/Commit on each failure.
Prove success after intentional manager forget, reject copied/foreign completion,
wrong config/L7 identity and ACK-only evidence, then retry L7/receipt failures
without touching successor FDs/UIDs. Root/live acceptance separately requires the
actual root constructor, fresh mandatory Jailer, built digest-locked guest,
Linux raw-packet denial/rules and no-skip terminal/credential cleanup. No fake
component result, this document, or pending GREEN completes L7/L8/L10/L11.
