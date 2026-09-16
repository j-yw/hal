# Selected eight-role exec and terminal ownership

DESIGN ONLY; handoff refinement based on `d3baf34a8fe296f8a4b702171b1cab7152172685`.
The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md),
[pre-exec assembler](sandbox-runtime-v2-minimal-preexec-assembler.md),
[selected L7 bindings](sandbox-runtime-v2-minimal-l7-bindings.md), and
[work composition](sandbox-runtime-v2-minimal-supervisor-composition.md) govern.
Guest inspection `afcf1326`, preexec `c425da41` and paired supervisor `d6b4b1d8`
are accepted in this base. They do not constitute selected job activation.
No production change, RED, activation, native build or live run is authorized.

## Decision and trusted inputs

Extend the SAME `minimalTemplateAssetOwner` and `minimalPreexecAttempt`; no new owner,
selection, L7 Session or manager. Actual Workflow/local verification -> Reserve/Arm ->
binding.Start -> Claim -> one lease/sealed assets remains the only input authority.
Do not reuse `withJailerRecoveryProducerInputs` (second lease/snapshots) or
`startJailerRecoverySupervisorCommand` (second bootstrap reader, drops original channel,
detached Wait, early stopAndCommit). Preserve their seven-role/legacy behavior.

A private `acquireMinimalSelectedDeployment(ctx, options)` binds the existing
provider to its original `minimalPreexecHost` before exposing selection. Options
come from the explicitly selected, root-owned daemon construction path: fixed
deployment ID/revision, installed policy/tool/resource pins, independently trusted
executable SHA256, owner-root/key/executable paths, template association, L7 state
root and credential authorizer/source-registry/activators. They are NOT worker
JSON, template-provided expectations, environment discovery or downloaded policy.
No new installation manifest/parser is necessary: use immutable typed startup
options, require every field, and retain their canonical non-secret digest for
recovery. Missing historical deployment configuration fails closed, not defaults.
Use `openL8RuntimeOwnerDirectory` for the provisioned root, descriptor-relative
NOFOLLOW/CLOEXEC access and the existing exact root-owned 0600/32-byte key checks;
use `snapshotStrictJailerExecutable` once at host acquisition. Feed real handles
through `newMinimalPreexecHost` and retain its owned duplicates. Acquisition
does not provision keys, install binaries, reserve a UID or mint build evidence.
Only the supervisor reserves UID/store ownership and pins Jailer/Firecracker;
production root checks remain actual `Geteuid()==0` checks. Attach partial host
ownership before acquisition; every returned FD+error remains owned. Borrowed
registry/credential capabilities require explicit lifetime borrows; host close
revokes new work but joins existing cleanup before releasing their backing owners.

Use same-object root/key/executable duplicates, exclusive job directory, original assets,
sealed FC/selected config, separate seed and same Session namespace duplicates. Recheck
pins/digests/25 fields/Claim/request/template/host/provider/lease/loss before exec; no
resnapshot/path repair. Host close blocks new borrows/cancels jobs, not job-owned FDs.
Retain root through retirement. Acquire nonblocking exclusive flock on its original open
description; job duplicates retain it until last close, never alias LOCK_UN. A private
context-aware operation gate serializes create/recover/retire, rechecking cancellation
after admission. Every selected writer uses this scope; unexplained root entries reject.
This protects concurrent legitimate owners/non-root writers, not malicious host root.

## Exactly eight inherited roles

| Child FD | Retained source |
| --- | --- |
| 3 | New original AF_UNIX SOCK_SEQPACKET child endpoint |
| 4 | Original identity-bound per-job record directory |
| 5 | Existing sealed selected supervisor config |
| 6 | Original claimed sealed kernel |
| 7 | Original claimed sealed rootfs |
| 8 | Owned duplicate of deployment's stable recovery key |
| 9 | Existing sealed Firecracker config |
| 10 | One-shot sealed controller seed, never the stable key |

Address sealed executable through retained `/proc/<producer-pid>/fd/<fd>`, not a ninth
ExtraFile. Use private `supervise`, empty environment, no inherited stdin, discarded
stdout/stderr; no CommandContext/parent-death kill on cleanup supervisor. Preserve the
Jailer child's locked-thread namespace/cgroup/Pdeathsig gate. The same Session's actual
user/net namespace objects and pins cross BootstrapStart, not ExtraFiles.

## One startup attempt and two lifetimes

Proposed private entry: `(*minimalTemplateAssetOwner).startMinimalExec() error`.
No replacement ctx/deadline/config/descriptor/process is accepted; nil means private startup,
not Start/strict success. Until composition is accepted, no production caller exists and Start
stays owner-plus-unavailable. Later Start invokes preparation/exec in its ORIGINAL Claim
invocation, not by retrying an earlier unavailable return.

Under source.mu, admit once on the exact attempt; attach partial exec/client/cancel/done
ownership BEFORE sockets, duplicates, callbacks or goroutines. Capture FD/owner+error
immediately. Setup runs synchronously outside source.mu. Copy/second attempt/expired P/
closing/loss/mismatch rejects without replacing the slot. Sanitize panics; callbacks own
allocations they never return, not an imaginary outer receipt.

Retain original monotonic P/reservation.Context for startup. Run is a child of ORIGINAL
OwnedContext, revoked by host/Session/explicit cancel/owned transport/process loss; NOT
`a.ctx`, `WithoutCancel(a.ctx)` or a new now-plus-P budget. Split preparation watcher from
continuing loss ownership; retain the SAME Session and sole outer Loss observer.
Before publication, P/context loss cancels run too. Publish startup-complete only after
exact candidate/fresh proof while P is current; stop/join only startup watcher, serializing
cancellation against that transition. Never reset a lost latch. Later P expiry/normal prep
release does not kill accepted work; OwnedContext/host/L7/session loss still does.

Retain real exec.Cmd and joinable Wait before Start; record possible-exec admission BEFORE
the OS boundary. Thereafter panic/error/cancel is uncertainty, not AbortBeforeVM authority.
Only separately proved no-child Start failure may use a tested no-exec rollback branch;
missing returned process is not proof. No retry/kill/replacement clears ambiguity. Retain
command.Process despite inspection failure; exactly one Wait task/result survives timeouts.

Inspect actual supervisor PID/start/parent/live pidfd; retain partial observation before
errors. Original cleanup client owns it; minimalControlProducerLaunch only borrows through
joins. No numeric PID/event fabricates observation. Uncertainty retains command/client/
directory; later cleanup revalidates this same child, never adopts a successor.

Close producer child-socket alias and seed owner after Start handoff, including failure;
retain close uncertainty, never resend/redraw. Eight-role admission consumes/closes FD10
before callback and wipes derived key after its ENTIRE scope. Retain executable/config/
assets/key/directory through all consumers; no defer closes them while startup allocates.

Initialize minimalControlProducerLaunch with original endpoint/config/directory/observation;
start(runCtx) BEFORE BootstrapStart, using its sole revision2/RD2/loss reader. Send one
namespace-correlated BootstrapStart/two rights under original P and joined cancellation
I/O; no retry on ambiguity, other bootstrap reader or further parent messages. Await
bootstrap/work under original preparation context. RD2 remains candidate-only until its
post-send gate and fresh L7 inspection pass; EOF/bad rights/config/generation/late reply
never become readiness. Preserve work bounds/ordinal and completed-CopyIn semantics.

## Actual executable consumer, enabled last

Replace only unavailableMinimalControlSupervisor in runPrivateL8RuntimeOwnerExecutable,
after downstream gates exist. Inside exact withMinimalControlSupervisorAdmission borrow,
call newMinimalControlLinuxRuntime, retain partial ownership and construct ONE FSM from
actual store/genesis/UID/original callbacks. Call its serveMinimalControlSupervisor with
same FSM/admission; extract existing FSM option construction, not another algorithm.

Retain admission/key/runtime/cleanup accept loop through work/controller/reader/writer/
publication joins and scope completion. Loss closes admission/work then original containment;
cleanup accept remains. Preserve closeIO versus lifecycleDone/scopeDone: no joining tasks
under their FSM/containment lock. Dispose after scope exit, not at I/O barrier. Preserve
old six/seven-role dispatch/strict decoders; no RD1 widening or legacy bootstrap change.

## Terminal stages, retry and recovery

Extend original cancellable Finalize admission; no source/attempt/host bookkeeping
lock across cancellation, joins, L7/credential callbacks or filesystem I/O.
Wait for setup/exec callbacks to return before closing their results. A losing
finalizer observes its caller deadline without duplicating cleanup; admitted
trusted callbacks retain their existing bounded synchronous cleanup contract.
Keep a monotonic stage record on this same owner, never reset for another attempt:

1. Retire admission; JOIN original/work readers, admitted calls, writers/watchers. Start
   credential revocation promptly; failure never prevents containment, but blocks stage 4.
2. Original client.finalizeMinimalCleanup proves stop/reap/cgroup empty, jail/cgroup removal,
   UID/store release, confirmTerminalCleanup, namespace close and durable finalized readback.
   Retain exact minimalJailerFinalization; do NOT call stopAndCommit.
3. Same Session.CleanupAfterVMQuiesced uses selected terminal verifier and repeated SAME
   JFinalize/readback; callback never reenters L7/outer Finalize. Complete L7 quarantine/
   rules/TAP/topology/proxy and credentials; failure retains owner and forbids Commit.
4. Persist/read back exact outer checkpoint through ORIGINAL worker state owner, binding
   full identity/J/L7/credentials. Metadata is not persistence; uncertainty blocks Commit.
5. Same completion.commit, exact ACK semantics, retained supervisor Wait/serving join;
   close client observation/aliases after producer consumers join.
6. Execute the retirement/readback protocol below; close remaining owned resources
   and durably publish/read back terminal state before returning a receipt.

Receipt success requires the whole chain: neutral Finalize caches success. Preserve
pre-exec AbortBeforeVM; after possible exec, failed handshake/map absence/exited supervisor/
missing record is not child/cgroup/L7/credential absence. Never wait for supervisor exit
before Commit, which allows its serving loop to exit.

## Same-owner worker consumer and bound journal

Add optional selected methods through `MinimalLaunchOwnerBinding`, not a runtime
Driver factory or a metadata-to-owner constructor. Proposed neutral API shape:

```go
reservation.BindWorker(input MinimalLaunchWorkerInput, journal MinimalLaunchJournal) error
owner.Run(ctx context.Context) (ExecResult, error)
owner.Finalize(ctx context.Context) (MinimalLaunchCleanupReceipt, error) // unchanged
```

`BindWorker` is once-only before Arm on the ORIGINAL reservation. Input retains
the actual authority-issued principal, original cloned ExecRequest with bounded
worker log writers, credential intent and exact request key; no caller-supplied
deadline, owner, FD or ready descriptor. The private worker entry constructs it
after reserved readback. The neutral self-bound handle checks original principal
authority/provider/reservation pairing; copied/zero/foreign handles reject.
The provider borrows it only after genuine Claim. Register the SAME partial asset
owner on that handle before preparation callbacks; neutral Start returns that
one retained owner binding, including on error, rather than wrapping a replacement.
Worker checks after return that its entry still holds that exact owner.

`Run` dispatches only to the optional interface implemented by that original
owner, consumes the original command once, and never calls Start again. Internally
it uses the retained producer workload transport and guestagent.Client. Worker
imports root sandboxruntime only; concrete guest/client/FD/L7 imports remain in
firecrackerhost. No wire-exposed Run binding, raw FD getter or arbitrary Target
rebinding. Generic worker exec/copy and old credential Binder remain unselected.
Only exact accepted startup followed by credential activation admits the command.

The owner derives the credential seed from original Claim/L7/27-field session
and separately drawn activation generations. It retains the real credential
runtime/preflight/session and lifecycle on this same attempt. Revalidate the
original principal with the deployment's credential authorizer, call
AuthorizeJobCredentials for the original intent, then ResolveAuthorizedSource
with that returned opaque authorization; launch grants never substitute. Persist
seed before preflight, completed identity and all binding intents BEFORE the first
activator. Prepare receives actual authorization/sources; ActiveProof and the
original private ExecBinding gate execution and renewal, never a proof ID alone.
Selected guest credential Prepare/Renew/Revoke must use the original supervised
session with bounded typed operations, not CopyIn secrets or a second handshake.
Until those concrete adapters exist, reject activation; existing interface-shaped
test runtimes or optional HandleStore=nil cannot satisfy this contract.
Legacy Revoke returns before host cleanup on guest failure; preflight.Abort metadata
is not terminal proof and rejects transferred ownership. Selected cleanup always
attempts/joins host revokers and binds guest destruction to actual original JFinalize,
not invented helper proof. Complete host cleanup plus that binding (or admitted live
guest revoke) alone admits selected cleanup, never generic Abort metadata.

One worker-owned lifetime task invokes Run, publishes bounded/redacted existing
job logs, records its result and calls Finalize outside manager.mu. Preserve
original OwnedContext after request/P completion. Cancellation revokes immediately
before disk work, marks cancel intent once, then joins Run and cleanup; transport
loss never causes command replay. A failed cleanup retains its entry and retry
owner, not a completed job. Service close joins owned tasks before releasing the
original state lock; bounded unsuccessful close retains cleanup ownership/lock.
Status/resolve/log/cancel authenticate stored principal and exact job/submission. Duplicate
starts, including after restart, recompute RequestKey using stored origin daemon generation;
equal intent returns existing state, conflict rejects. Never another Run.
Start waits for RecordActive readback/failure via its entry, not a new ready object; Run continues.

`MinimalLaunchJournal` is a CLOSED typed port: `RecordInputs`, `RecordPrepared`,
`RecordExecAttempt`, `RecordSupervisor`, `RecordCredentials`, `RecordActive`,
`BeginCleanup`, `SealCleanup`, `BeginRetirement`, `Complete`, and `Readback`, each context-bound
with a dedicated payload and checked revision result. No arbitrary bytes, path,
key, delete, caller-selected phase or generic persist callback. Its sole production
implementation is a private worker entry holding the exact manager/store/lock,
reservation and registered owner. It verifies those pointers, full identity,
expected revision and exact predecessor bytes under manager.mu on EVERY call.
The neutral wrapper retains the same port across Start/Run/Finalize and checks
returned revision/identity; it cannot be reconstructed from serialized metadata.
No journal callback calls owner/Session or waits for their joins. All owner locks
are released before invoking it; caller cancellation is checked after lock waits.
Cleanup admission survives original reservation revocation; it cannot grant work.

## Selected durable schema and crash boundaries

Add only `minimalLaunch.selected,omitempty` to private `storedMinimalLaunchV1`:
version `sandboxjob-minimal-selected-v1`, deployment ID/revision/digest, preparation inputs,
supervisor observation, credential checkpoint, optional outer cleanup/retirement checkpoints.
Use camelCase fields; omit from public JobV2. Omitted-field v1 validation/bytes stay unchanged,
including rejection of legacy CredentialState/RecoveryReceipt. Selected validation is separate;
old readers reject unknown fields. Keep 64KiB whole-record limit, canonical unique-field JSON,
safe IDs/lowercase SHA256. No command/env/stdin/output/secrets/raw endpoint/path/key/proof object;
guest target binding IDs are safe IDs, not host paths.

The original MinimalLaunch.Revision is the single disk CAS counter; increment
once per transition, including cancellation. Selected Phase allowlist:
reserved -> dispatching -> preparing -> prepared -> exec_attempted -> bootstrapped
-> credential_preparing -> active -> cleanup_pending -> cleanup_sealed
-> retire_intent -> retired. Failure/cancel may enter cleanup_pending from any
nonterminal phase while retaining all earlier data; intermediate credential
updates stay credential_preparing/active with increasing revision. No regression,
skipping required evidence, revision wrap, or successor generation replacement.
JobV2 is queued before active, running at active, and terminal only at retired;
cancel intent is independent of phase. No completion receipt appears earlier.

RecordInputs persists exact L7 identity BEFORE Coordinator.Prepare and deployment/root
association; directory pin only after actual open. RecordPrepared adds config/measured asset
digests, namespace pins, public boot/controller generations and full correlation before exec.
RecordExecAttempt is write-ahead possible-exec intent. RecordSupervisor adds actual host boot/
PID/start/generation and revision2 record/config correlation before credential effects.
Crash before that readback: learn original supervisor only through exact pinned selected
record and actual reconnect authentication, never a PID guess/replacement launch.

Credential checkpoint stores validated seed/identity, lifecycle revision, per-binding recovery
intent/handle generations. Write intent BEFORE each effect, handle/readback before success.
Adapt existing mode revokers/handle validation into this SAME job file, no second handle store.
Require recovery/revocation by exact pre-recorded identity+binding generation even after lost
handle-result write; incapable revoker blocks activation. Partial prepare is not absence.

SealCleanup holds kind, expected sealing revision, full launch identity/request key,
deployment/root/directory pins (device/inode/type/UID/mode, not size/link count), config digest,
supervisor tuple, J commit ID/target revision and immutable terminal-record projection digest
(no mutable reconnect fields), exact L7 identity/terminal correlation, credential identity/
revision/completed bindings. Issue only after stages 1–3. MAC = stable-key HMAC-SHA256 over
`hal/minimal-outer-cleanup/v1` + NUL + canonical payload excluding MAC; encode raw base64url
(43 chars), NOT legacy receipt domain. Worker checks independently held identity/inputs too.
This authenticates historical cleanup, not readiness. Receipt OwnerCommitID is outer MAC,
FinalizedRevision its cleanup_sealed journal revision, NOT J fields. Typed no_exec requires
proved pre-exec rollback/L7 Abort/credential cleanup, omits J and skips Commit/Wait;
possible-exec uncertainty cannot select it. Wipe all owned key/MAC work buffers on failure.

All journal updates reuse saveMinimalLaunch/checkMinimalAuthority: original held
state lock, exact predecessor readback, private exclusive temp, bounded write,
file sync, same-root publication, directory sync, exact inode/bytes readback and
checked close. Only successful SealCleanup readback admits same-client Commit.
An uncertain publication poisons new work and blocks Commit; explicit same-entry
reconciliation may accept only exact prior/intended bytes+file identity under the
original lock, never overwrite an unknown third state. Preserve both outcomes
until resolved. This is the existing credential persist-before-Commit choreography,
not compatibility with its seed-bound receipt/schema or ignored recovery errors.

Finalize owns this whole journal choreography. Complete atomically persists the
terminal JobV2 result and final receipt AFTER Commit/exit/retirement/resources;
it then rereads that exact state before returning success. Thus neutral receipt
caching hides no pending operation. If Complete succeeds but reply/context fails,
the same owner/recovery reads it back; it never reruns Commit or the command.
BeginCleanup retains Run's exit/failure/cancel result without exposing terminal
success; a lost result after restart becomes interrupted, never assumed exit zero.

## Restart, lost ACK and exact directory retirement

Replace selected-only empty-store startup with strict enumeration/readback under
the existing state lock. Validate every entry first; unknown/corrupt/old incomplete
records fail closed, not removal or reinterpretation. Preserve original daemon
generation as historical correlation; the new daemon gets cleanup-only authority,
not a fresh principal/grant. For each nonterminal record retain one recovery
binding/partial owner and its journal before callbacks; disable launch for that
identity until resolved. Recovery does not Claim, transfer assets, redraw seed or
construct a replacement process manager. Use the surviving original supervisor,
existing reconnect/JFinalize and exact L7 Reconciler/mode recovery. A missing L7
journal/credential handle is not absence; validate existing generation-bound
retirement evidence or retain uncertainty. Host reboot without prior whole-job
cleanup checkpoint remains unavailable, not permission to synthesize JFinalize.
Add once-only recovery.BindJournal on the original recovery binding before Recover;
only its original authenticated worker-state entry can supply this cleanup-only port.

Before cleanup_sealed, always complete real J/L7/credential recovery; no ACK-only
shortcut. At cleanup_sealed the authenticated worker checkpoint proves those
completed historical stages. If the selected record still exists, reauthenticate
and verify the exact finalized checkpoint, then repeat ONLY Commit. If it is
absent, require valid outer HMAC, matching deployment/root/directory, actual
termination of the original boot/PID/start (never wait/kill a reused PID), and
absence of its owned reconnect endpoint before entering retirement. This resolves
lost ACK using durable pre-Commit cleanup evidence AND subsequent observations,
not record absence as VM-absence proof. A living unreachable supervisor, mismatch,
unknown file or failed observation remains uncertain. New recovery never sets the
old client's acknowledged bit from disk; use a separate private commit-only result.

After exact ACK plus retained Wait join, or that commit-only recovery result,
validate the original directory under the deployment root lock+operation mutex:
held FD and NOFOLLOW entry must match the recorded pin and be empty. Persist/
read back BeginRetirement with those pins and prior cleanup checkpoint digest
BEFORE unlink, releasing the operation mutex for journal calls and rechecking
everything after reacquisition. Keep owned control/record files absent; never remove them to
make this check pass. Use Unlinkat(AT_REMOVEDIR), fsync(root), NOFOLLOW absence
readback and held old-directory fstat with zero links, then checked close.
No stat-then-unlink atomicity is claimed; exclusive trusted-writer scope closes
that race. Symlink/different inode/foreign contents never become deletion targets.

Crash after unlink but before root sync/Complete: exact retire_intent authorizes
only checking the original name. If absent, sync/read back absence and complete;
if the same original empty inode remains, retry retirement; a successor rejects.
Never reuse RuntimeGeneration, including retained terminal tombstones. All new
allocations also honor root serialization; no rename/reuse recovery fallback.
Unknown empty directories left before a durable pin retain the accepted preexec
uncertainty and require explicit reconciliation, not automatic name-only removal.
Close snapshots/lease/job duplicates before Complete, retaining the journal and
non-owning deployment lifetime borrow until its readback. All job-owned FD closes,
including root duplicate, precede Complete; later borrow release only drops a
lifetime reference. No owning close error is hidden behind terminal success.

## Dependency order, narrow files and immediate REDs

1. On accepted preexec/paired serving, finish selected host inspection opcode 4
   and actual guest/terminal L7 adapters first. Replace incapable preexec
   verifiers at Coordinator CONSTRUCTION, never after Session creation. No
   temporary successful verifier or uninspected VM makes this dependency green.
2. New private `minimal_selected_exec_linux.go` owns command/partial startup
   and its focused lifetime sibling owns continuing lifetime/joins.
   Narrow changes to `minimal_preexec_assembler_linux.go` and
   `minimal_launch_template_handoff_linux.go` attach that state/cleanup routing.
   Existing config/seed/FD/L7 algorithms remain authoritative.
3. New neutral `minimal_launch_worker.go` and worker `minimal_launch_selected.go`:
   first RED is missing BindWorker/early registration with independent actual Claim,
   retained owner, original lock and durable-dispatch controls. Narrow admission/
   dispatch/store/cancel/startup edits add selected mode. Follow with actual bound
   SealCleanup sync/readback failures forbidding Commit/receipt, copied handles,
   one Run, active/log publication, credential write-ahead and cancel/close joins.
4. New selected deployment/terminal/recovery siblings implement the concrete
   contracts above beside `minimal_launch_template_association_linux.go`; RED
   root/key/executable acquisition, journal crash points, all stages and lost ACK,
   retirement interruption/successor preservation, then actual original-manager
   subprocess composition. Existing L7/mode algorithm changes need reached REDs;
   optional legacy persistence is never silently promoted to selected authority.
5. Only after credential and durable-finalization composition is accepted, wire
   the executable callback in `l8_runtime_owner_executable_linux.go` and its
   minimal-runtime sibling. Worker/default activation is a separate final slice.

Source anchors: `minimal_launch_owner.go` caches Finalize; worker `minimal_launch_dispatch.go`,
`minimal_launch_store{,_ops}.go` and `job_manager_v2.go:recoverStoredJobCredentialsV2` establish
ownership/durability. `minimal_preexec_{host,assembler}_linux.go`,
`minimal_jailer_finalization_linux.go`, `jailer_recovery_reconnect_linux.go`,
`l7network/{reconciler,journal}.go`, and `l8_job_credential_{runtime,handle_store}.go`
are the concrete adaptation points, not evidence this wiring exists already.
Deployment paths, approved policy/source allowlists and installed digests are operator-owned
inputs, not values to invent. Internal API choices above are fixed; missing capability rejects.

## Evidence boundary

Freeze compiling RED before GREEN; preserve old assertions. Ordinary fixtures use actual
Claim/preexec/L7/FD/seed/namespace/store locks with explicit fake host command/network.
Reach before/after-exec, seed-close, P/OwnedContext, cancel/join and every durable crash window.
Same-manager authenticated transcript/bounded harmless subprocess prove eight roles/Wait/
pidfd/no replay, not VM policy; rescue is not cleanup. Fixed candidates need focused races,
old guards, broad default/race/vet/build/docs/platform checks. Separate prepared-Linux gates:
real root eight-role exec, fresh Jailer/digest-locked guest/isolation/rules, all credential
modes/restart cleanup, no required skips. This design has source-review/diff-check only.
