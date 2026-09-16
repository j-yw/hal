# Selected eight-role exec and terminal ownership

DESIGN ONLY, based on `88dbd286cf289a3f0df4f024cfd43255c8487b1c`.
The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md),
[pre-exec assembler](sandbox-runtime-v2-minimal-preexec-assembler.md),
[selected L7 bindings](sandbox-runtime-v2-minimal-l7-bindings.md), and
[work composition](sandbox-runtime-v2-minimal-supervisor-composition.md) govern.
Guest inspection `afcf1326` is accepted in this base. Preexec `c425da41` is now
accepted at `8b22ba11`, but remains pre-exec-only. Paired supervisor `d6b4b1d8`
was inspected as a fixed pending-review dependency, not accepted here.
No production change, RED, activation, native build or live run is authorized.

## Decision and trusted inputs

Extend the SAME `minimalTemplateAssetOwner` and attached `minimalPreexecAttempt`;
never construct another owner, selection, L7 Session or process manager. Actual
Workflow/local verification -> Reserve/Arm -> binding.Start -> Claim -> the one
launch lease and measured sealed assets remain the only input authority.
The old `withJailerRecoveryProducerInputs` takes another lease and snapshots;
`startJailerRecoverySupervisorCommand` owns another bootstrap reader, drops the
original channel, detaches Wait and can call stopAndCommit. Neither is reusable
as the selected producer. Keep their seven-role/legacy behavior unchanged.

A private trusted host composition binds the existing provider to its original
`minimalPreexecHost` before any selection is exposed. Deployment supplies the
explicit installed policy/tool/resource pins, independently trusted executable
SHA256, private state root and stable key, never worker JSON or image metadata.
Use `openL8RuntimeOwnerDirectory` for the provisioned root, descriptor-relative
NOFOLLOW/CLOEXEC access and the existing exact root-owned 0600/32-byte key checks;
use `snapshotStrictJailerExecutable` once at host acquisition. Feed real handles
through `newMinimalPreexecHost` and retain its owned duplicates. Acquisition
does not provision keys, install binaries, reserve a UID or mint build evidence.
Only the supervisor reserves UID/store ownership and pins Jailer/Firecracker;
production root checks remain actual `Geteuid()==0` checks.

The job uses the preexec host's same-object root/key/executable duplicates, exact
exclusive per-job directory, original kernel/rootfs, sealed FC/selected config,
separate seed owner and same Session namespace duplicates. Recheck object pins,
independent digests, full 25-field expectation, original Claim/request/template,
host/provider association, lease and loss before exec. No resnapshot or path
repair is permitted. Shared host closure blocks new borrows and cancels jobs;
it cannot close job-owned duplicates. Retain the root FD through final retirement.

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

The sealed executable is addressed through its retained producer FD using the
existing `/proc/<producer-pid>/fd/<fd>` pattern; it is not a ninth ExtraFile.
Use the existing private `supervise` argument, empty environment, no inherited
stdin and discarded stdout/stderr. No `CommandContext` or parent-death kill on
this supervisor: it must survive producer death for cleanup. The Jailer child's
existing locked-thread namespace/cgroup/Pdeathsig gate remains unchanged.
Actual user/net namespace rights cross BootstrapStart, not ExtraFiles. Their
objects and namespace pins must be exactly the Session duplicates already held.

## One startup attempt and two lifetimes

Proposed private entry: `(*minimalTemplateAssetOwner).startMinimalExec() error`.
No replacement ctx, deadline, config, descriptor or process handle is accepted.
It retains its result; nil means private startup, not Start/strict success. Until
composition is accepted, there is no production caller and neutral Start stays
owner-plus-unavailable. Later Start invokes preparation/exec in its ORIGINAL
Claim invocation, not by retrying an earlier unavailable return.

Under source.mu, admit once on the exact prepared attempt; attach the partial
exec slot, cancel/done channels, client and all cleanup ownership BEFORE socket
allocation, duplication, process callbacks or goroutines. Capture FD/owner-plus-
error immediately. Setup runs synchronously outside source.mu. A copied owner,
second attempt, expired P, closing host/owner, lease loss or mismatched input
fails unavailable without replacing the slot. Sanitize panics; callbacks own
allocations they never return, not an imaginary outer receipt.

Retain original monotonic P and reservation.Context for startup admission. The
continuing run context is a child of ORIGINAL OwnedContext, additionally revoked
by host loss, Session loss, explicit cancellation and owned transport/process
loss. It is NOT `a.ctx`, `WithoutCancel(a.ctx)`, or a new now-plus-P budget.
Split the assembler's preparation watcher from continuing loss ownership; keep
the SAME Session and its sole outer Loss observer, rather than racing consumers.
Before startup publication, P/context loss cancels the run too. Publish the
startup-complete transition only after exact candidate/fresh-proof acceptance
while P is current; stop/join only the startup watcher, with cancellation races
serialized against that transition. Never clear a previously observed lost
latch. Thereafter P expiry and normal preparation-context release do not kill
accepted work; OwnedContext/host/L7/session loss still do. L7 adapter lifetimes
are already separately owned, not a reason to replace the Session options.

Build and retain the real `exec.Cmd` and joinable Wait state before Start.
Record possible-exec admission BEFORE invoking the OS start boundary. After
that point a panic/error/cancellation is retained uncertainty, never permission
to call AbortBeforeVM. A separately proved no-child Start failure may use only
an explicitly tested no-exec rollback branch; absence of a returned process is
not that proof. No retry, supervisor kill or replacement launch clears ambiguity.
Retain command.Process even with subsequent inspection failure; run exactly one
Wait task, preserve its result/done, and never abandon it on caller timeout.

Inspect the actual supervisor PID/start/parent and live pidfd. Capture partial
observation before checking errors. The original cleanup client owns that
observation; `minimalControlProducerLaunch` borrows it through its joins, never
closes a second owning copy. No numeric PID or event fabricates an observation.
An uncertain observation retains the command and original client/directory; a
later exact cleanup attempt may revalidate this same child, not adopt a successor.

Close the producer's child socket alias after Start returns; the child inherited
its own reference. Close the producer's seed owner once that handoff is over,
including failure; capture close uncertainty, never resend or redraw. The actual
eight-role admission consumes/closes FD10 before its callback and clears derived
key bytes after that entire callback. Keep executable/config/assets/key/directory
through all consumers; never let a scope defer close them while startup allocates.

Initialize `minimalControlProducerLaunch` from this retained endpoint, exact
config/directory and actual observation. Call its `start(runCtx)` BEFORE sending
BootstrapStart, then use its sole reader for revision 2, RD2 and later original-
channel loss. The parent sends one exact namespace-correlated BootstrapStart
with two rights, using the original P and joined cancellation I/O; an ambiguous
send is not retried. No other function reads BootstrapPublished or sends further
parent messages. Await bootstrap/work using the original preparation context.
RD2's transferred endpoint remains candidate-only until its existing post-send
publication gate and selected fresh L7 inspection succeed. Do not turn EOF,
wrong rights/config/generation, a complete late reply or candidate acquisition
into published readiness. Existing work bounds/ordinal and CopyIn rules remain.

## Actual executable consumer, enabled last

Replace only the selected `unavailableMinimalControlSupervisor` callback in
`runPrivateL8RuntimeOwnerExecutable`, after all downstream gates exist. Inside
that exact `withMinimalControlSupervisorAdmission` borrow, call the real
`newMinimalControlLinuxRuntime`, retain partial ownership, construct ONE FSM
from its actual store/genesis/UID and original callbacks, then call its
`serveMinimalControlSupervisor` with that same FSM/admission. A small extraction
of the existing FSM options construction is preferable to a second algorithm.

Keep admission, controller key, runtime and cleanup accept loop alive through
work/controller/reader/writer/publication joins and lifecycle scope completion.
On loss, close admission and work first, then use original containment; the
cleanup accept loop remains available. Follow the paired implementation's
closeIO versus lifecycleDone/scopeDone split: never join a lifecycle task while
holding the FSM/containment lock it needs. Final disposal is after scope exit,
not an interchangeable I/O barrier. Preserve old six/seven-role dispatch and
strict decoders; no RD1 rights widening, ninth role or legacy bootstrap change.

## Terminal stages, retry and recovery

Extend the original owner's cancellable Finalize admission; no source/attempt/
host lock across cancellation, joins, L7/credential callbacks or filesystem I/O.
Wait for setup/exec callbacks to return before closing their results. A losing
finalizer observes its caller deadline without duplicating cleanup; admitted
trusted callbacks retain their existing bounded synchronous cleanup contract.
Keep a monotonic stage record on this same owner, never reset for another attempt:

1. Retire admission and JOIN the producer's original/work readers, admitted calls,
   writers and watchers. Start credential revocation promptly; its failure must
   not prevent original containment. Complete its cleanup before stage 4.
2. Use the original client `finalizeMinimalCleanup` for selected stop/reap,
   cgroup emptiness, owned jail/cgroup removal, exact UID/store release,
   confirmTerminalCleanup, namespace closure and durable finalized readback.
   Retain the exact `minimalJailerFinalization`; do NOT call stopAndCommit.
3. Bind the same Session's `CleanupAfterVMQuiesced` to the selected terminal
   verifier. Its required repeated JFinalize/readback uses that same client and
   completion; do not enter L7/outer Finalize from inside its callback. Complete
   L7 quarantine/rules/TAP/topology/proxy and credential cleanup. Any failure
   retains the J-finalized owner and prevents receipt/Commit.
4. Durably persist/read back the exact outer cleanup checkpoint through the
   ORIGINAL worker state owner, binding full launch/config/directory identity,
   J finalization and completed L7/credential cleanup. Receipt metadata alone
   does not prove this persistence; publish/sync uncertainty blocks Commit.
5. Only then call the same completion.commit. Preserve its exact ACK semantics,
   join the supervisor's retained Wait and serving exit, and close the client's
   observation/owned aliases after producer consumers have joined.
6. Verify the original per-job directory entry/pin under the retained root,
   require empty, then descriptor-relative AT_REMOVEDIR and fsync the root.
   Prove exclusive identity-bound validation/removal; a path stat alone is not
   atomic protection against replacement. Until that retirement is established,
   keep the directory and report uncertainty rather than delete by name.
   Never recursively delete, follow a symlink or remove a successor. Unknown
   entries, unlink/sync/close failures retain explicit retirement uncertainty.
   Close remaining snapshots/lease/job host duplicates once no consumer exists.

Return a successful MinimalLaunchCleanupReceipt only after the complete required
chain. `MinimalLaunchOwnerBinding` caches success and cannot be relied on to call
Finalize again for unfinished Commit/directory work. Before possible exec, keep
the existing preexec AbortBeforeVM branch; after it, never infer absence from a
failed handshake, empty map, exited supervisor or missing record. Wait exit alone
does not prove child/cgroup/L7/credential cleanup. Do not wait for supervisor exit
before sending Commit, which is what allows its serving loop to exit.

Cleanup-only recovery authenticates the stored exact identity/config/directory
and original supervisor, using the existing reconnect/readback and L7/credential
recovery mechanisms. It never Start/Claims/reuses a lease/reissues seed/work.
Retain partial recovery handles and stage uncertainty. A lost Commit ACK is not
success from record absence; only already-retained exact ACK or separately
accepted durable commit-only recovery evidence can resolve that window.

## Dependency order, narrow files and unresolved handoffs

1. Accept preexec and paired serving; finish selected host inspection opcode 4
   and actual guest/terminal L7 adapters first. Replace incapable preexec
   verifiers at Coordinator CONSTRUCTION, never after Session creation. No
   temporary successful verifier or uninspected VM makes this dependency green.
2. New private `minimal_selected_exec_linux.go` owns command/partial startup
   and its focused lifetime sibling owns continuing lifetime/joins.
   Narrow changes to `minimal_preexec_assembler_linux.go` and
   `minimal_launch_template_handoff_linux.go` attach that state/cleanup routing.
   Existing config/seed/FD/L7 algorithms remain authoritative.
3. Selected terminal composition implements stages above; trusted provider/host
   pairing belongs beside `minimal_launch_template_association_linux.go`.
4. Only after credential and durable-finalization composition is accepted, wire
   the executable callback in `l8_runtime_owner_executable_linux.go` and its
   minimal-runtime sibling. Worker/default activation is a separate final slice.

Two concrete activation handoffs still need their own reviewed design/RED:
`minimal_launch_dispatch.go` retains owners but has no work/credential consumer
and deliberately returns unavailable; the neutral owner exposes Identity/Finalize
only. Select the smallest same-owner worker consumer without exposing raw work
FDs or treating a successful provider Start as a complete job result. Also,
minimal launch state explicitly forbids the legacy credential recovery receipt;
the existing worker persist-then-Commit pattern is reusable choreography, not an
already compatible schema/callback. Specify its selected outer checkpoint and
readback authorization before implementing terminal success. Prefer extending
the existing private worker state and narrow typed handoff, not another store
or an unreviewed generic persistence callback. Deployment provisioning source
and crash-safe post-Commit directory-retirement readback must be pinned there.

## RED-first evidence and live boundary

Freeze compiling REDs; preserve earlier assertions. Use actual Claim/preexec/L7
Coordinator and real FD/seed/namespace validators with
existing fake host network/process boundaries. Count every reached boundary.
Cover eight exact roles and no extra environment/FDs, same inputs/lease/owner,
failure before/after possible exec, partial return/panic, real observation errors,
seed closure, P expiry versus continuing OwnedContext, concurrent Finalize, and
one actual original reader through revision2/RD2. Use the same original-manager
authenticated guest fixture, not a replacement handle. Add real partial send,
loss/late publication, cleanup failure/retry, and successor-FD/directory probes.
An explicitly scoped harmless subprocess can prove inherited FDs, retained Wait,
real pidfd/parent identity and seed consumption; it cannot prove root/VM policy.
All tasks join; test rescue never counts as a production cleanup barrier.

Every terminal stage gets a reached failure forbidding later stages and success.
Test durable failure before Commit, ACK loss, same-owner retries, preparation
return followed by P cancellation, and post-Commit empty-directory retirement.
Run focused races, existing guards, full default/race/vet/build/docs and platform
compile on fixed integrated candidates. Prepared Linux must separately run the
real eight-role root executable, mandatory fresh Jailer, digest-locked guest,
fresh isolation/rules, three credential modes and failure/restart cleanup with
no required skips. This design itself has source-review/diff-check evidence only.
