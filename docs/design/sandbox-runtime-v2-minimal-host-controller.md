# Selected minimal host controller and producer handoff

## Status and scope

Design only, at `b6a440fe64f4a54352c92156d3c77e393d3641d3`. The
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md) and
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) govern.
The worker prelaunch design is frozen separately at
`3a4ae03d394879b6414158b891263c1993d7366f`,
`docs/design/sandbox-runtime-v2-minimal-worker-prelaunch.md`. Its authorizer,
reservation/provider contract and selected dispatch are dependencies, not
implemented authority at this base.

Implement one actual controller inside the existing surviving Jailer supervisor,
and return its current readiness to the original concrete producer/provider.
Do not add a dispatcher, daemon, job store, namespace manager, credential seed,
standalone readiness issuer, or default selection. This design refines the
producer handoff in the accepted minimal bootstrap/control designs. It does not
change the guest wire schema or supersede legacy six/seven-FD behavior.

Readiness means only `authenticated_minimal_control`. It proves neither workload
execution, guest executable attestation, network enforcement, guest seccomp,
credential activation nor cleanup. Same-UID guest code is hostile; the host's
retained VM/process/socket authority, not a guest assertion, identifies the peer.

## Concrete source constraints

Paths in this section are under `internal/sandboxruntime/microvm/`.

- `firecrackerhost/jailer_recovery_producer_linux.go:43`,
  `withJailerRecoveryProducerInputs`, consumes `TakeLaunchLease`, snapshots exact
  measured kernel/rootfs bytes, seals caller-supplied FC config, validates it,
  and starts the seven-role owner. It has no worker reservation, boot renderer,
  signing key, L7 session or authenticated readiness consumer.
- `firecrackerhost/l8_runtime_owner_executable_linux.go:294`,
  `startJailerRecoverySupervisorCommand`, creates the original seqpacket pair,
  starts the retained executable, observes the actual child supervisor, sends
  namespace FDs and waits for `BootstrapPublished`. Its deferred parent close is
  correct for that existing route and must remain unchanged there.
- `firecrackerhost/l8_runtime_owner_supervisor.go:796`, `HandleBootstrap`, holds
  the owner mutex while creating genesis, starting the gated child, recording
  revision 1, releasing the gate and publishing revision 2. Revision 2 means
  running/unclaimed ownership, not guest readiness. No handshake may be inserted
  into this mutex-held path or delay its reply until guest boot.
- `firecrackerhost/l8_runtime_owner_runtime_linux.go:265`, `serveBootstrap`,
  sends that reply and returns; `serveControllers` then serves the existing
  cleanup reconnect endpoint. The selected runtime retains the actual
  `lifecycle.manager`, `session` and `coordinator.generation.process`
  (`jailer_recovery_runtime_linux.go:18`, `jailer_coordinator.go:123`). These are
  the post-release authority, never a reconstructed PID or path from the daemon.
- That `serveBootstrap` currently passes `context.Background()` to the FSM;
  `jailer_recovery_runtime_linux.go:165`, `startChild`, independently replaces
  it with a background containment-budget context. The starter's `release`
  (`jailer_recovery_starter_linux.go:106`) has no cancellation/deadline check.
  A channel monitor alone therefore cannot prevent a canceled selected launch.
- `HandleController` holds `owner.mu` while StopReap calls `reinspectAbsence`
  and `ContainChild` (`l8_runtime_owner_supervisor.go:964,1044,1160`). The selected
  `contain` also holds `selected.mu` throughout containment. Neither callback is
  a safe location to close/join a controller that may need those same locks.
- `firecrackerhost/minimal_control_transport.go:66`, `Open`, is one-shot and
  enforces retained strict owner, private parent/socket, peer and manager
  currentness. Baseline owns the additive private
  `OpenWhenAvailable(ownerCtx, absoluteAdmissionDeadline)` dependency: same-owner
  initial ENOENT and narrowly classified empty pre-ACK retries, one 15-second
  ceiling, permanent retry termination after the first ACK, and one hard lifetime.
  That API is not present at this base; do not implement a second retry loop here.
- `guestagent/minimalcontrol/codec.go:146` has a private request decoder and
  response encoder but no shared host request encoder/response validator.
  `bootstrap.go` already owns `RenderBootCommandLine` and `Binding.BootstrapPrelude`.
  Reuse its 25/27-field validation and canonical bytes; no host schema copy.
- `guestagent/session/handshake.go:85` copies the signing key in
  `NewControllerHandshake`; `AcceptGuestHello` consumes and destroys that copy
  on every result. `State.WriteApplication` holds the state mutex across I/O
  (`session/state.go:117`), so closing/revoking in the wrong order can deadlock.
- `firecrackerhost/l7network/launch_handoff.go:64` issues an opaque descriptor
  from the actual prepared session and exact ten-field L7 identity. The snapshot
  is not revocable authority and cannot be recreated after exec. `ProcessNamespace`
  revalidates on duplication; `Session.Loss()` is a single-consumer loss result,
  not a broadcast channel for independent readers.

The separately accepted L7 mapper submission
`95c748a7400e7e55c4a5bc393982544079253e4f` is integrated as ordered
`935285d4`, `c734b967`, `47ddd3ecc069406d57aac21860ee420914feb1e9`.
It defines `renderMinimalL7Config` and selected exact NIC/boot validation. This
design checkout remains at b6; implementation must use the accepted integrated
dependency. Its descriptor-only source guard must not be widened into lifecycle
construction inside the pure mapper.

## Selected producer inputs and eight-FD admission

The concrete `MinimalJobRuntimeProvider.StartMinimalJob` adapter, not worker JSON,
consumes the manager's one-shot reservation before first host allocation. Keep
the returned cleanup owner even when subsequent preparation/readiness fails.
The immutable inputs are:

- Exact claimed reservation, request fingerprint, worker/job/submission/plan,
  principal, host/runtime and policy correlations, preparation deadline and
  revocation signal, from the existing service/manager's selected issuer.
- Retained provider-owned verified distribution/selection, trusted host policy,
  owner directory/root key/executable pins, and actual selected L7 session plus
  its independently expected ten-field identity. Selection resolution is not
  permission to allocate these resources before the reservation claim.
- Validated credential-intent `admissionGrantId` and `admissionRevision` from
  that authenticated request, unchanged. Internal `launchGrantId` and launch
  policy revision authorize preparation only; they NEVER replace those two
  guest-binding fields. No credential authorizer is called by this controller.

All guest-bound IDs must pass the shared 1–64-byte syntax. Do not hash/truncate
broader IDs, infer a completed credential grant or mint a helper generation.
The provider owns one consumer of L7 loss and fans it into its existing job
cancellation latch. It retains the same L7 session until actual terminal cleanup;
a copied descriptor alone is insufficient at prelaunch or later consumption.
The L7 Session/proxy remain in that producer daemon, not in the exec'ed Jailer
supervisor. The original channel is the supervisor's exact live-owner-loss
signal; it cannot recover that Session pointer after daemon death. Combined
terminal success remains unavailable without actual L7 cleanup/recovery.

Proposed config discriminator: `jailer-runtime-owner-minimal-control-config-v1`.
Keep the existing private supervise executable entrypoint and first seven roles:

| Inherited FD | Role | Selected control rule |
| --- | --- | --- |
| 3 | control-socket | Original private bootstrap seqpacket, retained on this route only |
| 4 | owner-directory | Existing private retained recovery directory |
| 5 | supervisor-config | Canonical sealed public config, total at most existing 32 KiB |
| 6 | kernel-asset | Existing measured immutable kernel snapshot |
| 7 | rootfs-asset | Existing measured immutable minimal rootfs snapshot |
| 8 | owner-root-key | Existing stable recovery HMAC key; never controller entropy |
| 9 | firecracker-config | Exact sealed final FC config |
| 10 | minimal-controller-key | One-shot sealed 32-byte Ed25519 seed, host-only |

Add a selected-only schema/decoder; do not add optional control fields to the
seven-role schema. Its public portion contains the existing job/policy/assets,
exact roles, all 25 prelaunch fields, boot nonce/controller public key and their
generations, the preparation deadline, distinct launch-grant correlation, and
the validated NIC/six-static-field projection plus the actual duplicated user/
network namespace device/inode tuple. JSON must be canonical and exact:
reject duplicate/unknown/aliased/null/missing fields and inconsistent redundant
runtime/image/L7 values. No private seed, private-key digest, credential, raw job
environment or completed credential identity is serialized. Existing cleanup
records can retain only their current safe config-correlation digest and job
tuple; public boot pins are not copied into the journal.
The existing seven-config validators do not accept this new type/version. Reuse
their host-policy/asset/cleanup checks explicitly, without laundering eight-role
input through an accepted seven-role discriminator. The same selected store must
bind its existing config-correlation field to the complete eight-role canonical
config digest, obtained only after its private admission. This is a coupled
internal projection change, not a new store or a caller-supplied digest override.

The selected loader must identify this exact discriminator from the bounded
sealed config, own and mark FD 9/10 CLOEXEC before any duplication that could
reuse their numbers, validate all eight roles and close every partial import.
No absent/malformed eighth FD may select the seven-role or legacy route. Keep
the six-role credential path, seven-role recovery schema and two-FD pre-exec
Jailer gate byte-semantically unchanged. No seed FD is passed to that gate or
to Jailer/Firecracker; a descriptor-inheritance test must inspect actual argv,
environment and extra-file construction, not just the role list.

The producer generates fresh boot nonce, controller key generation and boot/image
generation correlation only after reservation/input checks. Image SHA-256 comes
from the retained measured rootfs, not a caller digest. Generate the key from
fresh bounded OS entropy, independent of the recovery key. A dedicated 32-byte
sealed-copy helper checks regular/unlinked/read-only/CLOEXEC FD, exact required
seals, size 32, nonzero seed and trusted owner/mode, and verifies the derived
public key against sealed public pins. It must not use the generic 128-KiB asset-copy buffer without
wiping it. Parent seed/key copies are cleared and its seed FD closed immediately
after successful exec handoff; failure closes/clears them too. The supervisor
reads once, derives its private key, checks the public key, clears the seed and
closes the inherited seed FD BEFORE creating a Jailer child. No key is retained
for reconnect; ordinary memfd closure is not a physical-memory erasure claim.
The selected host entropy adapter must also be bounded: a single nonblocking
Linux getrandom call per 32-byte draw, fail on error/short output and clear it,
with no waiting/fallback. Use fresh draws for seed, nonce and generation/request
tokens; clear temporary arrays after encoding. Inject that bounded adapter into
the unchanged session handshake instead of allowing an arbitrary blocking reader
to defeat admission cancellation. Existing legacy randomness stays unchanged.

### Render and cross-process L7 authority

The producer obtains `Session.LaunchDescriptor(expectedL7)` and
`Session.ProcessNamespace(expectedL7)` from the same retained session. Map the
exact NIC and six raw `hal_l7_*` values, then invoke
`minimalcontrol.RenderBootCommandLine` LAST using the exact 25-field binding and
partial `session.Identity` (process/vsock fields empty). Validate the final
whole line at 4095 bytes plus Linux's counted newline, construct the complete
FC JSON, revalidate the issued-descriptor mapping, and only then hash/seal it.
Recheck reservation, selected assets and same-session namespace duplication at
the final launch barrier. No independently rendered suffix gets its own budget.
Freeze the device/inode tuple of those exact namespace duplicates into the sealed
supervisor config and transfer those same retained FDs, not replacements. The
six network binding fields come from the independently expected full L7 identity
(`networkPlanId` uses its `PlanID`, not the worker's separate `planId`); the NIC
and static fields come from its issued descriptor. Do not derive an expected
projection by parsing the candidate FC config it is supposed to validate.

An opaque descriptor cannot cross exec. The supervisor must NOT reconstruct
`l7network.LaunchDescriptor` from public JSON or stat arbitrary network state to
mint one. Proposed narrow coupled seam: after eight-role admission, build a
private sealed-projection expectation from that exact retained supervisor config;
compare its NIC/six raw values and generations against the exact FC bytes and
the 25 public pins. Reuse the pure equality/namespace scanner; keep live-descriptor
issuance in the producer. This projection proves trusted producer byte binding,
not a live L7 session. The two namespace FDs still cross via the original
BootstrapStart SCM_RIGHTS operation and existing exact device/inode/type checks.
The new branch additionally matches those actual FDs to the independently frozen
namespace tuple, not merely the correlation supplied alongside received FDs.
Provider loss closes the retained channel, causing supervisor containment.
This seam needs explicit mapper/J owner approval before GREEN; forging a
descriptor seal or relaxing the ordinary nil-expectation validator is forbidden.

## Launch reply, asynchronous ownership and readiness publication

Proposed private owner returned by a new selected producer route:

```text
launchMinimalJailerSupervisor(preparationCtx, ownerCtx, selectedInputs)
    -> ownedLaunch, error                  // preserve ownedLaunch on partial failure
ownedLaunch.WaitReady(waitCtx) -> opaqueCurrentReadiness, error
ownedLaunch.Loss() -> closed-channel notification
ownedLaunch.StopAndCommit(cleanupCtx) -> exact existing terminal result
```

These are internal producer/provider APIs, not worker JSON constructors. The
result holds the existing `jailerRecoveryClient` for cleanup and the original
bootstrap endpoint for readiness/loss. Wait cancellation does not cancel a
durably accepted job; explicit reservation cancellation/service ownership loss
does. Concurrent WaitReady callers share one result/latch, never another dial
or controller. No nil/nil success, and no readiness object from decoded metadata.

Keep `HandleBootstrap`'s existing genesis/revision 1/gate release/revision 2
sequence and immediate `BootstrapPublished` reply. Validate its exact revision 2
body and the actual observed supervisor/config/job correlation in the selected
producer. Start no guest handshake while owner/store/coordinator locks are held.
The selected bootstrap branch transfers the reader role to an original-channel
EOF monitor after consuming BootstrapStart and before launch; there are never
two readers on that endpoint. Only after the revision-2 reply is sent does it
release one owned controller task. Failure to send that reply cancels admission
and invokes existing owned containment;
it never drops the reconnect client or surviving coordinator.

For this eight-role branch only, create one owned cancellation context before
prelaunch allocations; original-channel EOF/error, reservation cancellation and
owner loss cancel it. Derive preparation operations from that context and the
same absolute preparation deadline. Pass it through selected bootstrap/FSM store
operations, coordinator preparation and gated child creation: do not replace it
with Background or a fresh independent 30-second budget in selected `startChild`.
Keep cleanup's independent bounded context and retained owner even after launch
cancellation. Returning the immediate bootstrap reply must not cancel the owned
context; successful readiness ends only its separate admission timer.

The selected release wrapper needs an immediate pre-release latch/deadline
barrier after the durable revision-1 transition and immediately before the
existing gate send. Serialize observed cancellation against release admission,
check the absolute deadline with half-open semantics, and refuse the send when
either has already won. Do not wait for owner.mu to publish cancellation. Capture
a conservative release timestamp immediately BEFORE the admitted send, never
after the send or revision-2 reply; bound the send by the remaining preparation
budget and make cancellation interrupt its I/O. Cancellation after send admission
is not proof that no byte reached the child: contain the exact owned process and
retain uncertain checkpoints. The monitor cannot promise observation of physical
EOF before it has actually received it. Legacy six/seven startup and release
remain unchanged; this is an explicit selected-only lifecycle seam requiring REDs.

The main supervisor goroutine enters the existing `serveControllers` loop while
the controller task runs. Cleanup reconnects must remain usable during slow
guest boot, blocked handshake and idle readiness. An error/EOF on the original
channel at ANY phase (including before readiness), process/socket loss, explicit
cancel or deadline closes guest I/O, revokes readiness and contains through the
same selected owner. Producer disappearance cannot orphan an active controller.
No closing channel is itself VM/cgroup/network absence proof.

Only the eight-role branch retains the original socket after launch. After the
normal revision-2 reply it permits one bounded selected readiness notification,
then no further successful messages. Use a private selected-channel codec, not
a new cleanup opcode or an expanded legacy packet validator. Proposed exact
ready datagram (network byte order), at most 238 bytes:

```text
"HLMINRD1"[8] | version:u16=1 | eventSequence:u64=1 | launchRevision:u64=2
configSHA256[32] | supervisorGeneration[43] | processIDLength:u8
processGeneration[1..64] | transportGeneration:u64>0
sessionID[32] | readinessBindingSHA256[32]
```

It carries no FDs, raw PID, socket path, helper or credential proof. The bounded
receiver rejects MSG_TRUNC/MSG_CTRUNC, ancillary rights, extra bytes, noncanonical
IDs, zero fields, duplicate events and any other datagram. Preserve the legacy
512-byte transport bound. This event's trust comes from the original private
channel and independently observed supervisor, not a signature added to metadata.
The receiver reconstructs the full binding from its retained 25 fields plus the
two late correlations, validates `NewBinding` and the session-bound digest, and
matches the exact config/owner tuple before publishing an opaque current handle.
It does not accept an `ok` flag or replay cleanup `Inspect` as readiness.

One producer-side reader owns this endpoint from the launch reply onward and
continues detecting EOF/error/any later datagram. The supervisor-side monitor
accepts no further parent data after BootstrapStart: EOF or any unsolicited data
revokes. Ready-event writing has its own remaining admission deadline and never
blocks the cleanup server. Revocation first retires the latch, then shuts down
the original endpoint so the producer observes loss; a best-effort loss message
is unnecessary. Supervisor exit also revokes through endpoint EOF/process loss.
Later reconnected daemons get ONLY the existing cleanup client, never this latch.
Do not inherit the bootstrap socket's five-second receive timeout into idle
ownership. The selected branch must explicitly change that timeout when the
reader role transfers; a single absolute admission timer remains authoritative
until ready. Cancellation uses `shutdown(SHUT_RDWR)` on the retained seqpacket
before closing/joining a blocked receiver, not an assumption that closing a raw
FD in another goroutine interrupts `recvmsg`. Bound sends by the remaining A/D
budget and avoid socket-timeout changes that reset a pending admission budget.

## Exact controller transcript and deadlines

The selected runtime resolves the active coordinator session under its existing
lock, copies the actual retained `strictJailerLifecycleProcess`, then releases
that lock before I/O. Recheck coordinator generation/state and manager ownership
at admission and readiness publication. Construct exactly one
`newMinimalControlTransport(selected.lifecycle.manager, process.handle, runtimeID)`.
No serialized PID, recovered handle, v1 bridge session or guest-provided generation
may enter that constructor.

Let `D = min(preparationDeadline, preReleaseBarrierTime + 15s)`, using the
conservative timestamp immediately before the actual gate-send attempt, not a
later success observation. Call baseline's
`OpenWhenAvailable(ownerCtx, D)` once. `ownerCtx` belongs to this surviving launch,
not the initiating CLI and not a short-lived admission context canceled when
Open returns. Only the connector owns permitted pre-ACK retries. First canonical
ACK permanently ends retries; every later error is terminal. Its hard lifetime
starts once and must not be reset by retries, handshake or readiness publication.

After successful ACK and currentness checks, `stream.Correlation()` supplies the
exact manager handle and nonzero transport counter. `processGeneration` is the
actual `handle.ID` after exact source check; `vsockGeneration` is canonical decimal
of that counter. These labels are scoped by the already pinned runtime/boot/image
tuple, not persistent authority. Neither is guessed before launch.

Use `A = min(D, timeImmediatelyBeforePrelude + session.HandshakeDeadline)` for
all remaining admission I/O, with explicit half-open deadline checks after each
bounded observation and immediately before publishing readiness. The session's
own deadline can shorten A, never lengthen it. Five seconds is also the guest
attempt bound; do not start a fresh five seconds at readiness. The exact transcript:

1. Complete `session.Identity` and shared `minimalcontrol.NewBinding` with those
   two actual fields. Obtain `prelude, err := binding.BootstrapPrelude()`, then
   send `frame.Write(stream, prelude, minimalcontrol.MaxMessageBytes)`. No
   fixed-constructor readiness prelude, v1 probe, second connection or work
   request is sent.
2. Read one bounded 4-byte-length GuestHello (`MaxHandshakeInnerBytes=4096`).
   Construct `session.NewControllerHandshake` with exact expected identity and
   the one-shot key; immediately call `AcceptGuestHello` on that wire. Install
   `defer AcceptGuestHello(nil)` at construction as the existing guest handler
   does for its counterpart, so an early return still consumes/destroys its key
   copy. Clear the controller's original signing key on every path at this point.
3. Send the returned ControllerAuth. Read a bounded secure record and call
   `state.OpenFinished` for guest Finished, then `state.SealFinished` and send
   controller Finished. Require established state; no application before both.
4. Generate one canonical 16-byte/32-lowercase-hex request ID. Encode the exact
   shared readiness request, call `state.WriteApplication` with
   `FrameTypeControlRequest`, read one bounded response record, and call
   `state.OpenApplication` with a shared validator requiring
   `FrameTypeControlResponse`, exact request ID/binding digest/session ID and
   ONLY `authenticated_minimal_control`. Destroy plaintext on all results.
5. Recheck A, owner/channel/loss, selected coordinator and transport correlation;
   arm the sole joined idle reader and publish once. Clear only the admission
   deadline, keeping the earliest owner/transport/session hard expiry. The
   successful datagram does not stop lifetime observation or detach ownership.

Shared minimal codec additions, implemented in `guestagent/minimalcontrol`, should
be only `Binding.EncodeReadinessRequest(requestID, sessionID)` and
`Binding.ValidateReadinessResponse(payload, requestID, sessionID) error` (proposed
names). Refactor the existing private response struct into the same package's
common schema and canonical re-encoding check. Require existing exact key/order,
ASCII/non-null/unknown/duplicate/type/depth and 8192-byte limits. The host must not
maintain a parallel response struct or capability list. Session cryptography,
GuestHello identity equality, Finished order and record counters remain unchanged.

Use 52-byte secure headers and reject ciphertext length above 8192+16 before
allocation. Before readiness there is one protocol reader; after it transfers
ownership there is one idle reader doing a bounded one-byte read. Any byte,
EOF or error is terminal in this readiness-only profile; it must not wait for
an unsolicited complete frame. No concurrent record reader, drain goroutine,
unbounded line accumulation or silent post-ready connection loss is allowed.
Controller read helpers own their bounded allocations and clear partial buffers
on error. Do not claim an allocation was wiped merely because an existing helper
returned nil after a partial read. Secret seed copying never uses generic framing.

## Destruction, joins and cleanup order

Keep one small per-launch controller latch/task inside the existing selected
runtime. Do not hold owner/store/coordinator/selected mutexes across network I/O,
deadline waits, goroutine joins or controller closure. A reader reports loss to
the lifecycle task; it never calls a Close that joins itself.

The shutdown/join portion below must run at the selected cleanup dispatch
boundary BEFORE entering `HandleController` for cleanup or acquiring owner.mu,
and before any selected containment lock. Never put it inside `ContainChild`,
`selected.contain`, or a mutex-held FSM callback. Preserve authentication and
packet/session/sequence checks when admitting cleanup intent; any necessary
private admission split needs its own RED and source-owner review, not a second
permissive protocol validator. Loss-driven cleanup uses the same outside-lock
shutdown barrier before entering the existing cleanup FSM. An in-progress
shutdown may be joined there, but no join may wait on itself or hold these locks.
Idempotent terminal handling follows this order:

1. Atomically mark readiness unavailable, cancel further admission and close the
   public loss latch. Close/shutdown original bootstrap I/O and guest stream to
   interrupt blocked readers/writers; cancel timers/watchers.
2. Join the controller transcript task, idle reader, original-channel monitor,
   and transport watcher. A cancellation callback's Stop failure requires waiting
   for that callback's completion; stopped timers are not leaked join substitutes.
3. Only after I/O has unblocked and writers have joined, call `state.Revoke`.
   Clear seed/private-key copies, plaintext, request/response/handshake/Finished
   and record buffers, including partial-read/error branches. The protocol's
   private key copy is consumed as above. Existing Go crypto objects' internal
   allocations are not newly claimed to be physically zeroizable.
4. Invoke the same selected coordinator's containment outside those control
   locks; preserve exact process/cgroup/staging/UID ownership and cleanup
   checkpoints. Concurrent cleanup reconnects converge through that existing
   idempotent owner, never a second kill/reap or release authority.
   The unchanged cleanup FSM may still hold owner.mu during its existing
   containment callback: controller shutdown has already finished before that
   FSM entry. This design does not relocate joins into that callback or claim
   existing containment itself is lock-free.
5. Keep the reconnect service/record while cleanup or terminal acknowledgment
   is uncertain. Existing StopReap/Finalize/Commit and exact terminal ACK/record
   retirement remain authoritative. Local controller termination does not retire
   records or synthesize successful cleanup. The historical owner record's
   `running` describes launch until its existing cleanup FSM advances, not active
   readiness; the selected worker projection remains unavailable/cleanup pending.

The concrete provider also quiesces its original L7 session on loss/cancellation
and uses `CleanupAfterVMQuiesced` only with actual correlated J termination
authority. It must not call `AbortBeforeVM` after launch just because readiness
failed. L7 teardown/recovery integration needs its exact existing verifier and
journal; the J-only commit is not whole-job/network absence. No new packet,
guest ACK or returned interface implementation is a substitute for that proof.

## Actual later consumer, RED sequence and approval seams

`MinimalJobRuntimeProvider.StartMinimalJob` must return this exact launch owner
even on readiness failure. It may await its readiness as one preparation stage,
but the manager's `owned` bookkeeping is not credential or workload success.
The future minimal credential adapter must consume the opaque handle through
the same provider, check its live latch, exact full binding and retained owner at
the operation boundary, independently authorize the unchanged credential intent,
then use a separately reviewed authenticated operation on this same controller.
It may not use a stale readiness snapshot to complete the historical
`JobCredentialIdentitySeed`, `L8V2ControlReadiness` or helper-based identity.
The current guest closes on any later operation; exec/copy/activation support
and their concrete operation dispatcher are explicitly outside this slice.

Required dependency-ordered behavior REDs before implementation:

1. Shared host codec round-trips the actual guest encoder; wrong request/session/
   all binding fields, additive capability, duplicate/aliased/unknown/null/type,
   order/trailing/multiple/depth/size variants fail unchanged canonical rules.
2. Actual selected producer refuses eight-FD substitution/missing/extra or
   swapped roles, wrong seals/size/mode/key correlation, changed measured assets,
   unclaimed/replayed/revoked reservation and mismatched L7 session. Verify L7
   then minimal rendering before config sealing, actual inheritance excludes the
   seed, all secret-buffer failure paths clear, and six/seven paths stay exact.
3. Actual supervisor path sends revision 2 before a deliberately blocked guest
   handler, while cleanup reconnect remains serviceable. Same surviving manager
   and actual process reach `NewBootstrap` through a fake retained transport and
   real session crypto; exactly one authenticated exchange reaches readiness.
   Missing route/early dispatch failure must not be reported as later-negative
   coverage. Nil success, a stale Inspect reply or adjacent fabricated JSON fails.
   Separately pause the actual selected path after child armed and at durable
   revision 1: observe original-channel EOF/cancel or exact preparation expiry,
   resume, and require zero gate releases plus retained same-owner cleanup. Test
   cancellation during preparation, the pre-release race, and uncertain send;
   no background-context reset or late release-time sampling may extend budget.
4. Same original channel and tuple are required for adoption. EOF before reply,
   between reply/ready, immediately after ready, duplicate/truncated/extra event,
   ancillary rights, wrong supervisor/config/digest/process and producer death
   all revoke and request same-owner containment; reconnect never reissues ready.
5. Every blocked handshake/write/readiness/idle phase: explicit cancel, D/A exact
   expiry and delayed timer, manager/strict-owner/socket/process drift and L7 loss.
   Retry happens only inside the accepted connector before first ACK. Assert one
   generation, no fallback, all joins without watchdog assistance, and key/buffer
   clearing even when `WriteApplication` holds its mutex during blocked I/O.
6. Cleanup races/readiness publication/terminal retry preserve successor canaries
   and existing Jailer uncertainty/terminal checkpoint behavior. Separate actual
   L7 terminal correlation tests are needed before whole-provider cleanup claims.
   Block `WriteApplication` while it holds the session mutex, concurrently enter
   actual selected StopReap dispatch and trigger controller loss; require stream
   closure and all joins BEFORE mutex-held FSM containment, bounded completion
   without watchdog rescue, no self-join, and one retained cleanup authority.

Source-owner approval is required for the selected config/FD decoder, producer,
runtime and close-order changes; the sealed L7 projection validation seam; the
small shared minimal codec; and the private original-channel event codec. No
source guard may be widened by an unconditional new filename exception. The
baseline connector change and worker reservation/provider contracts must be
accepted at exact commits before their dependents are tested together.

Open operational dependencies are trusted provider construction, selected L7
lifetime/recovery ownership and preparation-budget propagation across the private
process handoff. The design selects the same reservation's absolute preparation
deadline capped from actual gate release; if the caller cannot supply it, reject
before launch rather than invent an independent budget. The selected public
readiness event layout and cleanup-only projection correlation are approval
decisions here, not implemented protocol versions.

After each GREEN, run focused transcript/producer/owner/source-guard tests and
adjacent race/vet/Darwin compilation, then integration-owned broad gates. Default
tests use injected process/socket observations, bounded in-memory streams and
ordinary private-file/unnamed-socketpair fixtures, with no real VM or privilege.
Only rebuilt exact guest/image and no-skip prepared-Linux Jailer/control/network/
credential/terminal tests establish product acceptance. This document is checked
by source inspection and `git diff --check`; no executable RED, production code,
live boot, credential usability or complete Sandbox v2 claim is included.
