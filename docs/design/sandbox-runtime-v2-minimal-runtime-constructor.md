# Selected minimal runtime constructor and supervisor composition

## Status and boundary

Design only, based on `f5b39e2bbf37af21c205bf9d4643fe656cdbf93d`.
The independently accepted controller is referenced at
`2d91b1d18671c8a2721dd01ead69f0e22c129bab`; it is not present in this
document's base. No constructor, test, gate, producer or runtime is enabled by
this document. It refines the accepted
[host controller handoff](sandbox-runtime-v2-minimal-host-controller.md), the
[Linux completion architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and the [selected guest reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md).

The next implementation must run the eight-role selected variant inside the
existing runtime-owner executable, supervisor, coordinator and record store.
It must consume the actual admitted assets and namespace pins, start the gated
child, then keep the accepted authenticated controller and cleanup reconnect
service alive in that same owner. A second owner, reconstructed manager, fake
credential seed, fabricated L7 descriptor or admission-only constructor is not
the result. Six/seven-role behavior and strict default-off selection remain.

The concrete worker provider/producer is a later dependency. That producer
retains the genuine L7 session and original channel. J containment alone cannot
attest L7 cleanup, credential authorization, complete job execution or live KVM
acceptance. Losing every owner still leaves quarantine, not reconstructed launch
or automatic identity-slot reuse.

## Current source and missing consumers

Paths below are in `internal/sandboxruntime/microvm/firecrackerhost/`.

| Existing consumer | Required selected change |
| --- | --- |
| `l8_runtime_owner_executable_linux.go`, `SelectSupervisor` | Replace only the eight-role unavailable callback with the completed same-owner consumer. Keep discriminator/role admission unchanged. |
| `minimal_control_config_linux.go`, `withMinimalControlSupervisorAdmission` | Already checks exact sealed assets and independently configured FC/NIC/boot equality before consuming the seed. Retain an immutable expectation for the later request, alongside the existing namespace/recovery projections. |
| `jailer_recovery_runtime_linux.go`, `newJailerRecoveryLinuxRuntime` | Currently requires exact seven-role config and root. Add an explicit eight-role construction path; do not disguise eight roles as seven. |
| `jailerRecoveryRuntime.request` and `validateStrictJailerCoordinatorConfig` | The request leaves `minimalL7` nil. A NIC then fails the existing descriptor-based check before other coordinator validation. Add a distinct admitted expectation, not a forged descriptor or permissive nil branch. |
| `jailerRecoveryStore.recordBinding` and `bindMinimalControlNamespaces` | Their eight-role projections already exist. The real constructor must install the original full-config correlation and bind the actual bootstrap namespace admission before launch. |
| `jailerRecoveryRuntime.startChild` and `jailerRecoveryStarter.release` | The former creates a Background cleanup-budget context; the latter sends without an owned preparation barrier. Both need selected-only lifecycle coupling. |
| `serveBootstrap`, `HandleBootstrap`, `serveControllers` | Preserve genesis → armed PID/revision 1 → release → revision 2/reply. Retain the original channel, start the controller only after that reply, and keep cleanup available during boot. |
| `withMinimalControlController` at the accepted controller revision | Already implements the real transcript and local lifetime. It does not own coordinator cleanup, the original channel or an `HLMINRD1` event. |

## 1. Actual eight-role assembly and independent request expectation

The private selected entry is proposed as
`runMinimalControlSupervisor(admission *minimalControlSupervisorAdmission)`.
It runs synchronously inside the existing admission callback until its controller
and all owned tasks have joined. A private `newMinimalControlLinuxRuntime` takes
that admission, not public config plus an arbitrary correlation string. It
enforces the actual root gate and exact eight-role version. No root-check bypass,
test-mode Boolean or configurable operations framework is added.

Reuse the existing constructor's concrete resource assembly: duplicate the
three sealed input FDs with CLOEXEC, load the existing recovery key for cleanup
authentication only, inspect the real boot/supervisor identity, create the one
reconnect listener, and create the same namespace runner, lifecycle manager,
identity authority and coordinator. Factor only genuinely shared assembly if
needed; separate seven/eight admission predicates remain explicit. Existing
partial-construction cleanup must cover every duplicated FD/listener/key.

Ownership remains exact: the outer dispatcher owns the first six FDs; admission
owns imported FD9 and consumes/closes FD10 before callback entry. The runtime
owns its asset duplicates, not those borrowed numbers. The admission owns the
borrowed controller key until the nested controller scope has joined; the
runtime neither persists it nor uses the recovery key as controller authority.

Add one private admission-captured FC expectation containing full config
correlation, FC digest, exact NIC and six static-network strings, and the shared
opaque expected `minimalcontrol.BootConfig`. Derive the expected boot value from
the independently decoded public config using the existing renderer/parser,
not from candidate FC bytes. Freeze it at actual admission, like the existing
namespace and recovery projections; mutable callback config cannot replace it.

The coordinator request may contain either the existing `minimalL7` descriptor
expectation or this admitted eight-role expectation, never both. With neither,
the existing NIC rejection remains. The eight-role branch reuses strict FC
parsing, exact NIC/raw-static comparison and canonical shared BootConfig
equality against the captured value. It verifies the request's actual measured
FC digest and selected job/config correlation. All other resource, machine,
drive, support-file, path and vsock checks stay intact. This proves configured
bytes agree; it does not issue the producer's opaque live L7 authority.

Construct `jailerRecoveryStore` with the copied original `admission.recovery`,
retain the eight-role config version, and use the full admitted config digest
in genesis. Do not substitute the seven-role re-encoding or FC digest. Call the
existing single-use namespace binder before receiving bootstrap FDs; its actual
SCM/nsfs/type/tuple checks remain the pre-FSM boundary. The existing coordinator
then consumes the retained network namespace through the same namespace runner.

## 2. Owned preparation, release and truthful failure

Create one launch-owned cancellation context before selected prelaunch
allocation. Derive preparation from it and the admitted absolute deadline `P`.
Pass that context into bootstrap store operations and selected `startChild`
through an explicit selected closure; do not change the legacy callback ABI.
Preserve the independent existing stage and cleanup limits. A larger `P` cannot
enlarge the stage limit; cancellation does not eliminate the independent bounded
cleanup context. Successful bootstrap reply does not cancel launch ownership.

After consuming and validating BootstrapStart, transfer the original endpoint's
sole reader role to a monitor before launch. Clear the bootstrap receive timeout
when transferring roles. EOF, error or unsolicited parent data publishes sticky
cancellation without waiting for owner/coordinator/selected mutexes. The monitor
does not call a shutdown operation that joins itself. There is never a second
reader racing the bootstrap decoder.

After durable revision 1, the selected release closure performs a serialized
last cancellation/half-open `now < P` check immediately before admitting the
existing gate send. It records a conservative timestamp `R` before that send,
never after successful send or revision-2 publication. The send gets only the
remaining preparation budget and must be interruptible by cancellation.

Use the existing retained gate endpoint with a narrowly owned shutdown lifetime;
do not race raw FD closure/reuse against a blocked send or hold the cancellation
latch over I/O. If a duplicate is needed for shutdown, retain it through the
joined operation and never deliver it to the child. A cancellation already
observed before admission means zero release sends. Cancellation after send
admission is uncertain execution: contain the exact coordinator generation,
never claim that the child could not have received the byte. Physical EOF before
the monitor observes it cannot be retrospectively ordered ahead of release.

Cgroup-at-clone, private executable mounts, retained creating thread and additive
Pdeathsig stay in the existing starter. No migrate-after-exec fallback, new
binary, inherited environment or additional child FD role is introduced.

There is an important pre-reservation failure boundary. `HandleBootstrap`
creates genesis before `StartChild`; `startWithMinimalLease` can return before
creating a generation, including an already-canceled context or nil result from
identity reservation. Existing terminal proof needs the original reservation
and durable cleanup checkpoint. Therefore nil generation, PID zero or a missing
reservation cannot retire that genesis or imply idle. Pre-genesis rejection
can release only its known local handles. Post-genesis missing terminal proof
remains quarantined; an eventual clean no-allocation outcome would require an
explicit same-invocation coordinator proof and separate reviewed RED, not a new
inference or access to a successor's identity journal.

## 3. Post-reply controller and original-channel publication

Keep `HandleBootstrap`'s immediate revision-2 reply; no controller handshake runs
under its mutex. Only after the actual reply send succeeds, resolve the exact
active selected session/generation and retained process under coordinator locks.
Release locks and construct `newMinimalControlTransport` with that process's
handle, the original `selected.lifecycle.manager` and runtime ID. Recheck the
same session/process at local admission and external ready publication. Never
reconstruct a handle from the durable PID/record or open a v1 readiness session.

Compute `D = min(P, R + 15s)` from the original pre-send timestamp. Nest
`withMinimalControlController(ownerCtx, transport, admission, D, consume)` inside
the still-running admission callback. Its `consume` scope hosts the existing
cleanup serving loop while the controller task performs the transcript. The
ready publisher waits for the controller's opaque local readiness, rechecks
currentness and the selected coordinator, and sends exactly one `HLMINRD1`
datagram after the normal bootstrap reply. It derives fields from the
actual genesis/config, retained process/transport and shared readiness binding,
not a decoded packet or caller assertion. The accepted handoff specifies this
layout, but its codec does not yet exist: add only that bounded private codec
with exact size, canonical-field, ancillary-rights and truncation negatives.
Do not extend the legacy cleanup packet decoder or add a cleanup opcode.

One small controller handoff is required: local readiness currently retains hard
expiry `H` but not the exact admission deadline `A` returned by `authenticate`.
Retain that exact `A` in the private result or expose a callback-scoped accessor
so original-channel publication uses only its remainder. Do not rebase from
WaitReady time or use `D` as a substitute. This is a separately reviewed private
controller delta; `Current` remains bounded by `H` after successful admission,
not by the expired handshake deadline. No session crypto or wire change follows.

The publisher enforces half-open `A` before and after bounded send, process and
channel currentness, and one-shot publication. An uncertain/late send revokes
and shuts down the original endpoint; it does not report a second successful
event. The event is readiness-only and uses that approved exact layout without
FDs. The admission timer ends only after publication succeeds; the
owner context, process observation, original-channel monitor and controller's
sole idle reader remain active. Failed reply/event publication invokes the same
owned containment and keeps unresolved reconnect authority.

## 4. Shutdown before cleanup, using the same FSM

Use a small selected-only shutdown barrier outside all owner/store/coordinator/
selected locks. It retires publication, cancels admission and shuts down original
and guest I/O before joining the publisher, original monitor and controller.
`controller.Close` already joins before its task revokes shared session state.
No joined reader invokes this barrier; readers only report loss. Callback return,
panic and runtime close pass through the same barrier before resource cleanup.

An authenticated cleanup request must also pass this barrier before entering
`HandleController`, because that method holds owner.mu over containment. Merely
checking an opcode is insufficient: a stale or wrong request must not revoke a
valid controller. Propose factoring the existing request preflight into one
shared internal check, used by normal dispatch and selected cleanup admission.
It checks exact session/sequence/status/body and current record/state/revision,
preserving cached replay semantics. It produces only a private immutable cleanup
intent for that owner/request, with no resource or launch authority.

For StopReap/Finalize/Commit, the selected server checks that intent under the
existing owner lock, releases the lock, shuts down/joins control, then reacquires
and revalidates before normal dispatch. Invalid/replayed traffic cannot mint new
shutdown intent; an already cached successful response remains a replay. If
loss-driven cleanup advanced the state during the join, use the existing retry
rules rather than a stale transition. Inspect, AcquireNamespaces, Close,
handshake authentication and six/seven dispatch behavior remain unchanged.
This common preflight extraction needs its own behavioral RED and source-owner
review; no parallel permissive packet validator is proposed.

Loss is an internal same-owner event, not a forged authenticated request. A
separate lifecycle dispatcher waits for reported loss, completes the same
shutdown barrier, then enters a narrow owner method which loads current state
under owner.mu and reuses existing `reinspectAbsence`/bootstrap-quarantine logic.
It is not among the readers joined by that barrier, avoiding self-join. The outer
runtime joins it before closing retained resources. Concurrent authenticated
cleanup still converges on the existing serialized FSM and exact coordinator.

Loss never automatically finalizes/commits, infers absence from controller EOF,
or retires a record on a missing ACK. Keep the existing cleanup listener and
surviving owner while resource cleanup or acknowledgment is uncertain. Fresh
daemon clients remain cleanup-only, including finalizing/finalized retries.
The producer must separately contain its original L7 session on channel loss and
use actual VM-quiescence authority for its network cleanup; J commit alone is
not that authority.

## Ordered implementation and compiling RED checkpoints

Each checkpoint needs review before GREEN. Keep production eight-role selection
unavailable until the coupled path, not just a constructor helper, is safe.

1. **Request and assembly.** Use `newMinimalControlAdmissionFixture`'s actual
   sealed assets/public config and the existing runtime fixture to reach actual
   `request`/coordinator validation. The valid admitted NIC currently fails;
   root-gate refusal is a passing control, not this RED. Cover foreign/mutated
   projection, both/nil expectations, FC digest, full-versus-seven correlation,
   namespace binder, duplication failure and original borrowed FD survival.
   Exercise concrete below-gate assembly using existing narrow fixtures, not
   an injected EUID pass. Positive root construction stays a prepared-host gate.
2. **Preparation/release.** Reuse `jailerRecoveryRuntimeFixture`, real private
   store/sealed files, fake coordinator dependencies and the ordinary gate
   socketpair. Pause stage and revision-1 publication; cancel/expire before
   resume and require zero gate sends. Cover cancellation before reservation,
   post-send uncertainty, failed revision 2 and exact retained cleanup. Explicitly
   separate actual store/transport behavior from fake process/cgroup evidence.
3. **Controller/publication.** First cover the approved bounded event codec;
   then combine the original lifecycle manager with the
   accepted ordinary-Unix/shared-guest-crypto fixture. A real reference transcript
   is the setup control. Assert reply precedes prelude/event, cleanup reconnect
   works during blocked boot, `R`/`D`/`A` cannot rebase, no event after owner loss,
   exact event fields/one send, hard lifetime persists and all tasks/key scopes
   join. Later assertions blocked by an earlier seam are not reproduced defects.
4. **Authenticated shutdown and loss.** Block shared WriteApplication and race
   exact StopReap, original EOF and idle loss. Require I/O closure and joins before
   owner.mu/containment, no self-join, one retained coordinator and replay-safe
   terminal retry. Wrong/stale auth cannot retire readiness. Fail cleanup/store
   readback and require quarantine; no nil-owner, PID-zero or missing-record
   terminal success. Then wire and test the actual executable selected consumer.

Likely coupled ownership is narrow `minimal_control_runtime*` additions plus
the actual executable/runtime/supervisor, selected recovery runtime/starter,
coordinator expectation and admission projection. Only the exact `A` handoff
touches controller internals. No new public schema, worker/provider changes or
generic syscall/filesystem abstraction is needed. Source guards remain in force;
any required ownership enrollment needs the exact failure and review.

Use focused/default and race tests, full firecrackerhost tests, affected source
guards, vet and Darwin compile after implementation. Existing namespace fixtures
observe real read-only namespace FDs but never enter/create namespaces; ordinary
Unix fixtures use fake recorded process ownership. No privileged launch test is
authorized by this plan. Actual root construction, cgroup enforcement, private
mount/exec, KVM boot and complete producer/L7/credential/worker handoff remain
separate required acceptance, never inferred from these local tests.
