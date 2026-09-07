# Selected minimal workload control

## Status and source boundary

DESIGN ONLY, based on accepted `54195a3c711ec49449b45773fd29bcfd572e7987`
and the supervisor's `minimal-control-audit.md` update of 2026-09-07 14:18 UTC.
This proposes coordinated host/guest exec and workspace copy on the original
authenticated control connection. It adds no implementation, test scaffolds,
image changes, protocol capability, credential authority or strict selection.
The Linux completion architecture and L8 minimal contract reset remain controlling.

Source references below are relative to this revision; `guest/` means
`internal/sandboxruntime/microvm/guestagent/`, and `host/` means
`internal/sandboxruntime/microvm/firecrackerhost/`.

- `guest/minimalcontrol/server.go:210` authenticates/claims exactly one session;
  `connection` then sends canonical readiness and rejects every next record.
  `readRecord` at line 343 caps plaintext at 8 KiB before body allocation.
- `guest/minimalcontrol/codec.go:122` binds all 27 immutable fields and the exact
  public session ID. The existing readiness schema/capability stays unchanged.
- `host/minimal_control_controller_linux.go:192` owns the established state;
  its sole idle reader currently retires on any byte. `Close` at line 156 closes
  I/O outside the controller mutex, joins, and lets the owner revoke state.
- `guest/session/state.go:111,130` holds `State.mu` through WriteApplication I/O
  and through the OpenApplication validator. State getters also take this mutex.
- `guest/server/server.go:147,358` owns real StateServing and bounded backend
  admission. A newly constructed server is not serving; calling Handle directly
  or setting isolationProven would not be valid reuse.
- `guest/server/protocol.go:17,141,205,266` already owns strict v1 dispatch,
  bounds, environment rejection, copy digests and published-but-uncertain results.
  `guest/client.go:100,116,133,150` owns request/response validation, including
  request-bound CopyIn publication that can outrank a late caller cancellation.

## Decision: reuse both existing protocol endpoints

Use the existing `server.Transport.Serve(ctx, Limits, Handler)` and
`guestagent.Transport.RoundTrip(ctx, TransportRequest)` boundaries. Keep the
inner exec/copy request and response byte contracts exactly guest-agent-v1;
the selected outer envelope authenticates their ownership/correlation. This is
not a second v1 listener or a new v1 readiness exchange.

Proposed guest entry is `minimalcontrol.NewWorkloadTransport(BootstrapOptions)`.
Its private adapter reuses the existing bootstrap/session loop, receiving the
real Handler only when the enclosing `server.Server.Serve` calls it. Default
New/NewBootstrap and their direct Serve remain readiness-only, including nil
workload behavior. There is no socket, backend or handler reconstructed from
wire fields. The adapter is one-shot and cannot move to another server/session.

One small server-side seam is necessary: a selected `WorkloadHandler` interface
with `PrepareWorkload(context.Context) error` and
`HandleWorkload(context.Context, Request) Response`. Server implements these;
the adapter rejects an incompatible handler. HandleWorkload reuses Handle's
single strict classifier and dispatch body, but rejects readiness and every
operation except exec/copy_in/copy_out before any backend or proof-state call.
Do not separately inspect JSON operation fields in the adapter. This is a
narrow common-dispatch extraction, not a new decoder, lifecycle or backend.

The private host transport is obtained only from the current, self-bound
minimalControlReadiness/controller inside withMinimalControlController's owned
scope. It implements RoundTrip for `guestagent.NewClient`, rejects readiness and
non-v1/non-work operations, and retains the original state, stream, process
handle and transport generation. No exported stream/state/key or serializable
client authority is returned. Zero/copied/stale readiness cannot obtain it.
The existing client remains responsible for strict inner response validation.

## Resolve the required local proof gate, without fake legacy readiness

The future selected command must not quietly set
RequireNetworkProofBeforeWork=false to make HandleWorkload run. The proposed
selected server mode retains that gate (and its implied process gate) as true.

Add an explicit local-workload verifier interface returning the existing
IsolationProofResult without accepting a legacy IsolationProofRequest. Factor
the body of `guest/server/isolation_linux.go:37` into one implementation shared
by the existing VerifyIsolation wrapper and a selected no-request verifier
sibling. The current Linux implementation already ignores that request. Keep
its exact UID/GID1000, capability, no-new-privileges, supplementary-group and
raw-socket denial checks, including the actual injected L7 verifier; do not
invent generation fields or return a legacy wire proof.

Future `server.Options` may carry this explicitly selected local verifier,
mutually exclusive with legacy IsolationVerifier/CredentialClient selection.
Construction requires both existing work-proof requirements enabled. Legacy
nil options and legacy Handle remain unchanged; selected construction rejects
the legacy readiness operation even through Handle. This additive API requires
its own reviewed RED; the present document does not authorize it.

PrepareWorkload runs Backend.Ready and the real verifier outside server/session
mutexes, under a tracked non-state-changing backend call. It clears/begins the
existing private proof attempt, checks the same complete process/network result
predicate used by isolationReadinessResponse, and commits isolationProven only
if that exact attempt is still current and the context is live. Factor that
predicate rather than duplicate it. Failure/cancellation leaves work closed.
The adapter runs preparation before its first minimal readiness response,
within the unchanged remaining handshake/readiness deadline. For each later
HandleWorkload, the selected branch of the shared backend admission runs that
same real inspection again after strict decoding and contextWithTiming, before
returning the backend permit. It substitutes a fresh checked attempt for cached
proof acceptance, not a disabled requirement. Inspection is outside mutexes,
inside the single tracked operation/permit, using min(H, request timing).
The transport must not duplicate timing parsing. No phase extends the initial
five-second budget.

The readiness-only constructor never runs these local checks. The workload
adapter still emits the old readiness bytes and only the capability
authenticated_minimal_control: the selected immutable image/constructor chooses
work support, not a new capability inferred from that reply. A local proof is
an observation of this guest process/topology at that attempt, not continuous
host L7 rule ownership, agent/workload UID separation, seccomp or terminal proof.
Host policy/rules/proxy currentness remains an independent required authority.

## Canonical operation envelope and hard bounds

Use ControlRequest/ControlResponse on the unchanged session channel. The new
shared minimal codec owns only this exact canonical envelope (key order shown):

```json
{"body":{"bindingDigest":"sha256-<64 lower hex>","guestSessionGeneration":"<43 base64url>","payload":"<canonical padded base64 of exact v1 bytes>"},"operation":"workload","protocolVersion":"guest-agent-minimal-v1","requestId":"<32 lower hex>"}
```

Expected bindingDigest comes from the retained Binding.Digest(sessionID), not
the payload. guestSessionGeneration is the exact retained nonzero session ID.
Both directions use the originating request ID; request/response direction is
enforced by the authenticated frame type. The inner payload is opaque to this
codec. It must not interpret args, paths, v1 operations, errors or copy results.

Request IDs are the fixed-width 32-lower-hex encoding of a monotonic uint64
operation ordinal, starting at one; no zero, gaps, reuse or wrap. This is local
request correlation, not a new job generation or admission grant. Guest expects
exactly the next ordinal; host retains exactly one pending ordinal. Existing
AEAD counters additionally reject replay/reordering of records. No unbounded
seen-ID table, retry cache or command resubmission exists. Readiness's existing
request ID remains independent and unchanged.

| Boundary | Limit |
| --- | --- |
| Bootstrap/readiness plaintext | Existing 8,192 bytes, unchanged |
| Inner request / response | Existing default 1,048,576 bytes each |
| Base64 of maximum inner bytes | 1,398,104 bytes |
| Fixed envelope overhead | 297 bytes with the specified fixed-width fields |
| Operation plaintext / secure wire | 1,398,401 / 1,398,469 bytes |
| Decoded stdin / copy, stdout / stderr | Existing 512 KiB / 512 KiB, 256 KiB each |

The operation limit stays below session's 2 MiB plaintext ceiling. Check the
52-byte secure header and ciphertext bound including its 16-byte tag before
allocating its body. After decrypting, match the expected exact prefix/suffix
(including immutable binding/session/next request ID), validate canonical base64
and derive its exact decoded length from padding before allocating at most
1 MiB. A fixed canonical encoder/decoder can avoid a general outer JSON parser:
unexpected keys/order/types/null/escapes/depth/trailing bytes simply cannot
match. Preserve arbitrary inner Unicode/JSON escapes byte-for-byte in base64.
Do not use or widen readiness's scalar-only boundedJSON routine.

Guest response wrapping enforces server Limits; host unwrapping additionally
enforces the smaller pending caller MaxResponseBytes. That local caller limit
is not an implicit guest wire field. No caller can enlarge the fixed selected
ceiling. Large valid
inner requests can still be rejected by the existing aggregate 1 MiB cap. No
streaming/chunk protocol, network-sized allocation or unlimited output is added.
Lock envelope sizes with independent golden bytes and max/max+1 tests.

## One reader, one work task, one retained owner

After Finished, the guest's one continuous reader validates readiness and then
operations. It never synchronously waits for Backend.Ready, local inspection,
Exec, Copy or a response write. A single tracked task performs preparation,
HandleWorkload and the bounded response write, with no work queue. An incoming
record while a task is occupied is a protocol violation: cancel/retire, do not
spawn another handler or hold a queued command. A reader may retain at most one
bounded in-progress frame in addition to that task's bounded buffers.

Before OpenApplication cache sessionID, binding digest and expected ordinal.
Its validator performs only bounded envelope validation/copy and frame-kind
checks. No backend, Handler, I/O, state getter, callback or reentrant State call
is permitted there. Commit pending/task state only after it returns successfully.
The reader continues reading during Exec, so EOF/authentication error/owner loss
cancels the work context immediately; it does not wait for Exec's natural end.

On the host, replace the idle reader with the sole bounded response reader from
the moment authenticated readiness completes; never stop one reader and start
a competing RoundTrip reader. Readiness-only mode still retires on any byte.
The selected mode rejects unsolicited, duplicate, wrong-frame, wrong-session,
wrong-binding and wrong-request responses. Install one pending request under
the controller mutex before writing; no I/O/joins under that mutex. Concurrent
RoundTrip returns busy without canceling the existing request. An admitted
request uses one bounded writer and one response slot; no automatic resend.

Use original H = min(session hard expiry, retained stream hard deadline, owner
deadline), never a new lifetime per work request. Initial A/D still govern
readiness only. Exec timing further narrows H through the existing Handler.
The host caller's deadline narrows its operation; cancellation after admission
retires/closes the whole selected connection, causing guest EOF cancellation.
Invalid/pre-canceled calls before admission do not consume or cancel another
operation. A canceled caller may stop waiting only with owned cleanup still
retained; it cannot transfer or abandon writer/reader ownership.

Shutdown order is sticky loss/cancel; close original I/O outside locks; join
reader plus active preparation/handler/writer; revoke session and destroy owned
buffers/key copies; return transport control to Server.Serve so its existing
operation tracking/backend close runs. This orders explicit owner Revoke;
session's existing immediate fail-locked cryptographic revocation is unchanged.
No join inside a state validator or reader self-close path. Server cleanup has
a timeout and Linux exec can retain
a reaper after its short wait expires: transport join alone is not proof all
guest processes disappeared. Backend cleanup failure remains failure, and
unjoined cleanup retains ownership pending VM/host containment, never success.

Retain a fully received/correlated response before an outward late cancellation.
Return its exact inner bytes to the existing Client so its established CopyIn
publication/durability-uncertain rule remains effective; do not replace a known
publication with a retry-safe transport cancellation. An absent/truncated/lost
reply is ambiguous, never evidence that Exec/CopyIn did not happen. No retry
relaunch, durable convergence or host terminal result is inferred.

Clear owned mutable plaintext/encoded buffers on success/failure/partial reads
after their consumers join. V1 JSON strings and existing backend copies are not
a proven secret-wiping channel: these exec/copy messages carry ordinary work,
not credential delivery. Errors stay existing sanitized codes; never log raw
frames, args, env, copied content or panic payloads. Preserve output/artifact
bytes; redaction remains at the established caller/log boundary.

## Actual selected entry and image prerequisite (later slice)

`tools/microvm/l8-minimal/rootfs-overlay/sbin/init:9` mounts an unaliased private
uid/gid1000 workspace tmpfs and invokes hal-init with --require-l7-network, then
setpriv and the guest agent. `cmd/hal-guest-init/main_linux_l7.go:39` validates the
single public cmdline before configuring L7 and supplies generated proxy env.
`cmd/hal-guest-agent/main.go:77` currently ignores that config on the minimal
route; only the legacy route calls linuxGuestAgentConfigurationFromLookup.

The later selected command must parse L7 from the same retained cmdline, require
Valid/present, and compare its exact ProxyURL with all four inherited proxy
variables through the existing validatedL7ProxyEnvironment. Missing/partial or
mismatched settings fail before backend/listener; never reload /proc/cmdline or
use job-provided env for boot authority. Reuse fixed /workspace roots, executable
roots and the existing narrow BaseEnvironment builder. Request env cannot
override inherited proxy assignments; retain existing duplicate/name/source
checks and rejecting default resolver, including all secret sources.

Construct the real guestnetwork.NewLinuxNetworkIsolationVerifier from that
retained BootConfig and the selected local process verifier above. Its actual
implementation inspects topology, probes the exact proxy, then reinspects under
a bounded context (`guestnetwork/verifier_linux.go:58`). No metadata-only
substitute is permitted in the command. Its result gates work but does not
upgrade the existing readiness capability or host enforcement claim.

Reuse NewLinuxBackend without relaxing verifyLinuxWorkspaceBoundary
(`guest/server/backend_linux.go:331`): distinct filesystem, exactly one mount,
retained nofollow descriptors. Ordinary host temp directories are not fixtures
for this constructor. Real backend acceptance needs an explicitly authorized
isolated mount fixture or prepared guest, followed by exact rebuilt release
images and live exec/copy/cancel/teardown. Same UID for agent and workload is
the reset topology, not privilege separation or guest seccomp evidence.

## Dependency-ordered RED and ownership

1. First compiling RED: an explicitly injected WorkloadTransport adapter may
   delegate unchanged NewBootstrap.Serve while ignoring the handler. Run the
   real enclosing Server.Serve with counted fake Backend/local inspection,
   actual bootstrap pins, shared cryptographic handshake and old readiness
   golden. Send an exact-bound authenticated exec and expect the backend call;
   current readiness-only connection rejects it. No real backend/entrypoint
   activation. Keep an independent default NewBootstrap no-work control.
2. Shared envelope golden/bounds plus server common workload dispatch/local
   proof preparation REDs. Every negative must get past real authentication to
   the intended boundary: all binding/session changes, frame/replay/ordinal,
   oversized header before body allocation, malformed inner request, readiness
   smuggling, nil backend/handler/verifier, failed/stale/canceled proof attempts.
   Preserve old server/crypto/readiness/client transcripts and flags.
3. Guest reader/task and host sole-reader adapter in a coordinated slice. Real
   authenticated injected transport/backend fixtures: blocked Exec observes EOF
   before its release; blocked writer/partial frame, H/caller/owner loss, busy
   second request, max output/copy, late published CopyIn, no resend, panic and
   every partial-construction close/join. Verify exact response bytes through
   existing Client, immutable caller buffers and no callbacks under State.mu.
4. Separate selected command/config/local-verifier entrypoint RED, then explicit
   real Linux backend/mount and final-image/live gates. No guard exemptions are
   assumed: actual coupled import/source-guard changes need separate approval.

Prospective ownership: guest minimalcontrol envelope/transport; guest server
common dispatch, selected proof mode and no-request inspector extraction;
host controller/transport adapter; later cmd guest configuration and image
rebuild. Coordinate each shared file with its current owner before work. Do not
change worker schema, producer, supervisor cleanup/preparation/release or session
crypto to make this slice executable.

## Deferred authority and completion

HTTP credential routes, private tmpfs files and SSH-agent relay remain three
separate required implementations. Host Materialize currently creates host
scratch and exposes only target/size/digest/revoke
(`host/l8_job_credential_tmpfs_activator.go:68,140`); it does not deliver bytes
into the guest. Work CopyIn only targets workspace and must not become secret
delivery. A later bounded authenticated private transfer must own guest tmpfs
outside workspace, exact job activation, redaction, revocation and teardown;
the legacy helper-generation protocol cannot be satisfied by invented values.

Actual trusted producer/provider, retained L7 owner/cleanup, J Finalize→durable
worker receipt→Commit, host cleanup on guest loss, credential usable-only-in-job
tests, exact rebuilt image and L10 correlated proof consumers remain required.
A successful injected or real Exec response is workload evidence only, never
proof of strict readiness, credential delivery or terminal resource absence.

## First compiling RED checkpoint

The additive 24-line workload_transport.go scaffold delegates only the existing
NewBootstrap/Serve and deliberately ignores the passed Handler/Limits. No
existing constructor, server dispatch, proof flag, local inspector, host reader,
command, image or guard changes. The explicitly injected L4 server owns its
normal StateServing; no test writes cached state or calls v1 readiness.

The first actual wire test completes bootstrap/Finished/readiness, verifies the
enclosing server is still serving, and sends an independently encoded, small
exact-binding/session operation carrying a valid v1 exec. Its expected backend
call fails with calls=0 and a transport failure. This proves the missing dispatch
boundary, not any later operation parser, proof-mode or cancellation matrix.
The fake backend has no filesystem/process/network authority. Its fixture setup
can later select a real proof-mode API with explicitly fake inspection without
changing the frozen exec/readiness behavior assertions.

`go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/guestagent/minimalcontrol -run '^(TestMinimalWorkload|TestHostReadinessCodecLegacyGolden)'`
reproduced three expected failure events, twelve passing controls and zero
skips. Controls cover actual enclosing serving/readiness without work, unchanged
direct readiness-only rejection, nil backend rejection and the old independent
readiness golden. No production proof or prepared-Linux acceptance was run.

## Shared codec and work-only server compiling RED

The second checkpoint adds only unavailable codec methods and an inert server
entry seam. It does not implement the workload transport or select it in the
guest command. The original 196-line authenticated transport RED is unchanged.

The pure Binding methods are EncodeWorkload(payload, ordinal, sessionID),
DecodeWorkloadRequest(kind, payload, ordinal, sessionID), and
DecodeWorkloadResponse(kind, payload, ordinal, sessionID). They all return
ErrInvalid in this RED. Fixed plaintext/inner bounds and an independently written
golden reuse the existing 27-field readiness digest vector, not a paired new
encoder's output. Empty/non-JSON inner bytes are opaque at this layer; the
existing server parser rejects invalid requests later. Exact decoded max+1 must
fail even when padded base64 still fits the maximum outer length.

The additive server interfaces are WorkloadHandler with PrepareWorkload(ctx)
and HandleWorkload(ctx, Request), and WorkloadIsolationVerifier with
VerifyWorkloadIsolation(ctx) (IsolationProofResult, error). Options retains an
explicit WorkloadIsolationVerifier. The sole existing constructor change permits
either the existing legacy verifier or this local verifier to satisfy the
required-verifier presence check. Both work-proof flags remain true in selected
Serve fixtures. New mode-exclusivity/flag validation is deliberately missing
and separately reached by constructor REDs; this intermediate scaffold must not
be integrated as a usable selected mode. PrepareWorkload remains unavailable;
HandleWorkload delegates unchanged Handle. Neither sets proof/lifecycle flags,
invokes the retained local verifier, nor manufactures a legacy proof request.

The new server fixture enters actual Server.Serve through an injected transport,
receives its actual handler, and cancels/joins Serve before checking exact backend
Close. No test assigns StateServing or isolationProven. Local process/network
results are explicitly fake observations from existing L7 fixtures, not inspected
guest or host authority. Reached failures establish legacy readiness side effects,
missing local preparation, accepted incomplete/mixed selected options, and an
unselected server dispatching through the new entry. Callback-dependent
stale/canceled/fresh-proof/timing checks and the codec mutation/correlation matrix
are guarded by valid-entry assertions which currently fail: these later checks
are specified, not claimed as exercised acceptance. Original legacy exec,
malformed inner parsing, absent/typed-nil verifier, pre-canceled preparation,
independent golden and readiness-only controls are executed.

`go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/guestagent/server ./internal/sandboxruntime/microvm/guestagent/minimalcontrol -run '^(TestWorkloadDispatch|TestWorkloadCodec|TestMinimalWorkload|TestHostReadinessCodecLegacyGolden)'`
produces 114 expected test failure events, 45 passing controls, and zero skips.
This is a compiling RED checkpoint only; shared parser/predicate extraction,
local proof implementation and all coordinated authenticated I/O remain pending.

## Codec and injected work-only dispatch GREEN scope

The subsequent bounded implementation supplies the three pure codec methods
and selected server dispatch/preparation, not the authenticated workload
transport. Fixed expected prefix/suffix bytes bind the complete existing digest,
nonzero session, nonzero expected ordinal and frame direction. The middle is
only canonical padded base64. Outer length is checked first; exact decoded size
(including terminal padding) is checked before allocating owned inner bytes.
An explicit alphabet check rejects CR/LF which Go's strict base64 decoder would
otherwise ignore. The strict decoder rejects nonzero padding bits. No generic
JSON object or alternate v1 schema is decoded by this envelope codec.

The selected server requires both proof options explicitly true and rejects
legacy verifier/client mixing, including typed-nil local configuration. Existing
Handle is the sole strict classifier, and its selected branch rejects readiness
before any backend/proof attempt. HandleWorkload is unavailable on a legacy
server. The existing timed exec/copy handlers and publication responses remain
shared; the existing process/network predicates have one definition used by
both legacy readiness and the selected inspector.

PrepareWorkload runs Ready and the injected local verifier inside a tracked
non-state-changing backend call. Valid selected work reserves the existing
bounded permit and runs a fresh local inspection inside that tracked lifetime,
after the shared strict request validation/timing setup. Callbacks are outside
server.mu. Only the current attempt, live context and still-serving lifecycle
may publish the existing private isolationProven observation. Late older
failures cannot clear a newer success; older successes cannot overwrite a
newer failed attempt. Local verifier/Ready errors and panics remain fixed and
redaction-safe, and every path releases the tracked call/permit.

No extra boolean grants authority. In particular, a cached false observation
does not permanently prevent inspection: a later valid work call can recover
only through its own fresh successful check. Malformed protocol requests and
pre-canceled work do not inspect. Work admission is not an assertion that
Prepare already ran; the future selected transport must run preparation before
its first readiness response. Existing copy-in publication results continue to
outrank a cancellation observed after publication, with uncertainty preserved.

The local verifier is still only an explicit injected interface. The concrete
Linux no-request sibling and actual retained L7 boot/proxy consumption require a
separate body-equivalence RED before implementation; no result in this slice
claims a real process/network inspection. The workload transport scaffold and
its original authenticated-exec RED are unchanged and still fail as expected.
All transport, host reader, guest command, credentials, prepared workspace and
image/live/terminal acceptance dependencies listed above remain incomplete.
