# Selected minimal authenticated control: design and executable RED

## Status and authority

This is DESIGN/RED only against `3a8430e778dd2ec3c009cd9b557cda2c59262b4d`.
There is no production implementation, selected minimal listener, credential
activation, new readiness proof, or live acceptance in this change. GREEN needs
review of this fixed revision first. The authority is the selected fresh-VM/job
contract in [the L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md),
not the historical helper topology. L7 owns enforcement, L8 owns credentials,
and L10 owns strict selection. Their current fail-closed dependencies remain.

The first slice is a pure minimal readiness codec plus an injectable,
authenticated guest connection handler. Proposed package:
`internal/sandboxruntime/microvm/guestagent/minimalcontrol`. Its construction
receives immutable public boot/session identity, complete job/network binding,
pinned controller public key, an injected listener, clock and randomness. It
does not construct a listener, process, network policy, credential owner or
workload backend. Only the injected test adapter changes to that constructor in
GREEN; production entrypoint/host wiring requires a separate reviewed slice.

## What exists and why it is insufficient

- `cmd/hal-guest-agent/main.go` constructs `vsock.ListenLinux` on port 1024,
  the one-frame v1 transport and `server.New`. `server/protocol.go` rejects
  every non-v1 version before dispatching readiness/work. It has no minimal
  authenticated session entrypoint.
- `guestagent/session` already implements bounded X25519/Ed25519 handshake,
  exact identity matching, Finished, AES-GCM records, expiry, replay and
  revocation. Reuse it unchanged. A control-channel `session.Identity` forbids
  job/activation/relay generations; do not change that legacy rule to add a job.
- `guestagent/v2control/readiness.go` promises service UID/GID 998, workload
  UID/GID 1000, `helper_exact_pid`, `guest-helper-v1`, file and SSH support.
  `firecrackerhost/l8_v2_control_session.go` consumes that exact contract. Those
  are historical v2 claims, not truthful minimal readiness.
- `tools/microvm/l7/rootfs-overlay/sbin/init` mounts proc/dev/sys, private `/run`,
  `/tmp`, and a UID/GID 1000 workspace, then runs root `hal-init` and `setpriv`.
  `cmd/hal-guest-init/main_linux_l7.go` configures networking before releasing
  the agent start gate. The agent and workload run as UID/GID 1000 with groups
  and capability sets cleared and no-new-privileges. No agent/workload UID
  separation or installed guest seccomp filter is evidenced.
- `ProcessLifecycleManager.StartProcess` retains the actual process only after
  the runner returns. `ProductionVsockBridge.ActivateSession` creates a vsock
  generation only after **v1** readiness. The existing v2 connector requires
  that active session, while retaining exact process/socket owner currentness.
  Reusing it unchanged would impose an incorrect v1 prerequisite.

## Isolation decision and forbidden claims

Same UID 1000 is compatible with one fresh VM per job, under an explicitly
hostile-guest assumption. It is not isolation between agent and workload.
Same-job code may signal, inspect or interfere with the agent and may retain
job-readable plaintext. A handshake authenticates the controller to the guest;
host confidence that the stream belongs to the selected VM comes from retained
Jailer/process/vsock authority, not guest executable attestation. Neither
cryptography nor another guest UID makes an authorized malicious job truthful.

The host must scope every later operation to one immutable worker/execution/
job/network/runtime tuple. Guest input may not select another credential,
policy, relay operation, route, path on the host, or generation. HTTP credential
injection and SSH private keys remain host-owned. The guest may only exercise
the explicitly authorized job capability. There is no reuse, pool, reconnect
into a prior job, or snapshot with credentials.

Guest readiness, exit, revoke, unlink or mount acknowledgments are **never**
terminal absence proof. On success/failure/cancel/loss/restart the single host
owner first revokes routes, tickets and relays, zeroes buffers and persists safe
cleanup intent; it then observes exact VM/cgroup termination and retained
resource cleanup. Jailer/network release remains ordered by existing owners.
Guest interference produces failed/quarantined cleanup, never successful
completion based solely on an ACK. A destroyed VM cannot replace host cleanup.

Initial readiness claims exactly `authenticated_minimal_control`. It makes no
credential usability, exec/copy, helper, UID separation, seccomp, network
enforcement, or cleanup claim. It is not an L8 active/cleanup proof and cannot
unlock strict selection. Historical v1/v2 paths keep their existing semantics.

## First-slice protocol and binding

The label is `guest-agent-minimal-v1`, distinct from `guest-agent-v1` and
`guest-agent-v2`. The deterministic first-slice transport begins with the
existing 4-byte bounded frame containing only that `protocolVersion` and
`operation: readiness`. Expected identity and binding are injected, not read
from this untrusted prelude. Actual late-identity delivery is a later step below.

After the prelude, exchange the **unchanged** `session` GuestHello and
ControllerAuth handshake frames, then guest Finished followed by controller
Finished. No application bytes are processed before both Finished messages.
Use the unchanged control channel, CID 3, port 1025 and record types. Both sides
reject any mismatch in nonce, controller-key generation, runtime ID/generation,
retained process/vsock generation, boot generation, image generation or digest.

The first encrypted `FrameTypeControlRequest` is one canonical JSON object:

```json
{"body":{"binding":{},"bindingDigest":"sha256-<64 lowercase hex>"},"operation":"readiness","protocolVersion":"guest-agent-minimal-v1","requestId":"<32 lowercase hex>"}
```

The displayed empty binding is a schema illustration and is invalid on wire.
The binding has exactly these 27 required string fields (no null/defaults):

```text
sandboxId executionId workerId hostId
runtimeDriver runtimeId runtimeGeneration processGeneration vsockGeneration
bootGeneration imageGeneration imageDigest
workerJobId submissionId planId jobGeneration
admissionGrantId admissionRevision principalId templatePolicyId workspacePolicyId
networkPlanId policySnapshotId proxySessionId proxyGenerationId
topologyGenerationId ruleGenerationId
```

Safe IDs use bounded nonempty ASCII `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`;
`runtimeDriver` is exactly `microvm`, `imageDigest` is nonzero `sha256-` plus
64 lowercase hex, and `admissionRevision` is canonical decimal uint64 greater
than zero. Require nonzero boot nonce, image digest and session ID. The host
pins every binding field, not merely its digest. Runtime fields must also equal
the handshake identity. `jobGeneration` is a fresh admission correlation token,
not a fake credential activation/helper generation or a new durable store.

The last six fields map to the existing L7 identity: plan, policy snapshot,
proxy session/generation, topology generation and rule generation. Match its
sandbox/execution/worker/runtime fields as well. Namespace/TAP/rule ownership
stays behind that retained L7 owner, not a new parallel namespace-ID scheme.
These are correlations, not evidence of active enforcement. Do not reuse
`JobCredentialIdentitySeed` as the first-slice binding: it requires credentials
and forbids its network tuple for non-HTTP modes, whereas selected strict
minimal readiness needs the L7 tuple regardless of later credential mode.

Define the digest byte-for-byte as SHA-256 of:

1. ASCII `hal/guest-agent-minimal-v1/readiness-binding/v1` followed by NUL;
2. the raw 32-byte established session ID;
3. uint16 big-endian field count (27);
4. each key in ascending ASCII order: uint16 big-endian key byte length, raw
   key bytes, uint16 big-endian value byte length, raw value bytes.

Expose the result only as `sha256-` plus lowercase hex. No raw secret or
session key is in this binding; the public session identifier is not a key.
Domain separation, lengths, count and session ID prevent ambiguous joins,
profile substitution and cross-session reuse. Validate all fields before
hashing/comparison; hashing invalid or incomplete input never makes it valid.

JSON is compact, with exact unescaped field names and ascending key order in
every object. Reject duplicate/case-alias/unknown keys at every depth, nulls,
wrong types, escaped aliases, noncanonical values, trailing/multiple objects,
excess depth and excess bytes. The first-slice maximum plaintext is 8192 bytes,
stricter than the unchanged session control-record maximum. Check frame and
ciphertext lengths before allocation. Use one narrow codec, not another
generic schema framework or changes to historical v2 decoding.

A successful encrypted `FrameTypeControlResponse` has exactly the matching
version, operation and request ID, `ok: true`, and body containing the matching
binding digest, `guestSessionGeneration` (raw-URL base64 of session ID), and
`capabilities: ["authenticated_minimal_control"]`. No extra capability is
accepted. Invalid framing/authentication/identity/binding closes and revokes
the connection without a success response or fallback. Transport EOF is not
guest cleanup evidence. Readiness is one-shot; both repeated ciphertext and a
fresh sequence replaying readiness close the session.

The server receives immutable copies, not caller-owned mutable maps/key slices.
Use one active connection and one bounded pending accept; at most three total
pre-auth attempts per boot, no reset by reconnect. `GenerationGate` can own
claim/replay exhaustion, but its `Ready()` is NOT authenticated readiness and
`Lose()` before authentication does not cancel pending attempts. The new
acceptor must close listener/pending streams on cancellation, owner loss or
boot deadline independently, then join all handlers. Enforce the existing
5-second handshake deadline including provisional prelude and Finished;
readiness must complete within the same initial deadline. An idle established
connection is still bounded by the existing 35-minute session hard expiry and
caller lifetime. Failed authentication consumes an attempt. Once claimed,
loss is terminal: revoke state, notify the host owner, no reconnect/fallback.

## Boot and host producer handoff (not implemented here)

Full actual process/vsock generations do not exist before launch. Do not invent
them to fit a kernel command line. Before launch, the existing host owner can
freeze public controller key/key generation, fresh boot nonce, runtime/boot/
image identity and a prelaunch job/L7 digest. All job/admission/policy and L7
generations must already exist at this point; otherwise launch is blocked.
The prelaunch digest uses the binding encoding above without session ID or the
two late process/vsock fields, under the separate NUL-terminated domain
`hal/guest-agent-minimal-v1/prelaunch-binding/v1` (count 25).

Deliver only those public pins through an exact host-rendered, measured boot
configuration. Existing `guestnetwork/boot.go` and Firecracker L7 boot rendering
provide a 4-KiB total-command-line, duplicate/unknown/partial fail-closed
precedent. A dedicated bounded public minimal config loader must validate its
own keys, profile and encoding; it must not trust workspace or job environment.
Root PID1 validates before dropping privileges; immutable public inputs can
be read from `/proc/cmdline` by the agent. Host image inspection/config digest
must correlate the exact pins and selected bootstrap. A rootfs image digest
does not recursively include the config digest. Oversized pins fail before
launch; never truncate them or replace the expected artifact with a new hash.

After the exact Jailer process and socket are retained, issue the late actual
process/vsock generations. A separately specified bounded public prelude may
supply these provisional fields to the guest. The guest checks all prelaunch
pins and structural bounds, then echoes the full identity in GuestHello. The
existing ControllerAuth signature authenticates that complete transcript;
there is no new cryptographic scheme or trust in an unsigned late field.
Discard all provisional state on failure. The full encrypted readiness binding
must correlate those late fields and the prelaunch digest before promotion.
Private controller/signing keys, session secrets and raw credentials never
enter argv, environment, image, workspace, logs or durable state.

Reuse the existing retained process/socket identity checks, private parent/UID
checks, peer credentials, owner-loss notifications, deadlines and lifecycle
cleanup. Separate **transport availability** from v1 readiness admission:
extract the narrow retained stream authority from the existing owner rather
than requiring a v1 ready session or treating socket presence as readiness.
This later step touches existing owner wiring and therefore needs independent
review; it is not authorized by the first-slice test constructor.

The selected minimal profile must open only its authenticated entrypoint.
Leaving unauthenticated v1 exec/copy on port 1024 would bypass the boundary.
Legacy/default v1 still selects its current path; explicit minimal profile
with missing/bad metadata fails, never falls back. A first-slice connection
handler does not justify changing the default binary selection or listener.

## Dependent network, workload and credential slices

1. **N / authenticated network readiness:** exact host L7 owner, retained
   namespace/TAP/rule inspection and guest immutable-boot network checks must
   agree. Carry any guest observation over authenticated control, not a v1
   bypass, and keep it separate from this modest readiness capability. Review
   strict Jailer config/NIC correlation with its owner; do not relax its config
   allowlist. Socket readiness alone proves neither topology nor enforcement.
2. **C / workload admission:** add bounded authenticated exec/copy separately,
   with pinned job binding, no arbitrary host authority and no early workload
   backend call. New operation support needs behavioral REDs before its label
   is advertised. Preserve L7-before-work and actual terminal process handling.
3. **C / credentials:** reuse `L8JobCredentialRuntime` and its host activators,
   handle store, loss/recovery and terminal owner. Its current guest interface
   and `CompleteJobCredentialIdentity` require a historical helper generation.
   A reviewed explicit minimal profile/identity completion seam is needed;
   never synthesize a helper generation or weaken the legacy validator. Bind
   later activation/binding IDs, mode, expiry and relay job identity to this
   authenticated readiness. HTTP values and SSH private keys remain host-side.
4. **Tmpfs:** the existing root PID1 may mount a bounded dedicated private
   tmpfs before `setpriv`, outside workspace/rootfs; the agent can then perform
   bounded fd-relative regular-file operations with restrictive permissions.
   No extra UID/helper is justified merely by preference. Exact mount identity,
   symlink/replacement rejection, guest partial failure and terminal VM absence
   require their own REDs. This changes B2 bootstrap/permissions and must be
   agreed with its owner, rebuilt and verified; this design does not change it.
5. **Selected acceptance:** rebuild exact final guest binaries/image, then run
   real Jailer-owned network/control/job/three-mode credential usability,
   failure, cancellation, restart, isolation and redaction/absence tests. Keep
   historical v2/D7/HL8E and selected live dependency stubs fail-closed. Do not
   replace them with constructor success, fake readiness, renamed proof or
   skips. Strict default selection remains a later correlated L10 decision.

## Executable RED and its limits

`cmd/hal-guest-agent/minimal_control_red_test.go` deliberately adapts the actual
current `vsock.NewTransport` + `server.New` construction with an in-memory
`io.Pipe` listener and a backend that counts/rejects work. It does not pretend
there is a minimal endpoint. Production v1 dispatch currently returns a framed
`unsupported_protocol_version`, not a parseable cryptographic GuestHello.
This is the observed protocol gap, not a missing-symbol/source-shape test.

Every new rejection case first requires a real parseable GuestHello; application
rejection cases additionally require Finished. Today they all fail at the
absent GuestHello. Consequently missing/mismatched
binding, wrong key, cross-runtime, duplicate-key, replay and cancellation
assertions are frozen future acceptance requirements, **not already exercised
negative protocol evidence**. GREEN must retain their full transcripts while
replacing only the explicit adapter construction with production minimal code.
The legacy constructor has separate passing rejection assertions and may not
be changed to accept either new minimal or historical v2 labels.

The independent 2-second watchdog fails the test if it must close a stuck pipe;
it is not counted as product cancellation/deadline behavior. All server
goroutines are joined. No sockets, listeners bound to the host, subprocesses,
KVM, privileges, credentials or network are used. Before GREEN acceptance add
focused codec bounds/alias tests, deterministic clock expiry and three-attempt/
one-claim tests around the real new acceptor; existing session tests alone do
not prove acceptor integration. Host producer, public boot delivery, actual
listener selection, network/credential activation and live cleanup remain
missing dependencies even if this first slice later becomes green.

Focused commands (the two `RED` tests intentionally fail at this revision):

```sh
go test -p 2 ./cmd/hal-guest-agent -run '^TestMinimalControlRED' -count=1
go test -p 2 -race ./cmd/hal-guest-agent -run '^TestMinimalControl' -count=3
go test -p 2 ./cmd/hal-guest-agent -skip '^TestMinimalControlRED' -count=1
go test -p 2 -race ./internal/sandboxruntime/microvm/guestagent/session ./internal/sandboxruntime/microvm/guestagent/v2control -count=1
go vet -p 2 ./cmd/hal-guest-agent
```
